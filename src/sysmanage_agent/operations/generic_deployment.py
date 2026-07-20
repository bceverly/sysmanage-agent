# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Generic deployment operations module for SysManage agent.
Handles generic file deployment and command sequence execution,
enabling server-side orchestration without agent domain knowledge.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import tempfile
from typing import Any, Dict, Optional

import aiofiles
from src.i18n import _

# ``asyncio`` is imported (used by the command-sequence handlers below) and
# also referenced by name in tests that patch
# ``generic_deployment.asyncio.sleep`` /
# ``generic_deployment.asyncio.create_subprocess_exec``; those patches mutate
# the shared ``asyncio`` module object, so they also reach the plan mixin's
# calls in ``generic_deployment_plan``.

# The plan-execution methods live in a mixin to keep this module under the
# per-file line budget; ``GenericDeployment`` mixes it in so every method
# remains accessible on the class exactly as before.
from src.sysmanage_agent.operations.generic_deployment_plan import (
    GenericDeploymentPlanMixin,
)

# Byte-decoding helpers live in ``generic_deployment_helpers`` (imported by both
# this module and the plan mixin to avoid a circular import).  ``_decode_command_output``
# is re-exported here so ``src.sysmanage_agent.wsl.capability`` can keep importing
# it from ``generic_deployment``.
from src.sysmanage_agent.operations.generic_deployment_helpers import (  # pylint: disable=unused-import
    _decode_command_output,
)


class GenericDeployment(GenericDeploymentPlanMixin):
    """Handles generic file deployment and command sequence execution."""

    def __init__(self, agent_instance):
        """Initialize generic deployment with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        # Set by ``apply_deployment_plan`` while a plan is in flight; read
        # by ``_exec_plan_command`` so each subprocess in the plan can
        # write/refresh the per-plan in-flight journal under that ID.
        self._current_plan_message_id: Optional[str] = None

    # ================================================================
    # deploy_files handler
    # ================================================================

    async def deploy_files(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deploy files to the filesystem atomically.

        Parameters:
            files: list of dicts with keys:
                - path: absolute destination path
                - content: file content as string
                - permissions: octal string e.g. "0644" (optional, default "0644")
                - owner_uid: numeric UID (optional, default 0)
                - owner_gid: numeric GID (optional, default 0)

        Returns:
            {success, deployed_files[], errors[]}
        """
        files = parameters.get("files", [])
        if not files:
            return {"success": False, "error": _("No files provided")}

        deployed_files = []
        errors = []

        for file_spec in files:
            path = file_spec.get("path")
            content = file_spec.get("content")

            if not path:
                errors.append("File entry missing 'path'")
                continue
            if content is None:
                errors.append(f"File entry missing 'content' for path '{path}'")
                continue

            try:
                result = await self._deploy_single_file(file_spec)
                if result["success"]:
                    deployed_files.append(result)
                else:
                    errors.append(result.get("error", f"Failed to deploy {path}"))
            except Exception as exc:
                error_msg = f"Error deploying '{path}': {exc}"
                self.logger.error(error_msg)
                errors.append(error_msg)

        return {
            "success": len(deployed_files) > 0,
            "deployed_files": deployed_files,
            "deployed_count": len(deployed_files),
            "errors": errors if errors else [],
            "error_count": len(errors),
        }

    async def _deploy_single_file(self, file_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy a single file atomically using temp file + rename.

        Optional fields on `file_spec` (in addition to path/content/permissions/owner):
            expected_sha256: hex digest the content must match. If provided and
                the SHA-256 of the content doesn't match, the deployment is
                rejected without touching the filesystem. After the atomic
                rename, the on-disk file's hash is verified to match — if not,
                the deployment is rolled back from backup (or the file is
                removed if no backup existed).
            backup: bool, default False. If True and the target path already
                exists, the existing file is copied to <path>.sysmanage.bak
                before the new content is written. The backup is left in
                place on success (admin can clean up); on post-write
                verification failure the backup is restored.
        """
        path = file_spec["path"]
        content = file_spec["content"]
        permissions = file_spec.get("permissions", "0644")
        owner_uid = file_spec.get("owner_uid", 0)
        owner_gid = file_spec.get("owner_gid", 0)
        expected_sha256 = file_spec.get("expected_sha256")
        backup_requested = bool(file_spec.get("backup", False))
        mode = _parse_octal_mode(permissions)

        pre_err = self._verify_pre_write_hash(content, expected_sha256, path)
        if pre_err:
            return pre_err

        parent_dir = os.path.dirname(path)
        if parent_dir:
            try:
                os.makedirs(parent_dir, mode=0o755, exist_ok=True)
            except PermissionError:
                # Agent can't create the parent dir as its unprivileged
                # user (e.g. /var/mirror/<name> when /var/mirror is
                # root-owned).  Don't fail here — ``_write_via_sudo``
                # uses ``install -D`` which creates intermediate
                # directories as root, so a missing parent is fine
                # as long as we fall through to that path.
                self.logger.debug(
                    "Parent dir %s not creatable by agent user; will "
                    "rely on sudo install -D to create it",
                    parent_dir,
                )

        backup_path, backup_err = self._maybe_backup(path, backup_requested)
        if backup_err:
            return backup_err

        try:
            await self._write_atomic(
                parent_dir,
                content,
                mode=mode,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                dest_path=path,
            )
            post_err = self._verify_post_write_hash(path, expected_sha256, backup_path)
            if post_err:
                return post_err
        except PermissionError as exc:
            self._rollback_file(path, backup_path)
            return {
                "success": False,
                "error": f"Permission denied writing '{path}': {exc}",
            }
        except OSError as exc:
            self._rollback_file(path, backup_path)
            return {
                "success": False,
                "error": f"OS error writing '{path}': {exc}",
            }

        self.logger.info(_("Deployed file: %s"), path)
        return {
            "success": True,
            "path": path,
            "permissions": permissions,
            "owner_uid": owner_uid,
            "owner_gid": owner_gid,
            "backup_path": backup_path,
            "verified_sha256": expected_sha256 if expected_sha256 else None,
        }

    def _verify_pre_write_hash(
        self, content: str, expected_sha256: Optional[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Reject content whose hash doesn't match the server-supplied digest."""
        if not expected_sha256:
            return None
        bytes_to_write = content
        if content and not content.endswith("\n"):
            bytes_to_write = content + "\n"
        content_hash = self._sha256_of_content(bytes_to_write)
        if content_hash.lower() == expected_sha256.lower():
            return None
        return {
            "success": False,
            "error": (
                f"Pre-write SHA-256 mismatch for '{path}': "
                f"server expected {expected_sha256}, content hashes to {content_hash}"
            ),
        }

    def _maybe_backup(self, path: str, requested: bool) -> tuple:
        """Snapshot an existing file before overwrite; return (backup_path, error_dict)."""
        if not requested or not os.path.exists(path):
            return None, None
        backup_path = path + ".sysmanage.bak"
        try:
            shutil.copy2(path, backup_path)
            self.logger.debug("Backed up existing file %s -> %s", path, backup_path)
            return backup_path, None
        except OSError as exc:
            return None, {
                "success": False,
                "error": f"Could not back up existing '{path}' before deploy: {exc}",
            }

    async def _write_atomic(
        self,
        parent_dir: str,
        content: str,
        *,
        mode: int,
        owner_uid: int,
        owner_gid: int,
        dest_path: str,
    ) -> None:
        """Write `content` to a sibling temp file, chmod/chown, then rename in place.

        Falls back to ``sudo install`` when the agent process can't write to
        ``parent_dir`` directly (e.g. ``/etc/apt/sources.list.d/`` on a host
        where the agent runs as the unprivileged ``sysmanage-agent`` user).
        Triggered by ``PermissionError`` from the unprivileged path OR when
        the spec declares root ownership and the directory isn't agent-
        writable — keeps the unprivileged fast path for user-owned drops.
        """
        try:
            file_descriptor, tmp_path = tempfile.mkstemp(
                dir=parent_dir, prefix=".sysmanage_deploy_"
            )
        except (PermissionError, FileNotFoundError):
            # PermissionError: parent_dir exists but agent can't write
            # to it.  FileNotFoundError: parent_dir doesn't exist yet
            # because deploy_file caught the os.makedirs PermissionError
            # and skipped creating it.  Both cases hand off to the
            # privileged path, which uses ``sudo install -D`` to
            # create the parent + drop the file as root.
            await self._write_via_sudo(
                content,
                mode=mode,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                dest_path=dest_path,
            )
            return
        try:
            # ``newline=""`` disables Python's universal-newlines
            # translation on the write side.  Without it, Python in
            # text mode on Windows converts every ``\n`` in ``content``
            # to ``\r\n`` on disk — which then breaks the post-write
            # SHA-256 verification (the server computed the hash from
            # the LF-only bytes; the on-disk bytes have extra CRs).
            # Same fix applies regardless of whether content itself
            # has any newlines; cheap to set unconditionally.
            async with aiofiles.open(
                file_descriptor,
                "w",
                encoding="utf-8",
                newline="",
                closefd=True,
            ) as temp_file:
                await temp_file.write(content)
                if content and not content.endswith("\n"):
                    await temp_file.write("\n")
            os.chmod(tmp_path, mode)
            # os.chown is Unix-only — Python doesn't even expose the
            # attribute on Windows.  Skip it there; the file's owner is
            # whatever the agent process is running as, which is what we
            # want anyway (Windows uses ACLs, not numeric UID/GID, and
            # the agent typically runs as LocalSystem or the configured
            # service account).
            if hasattr(os, "chown"):
                os.chown(tmp_path, owner_uid, owner_gid)
            # ``os.replace`` rather than ``os.rename``: rename refuses
            # to overwrite an existing destination on Windows
            # (WinError 183), which breaks every re-deploy.  replace
            # is the documented cross-platform atomic rename — same
            # semantics as rename on POSIX, allows replace on Windows.
            os.replace(tmp_path, dest_path)
        except PermissionError:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            await self._write_via_sudo(
                content,
                mode=mode,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                dest_path=dest_path,
            )
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    async def _write_via_sudo(
        self,
        content: str,
        *,
        mode: int,
        owner_uid: int,
        owner_gid: int,
        dest_path: str,
    ) -> None:
        """Stage the content in /tmp, then ``sudo install`` it to ``dest_path``.

        ``install(1)`` performs an atomic copy + chmod + chown in one shot, so
        the destination is never visible with intermediate permissions.  The
        staged tempfile is removed once install succeeds (or on any failure).
        """
        file_descriptor, staged_path = tempfile.mkstemp(prefix=".sysmanage_deploy_")
        try:
            # ``newline=""`` disables Python's universal-newlines
            # translation on the write side.  Without it, Python in
            # text mode on Windows converts every ``\n`` in ``content``
            # to ``\r\n`` on disk — which then breaks the post-write
            # SHA-256 verification (the server computed the hash from
            # the LF-only bytes; the on-disk bytes have extra CRs).
            # Same fix applies regardless of whether content itself
            # has any newlines; cheap to set unconditionally.
            async with aiofiles.open(
                file_descriptor,
                "w",
                encoding="utf-8",
                newline="",
                closefd=True,
            ) as temp_file:
                await temp_file.write(content)
                if content and not content.endswith("\n"):
                    await temp_file.write("\n")
            # 0o600 — staging file lives in /tmp briefly before
            # ``sudo install`` copies it to dest_path with the spec's
            # final mode.  Owner-only on the staged copy denies other
            # /tmp users a read window even though the destination
            # mode may end up world-readable.
            os.chmod(staged_path, 0o600)
            argv = [
                "sudo",
                "-n",
                "install",
                # ``-D`` creates any missing parent directories under
                # dest_path as root, with mode 0755 by default.
                # Required when the destination tree (e.g.
                # /var/mirror/<name>/) doesn't exist yet and the
                # agent's unprivileged user can't make it itself.
                "-D",
                "-m",
                f"{mode:o}",
                "-o",
                str(owner_uid),
                "-g",
                str(owner_gid),
                staged_path,
                dest_path,
            ]
            # Same safe-cwd / safe-HOME shim as ``_exec_plan_command``;
            # see the docstring there for why ``/nonexistent`` HOME on
            # service-user accounts breaks sudo's PAM session module.
            try:
                shim_cwd = os.getcwd()
                if not os.access(shim_cwd, os.R_OK | os.X_OK):
                    raise OSError("cwd not accessible")
            except OSError:
                # ``tempfile.gettempdir()`` resolves ``$TMPDIR`` /
                # ``$TEMP`` / ``$TMP`` and falls back to the platform
                # default (``/tmp`` on Unix, ``%TEMP%`` on Windows)
                # without a hardcoded literal.  We use this only as
                # ``cwd=`` for the subprocess — no temp file is
                # created here.
                shim_cwd = tempfile.gettempdir()
            shim_env = os.environ.copy()
            shim_home = shim_env.get("HOME", "")
            if not shim_home or not os.path.isdir(shim_home):
                shim_env["HOME"] = shim_cwd
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=shim_cwd,
                env=shim_env,
            )
            _stdout_bytes, stderr_bytes = await proc.communicate()
            if proc.returncode != 0:
                stderr_text = (stderr_bytes or b"").decode("utf-8", "replace").strip()
                raise PermissionError(
                    f"sudo install failed (rc={proc.returncode}): {stderr_text}"
                )
        finally:
            if os.path.exists(staged_path):
                try:
                    os.unlink(staged_path)
                except OSError:
                    self.logger.debug(
                        "Could not remove staged tempfile %s", staged_path
                    )

    def _verify_post_write_hash(
        self, path: str, expected_sha256: Optional[str], backup_path: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Re-hash the on-disk file; roll back from backup on mismatch."""
        if not expected_sha256:
            return None
        on_disk_hash = self._sha256_of_file(path)
        if on_disk_hash.lower() == expected_sha256.lower():
            return None
        rollback_msg = self._rollback_file(path, backup_path)
        return {
            "success": False,
            "error": (
                f"Post-write SHA-256 mismatch for '{path}': "
                f"expected {expected_sha256}, got {on_disk_hash}. {rollback_msg}"
            ),
        }

    @staticmethod
    def _sha256_of_content(content: str) -> str:
        """Return the SHA-256 hex digest of a string, encoded as UTF-8."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _sha256_of_file(path: str) -> str:
        """Return the SHA-256 hex digest of a file's bytes on disk."""
        digest = hashlib.sha256()
        # nosec B108 - server-supplied path, agent controls write
        with open(path, "rb") as fobj:
            for chunk in iter(lambda: fobj.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _rollback_file(self, path: str, backup_path: Optional[str]) -> str:
        """Restore the previous file from backup, if a backup exists.

        Returns a short human-readable status string suitable for inclusion
        in an error message reported back to the server.
        """
        if not backup_path:
            return "No backup available; failed file left in place."
        try:
            # ``os.replace`` rather than ``os.rename``: target file
            # always exists in the rollback path (we just wrote
            # corrupted content there), and Windows ``os.rename``
            # refuses to overwrite an existing destination (WinError
            # 183).  Same fix as the primary _write_atomic path.
            os.replace(backup_path, path)
            self.logger.warning(
                _("Rolled back %s from backup %s after failed deployment"),
                path,
                backup_path,
            )
            return f"Restored from backup {backup_path}."
        except OSError as exc:
            self.logger.error(
                _("Rollback failed for %s from %s: %s"), path, backup_path, exc
            )
            return f"Backup at {backup_path} could not be restored ({exc})."

    # ================================================================
    # execute_command_sequence handler
    # ================================================================

    async def execute_command_sequence(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a sequence of steps in order, stopping on failure.

        Parameters:
            steps: list of step dicts, each with:
                - type: "shell" | "deploy_file" | "wait_condition"
                - For "shell": command, timeout (optional, default 300)
                - For "deploy_file": path, content, permissions (optional)
                - For "wait_condition": command, match, timeout, interval
                - description: human-readable step description (optional)
            progress_message_type: message type for progress updates (optional)
            child_host_id: UUID for progress messages (optional)

        Returns:
            {success, completed_steps, total_steps, results[], errors[]}
        """
        steps = parameters.get("steps", [])
        if not steps:
            return {"success": False, "error": _("No steps provided")}

        progress_type = parameters.get(
            "progress_message_type", "command_sequence_progress"
        )
        child_host_id = parameters.get("child_host_id")

        results = []
        errors = []
        completed = 0

        for i, step in enumerate(steps):
            step_type = step.get("type", "shell")
            description = step.get("description", f"Step {i + 1}")

            # Send progress update
            await self._send_progress(
                progress_type,
                {
                    "step": i + 1,
                    "total_steps": len(steps),
                    "description": description,
                    "status": "running",
                    "child_host_id": child_host_id,
                },
            )

            try:
                if step_type == "shell":
                    result = await self._execute_shell_step(step)
                elif step_type == "deploy_file":
                    result = await self._execute_deploy_file_step(step)
                elif step_type == "wait_condition":
                    result = await self._execute_wait_condition_step(step)
                else:
                    result = {
                        "success": False,
                        "error": _("Unknown step type: %s") % (step_type),
                    }

                results.append(
                    {
                        "step": i + 1,
                        "type": step_type,
                        "description": description,
                        "success": result.get("success", False),
                        "output": result.get("output", ""),
                    }
                )

                if result.get("success"):
                    completed += 1
                else:
                    error_msg = result.get(
                        "error", f"Step {i + 1} failed: {description}"
                    )
                    errors.append(error_msg)
                    self.logger.error(
                        _("Command sequence step %d/%d failed: %s - %s"),
                        i + 1,
                        len(steps),
                        description,
                        error_msg,
                    )
                    # Stop on failure
                    break

            except Exception as exc:
                error_msg = f"Step {i + 1} exception: {exc}"
                errors.append(error_msg)
                results.append(
                    {
                        "step": i + 1,
                        "type": step_type,
                        "description": description,
                        "success": False,
                        "output": str(exc),
                    }
                )
                self.logger.error(error_msg)
                break

        # Send final progress
        final_status = "completed" if completed == len(steps) else "failed"
        await self._send_progress(
            progress_type,
            {
                "step": completed,
                "total_steps": len(steps),
                "description": "Sequence " + final_status,
                "status": final_status,
                "child_host_id": child_host_id,
            },
        )

        return {
            "success": completed == len(steps),
            "completed_steps": completed,
            "total_steps": len(steps),
            "results": results,
            "errors": errors if errors else [],
        }

    async def _execute_shell_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command step."""
        command = step.get("command", "")
        timeout = step.get("timeout", 300)

        if not command:
            return {"success": False, "error": _("Empty shell command")}

        result = await self.agent.execute_shell_command(
            {"command": command, "timeout": timeout}
        )

        success = result.get("success", False)
        output = result.get("result", {})
        if isinstance(output, dict):
            output = output.get("stdout", "") or output.get("output", "")

        return {
            "success": success,
            "output": output,
            "error": result.get("error") if not success else None,
        }

    async def _execute_deploy_file_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a file deployment step."""
        result = await self._deploy_single_file(
            {
                "path": step.get("path", ""),
                "content": step.get("content", ""),
                "permissions": step.get("permissions", "0644"),
                "owner_uid": step.get("owner_uid", 0),
                "owner_gid": step.get("owner_gid", 0),
            }
        )
        return result

    async def _execute_wait_condition_step(
        self, step: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a wait condition step, polling until match or timeout."""
        command = step.get("command", "")
        match_str = step.get("match", "")
        timeout = step.get("timeout", 120)
        interval = step.get("interval", 5)

        if not command:
            return {"success": False, "error": _("Empty wait_condition command")}

        elapsed = 0
        last_output = ""
        while elapsed < timeout:
            result = await self.agent.execute_shell_command(
                {"command": command, "timeout": 30}
            )
            output = result.get("result", {})
            if isinstance(output, dict):
                output = output.get("stdout", "") or output.get("output", "")
            last_output = str(output)

            if match_str in last_output:
                return {"success": True, "output": last_output}

            await asyncio.sleep(interval)
            elapsed += interval

        return {
            "success": False,
            "error": (
                f"Wait condition timed out after {timeout}s. "
                f"Expected '{match_str}' in output. Last output: {last_output[:200]}"
            ),
            "output": last_output,
        }

    async def _send_progress(self, message_type: str, data: Dict[str, Any]) -> None:
        """Send a progress message to the server."""
        try:
            message = self.agent.create_message(message_type, data)
            await self.agent.send_message(message)
        except Exception as exc:
            self.logger.warning(_("Failed to send progress message: %s"), exc)


def _parse_octal_mode(permissions: Any) -> int:
    """Parse an octal-string permission like '0644'; fall back to 0o644."""
    try:
        return int(permissions, 8)
    except (ValueError, TypeError):
        return 0o644
