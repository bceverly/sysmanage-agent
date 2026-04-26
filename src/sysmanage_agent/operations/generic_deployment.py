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


class GenericDeployment:
    """Handles generic file deployment and command sequence execution."""

    def __init__(self, agent_instance):
        """Initialize generic deployment with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

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
            return {"success": False, "error": "No files provided"}

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

        # Parse octal permissions string
        try:
            mode = int(permissions, 8)
        except (ValueError, TypeError):
            mode = 0o644

        # Compute the bytes we will actually write (mirrors the write loop
        # below, which appends a trailing newline if missing). The hash check
        # uses these bytes so the pre-write and post-write hashes agree.
        bytes_to_write = content
        if content and not content.endswith("\n"):
            bytes_to_write = content + "\n"

        # Pre-write integrity check: refuse to deploy content that doesn't
        # match the server-supplied hash (catches corruption in transit).
        if expected_sha256:
            content_hash = self._sha256_of_content(bytes_to_write)
            if content_hash.lower() != expected_sha256.lower():
                return {
                    "success": False,
                    "error": (
                        f"Pre-write SHA-256 mismatch for '{path}': "
                        f"server expected {expected_sha256}, content hashes to {content_hash}"
                    ),
                }

        # Ensure parent directory exists
        parent_dir = os.path.dirname(path)
        if parent_dir:
            os.makedirs(parent_dir, mode=0o755, exist_ok=True)

        # Optional backup: snapshot the existing file before we overwrite it.
        backup_path: Optional[str] = None
        if backup_requested and os.path.exists(path):
            backup_path = path + ".sysmanage.bak"
            try:
                shutil.copy2(path, backup_path)
                self.logger.debug("Backed up existing file %s -> %s", path, backup_path)
            except OSError as exc:
                # If we can't make a backup, refuse rather than overwrite blindly.
                return {
                    "success": False,
                    "error": f"Could not back up existing '{path}' before deploy: {exc}",
                }

        # Write atomically: temp file in same directory, then rename
        try:
            file_descriptor, tmp_path = tempfile.mkstemp(
                dir=parent_dir, prefix=".sysmanage_deploy_"
            )
            try:
                async with aiofiles.open(
                    file_descriptor, "w", encoding="utf-8", closefd=True
                ) as temp_file:
                    await temp_file.write(content)
                    if content and not content.endswith("\n"):
                        await temp_file.write("\n")

                os.chmod(tmp_path, mode)
                os.chown(tmp_path, owner_uid, owner_gid)
                os.rename(tmp_path, path)
            except Exception:
                # Clean up temp file on failure
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

            # Post-write integrity check: re-hash the file we just wrote.
            # Catches truncation, encoding-conversion bugs, or a different
            # process racing us between rename and now.
            if expected_sha256:
                on_disk_hash = self._sha256_of_file(path)
                if on_disk_hash.lower() != expected_sha256.lower():
                    rollback_msg = self._rollback_file(path, backup_path)
                    return {
                        "success": False,
                        "error": (
                            f"Post-write SHA-256 mismatch for '{path}': "
                            f"expected {expected_sha256}, got {on_disk_hash}. {rollback_msg}"
                        ),
                    }

            self.logger.info("Deployed file: %s", path)
            return {
                "success": True,
                "path": path,
                "permissions": permissions,
                "owner_uid": owner_uid,
                "owner_gid": owner_gid,
                "backup_path": backup_path,
                "verified_sha256": expected_sha256 if expected_sha256 else None,
            }

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
            os.rename(backup_path, path)
            self.logger.warning(
                "Rolled back %s from backup %s after failed deployment",
                path,
                backup_path,
            )
            return f"Restored from backup {backup_path}."
        except OSError as exc:
            self.logger.error(
                "Rollback failed for %s from %s: %s", path, backup_path, exc
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
            return {"success": False, "error": "No steps provided"}

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
                        "error": f"Unknown step type: {step_type}",
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
                        "Command sequence step %d/%d failed: %s - %s",
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
            return {"success": False, "error": "Empty shell command"}

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
            return {"success": False, "error": "Empty wait_condition command"}

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
            self.logger.warning("Failed to send progress message: %s", exc)

    # ================================================================
    # apply_deployment_plan handler
    # ================================================================

    async def apply_deployment_plan(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a complete declarative deployment plan.

        A "deployment plan" is what the open-source server's plan_builder
        modules and the Pro+ Cython engines (firewall_orchestration_engine,
        av_management_engine) emit. The agent runs the plan in this order:

            1. packages          (install via existing install_package handler)
            2. files             (atomic deploy via existing deploy_files)
            3. commands          (subprocess.exec, argv-style)
            4. service_actions   (start/stop/restart/enable/disable)
            5. packages_to_remove (uninstall via existing handler)

        Stops on first hard failure unless the failing step has
        ignore_errors=True. The order keeps "install before configure
        before start"; removal happens last so a service is stopped
        cleanly before its package goes.

        Parameters:
            plan: dict with optional keys:
                packages           : list of str OR list of {manager, name, args}
                files              : list of file specs (deploy_files schema)
                commands           : list of command specs:
                    - argv: list[str]              (required)
                    - sudo: bool                    (default False)
                    - elevated: bool                (Windows only; informational)
                    - timeout: int seconds          (default 60)
                    - ignore_errors: bool           (default False)
                    - description: str              (for logs)
                service_actions    : list of {service, action}
                packages_to_remove : same shape as packages

        Returns:
            {success, results: {packages, files, commands, service_actions,
                                packages_to_remove}, errors: [...]}
        """
        plan = parameters.get("plan") or parameters
        results: Dict[str, Any] = {}
        errors: list = []

        # 1. Install packages (if any)
        pkgs = plan.get("packages") or []
        if pkgs:
            pkg_results, pkg_errors = await self._apply_plan_packages(
                pkgs, install=True
            )
            results["packages"] = pkg_results
            errors.extend(pkg_errors)
            if pkg_errors and not _all_pkg_install_optional(pkgs):
                return _plan_result(False, results, errors, "packages")

        # 2. Deploy files
        files = plan.get("files") or []
        if files:
            files_result = await self.deploy_files({"files": files})
            results["files"] = files_result
            if not files_result.get("success"):
                errors.extend(files_result.get("errors", []))
                return _plan_result(False, results, errors, "files")

        # 3. Run commands
        cmds = plan.get("commands") or []
        if cmds:
            cmd_results, cmd_errors, hard_fail = await self._apply_plan_commands(cmds)
            results["commands"] = cmd_results
            errors.extend(cmd_errors)
            if hard_fail:
                return _plan_result(False, results, errors, "commands")

        # 4. Service actions
        svc_actions = plan.get("service_actions") or []
        if svc_actions:
            svc_results, svc_errors = await self._apply_plan_service_actions(
                svc_actions
            )
            results["service_actions"] = svc_results
            errors.extend(svc_errors)
            if svc_errors:
                return _plan_result(False, results, errors, "service_actions")

        # 5. Remove packages
        pkgs_rm = plan.get("packages_to_remove") or []
        if pkgs_rm:
            rm_results, rm_errors = await self._apply_plan_packages(
                pkgs_rm, install=False
            )
            results["packages_to_remove"] = rm_results
            errors.extend(rm_errors)
            if rm_errors:
                return _plan_result(False, results, errors, "packages_to_remove")

        return _plan_result(True, results, errors, None)

    async def _apply_plan_packages(self, pkgs: list, install: bool) -> tuple:
        """
        Install or uninstall a list of packages from a plan.

        Each entry can be a bare string (auto-detect package manager) or
        a dict like {"manager": "pkg", "name": "clamav"} for platforms
        with multiple managers.
        """
        results = []
        errors = []
        for entry in pkgs:
            if isinstance(entry, str):
                pkg_name = entry
                pkg_mgr = None
            elif isinstance(entry, dict):
                pkg_name = entry.get("name")
                pkg_mgr = entry.get("manager")
            else:
                errors.append(f"Bad package entry: {entry!r}")
                continue
            if not pkg_name:
                errors.append("Package entry missing 'name'")
                continue

            try:
                if install:
                    result = await self.agent.install_package(
                        {
                            "package_name": pkg_name,
                            "package_manager": pkg_mgr or "auto",
                        }
                    )
                else:
                    # Use install_packages with a single-entry list for
                    # uninstall — uninstall_packages expects UUID-tracked
                    # entries, install_package only installs. The plan
                    # caller surfaces the manager hint here.
                    result = await self.agent.uninstall_packages(
                        {
                            "packages": [
                                {
                                    "package_name": pkg_name,
                                    "package_manager": pkg_mgr or "auto",
                                }
                            ],
                        }
                    )
                results.append(
                    {
                        "name": pkg_name,
                        "manager": pkg_mgr,
                        "success": bool(result.get("success", False)),
                        "result": result,
                    }
                )
                if not result.get("success", False):
                    errors.append(
                        f"Package {'install' if install else 'remove'} failed for "
                        f"{pkg_name}: {result.get('error') or result}"
                    )
            except Exception as exc:
                errors.append(
                    f"Package {'install' if install else 'remove'} exception "
                    f"for {pkg_name}: {exc}"
                )
                results.append(
                    {
                        "name": pkg_name,
                        "success": False,
                        "error": str(exc),
                    }
                )
        return results, errors

    async def _apply_plan_commands(self, commands: list) -> tuple:
        """
        Run each plan command via asyncio.create_subprocess_exec.

        Stops on the first command whose `ignore_errors` is False AND that
        returned nonzero. Returns (per-command results, accumulated errors,
        hard_fail bool).
        """
        results = []
        errors = []
        for spec in commands:
            argv = spec.get("argv") or []
            if not argv or not isinstance(argv, list):
                errors.append(f"Plan command missing/invalid 'argv': {spec!r}")
                results.append({"argv": argv, "success": False, "error": "no argv"})
                if not spec.get("ignore_errors"):
                    return results, errors, True
                continue

            timeout = int(spec.get("timeout", 60))
            ignore_errors = bool(spec.get("ignore_errors", False))
            description = spec.get("description") or " ".join(argv)
            run_argv = list(argv)
            if spec.get("sudo") and os.geteuid() != 0:
                run_argv = ["sudo", "-n"] + run_argv

            try:
                proc = await asyncio.create_subprocess_exec(
                    *run_argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    errors.append(f"Command '{description}' timed out after {timeout}s")
                    results.append(
                        {
                            "argv": argv,
                            "description": description,
                            "success": False,
                            "error": "timeout",
                        }
                    )
                    if not ignore_errors:
                        return results, errors, True
                    continue

                returncode = proc.returncode or 0
                cmd_ok = returncode == 0
                results.append(
                    {
                        "argv": argv,
                        "description": description,
                        "returncode": returncode,
                        "stdout": stdout.decode(errors="replace")[-2000:],
                        "stderr": stderr.decode(errors="replace")[-2000:],
                        "success": cmd_ok,
                    }
                )
                if not cmd_ok:
                    err_msg = (
                        f"Command '{description}' exited {returncode}: "
                        f"{stderr.decode(errors='replace')[:300]}"
                    )
                    errors.append(err_msg)
                    if not ignore_errors:
                        return results, errors, True
            except FileNotFoundError as exc:
                errors.append(f"Command '{description}' not found: {exc}")
                results.append(
                    {
                        "argv": argv,
                        "description": description,
                        "success": False,
                        "error": f"FileNotFoundError: {exc}",
                    }
                )
                if not ignore_errors:
                    return results, errors, True
            except Exception as exc:
                errors.append(f"Command '{description}' exception: {exc}")
                results.append(
                    {
                        "argv": argv,
                        "description": description,
                        "success": False,
                        "error": str(exc),
                    }
                )
                if not ignore_errors:
                    return results, errors, True

        return results, errors, False

    async def _apply_plan_service_actions(self, actions: list) -> tuple:
        """
        Run each {service, action} pair through the agent's service control.

        Groups by action so we issue one service_control call per action
        with a list of services — matches the existing handler shape.
        """
        # Group: {action: [service, ...]}
        grouped: Dict[str, list] = {}
        for entry in actions:
            action = entry.get("action")
            service = entry.get("service")
            if not action or not service:
                continue
            grouped.setdefault(action, []).append(service)

        results = []
        errors = []
        # Preserved order: enable/disable before start/stop/restart so the
        # boot-time configuration is settled first.
        action_order = ["enable", "disable", "stop", "start", "restart"]
        for action in action_order:
            services = grouped.get(action) or []
            if not services:
                continue
            # Re-use the existing MessageProcessor service_control handler
            # the agent already exposes for the "service_control" command type.
            handler = getattr(
                getattr(self.agent, "message_processor", None),
                "_handle_service_control",
                None,
            )
            if handler is None:
                errors.append(
                    f"No service_control handler available for action '{action}'"
                )
                continue
            try:
                result = await handler({"action": action, "services": services})
                results.append(
                    {
                        "action": action,
                        "services": services,
                        "success": bool(result.get("success", False)),
                        "result": result,
                    }
                )
                if not result.get("success", False):
                    errors.append(
                        f"service_control {action} failed for {services}: "
                        f"{result.get('error') or result}"
                    )
            except Exception as exc:
                errors.append(
                    f"service_control {action} exception for {services}: {exc}"
                )
                results.append(
                    {
                        "action": action,
                        "services": services,
                        "success": False,
                        "error": str(exc),
                    }
                )
        return results, errors


def _all_pkg_install_optional(pkgs: list) -> bool:
    """A package list is 'all optional' if every entry has optional=True."""
    for entry in pkgs:
        if isinstance(entry, dict) and entry.get("optional") is True:
            continue
        return False
    return bool(pkgs)


def _plan_result(
    success: bool, results: Dict[str, Any], errors: list, failed_step: Optional[str]
) -> Dict[str, Any]:
    """Build the final apply_deployment_plan response."""
    return {
        "success": success,
        "results": results,
        "errors": errors,
        "failed_step": failed_step,
    }
