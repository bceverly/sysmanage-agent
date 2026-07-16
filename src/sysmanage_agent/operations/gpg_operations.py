# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
GPG key management operations module for SysManage agent.

Handles the ``install_gpg_key`` and ``remove_gpg_key`` commands the server's
secrets_engine enqueues (GPG Key Management Slice 3).  Imports or removes a GPG
key into/from a target user's (or the host/system) GnuPG keyring and returns a
structured result dict that ``handle_command`` wraps into a ``command_result``.

Design notes
------------
* We locate the gpg binary at call time (``gpg2`` then ``gpg`` on Unix,
  ``gpg.exe`` for Gpg4win on Windows).  Missing gpg is a structured
  ``success: False`` result, never an exception.
* To operate on a *target user's* keyring we run gpg AS that user with their
  ``GNUPGHOME`` pointing at ``<home>/.gnupg`` (created 0700, owned by the user,
  if missing).  On Unix that's ``su -s /bin/sh <user> -c ...``.  On Windows,
  running gpg as an arbitrary user is not feasible from the agent, so we import
  into the current keyring and record the limitation in the result.
* The armored private material is NEVER logged.  We log fingerprints, key_ids,
  usernames and gpg return codes only.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from src.i18n import _

# gpg import/list/delete rarely take long, but a wedged gpg-agent could hang
# forever.  Bound every gpg invocation.
_GPG_TIMEOUT_SECONDS = 120


class GpgOperations:
    """Handles installing and removing GPG keys in user/host keyrings."""

    def __init__(self, agent_instance):
        """Initialize GPG operations with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

    # ================================================================
    # gpg binary discovery
    # ================================================================

    @staticmethod
    def _find_gpg() -> Optional[str]:
        """Return the path to a usable gpg binary, or None if none is found.

        Prefers ``gpg2`` then ``gpg`` on Unix; ``gpg.exe`` (Gpg4win) on
        Windows.  ``shutil.which`` also resolves ``gpg`` on Windows when the
        Gpg4win bin dir is on PATH, so we try the bare names too.
        """
        candidates: List[str]
        if platform.system() == "Windows":
            candidates = ["gpg.exe", "gpg2.exe", "gpg", "gpg2"]
        else:
            candidates = ["gpg2", "gpg"]
        for name in candidates:
            found = shutil.which(name)
            if found:
                return found
        return None

    # ================================================================
    # target-user resolution
    # ================================================================

    @staticmethod
    def _resolve_user_home(target_username: str) -> Optional[str]:
        """Return the target user's home directory, or None if the user does
        not exist.  Unix-only lookup via the ``pwd`` module."""
        try:
            import pwd  # pylint: disable=import-outside-toplevel

            return pwd.getpwuid(pwd.getpwnam(target_username).pw_uid).pw_dir
        except (KeyError, ImportError):
            return None

    def _ensure_gnupg_dir(self, target_username: str, home: str) -> Optional[str]:
        """Ensure ``<home>/.gnupg`` exists (0700, owned by the user).

        Returns the GNUPGHOME path on success, or None on failure.  Uses
        ``install -d`` under ``su`` so the directory is created *as* the target
        user (correct ownership) even when the agent runs as root.
        """
        gnupghome = os.path.join(home, ".gnupg")
        if os.path.isdir(gnupghome):
            return gnupghome
        # Create it as the target user so ownership + perms are correct.
        try:
            import subprocess  # nosec B404 pylint: disable=import-outside-toplevel

            subprocess.run(  # nosec B603 B607 - fixed argv, no shell
                [
                    "su",
                    "-s",
                    "/bin/sh",
                    target_username,
                    "-c",
                    f"install -d -m 700 {gnupghome}",
                ],
                check=True,
                capture_output=True,
                timeout=_GPG_TIMEOUT_SECONDS,
            )
            return gnupghome
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.error(
                _("Could not create GNUPGHOME %s for user %s: %s"),
                gnupghome,
                target_username,
                exc,
            )
            return None

    # ================================================================
    # subprocess helper: run a gpg invocation, optionally as another user
    # ================================================================

    async def _run_gpg(
        self,
        gpg_path: str,
        gpg_args: List[str],
        *,
        target_username: Optional[str],
        gnupghome: Optional[str],
    ) -> Tuple[int, str, str]:
        """Run ``gpg_path`` with ``gpg_args``.

        If ``target_username`` is set (Unix), the invocation is wrapped in
        ``su -s /bin/sh <user> -c`` with ``GNUPGHOME`` exported so gpg touches
        the target user's keyring.  Otherwise gpg runs directly as the current
        (root/host) user.

        Returns ``(returncode, stdout, stderr)``.  Never raises for the
        subprocess itself timing out — a timeout returns rc=124 with a note in
        stderr.  ``gpg_args`` must NOT contain the armored key material; pass
        the key via a temp file instead.
        """
        run_as_user = bool(target_username) and platform.system() != "Windows"

        if run_as_user:
            # Build a shell command line for su.  Every argument is quoted so a
            # fingerprint or path with odd characters can't break out.  The key
            # material is never here — only paths/fingerprints/flags.
            inner = " ".join(_shell_quote(a) for a in [gpg_path, *gpg_args])
            if gnupghome:
                inner = f"GNUPGHOME={_shell_quote(gnupghome)} {inner}"
            argv = ["su", "-s", "/bin/sh", target_username, "-c", inner]
            env = None
        else:
            argv = [gpg_path, *gpg_args]
            env = os.environ.copy()
            if gnupghome:
                env["GNUPGHOME"] = gnupghome

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=_GPG_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return 124, "", "gpg timed out"
        except FileNotFoundError as exc:
            # su or gpg not found at exec time.
            return 127, "", str(exc)

        stdout = (stdout_b or b"").decode("utf-8", "replace")
        stderr = (stderr_b or b"").decode("utf-8", "replace")
        return proc.returncode or 0, stdout, stderr

    # ================================================================
    # install_gpg_key handler
    # ================================================================

    async def install_gpg_key(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Import a GPG key into the target user's (or host/system) keyring.

        Parameters:
            armored_key      : ASCII-armored key material (required).  NEVER logged.
            fingerprint      : full fingerprint of the key (for verification).
            target_username  : user whose keyring to import into; null/absent =>
                               host-level (root/system keyring).
            key_id           : server-side identifier, echoed back in the result.

        Returns:
            {success, key_id, fingerprint, target_username, detail, [note]}
        """
        armored_key = parameters.get("armored_key")
        fingerprint = parameters.get("fingerprint")
        target_username = parameters.get("target_username")
        key_id = parameters.get("key_id")

        base_result = {
            "key_id": key_id,
            "fingerprint": fingerprint,
            "target_username": target_username,
        }

        if not armored_key:
            return {
                **base_result,
                "success": False,
                "error": _("Missing required parameter 'armored_key'"),
            }

        gpg_path = self._find_gpg()
        if not gpg_path:
            return {
                **base_result,
                "success": False,
                "error": _("gpg binary not found on this host"),
            }

        gnupghome, note, resolve_err = self._prepare_target(target_username)
        if resolve_err:
            return {**base_result, "success": False, "error": resolve_err}

        self.logger.info(
            _("Importing GPG key %s (fingerprint %s) for target=%s"),
            key_id,
            fingerprint,
            target_username or "<host>",
        )

        # Import the armored material via a transient 0600 temp file (never
        # logged, never an argv); the helper always cleans it up.
        returncode, err = await self._import_armored_via_tempfile(
            gpg_path, armored_key, target_username, gnupghome
        )

        if returncode != 0:
            return {
                **base_result,
                "success": False,
                "error": _("gpg import failed (rc=%s): %s") % (returncode, err.strip()),
                **({"note": note} if note else {}),
            }

        # Verify the fingerprint is now present.
        present = await self._fingerprint_present(
            gpg_path, fingerprint, target_username, gnupghome
        )
        result = {
            **base_result,
            "success": bool(present),
            "detail": (
                _("Key imported and verified present")
                if present
                else _("gpg import returned success but fingerprint not found")
            ),
        }
        if note:
            result["note"] = note
        if not present:
            result["error"] = _("fingerprint %s not present after import") % (
                fingerprint,
            )
        return result

    async def _import_armored_via_tempfile(
        self,
        gpg_path: str,
        armored_key: str,
        target_username,
        gnupghome,
    ):
        """Import ``armored_key`` via a transient 0600 temp file.

        Writes the material to a mode-0600 temp file (via the mkstemp fd — not
        the sync builtin open(), which blocks the event loop), chowns it to the
        target user when importing into another user's keyring, runs
        ``gpg --batch --import``, and ALWAYS unlinks the temp file.  Returns
        ``(returncode, stderr)``.  The material never touches a log line or argv.
        """
        tmp_path = None
        try:
            file_descriptor, tmp_path = tempfile.mkstemp(prefix=".sysmanage_gpg_")
            try:
                os.write(file_descriptor, armored_key.encode("utf-8"))
            finally:
                os.close(file_descriptor)
            os.chmod(tmp_path, 0o600)
            if gnupghome and target_username and platform.system() != "Windows":
                self._chown_to_user(tmp_path, target_username)
            returncode, _out, err = await self._run_gpg(
                gpg_path,
                ["--batch", "--import", tmp_path],
                target_username=target_username,
                gnupghome=gnupghome,
            )
            return returncode, err
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    self.logger.debug("Could not remove gpg temp file %s", tmp_path)

    # ================================================================
    # remove_gpg_key handler
    # ================================================================

    async def remove_gpg_key(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove a GPG key from the target user's (or host/system) keyring.

        Parameters:
            fingerprint      : full fingerprint of the key to delete (required).
            target_username  : user whose keyring to delete from; null => host.
            key_id           : server-side identifier, echoed back.
            has_private      : if truthy, delete the secret key first.

        Returns:
            {success, key_id, fingerprint, target_username, detail, [note]}
        """
        fingerprint = parameters.get("fingerprint")
        target_username = parameters.get("target_username")
        key_id = parameters.get("key_id")
        has_private = bool(parameters.get("has_private"))

        base_result = {
            "key_id": key_id,
            "fingerprint": fingerprint,
            "target_username": target_username,
        }

        if not fingerprint:
            return {
                **base_result,
                "success": False,
                "error": _("Missing required parameter 'fingerprint'"),
            }

        gpg_path = self._find_gpg()
        if not gpg_path:
            return {
                **base_result,
                "success": False,
                "error": _("gpg binary not found on this host"),
            }

        gnupghome, note, resolve_err = self._prepare_target(
            target_username, create_missing=False
        )
        if resolve_err:
            return {**base_result, "success": False, "error": resolve_err}

        self.logger.info(
            _("Removing GPG key %s (fingerprint %s) for target=%s, has_private=%s"),
            key_id,
            fingerprint,
            target_username or "<host>",
            has_private,
        )

        # Delete the secret key first if it exists.  A "no secret key" error is
        # not a failure — the public-key delete below is the real gate.
        if has_private:
            await self._run_gpg(
                gpg_path,
                ["--batch", "--yes", "--delete-secret-keys", fingerprint],
                target_username=target_username,
                gnupghome=gnupghome,
            )

        returncode, _out, err = await self._run_gpg(
            gpg_path,
            ["--batch", "--yes", "--delete-keys", fingerprint],
            target_username=target_username,
            gnupghome=gnupghome,
        )

        # Success is defined by the key being gone afterward, not purely by rc
        # (delete-keys returns nonzero when the key was already absent, which
        # for a removal request is still the desired end state).
        still_present = await self._fingerprint_present(
            gpg_path, fingerprint, target_username, gnupghome
        )
        if not still_present:
            result = {
                **base_result,
                "success": True,
                "detail": _("Key removed"),
            }
        else:
            result = {
                **base_result,
                "success": False,
                "error": _("gpg delete failed (rc=%s): %s") % (returncode, err.strip()),
            }
        if note:
            result["note"] = note
        return result

    # ================================================================
    # shared helpers
    # ================================================================

    def _prepare_target(
        self, target_username: Optional[str], *, create_missing: bool = True
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Resolve the GNUPGHOME + any limitation note for a target.

        Returns ``(gnupghome, note, error)``:
          * host-level (no target_username): (None, None, None) — gpg uses the
            current user's default keyring.
          * Windows + target_username: (None, <limitation note>, None) — we
            can't run as another Windows user, so import into the current
            keyring and flag it.
          * Unix + target_username: resolve home, ensure ~/.gnupg; on unknown
            user return an error string.
        """
        if not target_username:
            return None, None, None

        if platform.system() == "Windows":
            note = _(
                "Running gpg as a specific Windows user is not supported by the "
                "agent; imported into the current keyring instead."
            )
            return None, note, None

        home = self._resolve_user_home(target_username)
        if not home:
            return None, None, _("target user '%s' does not exist") % (target_username,)

        if create_missing:
            gnupghome = self._ensure_gnupg_dir(target_username, home)
            if not gnupghome:
                return (
                    None,
                    None,
                    _("could not prepare GNUPGHOME for user '%s'") % (target_username,),
                )
        else:
            gnupghome = os.path.join(home, ".gnupg")
        return gnupghome, None, None

    def _chown_to_user(self, path: str, target_username: str) -> None:
        """Best-effort chown of ``path`` to the target user (Unix only)."""
        try:
            import pwd  # pylint: disable=import-outside-toplevel

            entry = pwd.getpwnam(target_username)
            if hasattr(os, "chown"):
                os.chown(path, entry.pw_uid, entry.pw_gid)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug(
                "Could not chown gpg temp file to %s: %s", target_username, exc
            )

    async def _fingerprint_present(
        self,
        gpg_path: str,
        fingerprint: Optional[str],
        target_username: Optional[str],
        gnupghome: Optional[str],
    ) -> bool:
        """Return True if ``gpg --list-keys <fingerprint>`` succeeds."""
        if not fingerprint:
            return False
        returncode, _out, _err = await self._run_gpg(
            gpg_path,
            ["--batch", "--list-keys", fingerprint],
            target_username=target_username,
            gnupghome=gnupghome,
        )
        return returncode == 0


def _shell_quote(value: str) -> str:
    """POSIX single-quote a string for safe inclusion in a ``su -c`` command."""
    return "'" + str(value).replace("'", "'\\''") + "'"
