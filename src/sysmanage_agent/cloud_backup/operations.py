# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The storage host's iCloud Photos commands (server ROADMAP 24.12).

* ``cloud_backup_enable`` -- "Enable iCloud backup": install the pinned
  icloudpd, make the cloud root under the storage path (a ZFS dataset there
  when the storage path is one) and the private session directory.  Run
  again, it repairs or upgrades.
* ``cloud_backup_run`` -- one account's job: ``connect`` (sign in, with the
  operator's two-factor code), ``download`` (incremental, ``--until-found``),
  ``reconcile`` (a full pass) or ``libraries``.
* ``cloud_backup_remove`` -- forget an account's sign-in: its session
  directory goes.  Its photos stay where they are.

Each handler checks what the server sent and answers at once; the work runs
in the background and ends with one ``cloud_backup_result`` (progress comes
as ``cloud_backup_progress``).  The password and the code come over HTTPS
from the server, for this run only (``/api/agent/cloud-backup-secret`` and
``/api/agent/cloud-backup-code``), never through a command.
"""

import asyncio
import logging
import os
import platform
import posixpath
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
from typing import Any, Dict, List, Optional, Tuple

from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import storage_prepare
from src.sysmanage_agent.cloud_backup import layout
from src.sysmanage_agent.cloud_backup import runner
from src.sysmanage_agent.cloud_backup import tool

logger = logging.getLogger(__name__)

ZFS_PATHS = ("/usr/sbin/zfs", "/sbin/zfs")
ACCOUNT_MODE = "750"


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def _first(paths: Tuple[str, ...]) -> str:
    return next((p for p in paths if os.path.exists(p)), paths[0])


def _blocking_run(argv: List[str], timeout: int) -> Tuple[int, str]:
    """For ``tool.install`` (off the event loop): exit code and output."""
    try:
        done = subprocess.run(  # nosec B603 - argv built by tool.py
            argv, capture_output=True, text=True, timeout=timeout, check=False,
            cwd="/",
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError) as error:
        return 1, str(error)
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def library_size(directory: str) -> Tuple[int, int]:
    """``(photos and videos, bytes)`` under an account's directory; the
    XMP sidecars count toward bytes only."""
    count = total = 0
    for root, _dirs, files in os.walk(directory):
        for name in files:
            try:
                total += os.lstat(posixpath.join(root, name)).st_size
            except OSError:
                continue
            if not name.lower().endswith(".xmp"):
                count += 1
    return count, total


class CloudBackupOperations:
    """The agent's half of 24.12."""

    def __init__(self, agent_instance, state_dir: str):
        self.agent = agent_instance
        self.state_dir = state_dir
        self._tasks: set = set()
        self._busy: set = set()
        self._startup: Optional[asyncio.Future] = None

    # --- helpers -------------------------------------------------------------

    @staticmethod
    def _privileged(argv: List[str]) -> List[str]:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return list(argv)
        return ["sudo", "-n"] + list(argv)

    @staticmethod
    async def _run(argv: List[str]) -> Tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/",
        )
        out, err = await proc.communicate()
        return (
            proc.returncode,
            (out or b"").decode("utf-8", "replace"),
            (err or b"").decode("utf-8", "replace").strip(),
        )

    async def _checked(self, argv: List[str]) -> None:
        code, _out, err = await self._run(self._privileged(argv))
        if code != 0:
            raise PermissionError(f"{' '.join(argv)}: {err or code}")

    def _spawn(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _send(self, message_type: str, data: Dict[str, Any]) -> None:
        payload = dict(data)
        approval = self.agent.registration_manager.get_host_approval_from_db()
        if approval:
            payload["host_id"] = str(approval.host_id)
        message = self.agent.create_message(message_type, payload)
        if not await self.agent.send_message(message):
            logger.warning("Could not queue the cloud backup report for %s",
                           data.get("run_id"))  # fmt: skip

    async def _result(self, run_id: str, action: str, data: Dict[str, Any]) -> None:
        await self._send(
            "cloud_backup_result", dict(data, run_id=run_id, action=action)
        )

    async def _progress(self, run_id: str, data: Dict[str, Any]) -> None:
        await self._send("cloud_backup_progress", dict(data, run_id=run_id))

    @staticmethod
    def _refusal(reason: str, message: str) -> Dict[str, Any]:
        return {"success": False, "reason": reason, "error": message}

    # --- the server, over HTTPS -------------------------------------------------

    async def _ask(
        self, path: str, run_id: str, session_factory=None
    ) -> Dict[str, Any]:
        """POST the run id with this host's credentials (as the backup key
        fetch does); the JSON answer.  Never logged."""
        # pylint: disable=import-outside-toplevel
        import aiohttp

        from src.sysmanage_agent.core.server_endpoint import ServerEndpoint

        endpoint = ServerEndpoint(self.agent.config)
        approval = self.agent.registration_manager.get_host_approval_from_db()
        host_id = str(getattr(approval, "host_id", "") or "")
        if not host_id:
            raise PermissionError("this host is not approved yet")
        token = await self.agent.get_auth_token()
        host_token = await self.agent.get_stored_host_token()
        factory = session_factory or (
            lambda: aiohttp.ClientSession(**endpoint.session_kwargs())
        )
        async with factory() as session, session.post(
            endpoint.rest_url(path),
            json={"host_id": host_id, "run_id": run_id},
            headers={"Authorization": f"Bearer {token}",
                     "X-Host-Token": host_token or ""},  # fmt: skip
            proxy=endpoint.proxy(),
        ) as response:
            body = await response.json(content_type=None)
            if response.status != 200:
                detail = body.get("detail") if isinstance(body, dict) else None
                raise PermissionError(f"HTTP {response.status}: {detail or 'refused'}")
            return body if isinstance(body, dict) else {}

    async def _password(self, run_id: str) -> str:
        answer = await self._ask("/api/agent/cloud-backup-secret", run_id)
        secret = answer.get("password")
        if not isinstance(secret, str) or not secret:
            raise PermissionError("the server sent no password")
        return secret

    async def _code(self, run_id: str) -> Optional[str]:
        answer = await self._ask("/api/agent/cloud-backup-code", run_id)
        value = answer.get("code")
        if value is None:
            return None
        value = str(value).strip()
        if not (len(value) == 6 and value.isdigit()):
            raise PermissionError("the server sent something that is not a code")
        return value

    # --- the cloud root and each account's place ---------------------------------

    async def _zfs_datasets(self) -> Dict[str, str]:
        zfs = _first(ZFS_PATHS)
        if not os.path.exists(zfs):
            return {}
        code, out, _err = await self._run(
            [zfs, "list", "-H", "-t", "filesystem", "-o", "name,mountpoint"]
        )
        return storage_prepare.zfs_datasets(out) if code == 0 else {}

    async def _owned(self, path: str) -> None:
        """The agent's account owns it, and only it and its group read it."""
        # pylint: disable=import-outside-toplevel
        import grp  # noqa: PLC0415  # Unix only (the Windows CI imports this module)
        import pwd  # noqa: PLC0415

        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        await self._checked(["chown", f"{user}:{group}", path])
        await self._checked(["chmod", ACCOUNT_MODE, path])

    async def _make(self, path: str, storage: str) -> str:
        """``path`` (the cloud root or an account's place, directly under its
        parent) made if missing: a ZFS child dataset where its parent is a
        dataset, else a directory.  Its kind."""
        datasets = await self._zfs_datasets()
        parent = datasets.get(posixpath.dirname(path))
        kind = "zfs" if parent else "directory"
        if path in datasets:
            kind = "zfs"
        elif parent:
            zfs = _first(ZFS_PATHS)
            argv = host_mount.in_host_namespace(
                [zfs, "create", f"{parent}/{posixpath.basename(path)}"],
                platform.system(),
                host_mount.systemd_running(),
            )
            await self._checked(argv)
        elif not os.path.isdir(path):
            if os.path.lexists(path):
                raise PermissionError(f"{path} exists and is not a directory")
            await self._checked(["mkdir", "-m", ACCOUNT_MODE, path])
        if not os.path.isdir(path):
            raise PermissionError(f"{path} is not there after it was made")
        await self._owned(path)
        logger.info("Cloud backup place %s ready (%s, under %s)", path, kind, storage)
        return kind

    def _sessions(self) -> str:
        root = layout.sessions_root(self.state_dir)
        os.makedirs(root, mode=0o700, exist_ok=True)
        # Owner-only, also when it already existed: Apple sessions live here.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(root, 0o700)
        return root

    # --- enable ----------------------------------------------------------------

    async def cloud_backup_enable(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        try:
            run_id = layout.run_id(parameters)
            # Reads the mount table: off the event loop.
            storage = await asyncio.to_thread(
                layout.storage_path,
                parameters.get("storage_path"),
                self.state_dir,
                _read_text,
            )
        except layout.LayoutError as error:
            return self._refusal("invalid_request", str(error))
        if tool.method() is None:
            return self._refusal(tool.REASON_WRONG_PLATFORM,
                                 "icloudpd is not offered on this system")  # fmt: skip
        if "enable" in self._busy:
            return self._refusal("busy", "iCloud backup is already being enabled")
        self._busy.add("enable")
        self._spawn(self._enable(run_id, storage))
        return {"success": True, "started": True, "run_id": run_id}

    async def _enable(self, run_id: str, storage: str) -> None:
        result: Dict[str, Any] = {"status": runner.FAILED}
        try:
            await self._progress(run_id, {"phase": "installing"})
            loop = asyncio.get_running_loop()
            found = await loop.run_in_executor(
                None, tool.install, self.state_dir, _blocking_run
            )
            result.update(tool_version=found["version"], install_method=found["method"])
            await self._progress(run_id, {"phase": "preparing"})
            root = layout.cloud_root(storage)
            kind = await self._make(root, storage)
            self._sessions()
            result.update(
                status=runner.OK, cloud_root=root, detail=f"cloud root: {kind}"
            )
        except tool.ToolError as error:
            result.update(reason=error.reason, message=str(error), detail=str(error))
        except OSError as error:
            result.update(
                reason="prepare_failed", message=str(error), detail=str(error)
            )
        except Exception as error:  # pylint: disable=broad-except
            logger.exception("Enabling iCloud backup failed")
            result.update(reason="internal_error", message=str(error))
        finally:
            self._busy.discard("enable")
        await self._result(run_id, "enable", result)

    # --- an account's job -----------------------------------------------------------

    async def cloud_backup_run(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        try:
            # Both read files (the mount table, the tool marker): off the loop.
            job = await asyncio.to_thread(
                layout.account_job, parameters, self.state_dir, _read_text
            )
        except layout.LayoutError as error:
            return self._refusal("invalid_request", str(error))
        found = await asyncio.to_thread(tool.installed, self.state_dir, _read_text)
        if found is None:
            return self._refusal(tool.REASON_MISSING_TOOL,
                                 "icloudpd is not installed: enable iCloud backup first")  # fmt: skip
        if job["dir_name"] in self._busy:
            return self._refusal("busy", "a job for this account is already running")
        self._busy.add(job["dir_name"])
        self._spawn(self._job(job, found))
        return {"success": True, "started": True, "run_id": job["run_id"]}

    # --- the upgrade as the agent starts ---------------------------------------------

    def start_upgrade(self) -> None:
        """Called once as the agent starts, which every package does after it
        installs or upgrades the agent: an icloudpd that is not this release's
        pin is upgraded now, before any job runs, not at the next idle
        download.  A job that arrives meanwhile waits for it."""
        if self._startup is None:
            self._startup = asyncio.ensure_future(self._upgrade_at_start())

    async def _upgrade_at_start(self) -> None:
        try:
            found = await asyncio.to_thread(tool.installed, self.state_dir, _read_text)
            if found is None or found.get("version") == tool.VERSION:
                return  # never enabled here, or already on the pin
            logger.info("icloudpd %s is not this agent's pin %s: upgrading it",
                        found.get("version"), tool.VERSION)  # fmt: skip
            await self._pinned(found, "")
        except Exception:  # pylint: disable=broad-except
            logger.exception("Upgrading icloudpd as the agent started failed")

    async def _after_startup(self, found: Dict[str, Any]) -> Dict[str, Any]:
        """What is installed once the start-up upgrade is done: it removes the
        old icloudpd, so a job must not start that one meanwhile."""
        startup = self._startup
        if startup is None or startup.done():
            return found
        await asyncio.shield(startup)
        return (
            await asyncio.to_thread(tool.installed, self.state_dir, _read_text) or found
        )

    async def _pinned(self, found: Dict[str, Any], dir_name: str) -> Dict[str, Any]:
        """The installed icloudpd, upgraded to the pin first when it is another
        version: Enable installs once, and an agent upgrade alone would leave
        the old one running.  Only while no other account's job runs (the
        install removes the old one, a venv included) and no Enable does; a
        failed upgrade leaves the old one to run, with a warning."""
        if found.get("version") == tool.VERSION or self._busy - {dir_name}:
            return found
        self._busy.add("enable")
        try:
            loop = asyncio.get_running_loop()
            upgraded = await loop.run_in_executor(
                None, tool.install, self.state_dir, _blocking_run
            )
            logger.info(
                "icloudpd upgraded from %s to %s",
                found.get("version"),
                upgraded["version"],
            )
            return upgraded
        except tool.ToolError as error:
            logger.warning(
                "icloudpd stays at %s: the upgrade to %s failed: %s",
                found.get("version"), tool.VERSION, error,
            )  # fmt: skip
            return found
        finally:
            self._busy.discard("enable")

    async def _icloudpd(
        self, job: Dict[str, Any], executable: str, xmp: bool
    ) -> Dict[str, Any]:
        run_id = job["run_id"]
        return await runner.run(
            layout.argv(executable, job, xmp=xmp),
            action=job["action"],
            session_dir=job["session_dir"],
            password=lambda: self._password(run_id),
            code=lambda: self._code(run_id),
            progress=lambda data: self._progress(run_id, data),
            cwd=job["session_dir"],
        )

    async def _job(self, job: Dict[str, Any], found: Dict[str, Any]) -> None:
        run_id, action = job["run_id"], job["action"]
        result: Dict[str, Any]
        try:
            found = await self._after_startup(found)
            found = await self._pinned(found, job["dir_name"])
            executable, version = found["path"], found.get("version")
            os.makedirs(self._sessions(), exist_ok=True)
            os.makedirs(job["session_dir"], mode=0o700, exist_ok=True)
            # Owner-only, also when it already existed: one account's session.
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.chmod(job["session_dir"], 0o700)
            transfer = action in ("download", "reconcile")
            before = (0, 0)
            if transfer:
                await self._make(job["directory"], job["storage_path"])
                before = await asyncio.to_thread(library_size, job["directory"])
            result = await self._icloudpd(job, executable, xmp=True)
            if (
                transfer
                and result.get("reason") == "xmp_crashed"
                and version in layout.XMP_RETRY_VERSIONS
            ):
                logger.warning(
                    "Cloud backup run %s: icloudpd crashed writing an XMP "
                    "sidecar; trying again without sidecars",
                    run_id,
                )
                result = await self._icloudpd(job, executable, xmp=False)
                if result.get("status") == runner.OK and not result.get("message"):
                    result["message"] = (
                        "Downloaded without XMP sidecar files: icloudpd "
                        f"{version} crashed writing one"
                    )
            result["tool_version"] = version
            if transfer:
                photos, size = await asyncio.to_thread(library_size, job["directory"])
                result.update(photos_local=photos, bytes_local=size,
                              bytes=max(0, size - before[1]))  # fmt: skip
        except OSError as error:
            result = {"status": runner.FAILED, "reason": "prepare_failed",
                      "message": str(error)}  # fmt: skip
        except Exception as error:  # pylint: disable=broad-except
            logger.exception("Cloud backup run %s failed", run_id)
            result = {"status": runner.FAILED, "reason": "internal_error",
                      "message": str(error)}  # fmt: skip
        finally:
            self._busy.discard(job["dir_name"])
        logger.info("Cloud backup %s run %s: %s", action, run_id, result.get("status"))
        await self._result(run_id, action, result)

    # --- remove ---------------------------------------------------------------------

    async def cloud_backup_remove(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Forget the account's sign-in.  Its photos are kept."""
        try:
            run_id = layout.run_id(parameters)
            session = layout.session_dir(self.state_dir, parameters.get("dir_name"))
        except layout.LayoutError as error:
            return self._refusal("invalid_request", str(error))
        shutil.rmtree(session, ignore_errors=True)
        removed = not os.path.exists(session)
        await self._result(run_id, "remove", {
            "status": runner.OK if removed else runner.FAILED,
            "reason": None if removed else "remove_failed",
            "message": None if removed else f"{session} could not be removed",
        })  # fmt: skip
        return {"success": removed, "run_id": run_id}
