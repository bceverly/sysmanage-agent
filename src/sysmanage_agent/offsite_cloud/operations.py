# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The storage host's ``offsite_cloud_run`` command (server ROADMAP 27.3).

``action`` is ``check`` (prove the bucket takes uploads; say whether Object
Lock is on), ``upload`` (one run of the copy) or ``restore`` (thaw and
receive a chain into a new dataset).  The handler checks the job, fetches
the credentials and the key over HTTPS for this run alone
(``POST /api/agent/offsite-cloud-secret``), and answers at once:

* ``check`` runs here, in a thread, and ends with ``offsite_cloud_result``;
* ``upload`` and ``restore`` run DETACHED (``runner``), handed the secrets
  on their standard input, so they outlive an agent restart.  A watcher
  sends ``offsite_cloud_progress`` from the run's status file and, when it
  ends, ``offsite_cloud_result``; the agent looks again at start-up, so a
  result written while it was down is still reported.

The secrets are never in a command, a file, an argument, the environment
or a log.
"""

import asyncio
import json
import logging
import os
import platform
import shutil
import subprocess  # nosec B404 - the agent's own runner, fixed argv
import sys
from typing import Any, Dict, Optional

from src.sysmanage_agent.offsite_cloud import job as jobs
from src.sysmanage_agent.offsite_cloud import runfiles
from src.sysmanage_agent.offsite_cloud import runner

logger = logging.getLogger(__name__)

ZFS_PATHS = ("/usr/sbin/zfs", "/sbin/zfs", "/usr/local/sbin/zfs")
WATCH_SECONDS = 30
SECRET_PATH = "/api/agent/offsite-cloud-secret"
AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # fmt: skip


def zfs_path() -> Optional[str]:
    """The path the sudoers rules name first (``/usr/sbin/zfs`` on Linux,
    ``/sbin/zfs`` on FreeBSD), then whatever PATH finds."""
    found = next((p for p in ZFS_PATHS if os.path.exists(p)), None)
    return found or shutil.which("zfs")


def unavailable_reason(_lookup=None, system: Optional[str] = None) -> Optional[str]:
    """Where the off-site copy can run: a Linux or FreeBSD host with ZFS."""
    system = system or platform.system()
    if system not in ("Linux", "FreeBSD"):
        return "wrong_platform"
    return None if zfs_path() else "no_zfs"


class OffsiteCloudOperations:
    """The agent's half of the off-site cloud copy."""

    def __init__(self, agent_instance, state_dir: str):
        self.agent = agent_instance
        self.state_dir = state_dir
        self._watching: set = set()
        self._tasks: set = set()

    # --- reports ---------------------------------------------------------------

    async def _send(self, message_type: str, data: Dict[str, Any]) -> None:
        payload = dict(data)
        approval = self.agent.registration_manager.get_host_approval_from_db()
        if approval:
            payload["host_id"] = str(approval.host_id)
        message = self.agent.create_message(message_type, payload)
        if not await self.agent.send_message(message):
            logger.warning(
                "Could not queue the off-site report for %s", data.get("run_id")
            )

    def _spawn(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # --- the server, over HTTPS ------------------------------------------------

    async def _secrets(self, run_id: str) -> Dict[str, Any]:
        # The same host-credential POST the iCloud password uses.
        # pylint: disable-next=import-outside-toplevel
        from src.sysmanage_agent.cloud_backup.operations import CloudBackupOperations

        asker = CloudBackupOperations(self.agent, self.state_dir)
        answer = await asker._ask(
            SECRET_PATH, run_id
        )  # pylint: disable=protected-access
        wanted = ("access_key", "secret_key", "key")
        if not all(isinstance(answer.get(k), str) and answer.get(k) for k in wanted):
            raise PermissionError("the server sent no credentials or key")
        return {k: answer[k] for k in wanted + ("session_token",) if answer.get(k)}

    # --- the command -----------------------------------------------------------

    async def offsite_cloud_run(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        try:
            job = jobs.validate(parameters)
        except jobs.JobError as error:
            return {"success": False, "reason": error.reason, "error": str(error)}
        zfs = zfs_path()
        if job["action"] != jobs.CHECK and zfs is None:
            return {"success": False, "reason": "no_zfs",
                    "error": "this storage host has no ZFS"}  # fmt: skip
        directory = runfiles.ensure(runfiles.run_dir(self.state_dir, job["copy_id"]))
        if runfiles.running(directory):
            return {"success": False, "reason": "busy",
                    "error": "an off-site run of this copy is still going"}  # fmt: skip
        try:
            secrets = await self._secrets(job["run_id"])
        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "reason": "no_secrets", "error": str(error)}
        if job["action"] == jobs.CHECK:
            self._spawn(self._check(job, secrets))
            return {"success": True, "started": True}
        runfiles.write_json(os.path.join(directory, runfiles.JOB), job)
        runfiles.remove(os.path.join(directory, runfiles.RESULT))
        try:
            await asyncio.to_thread(self._start, directory, zfs, secrets)
        except OSError as error:
            return {"success": False, "reason": "not_started", "error": str(error)}
        self.watch(job["copy_id"])
        return {"success": True, "started": True}

    async def _check(self, job: Dict[str, Any], secrets: Dict[str, Any]) -> None:
        try:
            key = runner.decode_key(secrets["key"])
            client = runner.client_for(job, secrets)
            result = await asyncio.to_thread(runner.check, job, key, client)
        except Exception as error:  # pylint: disable=broad-except
            result = {"run_id": job["run_id"], "copy_id": job["copy_id"],
                      "status": "failed", "errors": [str(error)]}  # fmt: skip
        await self._send("offsite_cloud_result", dict(result, action=jobs.CHECK))

    @staticmethod
    def _start(directory: str, zfs: str, secrets: Dict[str, Any]) -> None:
        with open(os.path.join(directory, runfiles.LOG), "ab") as log:
            # pylint: disable-next=consider-using-with
            proc = subprocess.Popen(  # nosec B603 - the agent's own runner
                [sys.executable, "-m", "src.sysmanage_agent.offsite_cloud.runner",
                 directory, zfs],
                stdin=subprocess.PIPE, stdout=log, stderr=log, cwd=AGENT_ROOT,
                start_new_session=True,
            )  # fmt: skip
        proc.stdin.write((json.dumps(secrets) + "\n").encode("utf-8"))
        proc.stdin.close()

    # --- watching ----------------------------------------------------------------

    def watch(self, copy_id: str) -> None:
        if copy_id in self._watching:
            return
        self._watching.add(copy_id)
        self._spawn(self._watch(copy_id))

    async def _watch(self, copy_id: str) -> None:
        directory = runfiles.run_dir(self.state_dir, copy_id)
        last = None
        try:
            while True:
                await asyncio.sleep(WATCH_SECONDS)
                status = runfiles.read_json(os.path.join(directory, runfiles.STATUS))
                if status and status != last:
                    last = status
                    await self._send(
                        "offsite_cloud_progress", dict(status, copy_id=copy_id)
                    )
                if await self._report(directory):
                    return
                if not runfiles.running(directory):
                    # ended without a result (killed): say so once
                    job = (
                        runfiles.read_json(os.path.join(directory, runfiles.JOB)) or {}
                    )
                    await self._send("offsite_cloud_result", {
                        "run_id": job.get("run_id"), "copy_id": copy_id,
                        "action": job.get("action"), "status": "interrupted",
                        "errors": ["the run stopped without a result"],
                    })  # fmt: skip
                    return
        finally:
            self._watching.discard(copy_id)

    async def _report(self, directory: str) -> bool:
        path = os.path.join(directory, runfiles.RESULT)
        result = runfiles.read_json(path)
        if result is None:
            return False
        job = runfiles.read_json(os.path.join(directory, runfiles.JOB)) or {}
        await self._send("offsite_cloud_result", dict(result, action=job.get("action")))
        runfiles.remove(path)
        runfiles.remove(os.path.join(directory, runfiles.STATUS))
        return True

    async def resume_watching(self) -> None:
        """At start-up: report what ended while the agent was down, and watch
        what still runs."""
        root = os.path.join(self.state_dir, "offsite-cloud")
        try:
            names = sorted(os.listdir(root))
        except OSError:
            return
        for name in names:
            directory = os.path.join(root, name)
            if await self._report(directory):
                continue
            if runfiles.running(directory):
                self.watch(name)
