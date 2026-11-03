# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""BackupOperations: starting a restate job, watching it, reporting it.

Split out of ``operations/backup_operations.py`` (which composes it).
"""

import asyncio
import os
import shutil
import time
from typing import Any, Dict, List, Optional, Tuple

from src.i18n import _
from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import key_files
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import restate_probe
from src.sysmanage_agent.backup import storage_reaudit


def _ops():
    """backup_operations, looked up at call time: its module-level constants
    and helpers are the ones callers (and tests) patch, and a top-level
    import would be circular."""
    from src.sysmanage_agent.operations import (  # pylint: disable=import-outside-toplevel
        backup_operations,
    )

    return backup_operations


class BackupJobLifecycleMixin:
    """Launch, watch, finish and report runs; needs BackupOperations' state
    files, privileged helpers and mount handling."""

    async def _unit_state(self, unit: str) -> Dict[str, str]:
        code, out, _err = await self._run(
            ["systemctl", "show", unit, "-p", "ActiveState", "-p", "Result",
             "-p", "ExecMainStatus"]
        )  # fmt: skip
        if code != 0:
            return {}
        state = {}
        for line in out.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                state[key] = value
        return state

    async def _job_state(self, record: Dict[str, Any]) -> Tuple[bool, Optional[int]]:
        """``(running, exit status)`` of a run; the status only from systemd."""
        if record.get("pidfile"):
            return job_runner.pidfile_locked(record["pidfile"]), None
        state = await self._unit_state(record["unit"])
        try:
            code: Optional[int] = int(state.get("ExecMainStatus", ""))
        except ValueError:
            code = None
        return state.get("ActiveState") in _ops()._ACTIVE, code

    def _new_record(self, policy_id: str, action: str) -> Dict[str, Any]:
        record = {"policy_id": policy_id, "action": action,
                  "started_at": _ops()._now(), "started": time.time()}  # fmt: skip
        if self.runner == job_runner.DAEMON:
            name = contract.job_name(policy_id, action)
            record["pidfile"] = job_runner.pidfile(self.state_dir, name)
            record["log"] = job_runner.logfile(self.state_dir, name)
        else:
            record["unit"] = contract.unit_name(policy_id, action)
        return record

    async def _launch(self, record: Dict[str, Any]) -> Tuple[int, str]:
        if not record.get("pidfile"):
            argv = ["systemctl", "--no-block", "start", record["unit"]]
            code, _out, err = await self._run(self._privileged(argv))
            return code, err
        restate = restate_probe.locate(shutil.which)
        if not restate:
            return 1, _("restate is not installed on this host.")
        os.makedirs(job_runner.run_dir(self.state_dir), mode=0o700, exist_ok=True)
        argv = job_runner.daemon_argv(
            restate,
            contract.job_path(record["policy_id"], record["action"]),
            record["pidfile"],
            record["log"],
            self._privileged,
        )
        code, _out, err = await self._run(argv)
        return code, err

    async def _start_job(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, run_id: str, policy_id: str, action: str, previous: bool = False,
        keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:  # fmt: skip
        """Start the job; a job that does not start leaves no key behind."""
        answer = await self._launch_job(run_id, policy_id, action, previous, keys)
        if not answer.get("success"):
            await key_files.remove(keys or [], self._run, self._privileged)
        return answer

    async def _launch_job(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, run_id: str, policy_id: str, action: str, previous: bool,
        keys: Optional[List[str]],
    ) -> Dict[str, Any]:  # fmt: skip
        record = self._new_record(policy_id, action)
        if previous:
            record["previous"] = True  # the repository before an encrypted one
        if keys:
            record["key_files"] = list(keys)  # removed when the run ends
        if (await self._job_state(record))[0]:
            return {"success": False, "run_id": run_id, "reason": "busy",
                    "error": _("That backup job is already running.")}  # fmt: skip
        for path in (
            job_builder.result_path(self.state_dir, policy_id, action),
            job_builder.progress_path(self.state_dir, policy_id, action),
            record.get("log"),
        ):
            if path and os.path.exists(path):
                os.unlink(path)
        error = await self._ensure_mount(run_id, policy_id, record)
        if error:
            return {"success": False, "run_id": run_id, "reason": "mount_failed",
                    "error": error}  # fmt: skip
        if action == "capture":
            error = await self._preflight(policy_id)
            if error:
                await self._release_mount(run_id, policy_id, record)
                return {"success": False, "run_id": run_id,
                        "reason": "preflight_failed", "error": error}  # fmt: skip
        code, err = await self._launch(record)
        if code != 0:
            await self._release_mount(run_id, policy_id, record)
            return {"success": False, "run_id": run_id, "reason": "start_failed",
                    "error": err or _("The backup job could not be started.")}  # fmt: skip
        inflight = self._load(_ops().INFLIGHT_FILE)
        inflight[run_id] = record
        self._save(_ops().INFLIGHT_FILE, inflight)
        self._spawn(self._watch(run_id, record, resumed=False))
        return {"success": True, "run_id": run_id, "status": "started"}

    def _spawn(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def resume_in_flight(self) -> None:
        """After a restart: watch every run the last agent left running.
        Once per process -- the task loop that calls it runs per connection."""
        if self._resumed:
            return
        self._resumed = True
        # Key files a crash left behind (no running job owns them) go first.
        self._spawn(
            key_files.sweep(
                self._load(_ops().INFLIGHT_FILE), self._run, self._privileged
            )
        )
        for run_id, record in self._load(_ops().INFLIGHT_FILE).items():
            if isinstance(record, dict) and (
                record.get("unit") or record.get("pidfile")
            ):
                self._spawn(self._watch(run_id, record, resumed=True))
        storage_reaudit.schedule(self.reaudit_storage)

    def _new_progress(
        self, record: Dict[str, Any], offset: int
    ) -> Tuple[Optional[dict], int]:
        path = job_builder.progress_path(
            self.state_dir, record["policy_id"], record["action"]
        )
        try:
            with open(path, "r", encoding="utf-8") as handle:
                handle.seek(offset)
                lines = handle.read().splitlines()
                return contract.last_progress(lines), handle.tell()
        except OSError:
            return None, offset

    async def _watch(self, run_id: str, record: Dict[str, Any], resumed: bool) -> None:
        seen_active, offset, last_sent = resumed, 0, 0.0
        while True:
            await asyncio.sleep(_ops().POLL_SECONDS)
            active, unit_exit = await self._job_state(record)
            progress, offset = self._new_progress(record, offset)
            if progress and time.time() - last_sent >= _ops().PROGRESS_EVERY_SECONDS:
                last_sent = time.time()
                await self._send("backup_progress", {"run_id": run_id,
                    "policy_id": record["policy_id"], "action": record["action"],
                    "progress": progress})  # fmt: skip
            seen_active = seen_active or active
            waited = time.time() - float(record.get("started") or 0)
            # A result file means it ran (the old one was cleared before the
            # start): a job quicker than one poll need not wait out the grace.
            ended = seen_active or os.path.exists(
                job_builder.result_path(
                    self.state_dir, record["policy_id"], record["action"]
                )
            )
            if not active and (ended or waited > _ops().START_GRACE_SECONDS):
                await self._finish(run_id, record, unit_exit)
                return

    async def _finish(
        self, run_id: str, record: Dict[str, Any], unit_exit: Optional[int]
    ) -> None:
        text = _ops()._read_text(
            job_builder.result_path(
                self.state_dir, record["policy_id"], record["action"]
            )
        )
        result = contract.parse_result(text) if text else None
        status, code = contract.outcome(result, unit_exit)
        if result is None and record.get("log"):
            # No result file: what restate said is the only clue to why.
            tail = job_runner.log_tail(record["log"])
            result = {"message": tail} if tail else None
        if result is None:
            # systemd keeps restate's output in the journal, which the
            # agent does not read; say where the reason is.
            unit = contract.unit_name(record["policy_id"], record["action"])
            result = {"message": _(
                "restate stopped (exit %(code)s) before writing a result; "
                "see journalctl -u %(unit)s on this host"
            ) % {"code": code, "unit": unit}}  # fmt: skip
        features = self._features() or {}
        await self._report(
            {"run_id": run_id, "policy_id": record["policy_id"], "action": record["action"],
             "status": status, "exit": code, "result": result,
             "started_at": record.get("started_at"), "finished_at": _ops()._now(),
             "restate_version": features.get("version")},  # fmt: skip
            then=lambda: self._forget(run_id),
        )
        await key_files.remove(
            record.get("key_files") or [], self._run, self._privileged
        )
        await self._release_mount(run_id, record["policy_id"], record)

    def _forget(self, run_id: str) -> None:
        inflight = self._load(_ops().INFLIGHT_FILE)
        inflight.pop(run_id, None)
        self._save(_ops().INFLIGHT_FILE, inflight)

    async def _report(self, data: Dict[str, Any], then=None) -> None:
        # The storage side reports its audit with every job, so the server's
        # picture of the append-only set-up never goes stale.
        policy = self._policy(str(data.get("policy_id") or ""))
        if policy and policy.get("role") == "storage":
            data = dict(data, storage_audit=self._audit(policy))
        await self._send("backup_result", data, then)

    async def _send(self, message_type: str, data: Dict[str, Any], then=None) -> None:
        """Queue a report; one that cannot be queued is retried, never dropped.
        A full disk refuses the agent's queue: beast's capture result was lost
        that way and its run sat "running" for 12 hours (production,
        2026-11-01).  ``then`` runs once it is queued -- a run's in-flight
        record stays until then, so a restart reports it again."""
        payload = dict(data)
        approval = self.agent.registration_manager.get_host_approval_from_db()
        if approval:
            payload["host_id"] = str(approval.host_id)
        message = self.agent.create_message(message_type, payload)
        if await self.agent.send_message(message):
            if then:
                then()
            return
        self.logger.warning(_("Could not queue the backup report"))
        self._spawn(self._send_later(message, then))

    async def _send_later(self, message: Dict[str, Any], then) -> None:
        await asyncio.sleep(_ops().RESEND_SECONDS)
        while not await self.agent.send_message(message):
            await asyncio.sleep(_ops().RESEND_SECONDS)
        self.logger.info("Queued backup report %s", message.get("message_id"))
        if then:
            then()
