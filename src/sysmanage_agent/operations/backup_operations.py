# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Backups with restate: configure, run, restore (server ROADMAP 24.2).

THE PRIVILEGE BOUNDARY
----------------------
restate runs as root; this agent does not.  The agent never builds a restate
command line.  It validates the server's policy (``backup.job_validation``),
writes root-owned job files with ``sudo install``, and starts the fixed
``restate-job@<policy>.<action>.service`` unit with ``systemctl --no-block
start``.  systemd runs restate; the agent only watches the unit and reads the
result file the job names.

A run outlives the agent: in-flight runs are recorded in a state file, and an
agent that restarts picks the watch back up and still reports the result.
Nothing here awaits a run inside the command handler -- the handler answers
at once and a background task does the waiting.
"""

import asyncio
import json
import logging
import os
import platform
import posixpath
import shutil
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.i18n import _
from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_validation as validation
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import restate_probe

DEFAULT_STATE_DIR = "/var/lib/sysmanage-agent"
POLL_SECONDS = 5
PROGRESS_EVERY_SECONDS = 10
START_GRACE_SECONDS = 60
ZFS_PATHS = ("/usr/sbin/zfs", "/sbin/zfs")
_ACTIVE = ("active", "activating", "deactivating", "reloading")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _agent_group() -> str:
    """The agent process's primary group: restate opens its reports to it."""
    import grp  # pylint: disable=import-outside-toplevel  # Unix only

    return grp.getgrgid(os.getgid()).gr_name


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


class BackupOperations:
    """The agent's half of Phase 24: the restate driver."""

    def __init__(self, agent_instance, state_dir: Optional[str] = None):
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self.state_dir = state_dir or os.environ.get(
            "SYSMANAGE_BACKUP_STATE_DIR", DEFAULT_STATE_DIR
        )
        self._tasks: set = set()
        self._resumed = False

    # ------------------------------------------------------------------
    # state files
    # ------------------------------------------------------------------

    def _backup_dir(self) -> str:
        return posixpath.join(self.state_dir, "backup")

    def _state_file(self, name: str) -> str:
        return posixpath.join(self._backup_dir(), name)

    def _load(self, name: str) -> Dict[str, Any]:
        text = _read_text(self._state_file(name))
        try:
            data = json.loads(text) if text else {}
        except ValueError:
            data = {}
        return data if isinstance(data, dict) else {}

    def _save(self, name: str, data: Dict[str, Any]) -> None:
        self._ensure_dirs()
        path = self._state_file(name)
        handle, tmp = tempfile.mkstemp(dir=self._backup_dir(), prefix=".state-")
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(data, out, sort_keys=True)
        os.replace(tmp, path)

    def _ensure_dirs(self) -> None:
        for sub in ("backup", "restore"):
            os.makedirs(posixpath.join(self.state_dir, sub), mode=0o700, exist_ok=True)

    # ------------------------------------------------------------------
    # privileged helpers
    # ------------------------------------------------------------------

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

    async def _install_root_file(self, content: str, dest: str) -> None:
        """Write ``content`` to ``dest`` root-owned 0644 via ``sudo install``."""
        self._ensure_dirs()
        handle, staged = tempfile.mkstemp(dir=self._backup_dir(), prefix=".job-")
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="") as out:
                out.write(content)
            os.chmod(staged, 0o644)  # root reads it; nothing secret in a job
            argv = [
                "install",
                "-D",
                "-m",
                "644",
                "-o",
                "0",
                "-g",
                "0",
                "--",
                staged,
                dest,
            ]
            code, _out, err = await self._run(self._privileged(argv))
            if code != 0:
                raise PermissionError(err or f"install exited {code}")
        finally:
            if os.path.exists(staged):
                os.unlink(staged)

    async def _remove_root_file(self, path: str) -> None:
        await self._run(self._privileged(["rm", "-f", "--", path]))

    # ------------------------------------------------------------------
    # probe
    # ------------------------------------------------------------------

    @staticmethod
    def _features() -> Optional[Dict[str, Any]]:
        executable = restate_probe.locate(shutil.which)
        return restate_probe.features(executable) if executable else None

    @staticmethod
    def _refusal(reason: str, message: str) -> Dict[str, Any]:
        return {"success": False, "reason": reason, "error": message}

    def _unusable(self) -> Optional[Dict[str, Any]]:
        reason = restate_probe.unavailable_reason(shutil.which, platform.system())
        if reason is None:
            return None
        return self._refusal(
            reason, _("restate is not usable on this host: %s") % reason
        )

    # ------------------------------------------------------------------
    # backup_configure
    # ------------------------------------------------------------------

    async def backup_configure(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a policy and install its job files."""
        refusal = self._unusable()
        if refusal:
            return refusal
        try:
            policy = validation.check_policy(
                parameters, mountinfo=lambda: _read_text("/proc/self/mountinfo") or ""
            )
            return await self._apply_policy(policy)
        except validation.PolicyError as error:
            return self._refusal("invalid_policy", str(error))
        except (OSError, PermissionError) as error:
            self.logger.error(_("Could not install the backup jobs: %s"), error)
            return self._refusal("install_failed", str(error))

    async def _apply_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        policy_id = policy["policy_id"]
        if policy["encrypt_key"]:
            await self._install_root_file(
                policy["encrypt_key"], contract.key_path(policy_id)
            )
        jobs = job_builder.build_jobs(
            policy,
            state_dir=self.state_dir,
            group=_agent_group(),
            key_installed=bool(policy["encrypt_key"]),
        )
        missing = contract.unsupported_keys(
            self._features() or {}, [key for job in jobs.values() for key in job]
        )
        if missing:
            return self._refusal(
                "tool_outdated",
                _("This restate does not support: %s") % ", ".join(missing),
            )
        for action, job in jobs.items():
            await self._install_root_file(
                contract.render_job(job), contract.job_path(policy_id, action)
            )
        removed = await self._remove_stale(policy_id, set(jobs))
        policies = self._load("policies.json")
        policies[policy_id] = {
            "role": policy["role"],
            "repository": policy["repository"],
            "actions": sorted(policy["jobs"]),
            "seal": policy["jobs"].get("seal"),
        }
        self._save("policies.json", policies)
        return {
            "success": True,
            "policy_id": policy_id,
            "installed": sorted(jobs),
            "removed": removed,
        }

    async def _remove_stale(self, policy_id: str, keep: set) -> List[str]:
        previous = self._load("policies.json").get(policy_id, {}).get("actions", [])
        stale = sorted(a for a in previous if a not in keep and a != "seal")
        for action in stale:
            await self._remove_root_file(contract.job_path(policy_id, action))
        return stale

    # ------------------------------------------------------------------
    # backup_run / backup_restore
    # ------------------------------------------------------------------

    def _policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        return self._load("policies.json").get(policy_id)

    async def backup_run(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Start one action of a configured policy; report when it ends."""
        refusal = self._unusable()
        if refusal:
            return refusal
        try:
            run_id = validation.check_uuid((parameters or {}).get("run_id"), "run_id")
            policy_id = validation.check_uuid(parameters.get("policy_id"), "policy_id")
        except validation.PolicyError as error:
            return self._refusal("invalid_request", str(error))
        action = parameters.get("action")
        policy = self._policy(policy_id)
        if not policy or action not in policy.get("actions", []):
            return self._refusal(
                "not_configured",
                _("That backup action is not configured on this host."),
            )
        if action == "seal":
            return self._start_seal(run_id, policy_id, policy.get("seal") or {})
        if not os.path.exists(contract.job_path(policy_id, action)):
            return self._refusal(
                "not_configured",
                _("That backup action is not configured on this host."),
            )
        return await self._start_unit(run_id, policy_id, action)

    async def backup_restore(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restore from a snapshot into a staging directory (never in place)."""
        refusal = self._unusable()
        if refusal:
            return refusal
        params = parameters or {}
        try:
            policy_id = validation.check_uuid(params.get("policy_id"), "policy_id")
            policy = self._policy(policy_id)
            if not policy or policy.get("role") != "host":
                return self._refusal(
                    "not_configured",
                    _("That backup action is not configured on this host."),
                )
            job = job_builder.build_restore_job(
                params,
                repository=policy["repository"],
                state_dir=self.state_dir,
                group=_agent_group(),
            )
            run_id = validation.check_uuid(params.get("run_id"), "run_id")
            os.makedirs(job["restore_root"], mode=0o700, exist_ok=True)
            await self._install_root_file(
                contract.render_job(job),
                contract.job_path(policy_id, job_builder.RESTORE_ACTION),
            )
        except validation.PolicyError as error:
            return self._refusal("invalid_request", str(error))
        except (OSError, PermissionError) as error:
            return self._refusal("install_failed", str(error))
        return await self._start_unit(run_id, policy_id, job_builder.RESTORE_ACTION)

    async def _unit_state(self, unit: str) -> Dict[str, str]:
        code, out, _err = await self._run(
            ["systemctl", "show", unit, "-p", "ActiveState", "-p", "Result",
             "-p", "ExecMainStatus"]
        )  # fmt: skip
        if code != 0:
            return {}
        return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)

    async def _start_unit(
        self, run_id: str, policy_id: str, action: str
    ) -> Dict[str, Any]:
        unit = contract.unit_name(policy_id, action)
        if (await self._unit_state(unit)).get("ActiveState") in _ACTIVE:
            return {"success": False, "run_id": run_id, "reason": "busy",
                    "error": _("That backup job is already running.")}  # fmt: skip
        for path in (
            job_builder.result_path(self.state_dir, policy_id, action),
            job_builder.progress_path(self.state_dir, policy_id, action),
        ):
            if os.path.exists(path):
                os.unlink(path)
        code, _out, err = await self._run(
            self._privileged(["systemctl", "--no-block", "start", unit])
        )
        if code != 0:
            return {"success": False, "run_id": run_id, "reason": "start_failed",
                    "error": err or _("The backup job could not be started.")}  # fmt: skip
        record = {"policy_id": policy_id, "action": action, "unit": unit,
                  "started_at": _now(), "started": time.time()}  # fmt: skip
        inflight = self._load("inflight.json")
        inflight[run_id] = record
        self._save("inflight.json", inflight)
        self._spawn(self._watch(run_id, record, resumed=False))
        return {"success": True, "run_id": run_id, "status": "started"}

    # ------------------------------------------------------------------
    # seal: the NAS snapshots its own dataset
    # ------------------------------------------------------------------

    def _start_seal(
        self, run_id: str, policy_id: str, seal: Dict[str, Any]
    ) -> Dict[str, Any]:
        self._spawn(self._seal(run_id, policy_id, seal))
        return {"success": True, "run_id": run_id, "status": "started"}

    async def _seal(self, run_id: str, policy_id: str, seal: Dict[str, Any]) -> None:
        started = _now()
        code: Optional[int] = 0
        message = ""
        if seal.get("mode") == "zfs_snapshot":
            zfs = next((p for p in ZFS_PATHS if os.path.exists(p)), ZFS_PATHS[0])
            argv = [zfs, "snapshot", f"{seal['dataset']}@sysmanage-{run_id}"]
            code, _out, message = await self._run(self._privileged(argv))
        status = "ok" if code == 0 else "failed"
        await self._report(
            {"run_id": run_id, "policy_id": policy_id, "action": "seal",
             "status": status, "exit": code, "result": {"message": message} if message else None,
             "started_at": started, "finished_at": _now()}  # fmt: skip
        )

    # ------------------------------------------------------------------
    # watching a run
    # ------------------------------------------------------------------

    def _spawn(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def resume_in_flight(self) -> None:
        """After a restart: watch every run the last agent left running.
        Once per process -- the task loop that calls it runs per connection."""
        if self._resumed:
            return
        self._resumed = True
        for run_id, record in self._load("inflight.json").items():
            if isinstance(record, dict) and record.get("unit"):
                self._spawn(self._watch(run_id, record, resumed=True))

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
            await asyncio.sleep(POLL_SECONDS)
            state = await self._unit_state(record["unit"])
            progress, offset = self._new_progress(record, offset)
            if progress and time.time() - last_sent >= PROGRESS_EVERY_SECONDS:
                last_sent = time.time()
                await self._send("backup_progress", {"run_id": run_id,
                    "policy_id": record["policy_id"], "action": record["action"],
                    "progress": progress})  # fmt: skip
            active = state.get("ActiveState") in _ACTIVE
            seen_active = seen_active or active
            waited = time.time() - float(record.get("started") or 0)
            if not active and (seen_active or waited > START_GRACE_SECONDS):
                await self._finish(run_id, record, state)
                return

    async def _finish(
        self, run_id: str, record: Dict[str, Any], state: Dict[str, str]
    ) -> None:
        text = _read_text(
            job_builder.result_path(
                self.state_dir, record["policy_id"], record["action"]
            )
        )
        result = contract.parse_result(text) if text else None
        try:
            unit_exit: Optional[int] = int(state.get("ExecMainStatus", ""))
        except ValueError:
            unit_exit = None
        status, code = contract.outcome(result, unit_exit)
        features = self._features() or {}
        await self._report(
            {"run_id": run_id, "policy_id": record["policy_id"], "action": record["action"],
             "status": status, "exit": code, "result": result,
             "started_at": record.get("started_at"), "finished_at": _now(),
             "restate_version": features.get("version")}  # fmt: skip
        )
        inflight = self._load("inflight.json")
        inflight.pop(run_id, None)
        self._save("inflight.json", inflight)

    async def _report(self, data: Dict[str, Any]) -> None:
        await self._send("backup_result", data)

    async def _send(self, message_type: str, data: Dict[str, Any]) -> None:
        payload = dict(data)
        approval = self.agent.registration_manager.get_host_approval_from_db()
        if approval:
            payload["host_id"] = str(approval.host_id)
        message = self.agent.create_message(message_type, payload)
        if not await self.agent.send_message(message):
            self.logger.warning(_("Could not queue the backup report"))
