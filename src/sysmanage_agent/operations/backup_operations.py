# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Backups with restate: configure, run, restore (server ROADMAP 24.2).

THE PRIVILEGE BOUNDARY
----------------------
restate runs as root; this agent does not.  The agent never builds a restate
command line from server data.  It validates the server's policy
(``backup.job_validation``), writes root-owned job files with ``sudo
install``, and starts the job: on Linux the fixed
``restate-job@<policy>.<action>.service`` unit with ``systemctl --no-block
start``; on FreeBSD (a storage host) ``restate run <that job file>`` under
daemon(8) (``backup.job_runner``).  The agent only watches the run and reads
the result file the job names.

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

from src.database.base import current_database_path
from src.i18n import _
from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import job_validation as validation
from src.sysmanage_agent.backup import key_files
from src.sysmanage_agent.backup.mount_mixin import BackupMountMixin
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import storage_audit
from src.sysmanage_agent.backup import storage_fs
from src.sysmanage_agent.backup import storage_prepare
from src.sysmanage_agent.backup import storage_reaudit
from src.sysmanage_agent.backup import repository_choice
from src.sysmanage_agent.backup import restate_probe
from src.sysmanage_agent.backup import seal_retention

DEFAULT_STATE_DIR = "/var/lib/sysmanage-agent"
# The driver's own state files, in its state directory.
POLICIES_FILE = "policies.json"
INFLIGHT_FILE = "inflight.json"
SEALS_FILE = "seals.json"
# The BSDs keep a daemon's state in /var/db (the FreeBSD rc script puts the
# agent's database there); there is no /var/lib to create one in.
STATE_DIRS = {"FreeBSD": "/var/db/sysmanage-agent"}


def default_state_dir() -> str:
    """Where backup job state lives: beside the agent's own database.

    NEVER a fixed /var/lib/sysmanage-agent: the database lookup takes that
    directory's mere existence as "use the system database there", so an
    agent whose database is elsewhere (a source checkout's ./agent.db) that
    created it for backup state switched to a new, empty database on its
    next restart and lost its host identity (lab, 2026-10-20).  Packaged
    agents keep their database in /var/lib (Linux) or /var/db (FreeBSD), so
    nothing moves for them.
    """
    configured = os.environ.get("SYSMANAGE_BACKUP_STATE_DIR")
    if configured:
        return configured
    database = current_database_path()
    if database:
        return os.path.dirname(os.path.abspath(database))
    return STATE_DIRS.get(platform.system(), DEFAULT_STATE_DIR)


POLL_SECONDS = 5
PROGRESS_EVERY_SECONDS = 10
START_GRACE_SECONDS = 60
ZFS_PATHS = ("/usr/sbin/zfs", "/sbin/zfs")
BTRFS_PATHS = ("/usr/bin/btrfs", "/usr/sbin/btrfs", "/sbin/btrfs")
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


def _stage_file(content: str, directory: str) -> str:
    """Write ``content`` to a new private (0600) file in ``directory``; its
    path.  ``sudo install`` then copies it into place root-owned with the
    mode the job file needs, so the staged copy never has to be readable by
    anyone else."""
    handle, staged = tempfile.mkstemp(dir=directory, prefix=".job-")
    with os.fdopen(handle, "w", encoding="utf-8", newline="") as out:
        out.write(content)
    return staged


def _first(paths: Tuple[str, ...]) -> str:
    return next((p for p in paths if os.path.exists(p)), paths[0])


def seal_argv(seal: Dict[str, Any], run_id: str) -> Optional[List[str]]:
    """The command that seals the repositories, or None for mode none.

    zfs: a RECURSIVE snapshot of the dataset -- each host's repository is
    its own child dataset (its own export), and a plain snapshot of the
    parent would leave every one of them out.  btrfs: a READ-ONLY snapshot of the
    subvolume into snapshot_dir (validated to lie outside it), so a host that
    later deletes or rewrites its repository cannot touch the sealed copy.
    """
    mode = seal.get("mode")
    if mode == "zfs_snapshot":
        return [
            _first(ZFS_PATHS),
            "snapshot",
            "-r",
            f"{seal['dataset']}@sysmanage-{run_id}",
        ]
    if mode == "btrfs_snapshot":
        target = posixpath.join(seal["snapshot_dir"], f"sysmanage-{run_id}")
        return [
            _first(BTRFS_PATHS),
            "subvolume",
            "snapshot",
            "-r",
            seal["subvolume"],
            target,
        ]
    return None


class BackupOperations(BackupMountMixin):
    """The agent's half of Phase 24: the restate driver."""

    def __init__(self, agent_instance, state_dir: Optional[str] = None):
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self.state_dir = state_dir or default_state_dir()
        self._tasks: set = set()
        self._resumed = False
        self.runner = job_runner.runner_for(platform.system())

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
        staged = _stage_file(content, self._backup_dir())
        try:
            for argv in self._install_argvs(staged, dest):
                code, _out, err = await self._run(self._privileged(argv))
                if code != 0:
                    raise PermissionError(err or f"install exited {code}")
        finally:
            if os.path.exists(staged):
                os.unlink(staged)

    def _install_argvs(self, staged: str, dest: str) -> List[List[str]]:
        """``install`` a root-owned 0644 file, creating its directory.

        GNU install's ``-D`` creates the parents; FreeBSD's ``-D`` takes a
        DESTDIR instead, so there the directory is made first with its own
        ``install -d`` (only when it is missing -- an existing one keeps its
        mode).
        """
        owner = ["-o", "0", "-g", "0"]
        if self.runner != job_runner.DAEMON:
            return [["install", "-D", "-m", "644"] + owner + ["--", staged, dest]]
        argvs = []
        directory = posixpath.dirname(dest)
        if not os.path.isdir(directory):
            argvs.append(["install", "-d", "-m", "755"] + owner + ["--", directory])
        argvs.append(["install", "-m", "644"] + owner + ["--", staged, dest])
        return argvs

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

    @classmethod
    def _not_configured(cls) -> Dict[str, Any]:
        return cls._refusal(
            "not_configured", _("That backup action is not configured on this host.")
        )

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
                parameters,
                mountinfo=lambda: _read_text(host_mount.HOST_MOUNTINFO)
                or _read_text(host_mount.SELF_MOUNTINFO)
                or "",
                zfs_mounts=lambda: storage_fs.zfs_mount_points(_read_text),
            )
            if policy["role"] not in job_runner.ROLES.get(self.runner, ()):
                return self._refusal(
                    "wrong_platform",
                    _("This platform can only be a backup storage host."),
                )
            return await self._apply_policy(policy)
        except validation.PolicyError as error:
            return self._refusal("invalid_policy", str(error))
        except OSError as error:
            self.logger.error(_("Could not install the backup jobs: %s"), error)
            return self._refusal("install_failed", str(error))

    async def _apply_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        policy_id = policy["policy_id"]
        if policy["encrypt_key"]:
            await self._install_root_file(
                policy["encrypt_key"], contract.key_path(policy_id)
            )
        await self._apply_rules(policy)
        features = self._features() or {}
        jobs = job_builder.build_jobs(
            policy,
            state_dir=self.state_dir,
            group=_agent_group(),
            key_installed=bool(policy["encrypt_key"]),
            can_create=contract.supports(features, "create"),
        )
        for action in contract.GATED_COMMANDS & set(jobs):
            if not contract.supports_command(features, action):
                del jobs[action]  # this restate cannot run it: no job file
        missing = contract.unsupported_keys(
            features, [key for job in jobs.values() for key in job]
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
        policies = self._load(POLICIES_FILE)
        policies[policy_id] = {
            "role": policy["role"],
            "repository": policy["repository"],
            "mount_point": policy["mount_point"],
            "actions": sorted(policy["jobs"]),
            "seal": policy["jobs"].get("seal"),
            "client_address": policy.get("client_address"),
            "service_account": policy.get("service_account", "restate"),
            "nfs": policy.get("nfs"),
            "previous": policy.get("previous"),
        }
        self._save(POLICIES_FILE, policies)
        reply = {
            "success": True,
            "policy_id": policy_id,
            "installed": sorted(jobs),
            "removed": removed,
        }
        if policy["role"] == "host":
            # The quiesce hooks this host's restate finds present (2.1+): the
            # server offers them in the policy dialog.
            reply["hooks"] = contract.present_hooks(features)
            reply["abilities"] = contract.host_abilities(features)
        if policy["role"] == "storage":
            # Can this filesystem seal at all?  The server warns when not.
            reply["storage_fs"] = storage_fs.describe(
                policy["mount_point"], read_text=_read_text
            )
            reply["storage_audit"] = self._audit(policies[policy_id])
            # Where a host mounts its repository over NFSv4 (the server
            # sends it to the host, which mounts it only while a job runs).
            reply["nfs_path"] = storage_audit.client_path(
                platform.system(), policy["repository"]
            )
        return reply

    async def _apply_rules(self, policy: Dict[str, Any]) -> None:
        """Install the policy's rules file, or remove one it no longer needs."""
        path = job_builder.rules_path(policy["policy_id"])
        text = job_builder.policy_rules(policy)
        if text:
            await self._install_root_file(text, path)
        elif os.path.exists(path):
            await self._remove_root_file(path)

    async def _remove_stale(self, policy_id: str, keep: set) -> List[str]:
        previous = self._load(POLICIES_FILE).get(policy_id, {}).get("actions", [])
        stale = sorted(a for a in previous if a not in keep and a != "seal")
        for action in stale:
            await self._remove_root_file(contract.job_path(policy_id, action))
        return stale

    # ------------------------------------------------------------------
    # backup_run / backup_restore
    # ------------------------------------------------------------------

    def _policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        return self._load(POLICIES_FILE).get(policy_id)

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
        allowed = list(policy.get("actions", [])) if policy else []
        if policy and policy.get("role") == "storage":
            allowed.append(storage_prepare.ACTION)
        if policy and policy.get("role") == "host":
            allowed += [job_builder.LIST_ACTION, job_builder.STATUS_ACTION]
        if action not in allowed:
            return self._not_configured()
        if action == "seal":
            return self._start_seal(run_id, policy_id, policy.get("seal") or {})
        if action in (job_builder.LIST_ACTION, job_builder.STATUS_ACTION):
            return await self._start_browse(run_id, policy_id, policy, parameters)
        if action == storage_prepare.ACTION and policy.get("role") == "storage":
            self._spawn(self._prepare(run_id, policy_id, policy))
            return {"success": True, "run_id": run_id, "status": "started"}
        if not os.path.exists(contract.job_path(policy_id, action)):
            return self._not_configured()
        return await self._start_job(run_id, policy_id, action)

    async def _start_browse(
        self,
        run_id: str,
        policy_id: str,
        policy: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """A snapshot listing or a what-changed check: read-only host jobs,
        each written fresh from the request (like a restore)."""
        action = params.get("action")
        if not contract.supports_job_command(self._features(), action):
            return self._refusal(
                "tool_outdated",
                _("This restate cannot run %s as a job; upgrade restate.") % action,
            )
        keys: List[str] = []
        try:
            repository, _source, previous = repository_choice.choose(policy, params)
            keys = await self._decrypt_keys(run_id, params)
            common = {"repository": repository, "decrypt_with": keys,
                      "state_dir": self.state_dir, "group": _agent_group()}  # fmt: skip
            if action == job_builder.LIST_ACTION:
                job = job_builder.build_list_job(params, **common)
            else:
                job = job_builder.build_status_job(params, **common)
            await self._install_root_file(
                contract.render_job(job), contract.job_path(policy_id, action)
            )
        except (validation.PolicyError, key_files.KeyFetchError, OSError) as error:
            await key_files.remove(keys, self._run, self._privileged)
            return self._refusal(key_files.refusal_code(error), str(error))
        return await self._start_job(run_id, policy_id, action, previous, keys)

    async def backup_restore(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restore from a snapshot into a staging directory, or into place
        (``in_place``: over the host's own files; see build_restore_job)."""
        refusal = self._unusable()
        if refusal:
            return refusal
        params = parameters or {}
        keys: List[str] = []
        try:
            policy_id = validation.check_uuid(params.get("policy_id"), "policy_id")
            policy = self._policy(policy_id)
            if not policy or policy.get("role") != "host":
                return self._not_configured()
            repository, _source, previous = repository_choice.choose(policy, params)
            run_id = validation.check_uuid(params.get("run_id"), "run_id")
            keys = await self._decrypt_keys(run_id, params)
            job = job_builder.build_restore_job(
                params,
                repository=repository,
                state_dir=self.state_dir,
                group=_agent_group(),
                can_plan=contract.supports(self._features(), "plan"),
                decrypt_with=keys,
            )
            if job["restore_root"] != "/":
                os.makedirs(job["restore_root"], mode=0o700, exist_ok=True)
            await self._install_root_file(
                contract.render_job(job),
                contract.job_path(policy_id, job_builder.RESTORE_ACTION),
            )
        except (validation.PolicyError, key_files.KeyFetchError, OSError) as error:
            await key_files.remove(keys, self._run, self._privileged)
            return self._refusal(key_files.refusal_code(error), str(error))
        return await self._start_job(
            run_id, policy_id, job_builder.RESTORE_ACTION, previous, keys
        )

    async def _decrypt_keys(self, run_id: str, params: Dict[str, Any]) -> List[str]:
        """This run's key files when it reads an encrypted repository."""
        return await key_files.for_run(
            self.agent, self._features(), run_id, params, self._run, self._privileged
        )

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
        return state.get("ActiveState") in _ACTIVE, code

    def _new_record(self, policy_id: str, action: str) -> Dict[str, Any]:
        record = {"policy_id": policy_id, "action": action,
                  "started_at": _now(), "started": time.time()}  # fmt: skip
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
        inflight = self._load(INFLIGHT_FILE)
        inflight[run_id] = record
        self._save(INFLIGHT_FILE, inflight)
        self._spawn(self._watch(run_id, record, resumed=False))
        return {"success": True, "run_id": run_id, "status": "started"}

    # ------------------------------------------------------------------
    # the host's own export, mounted only while a job runs
    # ------------------------------------------------------------------

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
        argv = seal_argv(seal, run_id)
        result: Dict[str, Any] = {}
        if argv:
            code, _out, message = await self._run(self._privileged(argv))
        if code == 0 and argv and seal.get("mode") == "btrfs_snapshot":
            ledger = self._load(SEALS_FILE)
            ledger[argv[-1]] = time.time()
            self._save(SEALS_FILE, ledger)
        if code == 0 and seal.get("keep_days"):
            result = await self._expire_seals(seal)
            message = message or "; ".join(result.get("errors", []))
        if message:
            result["message"] = message
        status = "ok" if code == 0 else "failed"
        await self._report(
            {"run_id": run_id, "policy_id": policy_id, "action": "seal",
             "status": status, "exit": code, "result": result or None,
             "started_at": started, "finished_at": _now()}  # fmt: skip
        )

    async def _expire_seals(self, seal: Dict[str, Any]) -> Dict[str, Any]:
        """Remove this agent's seals older than ``keep_days`` (never the
        newest).  A failure is reported but never fails the seal itself."""
        keep, now = seal["keep_days"], time.time()
        if seal["mode"] == "zfs_snapshot":
            zfs = _first(ZFS_PATHS)
            code, out, err = await self._run(
                seal_retention.zfs_list_argv(zfs, seal["dataset"])
            )
            if code != 0:
                return {"errors": [_("Could not list the sealed snapshots: %s") % err]}
            seals = seal_retention.zfs_seals(out, seal["dataset"])
            tool = zfs
        else:
            ledger = self._load(SEALS_FILE)
            seals = seal_retention.btrfs_seals(ledger, seal["snapshot_dir"])
            tool = _first(BTRFS_PATHS)
        removed, errors = [], []
        for name in seal_retention.expired(seals, keep, now):
            code, _out, err = await self._run(
                self._privileged(seal_retention.delete_argv(seal["mode"], tool, name))
            )
            if code == 0:
                removed.append(name)
            else:
                errors.append(_("Could not remove the old sealed snapshot %(name)s: %(error)s")
                              % {"name": name, "error": err or code})  # fmt: skip
        if seal["mode"] == "btrfs_snapshot" and removed:
            ledger = self._load(SEALS_FILE)
            for path in removed:
                ledger.pop(path, None)
            self._save(SEALS_FILE, ledger)
        return {"seals_removed": len(removed), "seals_kept": len(seals) - len(removed),
                "errors": errors}  # fmt: skip

    # ------------------------------------------------------------------
    # prepare: the storage host gives one host its own export
    # ------------------------------------------------------------------

    async def _zfs_datasets(self) -> Dict[str, str]:
        zfs = shutil.which("zfs") or _first(ZFS_PATHS)
        if not os.path.exists(zfs):
            return {}
        code, out, _err = await self._run(
            [zfs, "list", "-H", "-t", "filesystem", "-o", "name,mountpoint"]
        )
        return storage_prepare.zfs_datasets(out) if code == 0 else {}

    @staticmethod
    def _is_subvolume(path: str) -> bool:
        try:
            return os.stat(path).st_ino == storage_fs.BTRFS_SUBVOLUME_ROOT_INODE
        except OSError:
            return False

    async def _prepare_steps(self, policy_id: str, steps: Dict[str, Any]) -> None:
        tools = {storage_prepare.ZFS: _first(ZFS_PATHS),
                 storage_prepare.BTRFS: _first(BTRFS_PATHS)}  # fmt: skip
        # The dataset / subvolume / directory first, then its export, then
        # its ownership (chown needs the new mount, not the directory under it).
        for argv in steps["commands"]:
            await self._checked([tools.get(argv[0], argv[0])] + argv[1:])
        if steps["export_file"]:
            path, text = steps["export_file"]
            await self._install_root_file(text, path)
            await self._checked(["exportfs", "-ra"])
        for argv in steps["protect"]:
            await self._checked(argv)
        self.logger.info(
            "Prepared backup storage for policy %s (%s)", policy_id, steps["kind"]
        )

    async def _checked(self, argv: List[str]) -> None:
        code, _out, err = await self._run(self._privileged(argv))
        if code != 0:
            raise PermissionError(f"{' '.join(argv)}: {err or code}")

    async def _prepare(
        self, run_id: str, policy_id: str, policy: Dict[str, Any]
    ) -> None:
        started = _now()
        result: Dict[str, Any] = {}
        try:
            mount_point = policy.get("mount_point") or posixpath.dirname(
                policy["repository"]
            )
            steps = storage_prepare.plan(
                dict(policy, policy_id=policy_id),
                system=platform.system(),
                fstype=storage_fs.describe(mount_point, read_text=_read_text)["type"],
                datasets=await self._zfs_datasets(),
                is_subvolume=self._is_subvolume,
            )
            await self._prepare_steps(policy_id, steps)
            status, code = "ok", 0
            result = {"kind": steps["kind"]}
        except storage_prepare.PrepareRefused as refused:
            status, code = "failed", 1
            result = {"reason": refused.code, "errors": [str(refused)]}
        except OSError as error:
            status, code = "failed", 1
            result = {"reason": "command_failed", "errors": [str(error)]}
            self.logger.error(
                _("Could not prepare backup storage for policy %s: %s"),
                policy_id,
                error,
            )
        await self._report(
            {"run_id": run_id, "policy_id": policy_id,
             "action": storage_prepare.ACTION, "status": status, "exit": code,
             "result": result, "started_at": started, "finished_at": _now()}  # fmt: skip
        )

    # ------------------------------------------------------------------
    # watching a run
    # ------------------------------------------------------------------

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
            key_files.sweep(self._load(INFLIGHT_FILE), self._run, self._privileged)
        )
        for run_id, record in self._load(INFLIGHT_FILE).items():
            if isinstance(record, dict) and (
                record.get("unit") or record.get("pidfile")
            ):
                self._spawn(self._watch(run_id, record, resumed=True))
        storage_reaudit.schedule(self.reaudit_storage)

    async def reaudit_storage(self) -> int:
        """Send every storage policy's audit now (start, daily, Request Host Data)."""
        policies = self._load(POLICIES_FILE)
        return await storage_reaudit.send_all(policies, self._audit, self._send)

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
            active, unit_exit = await self._job_state(record)
            progress, offset = self._new_progress(record, offset)
            if progress and time.time() - last_sent >= PROGRESS_EVERY_SECONDS:
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
            if not active and (ended or waited > START_GRACE_SECONDS):
                await self._finish(run_id, record, unit_exit)
                return

    async def _finish(
        self, run_id: str, record: Dict[str, Any], unit_exit: Optional[int]
    ) -> None:
        text = _read_text(
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
             "started_at": record.get("started_at"), "finished_at": _now(),
             "restate_version": features.get("version")}  # fmt: skip
        )
        inflight = self._load(INFLIGHT_FILE)
        inflight.pop(run_id, None)
        self._save(INFLIGHT_FILE, inflight)
        await key_files.remove(
            record.get("key_files") or [], self._run, self._privileged
        )
        await self._release_mount(run_id, record["policy_id"], record)

    def _audit(self, policy: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """The storage audit for one repository; None if it cannot run."""
        try:
            return storage_audit.audit(
                policy["repository"],
                client=policy.get("client_address"),
                account=policy.get("service_account") or "restate",
                read_text=_read_text,
            )
        except Exception as error:  # pylint: disable=broad-except
            self.logger.warning(_("The storage audit could not run: %s"), error)
            return None

    async def _report(self, data: Dict[str, Any]) -> None:
        # The storage side reports its audit with every job, so the server's
        # picture of the append-only set-up never goes stale.
        policy = self._policy(str(data.get("policy_id") or ""))
        if policy and policy.get("role") == "storage":
            data = dict(data, storage_audit=self._audit(policy))
        await self._send("backup_result", data)

    async def _send(self, message_type: str, data: Dict[str, Any]) -> None:
        payload = dict(data)
        approval = self.agent.registration_manager.get_host_approval_from_db()
        if approval:
            payload["host_id"] = str(approval.host_id)
        message = self.agent.create_message(message_type, payload)
        if not await self.agent.send_message(message):
            self.logger.warning(_("Could not queue the backup report"))
