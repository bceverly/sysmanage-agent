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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.database.base import current_database_path
from src.i18n import _
from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import job_validation as validation
from src.sysmanage_agent.backup import key_files
from src.sysmanage_agent.backup.job_lifecycle_mixin import BackupJobLifecycleMixin
from src.sysmanage_agent.backup.keys_mixin import BackupKeysMixin
from src.sysmanage_agent.backup.mount_mixin import BackupMountMixin
from src.sysmanage_agent.backup.network_rules_mixin import NetworkRulesMixin
from src.sysmanage_agent.backup.self_backup_mixin import SelfBackupMixin
from src.sysmanage_agent.backup.storage_actions_mixin import (
    BackupStorageActionsMixin,
)
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import storage_fs
from src.sysmanage_agent.backup import storage_prepare
from src.sysmanage_agent.backup import repository_choice
from src.sysmanage_agent.backup import restate_probe
from src.sysmanage_agent.backup import self_backup
from src.sysmanage_agent.backup import signing

DEFAULT_STATE_DIR = "/var/lib/sysmanage-agent"
# The driver's own state files, in its state directory.
POLICIES_FILE = "policies.json"
INFLIGHT_FILE = "inflight.json"
RESEND_SECONDS = 60  # a report the queue refused is tried again this often
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


def _wrong_platform(role: str) -> str:
    """Why this platform cannot take ``role``."""
    if platform.system() == "Darwin" and role != "host":
        return _("A Mac can only be a backed-up host, not a backup storage host.")
    return _("This platform cannot take that backup role.")


def _allowed_actions(policy: Optional[Dict[str, Any]]) -> List[str]:
    """What a ``backup_run`` may start for this policy: its job files'
    actions, plus prepare and sign on the storage side and the read-only
    browse jobs where it captures."""
    allowed = list(policy.get("actions", [])) if policy else []
    role = (policy or {}).get("role")
    if role in ("storage", validation.SELF):
        allowed += [storage_prepare.ACTION, signing.SIGN_ACTION]
    if role in validation.CAPTURING_ROLES:
        allowed += list(job_builder.BROWSE_JOBS)
    return allowed


class BackupOperations(  # pylint: disable=too-many-ancestors
    BackupMountMixin,
    NetworkRulesMixin,
    BackupKeysMixin,
    SelfBackupMixin,
    BackupJobLifecycleMixin,
    BackupStorageActionsMixin,
):
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
    async def _run(
        argv: List[str], input_data: Optional[str] = None
    ) -> Tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/",
        )
        out, err = await proc.communicate(
            input_data.encode("utf-8") if input_data is not None else None
        )
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
        if self.runner != job_runner.DAEMON and platform.system() == "Linux":
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
                mount_table=(
                    None
                    if platform.system() == "Linux"
                    else lambda: self_backup.mount_types(platform.system())
                ),
            )
            if policy["role"] not in job_runner.roles_for(
                platform.system(), self.runner
            ):
                return self._refusal("wrong_platform", _wrong_platform(policy["role"]))
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
        await self._apply_trusted_key(policy)
        await self._apply_rules(policy)
        features = self._features() or {}
        network_rules, network = await self._apply_network_rules(policy, features)
        self_points = await self._apply_self_rules(policy)
        jobs = job_builder.build_jobs(
            policy,
            state_dir=self.state_dir,
            group=_agent_group(),
            key_installed=bool(policy["encrypt_key"]),
            can_create=contract.supports(features, "create"),
            network_rules=network_rules,
            include_mounts=(network or {}).get("kept") if not network_rules else None,
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
            # For the network-mount refresh before each walk.
            "network_rules": network_rules,
            "network_excluded": (network or {}).get("excluded") or [],
            "keep_paths": (policy["jobs"].get("capture") or {}).get("keep_paths") or [],
        }
        self._save(POLICIES_FILE, policies)
        reply = {
            "success": True,
            "policy_id": policy_id,
            "installed": sorted(jobs),
            "removed": removed,
            # The restate these job files were written for (the server shows
            # it, and re-sends the files when a later job reports another).
            "restate_version": features.get("version"),
        }
        return await self._configure_reply(
            policy, policies[policy_id], reply, network, self_points
        )

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
        role = (policy or {}).get("role")
        if action not in _allowed_actions(policy):
            return self._not_configured()
        if action == "seal":
            return self._start_seal(run_id, policy_id, policy.get("seal") or {})
        if action in job_builder.BROWSE_JOBS:
            return await self._start_browse(run_id, policy_id, policy, parameters)
        if action == signing.SIGN_ACTION and role in ("storage", validation.SELF):
            return await self._start_sign(run_id, policy_id, policy, parameters)
        if action == storage_prepare.ACTION and role in ("storage", validation.SELF):
            self._spawn(self._prepare(run_id, policy_id, policy))
            return {"success": True, "run_id": run_id, "status": "started"}
        return await self._start_configured(run_id, policy_id, policy, action)

    async def _start_configured(
        self, run_id: str, policy_id: str, policy: Dict[str, Any], action: str
    ) -> Dict[str, Any]:
        """An action with a job file of its own: refresh its rules files
        (the self and network-mount ones), then start it."""
        if not os.path.exists(contract.job_path(policy_id, action)):
            return self._not_configured()
        await self._refresh_self_rules(policy_id, policy, action)
        excluded = await self._refresh_network_rules(policy_id, policy, action)
        if excluded is not None:
            policies = self._load(POLICIES_FILE)
            policies.setdefault(policy_id, {})["network_excluded"] = excluded
            self._save(POLICIES_FILE, policies)
        return await self._start_job(run_id, policy_id, action)

    async def _start_browse(
        self,
        run_id: str,
        policy_id: str,
        policy: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """A snapshot listing, a what-changed check, a full-read verification
        or two snapshots compared: read-only host jobs, each written fresh
        from the request (like a restore)."""
        action = params.get("action")
        command, build = job_builder.BROWSE_JOBS[action]
        if not contract.supports_job_command(self._features(), command):
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
            job = build(params, **common)
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
            if not policy or policy.get("role") not in validation.CAPTURING_ROLES:
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
                trusted_key=self._trusted_key(policy_id),
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
