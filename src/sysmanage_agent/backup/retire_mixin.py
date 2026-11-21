# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""BackupOperations: remove a moved host's old repository (27.3).

What may be removed, and how, is ``storage_retire``'s; this runs it and
reports.  Composed into ``operations/backup_operations.py``.
"""

import os
import platform
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import storage_retire as retire


def _exists(path: str) -> bool:
    return os.path.lexists(path)


def _ops():
    """backup_operations, looked up at call time (as the storage mixin
    does): its constants and helpers are the ones tests patch."""
    from src.sysmanage_agent.operations import (  # pylint: disable=import-outside-toplevel
        backup_operations,
    )

    return backup_operations


class BackupRetireMixin:
    """Needs BackupOperations' state files, privileged helpers, the storage
    mixin's ZFS listing and subvolume test, and reporting."""

    def _start_retire(
        self, run_id: str, policy_id: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check the request now (a refusal is the answer), then remove the
        repository in the background and report when it is done."""
        forget = bool(parameters.get("forget"))
        repository = parameters.get("repository")
        try:
            entry = retire.check(
                self._load(_ops().POLICIES_FILE), policy_id, repository, forget
            )
        except retire.RetireRefused as refused:
            return self._refusal(refused.code, str(refused))
        self._spawn(self._retire(run_id, policy_id, entry, repository, forget))
        return {"success": True, "run_id": run_id, "status": "started"}

    async def _retire(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        run_id: str,
        policy_id: str,
        entry: Dict[str, Any],
        repository: str,
        forget: bool,
    ) -> None:
        started = _ops()._now()
        try:
            code, out, err = await self._run(
                self._privileged(retire.probe_argv(repository))
            )
            steps = retire.plan(
                repository,
                system=platform.system(),
                state=retire.probe_state(code, out, err),
                datasets=await self._zfs_datasets(),
                is_subvolume=self._is_subvolume,
            )
            await self._retire_steps(steps)
            removed = await self._retire_grants(repository)
            sharing = retire.sharers(
                self._load(_ops().POLICIES_FILE), policy_id, repository
            )
            for other_id in sharing:
                removed += await self._forget_storage_policy(
                    other_id, self._policy(other_id) or {}
                )
            if forget:
                removed += await self._forget_storage_policy(policy_id, entry)
            else:
                self._drop_former(policy_id, repository)
            status, code = "ok", 0
            result: Dict[str, Any] = {
                "kind": steps["kind"], "repository": repository,
                "forgot": forget, "files_removed": removed,
                "also_forgot": sharing,
            }  # fmt: skip
            self.logger.info("Removed the old repository %s of policy %s (%s)",
                             repository, policy_id, steps["kind"])  # fmt: skip
        except retire.RetireRefused as refused:
            status, code = "failed", 1
            result = {"reason": refused.code, "errors": [str(refused)]}
        except OSError as error:
            status, code = "failed", 1
            result = {"reason": "command_failed", "errors": [str(error)]}
            self.logger.error(_("Could not remove the old repository %s: %s"),
                              repository, error)  # fmt: skip
        await self._report(
            {"run_id": run_id, "policy_id": policy_id, "action": retire.ACTION,
             "status": status, "exit": code, "result": result,
             "started_at": started, "finished_at": _ops()._now()}  # fmt: skip
        )

    async def _retire_steps(self, steps: Dict[str, Any]) -> None:
        tools = {"zfs": _ops()._first(_ops().ZFS_PATHS),
                 "btrfs": _ops()._first(_ops().BTRFS_PATHS)}  # fmt: skip
        systemd = host_mount.systemd_running()
        for argv in steps["commands"]:
            argv = [tools.get(argv[0], argv[0])] + argv[1:]
            if steps["host_namespace"]:
                argv = host_mount.in_host_namespace(argv, platform.system(), systemd)
            await self._checked(argv)

    async def _retire_grants(self, repository: str) -> int:
        paths = retire.grants_for(repository, os.listdir, _ops()._read_text)
        for path in paths:
            await self._remove_root_file(path)
        return len(paths)

    async def _forget_storage_policy(
        self, policy_id: str, entry: Dict[str, Any]
    ) -> int:
        """Its job files, rules, key and export go; the agent forgets it."""
        removed = 0
        for path in retire.forget_files(policy_id, entry):
            # rm -f either way: the agent's account may not see into the
            # directory (the key directory is root's alone).
            await self._remove_root_file(path)
            removed += 1
        export = retire.export_file(policy_id)
        if _exists(export):
            await self._remove_root_file(export)
            await self._checked(["exportfs", "-ra"])
            removed += 1
        policies = self._load(_ops().POLICIES_FILE)
        policies.pop(policy_id, None)
        self._save(_ops().POLICIES_FILE, policies)
        return removed

    def _drop_former(self, policy_id: str, repository: str) -> None:
        policies = self._load(_ops().POLICIES_FILE)
        entry = policies.get(policy_id)
        if isinstance(entry, dict):
            entry["former"] = [p for p in entry.get("former") or [] if p != repository]
            self._save(_ops().POLICIES_FILE, policies)
