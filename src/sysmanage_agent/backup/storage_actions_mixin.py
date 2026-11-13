# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""BackupOperations: the storage host's own actions -- seal, prepare, audit.

Split out of ``operations/backup_operations.py`` (which composes it).
"""

import asyncio
import os
import platform
import posixpath
import shutil
import time
from typing import Any, Dict, List, Optional

from src.i18n import _
from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import proxy_access
from src.sysmanage_agent.backup import seal_retention
from src.sysmanage_agent.backup import storage_audit
from src.sysmanage_agent.backup import storage_fs
from src.sysmanage_agent.backup import storage_prepare
from src.sysmanage_agent.backup import storage_reaudit


def _ops():
    """backup_operations, looked up at call time: its module-level constants
    and helpers are the ones callers (and tests) patch, and a top-level
    import would be circular."""
    from src.sysmanage_agent.operations import (  # pylint: disable=import-outside-toplevel
        backup_operations,
    )

    return backup_operations


class BackupStorageActionsMixin:
    """Seal, prepare and audit storage; needs BackupOperations' state files,
    privileged helpers and reporting."""

    # ------------------------------------------------------------------
    # seal: the NAS snapshots its own dataset
    # ------------------------------------------------------------------

    def _start_seal(
        self, run_id: str, policy_id: str, seal: Dict[str, Any]
    ) -> Dict[str, Any]:
        self._spawn(self._seal(run_id, policy_id, seal))
        return {"success": True, "run_id": run_id, "status": "started"}

    async def _seal(self, run_id: str, policy_id: str, seal: Dict[str, Any]) -> None:
        started = _ops()._now()
        code: Optional[int] = 0
        message = ""
        argv = _ops().seal_argv(seal, run_id)
        result: Dict[str, Any] = {}
        if argv:
            code, _out, message = await self._run(self._privileged(argv))
        if code == 0 and argv and seal.get("mode") == "btrfs_snapshot":
            ledger = self._load(_ops().SEALS_FILE)
            ledger[argv[-1]] = time.time()
            self._save(_ops().SEALS_FILE, ledger)
        if code == 0 and seal.get("keep_days"):
            result = await self._expire_seals(seal)
            message = message or "; ".join(result.get("errors", []))
        if message:
            result["message"] = message
        status = "ok" if code == 0 else "failed"
        await self._report(
            {"run_id": run_id, "policy_id": policy_id, "action": "seal",
             "status": status, "exit": code, "result": result or None,
             "started_at": started, "finished_at": _ops()._now()}  # fmt: skip
        )

    async def _expire_seals(self, seal: Dict[str, Any]) -> Dict[str, Any]:
        """Remove this agent's seals older than ``keep_days`` (never the
        newest).  A failure is reported but never fails the seal itself."""
        keep, now = seal["keep_days"], time.time()
        if seal["mode"] == "zfs_snapshot":
            zfs = _ops()._first(_ops().ZFS_PATHS)
            code, out, err = await self._run(
                seal_retention.zfs_list_argv(zfs, seal["dataset"])
            )
            if code != 0:
                return {"errors": [_("Could not list the sealed snapshots: %s") % err]}
            seals = seal_retention.zfs_seals(out, seal["dataset"])
            tool = zfs
        else:
            ledger = self._load(_ops().SEALS_FILE)
            seals = seal_retention.btrfs_seals(ledger, seal["snapshot_dir"])
            tool = _ops()._first(_ops().BTRFS_PATHS)
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
            ledger = self._load(_ops().SEALS_FILE)
            for path in removed:
                ledger.pop(path, None)
            self._save(_ops().SEALS_FILE, ledger)
        return {"seals_removed": len(removed), "seals_kept": len(seals) - len(removed),
                "errors": errors}  # fmt: skip

    # ------------------------------------------------------------------
    # prepare: the storage host gives one host its own export
    # ------------------------------------------------------------------

    async def _zfs_datasets(self) -> Dict[str, str]:
        zfs = shutil.which("zfs") or _ops()._first(_ops().ZFS_PATHS)
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
        tools = {storage_prepare.ZFS: _ops()._first(_ops().ZFS_PATHS),
                 storage_prepare.BTRFS: _ops()._first(_ops().BTRFS_PATHS)}  # fmt: skip
        # The dataset / subvolume / directory first, then its export, then
        # its ownership (chown needs the new mount, not the directory under it).
        systemd = host_mount.systemd_running()
        for argv in steps["commands"]:
            argv = [tools.get(argv[0], argv[0])] + argv[1:]
            if argv[1:2] == ["create"] and steps["kind"] == storage_prepare.ZFS:
                argv = storage_prepare.in_host_namespace(
                    argv, platform.system(), systemd
                )
            await self._checked(argv)
        if steps.get("zfs_dataset"):
            await self._mount_host_wide(steps["zfs_dataset"], tools[storage_prepare.ZFS],
                                        steps["repository"], systemd)  # fmt: skip
        if steps["export_file"]:
            path, text = steps["export_file"]
            await self._install_root_file(text, path)
            await self._checked(["exportfs", "-ra"])
        # restate-proxy (25.5): the repository itself, before the ownership
        # and append-only rule -- restate init leaves the directory 0700
        # root's, which the proxy's account could not enter.
        if steps.get("init"):
            await self._init_repository(**steps["init"])
        for argv in steps["protect"]:
            await self._checked(argv)
        self.logger.info(
            "Prepared backup storage for policy %s (%s)", policy_id, steps["kind"]
        )

    async def _mount_host_wide(
        self, dataset: str, zfs: str, repository: str, systemd: bool
    ) -> None:
        """The dataset must be mounted where NFS exports it -- the host's
        mount table -- before anything is set on it: mount it there if it is
        not (one an older agent made in its own namespace), and stop if it
        still is not, rather than prepare the directory beneath it."""

        def mounted() -> bool:
            text = _ops()._read_text(host_mount.HOST_MOUNTINFO) or _ops()._read_text(
                host_mount.SELF_MOUNTINFO
            )
            return storage_prepare.zfs_mounted(repository, text)

        if not mounted():
            await self._checked(storage_prepare.in_host_namespace(
                [zfs, "mount", dataset], platform.system(), systemd))  # fmt: skip
        if not mounted():
            raise PermissionError(
                _("%(dataset)s is not mounted at %(path)s on this host") % {
                    "dataset": dataset, "path": repository}  # fmt: skip
            )

    async def _init_repository(
        self, repository: str, owner: str, encrypt_to: Optional[str] = None
    ) -> None:
        """restate-proxy (25.5): make the repository a host captures into
        through the proxy, which restate cannot do from the host.  One that
        is there already is left as it is."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.backup import restate_probe  # noqa: PLC0415

        restate = restate_probe.locate()
        if restate is None:
            raise PermissionError(_("restate is not installed on this storage host"))
        code, _out, err = await self._run(
            self._privileged(storage_prepare.init_argv(restate, repository, encrypt_to))
        )
        if code != 0:
            if storage_prepare.ALREADY_A_REPOSITORY in err:
                return
            raise PermissionError(f"restate init {repository}: {err or code}")
        await self._checked(storage_prepare.init_owner_argv(repository, owner))

    async def _checked(self, argv: List[str]) -> None:
        code, _out, err = await self._run(self._privileged(argv))
        if code != 0:
            raise PermissionError(f"{' '.join(argv)}: {err or code}")

    async def _prepare(
        self, run_id: str, policy_id: str, policy: Dict[str, Any]
    ) -> None:
        started = _ops()._now()
        result: Dict[str, Any] = {}
        try:
            mount_point = policy.get("mount_point") or posixpath.dirname(
                policy["repository"]
            )
            steps = storage_prepare.plan(
                dict(policy, policy_id=policy_id),
                system=platform.system(),
                fstype=storage_fs.describe(mount_point, read_text=_ops()._read_text)[
                    "type"
                ],
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
             "result": result, "started_at": started, "finished_at": _ops()._now()}  # fmt: skip
        )

    async def _sweep_markers(self, repository: str) -> None:
        """Remove empty ``.sysmanage-preflight-*`` files an older agent's
        pre-flight check left at the top of a host's repository directory.
        The host cannot (its access is append-only), and restate will not
        create a repository in a directory that holds them (production,
        ubiquiti, 2026-10-29).  Only zero-byte files of that exact name, one
        level deep; anything else is left alone."""
        code, _out, err = await self._run(self._privileged(
            ["find", repository, "-maxdepth", "1", "-type", "f",
             "-name", ".sysmanage-preflight-*", "-size", "0", "-delete"]
        ))  # fmt: skip
        if code != 0:
            self.logger.warning("Could not sweep stale pre-flight files in %s: %s",
                                repository, err.strip())  # fmt: skip

    async def reaudit_storage(self) -> int:
        """Send every storage policy's audit, and every policy's restate
        version, now (start, daily, Request Host Data)."""
        policies = self._load(_ops().POLICIES_FILE)
        loop = asyncio.get_running_loop()
        features = await loop.run_in_executor(None, self._features) or {}
        return await storage_reaudit.send_all(
            policies, self._storage_findings, self._send, features.get("version")
        )

    def _audit(self, policy: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """The storage audit for one repository; None if it cannot run."""
        try:
            return storage_audit.audit(
                policy["repository"],
                client=policy.get("client_address"),
                account=policy.get("service_account") or "restate",
                read_text=_ops()._read_text,
                export=proxy_access.needs_export(policy),
            )
        except Exception as error:  # pylint: disable=broad-except
            self.logger.warning(_("The storage audit could not run: %s"), error)
            return None
