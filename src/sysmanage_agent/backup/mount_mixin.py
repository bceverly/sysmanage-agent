# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The backed-up host's own export, mounted only while a job runs (24.1):
BackupOperations' mount handling, kept apart from the job plumbing.

Every decision reads the HOST's mount table, and on systemd hosts systemd
does the mounting -- see backup/host_mount.py for why (a private mount
namespace once let a capture write to the host's own disk).
"""

import asyncio
import platform
import posixpath
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import job_validation as validation
from src.sysmanage_agent.backup import repository_choice

MOUNTS_FILE = "mounts.json"


def no_nfs_client() -> str:
    return _(
        "This host has no NFS client, so it cannot mount its backup storage. "
        "Click Equip for backup, or install it (nfs-common on Debian and "
        "Ubuntu, nfs-utils on RHEL and Fedora)."
    )


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


class BackupMountMixin:
    """Needs ``_policy``, ``_load``, ``_save``, ``_run``, ``_privileged``
    and ``logger`` from the class it is mixed into."""

    @staticmethod
    def _mounts() -> Dict[str, str]:
        """The HOST's mount table (what restate's unit sees), not this
        process's private namespace -- see backup/host_mount.py."""
        text = _read_text(host_mount.HOST_MOUNTINFO)
        if text is None:
            text = _read_text(host_mount.SELF_MOUNTINFO)
        return validation.mount_types(text or "")

    async def _ensure_mount(
        self, run_id: str, policy_id: str, record: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Mount the run's export (the current repository's, or the one
        before it -- ``record``); None, or why it failed."""
        policy = self._policy(policy_id) or {}
        if policy.get("role") != "host":
            return None
        where, source, _previous = repository_choice.for_record(policy, record or {})
        state = self._load(MOUNTS_FILE)
        entry = state.get(where)
        mounts = self._mounts()
        if not source:
            return self._unmanaged_mount(where, mounts)
        if entry is None and host_mount.mounted_nfs(posixpath.dirname(where), mounts):
            return None  # the operator mounted the shared export: use it
        if host_mount.mounted_nfs(where, mounts):
            if entry is None:
                return None  # the operator's own mount: used, never unmounted
        else:
            failed = await self._mount_export(source, where)
            if failed:
                return failed
            entry = {"runs": []}
        entry["runs"] = sorted(set(entry.get("runs", [])) | {run_id})
        state[where] = entry
        self._save(MOUNTS_FILE, state)
        return None

    @staticmethod
    def _unmanaged_mount(where: str, mounts: Dict[str, str]) -> Optional[str]:
        """No export to mount from: the repository (or its parent) must
        already be an NFS mount.  Never let restate run against the host's
        own disk: it would write (or create) a repository there, not on the
        storage."""
        if host_mount.mounted_nfs(where, mounts) or host_mount.mounted_nfs(
            posixpath.dirname(where), mounts
        ):
            return None
        return _(
            "The backup storage is not mounted at %(where)s, and the server "
            "has not sent where to mount it from yet."
        ) % {"where": where}

    async def _mount_export(self, source: Dict[str, Any], where: str) -> Optional[str]:
        """Mount ``source`` at ``where``; None, or why it failed."""
        if host_mount.nfs_client_missing(platform.system()):
            return no_nfs_client()
        systemd = host_mount.systemd_running()
        for argv in (
            ["mkdir", "-p", where],
            host_mount.mount_argv(source, where, systemd),
        ):
            code, _out, err = await self._run(self._privileged(argv))
            if code != 0:
                return _("Could not mount the backup storage %(source)s at %(where)s: %(error)s") % {
                    "source": host_mount.device(source), "where": where,
                    "error": err or code}  # fmt: skip
        if not host_mount.mounted_nfs(where, self._mounts()):
            # Mounted where only this process can see it (a private mount
            # namespace): take it down again, and never let restate write
            # to the host's own disk.
            await self._run(self._privileged(host_mount.umount_argv(where, systemd)))
            return _("The backup storage is not mounted at %(where)s after mounting it.") % {
                "where": where}  # fmt: skip
        return None

    async def _preflight(self, policy_id: str) -> Optional[str]:
        """Can the repository take this capture?  Off the event loop: a hard
        NFS mount to a storage host that is down would block it."""
        policy = self._policy(policy_id) or {}
        if policy.get("role") != "host":
            return None
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, host_mount.preflight, policy["repository"]),
                host_mount.PREFLIGHT_SECONDS,
            )
        except asyncio.TimeoutError:
            return _("The backup storage at %s did not answer.") % policy["repository"]

    async def _release_mount(
        self, run_id: str, policy_id: str, record: Optional[Dict[str, Any]] = None
    ) -> None:
        """This run is done with the export; unmount after the last one."""
        policy = self._policy(policy_id) or {}
        try:
            where = repository_choice.for_record(policy, record or {})[0]
        except (KeyError, validation.PolicyError):
            where = policy.get("repository")
        state = self._load(MOUNTS_FILE)
        entry = state.get(where) if where else None
        if entry is None:
            return
        entry["runs"] = [r for r in entry.get("runs", []) if r != run_id]
        if entry["runs"]:
            self._save(MOUNTS_FILE, state)
            return
        systemd = host_mount.systemd_running()
        code, _out, err = await self._run(
            self._privileged(host_mount.umount_argv(where, systemd))
        )
        if code != 0 and host_mount.mounted_nfs(where, self._mounts()):
            self.logger.warning(
                _("Could not unmount the backup storage at %s: %s"), where, err
            )
            return  # keep the record: the next run's release tries again
        del state[where]
        self._save(MOUNTS_FILE, state)
