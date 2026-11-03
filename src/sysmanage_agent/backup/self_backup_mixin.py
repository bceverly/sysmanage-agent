# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""For BackupOperations: the configure reply per role, and the storage
host's own backup's rules file (24.13, see self_backup).

Moved out of ``backup_operations`` with the ``self`` role to keep that
module under the 1000-line limit.  Needs ``_install_root_file``,
``_remove_root_file``, ``_sweep_markers`` and ``_audit``.
"""

import asyncio
import logging
import os
import platform
from typing import Any, Dict, List, Optional

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import self_backup
from src.sysmanage_agent.backup import storage_audit
from src.sysmanage_agent.backup import storage_fs
from src.sysmanage_agent.backup.job_validation import CAPTURING_ROLES, SELF

logger = logging.getLogger(__name__)


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


class SelfBackupMixin:
    """The ``self`` role's rules and every role's configure reply."""

    async def _self_points(self, policy: Dict[str, Any]) -> List[str]:
        mounts = await asyncio.get_running_loop().run_in_executor(
            None, self_backup.read_mounts, platform.system()
        )
        return self_backup.leave_out(mounts, policy["mount_point"])

    async def _apply_self_rules(self, policy: Dict[str, Any]) -> List[str]:
        """Write (or, for another role, remove) the self rules file; the
        points it leaves out."""
        path = job_builder.self_rules_path(policy["policy_id"])
        if policy.get("role") != SELF:
            if os.path.exists(path):
                await self._remove_root_file(path)
            return []
        points = await self._self_points(policy)
        text, unexpressed = self_backup.rules_text(points)
        for point in unexpressed:
            logger.warning(
                "Backup policy %s: %r cannot be written as a restate rule; "
                "the storage host's own backup does NOT leave it out",
                policy["policy_id"],
                point,
            )
        await self._install_root_file(text, path)
        return points

    async def _refresh_self_rules(
        self, policy_id: str, policy: Dict[str, Any], action: str
    ) -> None:
        """Before a self-backup's walk: a dataset made since configure is
        left out too.  Never blocks the backup."""
        if policy.get("role") != SELF or action not in job_builder.WALKS:
            return
        try:
            await self._apply_self_rules(dict(policy, policy_id=policy_id))
        except OSError as error:
            logger.warning(
                "Backup policy %s: could not refresh its own-backup rules: %s",
                policy_id,
                error,
            )

    async def _configure_reply(
        self,
        policy: Dict[str, Any],
        entry: Dict[str, Any],
        reply: Dict[str, Any],
        network: Optional[Dict[str, Any]],
        self_points: List[str],
    ) -> Dict[str, Any]:
        """What the server learns from a configure, by role."""
        features = self._features() or {}
        role = policy["role"]
        if role in CAPTURING_ROLES:
            # The quiesce hooks this host's restate finds present (2.1+): the
            # server offers them in the policy dialog.
            reply["hooks"] = contract.present_hooks(features)
            reply["abilities"] = contract.host_abilities(features)
            # The network shares left out of this host's backup.
            reply["network_mounts"] = network
        if role in ("storage", SELF):
            await self._sweep_markers(policy["repository"])
            if role == SELF:
                # Both sides on one machine: its host abilities stay in
                # ``abilities``, its storage ones go beside them.
                reply["storage_abilities"] = contract.storage_abilities(features)
                # What the storage host's own backup leaves out (24.13).
                reply["self_left_out"] = self_points
            else:
                reply["abilities"] = contract.storage_abilities(features)
            # Can this filesystem seal at all?  The server warns when not.
            reply["storage_fs"] = storage_fs.describe(
                policy["mount_point"], read_text=_read_text
            )
        if role == "storage":
            reply["storage_audit"] = self._audit(entry)
            # Where a host mounts its repository over NFSv4 (the server
            # sends it to the host, which mounts it only while a job runs).
            reply["nfs_path"] = storage_audit.client_path(
                platform.system(), policy["repository"]
            )
        return reply
