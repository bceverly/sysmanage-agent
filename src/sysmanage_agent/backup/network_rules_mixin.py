# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The network-mount rules file of a host policy (see network_mounts).

Written at configure, and checked again before every capture or estimate:
a share mounted (or an automount added) between configure and the next
capture is left out of that capture too.  Only the host role walks the
host's files, so only it gets one.  Linux only: the host role runs only
under systemd (job_runner.ROLES).
"""

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_validation
from src.sysmanage_agent.backup import network_mounts
from src.sysmanage_agent.backup import restate_contract as contract

logger = logging.getLogger(__name__)

# The walks that read the host's files, and so the rules.
WALKS = job_builder.WALKS


class NetworkRulesMixin:
    """For BackupOperations: needs _install_root_file and _remove_root_file."""

    async def _found_network_mounts(
        self, policy: Dict[str, Any]
    ) -> network_mounts.Found:
        text = await asyncio.get_running_loop().run_in_executor(
            None, network_mounts.read_host_mountinfo
        )
        capture = (policy.get("jobs") or {}).get("capture") or {}
        return network_mounts.scan(
            text,
            repository_mount=policy.get("mount_point"),
            keep_paths=capture.get("keep_paths") or policy.get("keep_paths") or [],
        )

    async def _write_network_rules(
        self, policy_id: str, found: network_mounts.Found
    ) -> None:
        text, unexpressed = network_mounts.rules_text(found.excluded)
        for point in unexpressed:
            logger.warning(
                "Backup policy %s: network mount %r cannot be written as a "
                "restate rule; it is NOT left out of the backup",
                policy_id,
                point,
            )
        await self._install_root_file(text, job_builder.network_rules_path(policy_id))

    async def _apply_network_rules(
        self, policy: Dict[str, Any], features: Optional[Dict[str, Any]]
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """``(the walks read the agent's rules file, what to report)``."""
        if policy.get("role") not in job_validation.CAPTURING_ROLES:
            return False, None
        path = job_builder.network_rules_path(policy["policy_id"])
        native = network_mounts.skips_network_mounts(features)
        if native or not contract.supports(features, "rules"):
            if os.path.exists(path):
                await self._remove_root_file(path)
            if not native:
                return False, None
            return False, {
                "excluded": [],
                "kept": await self._included_mounts(policy, features),
                "native": True,
            }
        found = await self._found_network_mounts(policy)
        await self._write_network_rules(policy["policy_id"], found)
        return True, found.report()

    async def _included_mounts(
        self, policy: Dict[str, Any], features: Optional[Dict[str, Any]]
    ) -> List[str]:
        """The network mounts a keep path leads into, which a restate that
        skips them itself is told to walk (``include_mount``).  A point no
        job line can hold is left out, with a warning."""
        if not contract.supports(features, "include_mount"):
            return []
        kept = []
        for point in (await self._found_network_mounts(policy)).kept:
            try:
                kept += job_validation.check_mount_points([point])
            except job_validation.PolicyError:
                logger.warning(
                    "Backup policy %s: network mount %r cannot be written in a "
                    "job file; restate leaves it out of the backup",
                    policy["policy_id"],
                    point,
                )
        return kept

    async def _refresh_network_rules(
        self, policy_id: str, policy: Dict[str, Any], action: str
    ) -> Optional[List[str]]:
        """Before a walk: rewrite the rules file when the host's network
        mounts changed since it was written; the new list, else None.
        Never blocks the backup."""
        if action not in WALKS or not policy.get("network_rules"):
            return None
        try:
            found = await self._found_network_mounts(policy)
            if found.excluded == (policy.get("network_excluded") or []):
                return None
            await self._write_network_rules(policy_id, found)
            logger.info(
                "Backup policy %s: network mounts changed; now leaving out %s",
                policy_id,
                ", ".join(found.excluded) or "none",
            )
            return found.excluded
        except OSError as error:
            logger.warning(
                "Backup policy %s: could not refresh the network-mount rules: %s",
                policy_id,
                error,
            )
        return None
