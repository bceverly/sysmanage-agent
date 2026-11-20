# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Off-site copies on the storage host (server ROADMAP 27.3).

A mixin for :class:`BackupOperations`; see ``replicas`` for what is sent and
why.  At configure the storage host makes a copy token of its own for each
replica (once: it is kept and reused), installs the replica's CA, removes
what belonged to replicas no longer listed and reports the tokens' hashes.
A ``copy`` run writes that run's job and starts it.  Nothing here ever logs
or reports a token.
"""

import os
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.backup import job_validation as validation
from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import replicas
from src.sysmanage_agent.backup import restate_contract as contract

POLICIES_FILE = "policies.json"


class BackupReplicaMixin:
    """Copy tokens and off-site copy runs, for BackupOperations."""

    async def _apply_replicas(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Make this policy's copy tokens and CA files match its replicas;
        ``{"replicas", "copy_tokens"}`` for the saved policy, the reply
        carrying ``copy_tokens`` only.  When the server sent no replicas (an
        older server) what was saved before is kept and nothing changes."""
        policy_id = policy["policy_id"]
        before = self._load(POLICIES_FILE).get(policy_id) or {}
        wanted = policy.get("replicas")
        if wanted is None:
            return {key: before.get(key) for key in ("replicas", "copy_tokens")}
        known = before.get("copy_tokens") or {}
        tokens: Dict[str, str] = {}
        for replica in wanted:
            tokens[replica["id"]] = await self._copy_token(
                policy_id, replica["id"], known.get(replica["id"])
            )
            ca_file = replicas.ca_path(policy_id, replica["id"])
            if replica.get("ca"):
                await self._install_root_file(replica["ca"], ca_file)
            elif os.path.exists(ca_file):
                await self._remove_root_file(ca_file)
        for stale in replicas.stale_ids(
            policy_id, tokens, list(known), os.listdir
        ):  # fmt: skip
            for path in replicas.files_of(policy_id, stale):
                if os.path.exists(path):
                    await self._remove_root_file(path)
        return {"replicas": replicas.saved(wanted), "copy_tokens": tokens}

    async def _copy_token(
        self, policy_id: str, replica_id: str, known: Optional[str]
    ) -> str:
        """The hash of this host's copy token for one replica: the one made
        before when its file is still there, else a new one, made now."""
        path = replicas.token_path(policy_id, replica_id)
        if known and os.path.exists(path):
            return known
        token = access.new_token()
        await self._install_root_file(token, path, mode="600")
        return access.token_sha256(token)

    async def _start_replica_copy(
        self,
        run_id: str,
        policy_id: str,
        policy: Optional[Dict[str, Any]],
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Copy one snapshot of this storage policy's repository into one of
        its replicas: a job written fresh for the run (like a sign)."""
        refused = self._replica_copy_refusal(policy)
        if refused is None:
            try:
                refused = await self._write_copy_job(policy_id, policy, params)
            except replicas.ReplicaUnknown:
                refused = self._not_configured()
            except validation.PolicyError as error:
                refused = self._refusal("invalid_request", str(error))
            except OSError as error:
                refused = self._refusal("install_failed", str(error))
        if refused is not None:
            return refused
        return await self._start_job(run_id, policy_id, replicas.COPY_ACTION)

    async def _write_copy_job(
        self, policy_id: str, policy: Dict[str, Any], params: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Install the run's copy job; a refusal when this restate lacks a
        key it uses, else None."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.operations.backup_operations import _agent_group

        job = replicas.build_copy_job(
            params,
            repository=policy["repository"],
            replicas=policy.get("replicas"),
            state_dir=self.state_dir,
            group=_agent_group(),
        )
        missing = contract.unsupported_keys(self._features() or {}, job)
        if missing:
            return self._refusal(
                "tool_outdated",
                _("This restate does not support: %s") % ", ".join(missing),
            )
        await self._install_root_file(
            contract.render_job(job),
            contract.job_path(policy_id, replicas.COPY_ACTION),
        )
        return None

    def _replica_copy_refusal(
        self, policy: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Why this host cannot run an off-site copy for ``policy``, or None."""
        if not policy or policy.get("role") not in ("storage", validation.SELF):
            return self._not_configured()
        if replicas.COPY_ACTION in (policy.get("actions") or []):
            # Its own job file is the policy's configured copy: never
            # overwritten with a run's.
            return self._refusal(
                "invalid_request",
                _(
                    "This backup policy has a copy job of its own, so an "
                    "off-site copy cannot run for it."
                ),
            )
        if not contract.copies_remote(self._features()):
            return self._refusal(
                "tool_outdated",
                _(
                    "This restate cannot copy a snapshot to another storage "
                    "host; upgrade restate."
                ),
            )
        return None
