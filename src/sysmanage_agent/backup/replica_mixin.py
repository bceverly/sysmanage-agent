# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Off-site copies on the storage host, and the backed-up host's read
tokens for them (server ROADMAP 27.3).

A mixin for :class:`BackupOperations`; see ``replicas`` for what is sent and
why.  At configure the storage host makes a copy token of its own for each
replica (once: it is kept and reused), installs the replica's CA, removes
what belonged to replicas no longer listed and reports the tokens' hashes.
A backed-up host does the same for its off-site copies (``offsite``): a
read token of its own for each.  A ``copy`` run writes that run's job and
starts it.  Nothing here ever logs
or reports a token.
"""

import os
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.backup import job_validation as validation
from src.sysmanage_agent.backup import offsite
from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import replicas
from src.sysmanage_agent.backup import restate_contract as contract

POLICIES_FILE = "policies.json"
# What a policy lists -> (the tokens it reports, the module naming its files).
_FAR = {"replicas": ("copy_tokens", replicas), "offsite": ("offsite_tokens", offsite)}


class BackupReplicaMixin:
    """Copy tokens and off-site copy runs, for BackupOperations."""

    async def _apply_replicas(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Make this policy's copy tokens and CA files match its replicas;
        ``{"replicas", "copy_tokens"}`` for the saved policy, the reply
        carrying ``copy_tokens`` only.  When the server sent no replicas (an
        older server) what was saved before is kept and nothing changes."""
        return await self._apply_far_tokens(policy, "replicas")

    async def _apply_offsite(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """The same for a backed-up host's off-site copies (``offsite``):
        one read token each, ``{"offsite", "offsite_tokens"}``."""
        return await self._apply_far_tokens(policy, "offsite")

    async def _apply_far_tokens(
        self, policy: Dict[str, Any], kind: str
    ) -> Dict[str, Any]:
        """Tokens of this host's own for the repositories behind another
        storage host's restate-proxy that ``policy[kind]`` lists, made once
        and kept; the CA files installed; what belonged to entries no longer
        listed removed."""
        tokens_key, module = _FAR[kind]
        policy_id = policy["policy_id"]
        before = self._load(POLICIES_FILE).get(policy_id) or {}
        wanted = policy.get(kind)
        if wanted is None:
            return {key: before.get(key) for key in (kind, tokens_key)}
        known = before.get(tokens_key) or {}
        tokens: Dict[str, str] = {}
        for entry in wanted:
            tokens[entry["id"]] = await self._far_token(
                module.token_path(policy_id, entry["id"]), known.get(entry["id"])
            )
            ca_file = module.ca_path(policy_id, entry["id"])
            if entry.get("ca"):
                await self._install_root_file(entry["ca"], ca_file)
            elif os.path.exists(ca_file):
                await self._remove_root_file(ca_file)
        for stale in module.stale_ids(policy_id, tokens, list(known), os.listdir):
            for path in module.files_of(policy_id, stale):
                if os.path.exists(path):
                    await self._remove_root_file(path)
        return {kind: replicas.saved(wanted), tokens_key: tokens}

    async def _far_token(self, path: str, known: Optional[str]) -> str:
        """The hash of one of this host's tokens: the one made before when
        its file is still there, else a new one, made now (root's, 0600)."""
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
