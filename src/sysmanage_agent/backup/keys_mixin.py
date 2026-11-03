# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The restate driver's keys: decryption keys for one run, the snapshot
signer's public key on backed-up hosts, and the signing key for one run on
the storage host (Pro+ backup_engine, 24.6).

Split out of ``operations/backup_operations.py`` to keep it under the
1000-line limit; ``BackupOperations`` mixes it in.  Every method uses the
driver's own helpers (``_run``, ``_privileged``, ``_install_root_file``,
``_features``, ``_start_job``, ``_refusal``).
"""

import os
from typing import Any, Dict, List, Optional

from src.i18n import _
from src.sysmanage_agent.backup import job_validation as validation
from src.sysmanage_agent.backup import key_files
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import signing


class BackupKeysMixin:
    """Key handling for ``BackupOperations``."""

    async def _decrypt_keys(self, run_id: str, params: Dict[str, Any]) -> List[str]:
        """This run's key files when it reads an encrypted repository."""
        return await key_files.for_run(
            self.agent, self._features(), run_id, params, self._run, self._privileged
        )

    async def _apply_trusted_key(self, policy: Dict[str, Any]) -> None:
        """Install the signer's public key the configure carries, or remove
        one a policy no longer has (signing turned off)."""
        path = contract.trusted_key_path(policy["policy_id"])
        if policy.get("trusted_key"):
            await self._install_root_file(policy["trusted_key"], path)
        elif os.path.exists(path):
            await self._remove_root_file(path)

    @staticmethod
    def _trusted_key(policy_id: str) -> Optional[str]:
        """The signer's public key file for this policy, if installed."""
        path = contract.trusted_key_path(policy_id)
        return path if os.path.exists(path) else None

    async def _start_sign(
        self, run_id: str, policy_id: str, policy: Dict[str, Any], params: Any
    ) -> Dict[str, Any]:
        """Sign a snapshot on the storage host with the key fetched for this
        run only; the key is removed when the run ends (or fails to start)."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.operations.backup_operations import _agent_group

        features = self._features()
        if not (
            contract.supports_job_command(features, signing.SIGN_ACTION)
            and contract.supports(features, "sign_with")
        ):
            return self._refusal(
                "tool_outdated",
                _("This restate cannot sign a snapshot; upgrade restate."),
            )
        keys: List[str] = []
        try:
            keys = await key_files.for_run(
                self.agent, features, run_id, params or {}, self._run,
                self._privileged, need="sign_with",
            )  # fmt: skip
            if not keys:
                raise validation.PolicyError(_("A signing run needs its key"))
            job = signing.build_sign_job(
                params,
                repository=policy["repository"],
                state_dir=self.state_dir,
                group=_agent_group(),
                sign_with=keys[0],
            )
            await self._install_root_file(
                contract.render_job(job),
                contract.job_path(policy_id, signing.SIGN_ACTION),
            )
        except (validation.PolicyError, key_files.KeyFetchError, OSError) as error:
            await key_files.remove(keys, self._run, self._privileged)
            return self._refusal(key_files.refusal_code(error), str(error))
        return await self._start_job(
            run_id, policy_id, signing.SIGN_ACTION, False, keys
        )
