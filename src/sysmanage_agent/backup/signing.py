# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Snapshot signing (server ROADMAP 24.6, Pro+ backup_engine).

A snapshot is signed on the STORAGE host, never on the host it backs up: a
host that could sign could vouch for a snapshot it altered.  The server
queues a ``sign`` run right after a good capture and before ``protect`` --
restate cannot sign a snapshot protect has already made immutable -- with
``needs_key``; the storage host's agent fetches the signing key for that run
only (``key_files``), writes this run's job naming the key file, and removes
the key when the run ends.  restate signs the snapshot's index, which holds
every file's digest, so checking a signature decrypts nothing.

The backed-up hosts get the signer's PUBLIC key at configure
(``trusted_key``); their restores name it, so restate refuses a snapshot
with a bad signature or another key's (exit 4) and restores a signed one
without ``allow_unverified``.
"""

from typing import Any, Dict

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_validation as v

SIGN_ACTION = "sign"


def build_sign_job(
    params: Any,
    *,
    repository: str,
    state_dir: str,
    group: str,
    sign_with: str,
) -> Dict[str, Any]:
    """Sign one snapshot of the storage host's repository with the run's key
    file.  The server names the snapshot (the capture it follows); the agent
    chooses everything else."""
    if not isinstance(params, dict):
        raise v.PolicyError(job_builder.NOT_AN_OBJECT)
    policy_id = v.check_uuid(params.get("policy_id"), "policy_id")
    name = v.check_snapshot(params.get("snapshot"))
    job = {
        "command": SIGN_ACTION,
        "snapshot": f"{repository}::{name}",
        "sign_with": sign_with,
    }
    job.update(
        job_builder._reports(  # pylint: disable=protected-access
            state_dir, policy_id, SIGN_ACTION, group
        )
    )
    return job
