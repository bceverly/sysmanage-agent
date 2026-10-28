# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Scheduled verification (Pro+ 24.6): restate ``check --read-all`` on the
backed-up host, with the policy's keys for that one job when the repository
is encrypted -- the storage host never holds a key."""

import sys

import pytest

from src.sysmanage_agent.backup import job_builder as b
from src.sysmanage_agent.backup import key_files
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401  # pylint: disable=unused-import
    FEATURES,
    PID,
    RID,
    _host_policy,
    agent,
    ops,
)
from tests.test_backup_key_files import (  # noqa: F401  # pylint: disable=unused-import
    KEYED,
    keyed_ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")

KW = {"repository": "/mnt/backups/t14-1", "state_dir": "/var/lib/sysmanage-agent",
      "group": "sysmanage-agent"}  # fmt: skip


def test_the_verify_job_is_a_full_read_check_of_the_repository():
    job = b.build_verify_job({"policy_id": PID}, **KW)
    assert job["command"] == "check" and job["read_all"] is True
    assert job["repository"] == KW["repository"]
    assert "decrypt_with" not in job and "metadata_only" not in job
    assert job["result"].endswith(f"{PID}.verify.result.json")
    keyed = b.build_verify_job({"policy_id": PID}, decrypt_with=["/k/1", "/k/2"], **KW)
    assert keyed["decrypt_with"] == ["/k/1", "/k/2"]


def test_the_host_offers_verify_only_where_check_runs_as_a_job():
    assert "verify" not in contract.host_abilities(KEYED)
    assert "verify" in contract.host_abilities(
        dict(KEYED, job_commands=KEYED["job_commands"] + ["check"])
    )


@pytest.mark.asyncio
async def test_an_encrypted_verification_gets_every_key_for_that_run(
    keyed_ops, monkeypatch
):
    ops = keyed_ops
    can_check = dict(KEYED, job_commands=KEYED["job_commands"] + ["check"])
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: can_check))
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "verify", "needs_key": True}
    )
    assert answer["status"] == "started", answer
    job = ops.rendered[-1]
    assert job["command"] == "check" and job["read_all"] is True
    assert job["decrypt_with"] == [key_files.key_path(RID, 0)]
    for task in list(ops._tasks):  # pylint: disable=protected-access
        task.cancel()


@pytest.mark.asyncio
async def test_a_restate_without_a_check_job_is_refused_clearly(keyed_ops):
    ops = keyed_ops  # KEYED lists no "check" job command
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "verify"})
    assert answer["reason"] == "tool_outdated"


@pytest.mark.asyncio
async def test_a_storage_policy_cannot_be_asked_to_verify(ops):
    from tests.backup_ops_support import (  # noqa: PLC0415  # pylint: disable=import-outside-toplevel
        _storage_policy,
    )

    await ops.backup_configure(_storage_policy({"mode": "none"}))
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "verify"})
    assert answer["reason"] == "not_configured"
