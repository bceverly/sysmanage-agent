# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Two snapshots compared by package (Pro+ drift timeline, 24.7) and a
restore that puts the snapshot's packages back first (Pro+ 24.6): restate's
``diff`` job with ``packages``, and ``restore`` with ``packages``."""

import sys

import pytest

from src.sysmanage_agent.backup import job_builder as b
from src.sysmanage_agent.backup import job_validation as v
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
CAN_DIFF = dict(
    KEYED,
    job_keys=KEYED["job_keys"] + ["from", "to", "packages"],
    job_commands=KEYED["job_commands"] + ["diff"],
)


def test_a_diff_job_compares_by_package():
    job = b.build_diff_job(
        {"policy_id": PID, "from": "20261101T000000Z", "to": "20261102T000000Z"}, **KW
    )
    assert job["command"] == "diff" and job["packages"] is True
    assert (job["from"], job["to"]) == ("20261101T000000Z", "20261102T000000Z")
    assert job["repository"] == KW["repository"]
    assert "trusted_key" not in job  # it would refuse every unsigned snapshot
    assert job["result"].endswith(f"{PID}.diff.result.json")


def test_a_diff_defaults_to_the_newest_and_the_one_before():
    job = b.build_diff_job({"policy_id": PID}, **KW)
    assert "from" not in job and "to" not in job


def test_a_diff_refuses_a_bad_snapshot_name():
    with pytest.raises(v.PolicyError):
        b.build_diff_job({"policy_id": PID, "to": "../etc/passwd"}, **KW)


def test_the_host_offers_diff_and_packages_only_where_restate_has_them():
    assert "diff" not in contract.host_abilities(KEYED)
    assert "packages" not in contract.host_abilities(KEYED)
    found = contract.host_abilities(CAN_DIFF)
    assert "diff" in found and "packages" in found


def _restore(**extra):
    params = {"run_id": RID, "policy_id": PID, "snapshot": "20261102T000000Z"}
    params.update(extra)
    return b.build_restore_job(params, can_plan=True, **KW)


def test_a_package_preview_is_a_plan_with_packages():
    job = _restore(packages=True, dry_run=True)
    assert job["plan"] is True and job["packages"] is True


def test_a_package_restore_runs_in_place_only():
    with pytest.raises(v.PolicyError, match="in place only"):
        _restore(packages=True, dry_run=False)
    job = _restore(packages=True, dry_run=False, in_place=True, include=["/etc/proof"])
    assert job["packages"] is True and job["restore_root"] == "/"
    assert job["check_first"] is True


def test_packages_must_be_true_or_false():
    with pytest.raises(v.PolicyError):
        _restore(packages="yes")


def test_a_plain_restore_has_no_packages_key():
    assert "packages" not in _restore(dry_run=True)


@pytest.mark.asyncio
async def test_an_encrypted_diff_gets_every_key_for_that_run(keyed_ops, monkeypatch):
    ops = keyed_ops
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: CAN_DIFF))
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "diff", "needs_key": True,
         "from": "20261101T000000Z", "to": "20261102T000000Z"}  # fmt: skip
    )
    assert answer["status"] == "started", answer
    job = ops.rendered[-1]
    assert job["command"] == "diff" and job["packages"] is True
    assert job["decrypt_with"] == [key_files.key_path(RID, 0)]
    for task in list(ops._tasks):  # pylint: disable=protected-access
        task.cancel()


@pytest.mark.asyncio
async def test_a_restate_without_a_diff_job_is_refused_clearly(keyed_ops):
    ops = keyed_ops  # KEYED lists no "diff" job command
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "diff"})
    assert answer["reason"] == "tool_outdated"


@pytest.mark.asyncio
async def test_a_storage_policy_cannot_be_asked_to_diff(ops):
    from tests.backup_ops_support import (  # noqa: PLC0415  # pylint: disable=import-outside-toplevel
        _storage_policy,
    )

    await ops.backup_configure(_storage_policy({"mode": "none"}))
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "diff"})
    assert answer["reason"] == "not_configured"
