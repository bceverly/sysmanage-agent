# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The repository before an encrypted one (Pro+ backup_engine, 24.6 S3).

Encryption starts a new repository; the plain one stays restorable.  The
agent reads it only when a restore or listing says ``previous: true`` and the
server configured it -- a request can never name a path."""

# pylint: disable=protected-access,redefined-outer-name

import sys

import pytest

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import repository_choice
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401  pylint: disable=unused-import
    FEATURES,
    PID,
    RID,
    _host_policy,
    agent,
    ops,
)
from tests.test_backup_operations_storage import (  # noqa: F401  # pylint: disable=unused-import
    mounts,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only feature")
NFS = {"server": "192.168.4.10", "path": "/restate/nas-1-enc"}
OLD_NFS = {"server": "192.168.4.10", "path": "/restate/nas-1"}
NFS_MOUNTS = "36 25 0:44 / /mnt/sysmanage-backup rw - nfs4 nas:/b rw\n"


def _check(target):
    params = {"policy_id": PID, "role": "host", "target": target,
              "jobs": {"capture": {}, "snapshots": {}}}  # fmt: skip
    return v.check_policy(params, mountinfo=lambda: NFS_MOUNTS,
                          realpath=lambda p: p, isdir=lambda p: True)  # fmt: skip


def test_the_previous_repository_sits_beside_the_current_one():
    policy = _check({"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1-enc",
                     "previous": {"repo_dir": "nas-1", "nfs": OLD_NFS}})  # fmt: skip
    assert policy["previous"] == {
        "repository": "/mnt/sysmanage-backup/nas-1",
        "nfs": OLD_NFS,
    }
    assert (
        _check({"mount_point": "/mnt/sysmanage-backup", "repo_dir": "x"})["previous"]
        is None
    )


@pytest.mark.parametrize(
    "previous",
    [{"repo_dir": "../etc"}, {"repo_dir": "nas-1-enc"}, {"repo_dir": "a", "path": "/x"},
     {"repo_dir": "a", "nfs": {"server": "nas", "path": "/x"}}, "nas-1"],
)  # fmt: skip
def test_a_hostile_previous_repository_is_refused(previous):
    with pytest.raises(v.PolicyError):
        _check({"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1-enc",
                "previous": previous})  # fmt: skip


def test_a_request_cannot_ask_for_a_previous_repository_that_is_not_there():
    policy = {"repository": "/r/new", "nfs": None, "previous": None}
    assert repository_choice.choose(policy, {}) == ("/r/new", None, False)
    with pytest.raises(v.PolicyError):
        repository_choice.choose(policy, {"previous": True})
    with pytest.raises(v.PolicyError):
        repository_choice.choose(policy, {"previous": "yes"})


@pytest.mark.asyncio
async def test_a_restore_from_the_previous_repository_mounts_its_export(
    ops, mounts, monkeypatch
):
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    await ops.backup_configure(_host_policy(target={
        "mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1-enc", "nfs": NFS,
        "previous": {"repo_dir": "nas-1", "nfs": OLD_NFS}}))  # fmt: skip
    answer = await ops.backup_restore({"run_id": RID, "policy_id": PID,
                                       "include": ["/etc/hosts"], "previous": True})  # fmt: skip
    assert answer["status"] == "started", answer
    assert rendered[-1]["repository"] == "/mnt/sysmanage-backup/nas-1"
    assert "/mnt/sysmanage-backup/nas-1" in mounts
    assert "/mnt/sysmanage-backup/nas-1-enc" not in mounts
    for task in list(ops._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_a_listing_of_the_current_repository_is_unchanged(ops, monkeypatch):
    features = dict(FEATURES, job_commands=["capture", "list", "status"])
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: features))
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "list",
                                   "snapshot": "s1", "path": "/"})  # fmt: skip
    assert answer["status"] == "started", answer
    assert rendered[-1]["snapshot"].startswith("/mnt/sysmanage-backup/nas-1::")
    for task in list(ops._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_previous_without_one_configured_is_refused(ops):
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_restore({"run_id": RID, "policy_id": PID,
                                       "include": ["/etc"], "previous": True})  # fmt: skip
    assert answer["reason"] == "invalid_request"
