# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Snapshot signing (Pro+ backup_engine, 24.6).

The STORAGE host signs, with a key fetched for that one run and removed
after; the backed-up hosts get only the signer's public key, which their
restores name so restate refuses a bad or foreign signature (exit 4)."""

# pylint: disable=protected-access,redefined-outer-name

import sys

import pytest

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import key_files
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import signing
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401  # pylint: disable=unused-import
    FEATURES,
    PID,
    RID,
    STORAGE_TARGET,
    _host_policy,
    agent,
    job_files,
    ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only feature")
SECRET = f"-----{key_files._ARMORED}-----\nsigning key\n"
PUBLIC = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsigner\n-----END PGP PUBLIC KEY BLOCK-----\n"
)
SIGNING = dict(
    FEATURES,
    job_keys=FEATURES["job_keys"] + ["sign_with", "trusted_key", "keep_yearly"],
    job_commands=["capture", "sign", "restore", "check"],
)


def _storage_policy():
    return {"policy_id": PID, "role": "storage", "target": STORAGE_TARGET,
            "jobs": {"prune": {"keep_last": 3}, "seal": {"mode": "none"}}}  # fmt: skip


def test_the_storage_host_reports_it_can_sign():
    assert contract.storage_abilities(SIGNING) == ["keep_yearly", "sign", "signatures"]
    assert "sign" not in contract.storage_abilities(FEATURES)


def test_a_sign_job_names_the_snapshot_and_the_runs_key_file():
    job = signing.build_sign_job(
        {"policy_id": PID, "snapshot": "20261102T120000Z"},
        repository="/srv/backups/restate/h-1", state_dir="/var/lib/sa",
        group="sysmanage-agent", sign_with="/run/sysmanage-agent/backup-keys/k",
    )  # fmt: skip
    assert job["command"] == "sign"
    assert job["snapshot"] == "/srv/backups/restate/h-1::20261102T120000Z"
    assert job["sign_with"] == "/run/sysmanage-agent/backup-keys/k"
    for bad in ({"policy_id": PID}, {"policy_id": PID, "snapshot": "../x"}, "x"):
        with pytest.raises(v.PolicyError):
            signing.build_sign_job(bad, repository="/r", state_dir="/s",
                                   group="g", sign_with="/k")  # fmt: skip


def test_a_trusted_key_must_be_public():
    assert v.check_key(PUBLIC, "trusted_key") == PUBLIC
    with pytest.raises(v.PolicyError, match="trusted_key"):
        v.check_key(SECRET.replace("PRIVATE KEY", "PUBLIC KEY") + "PRIVATE KEY",
                    "trusted_key")  # fmt: skip


@pytest.fixture
def signing_ops(ops, monkeypatch):
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: SIGNING))

    async def fetch(_agent, run_id):
        assert run_id == RID
        return [SECRET]

    monkeypatch.setattr(key_files, "fetch", fetch)
    real_stage = key_files.stage
    monkeypatch.setattr(
        key_files, "stage", lambda c: real_stage(c, dirs=(ops.state_dir,))
    )
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    ops.rendered = rendered
    return ops


@pytest.mark.asyncio
async def test_the_storage_host_signs_with_a_key_for_that_run_only(
    signing_ops, monkeypatch
):
    ops = signing_ops
    monkeypatch.setattr(
        v,
        "check_target",
        lambda role, target, **kw: (
            target["mount_point"],
            target["mount_point"] + "/" + target["repo_dir"],
        ),
    )
    await ops.backup_configure(_storage_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "sign",
                                   "snapshot": "20261102T120000Z", "needs_key": True})  # fmt: skip
    assert answer["status"] == "started", answer
    job = ops.rendered[-1]
    assert job["command"] == "sign" and job["sign_with"] == key_files.key_path(RID, 0)
    assert job["snapshot"].endswith("::20261102T120000Z")
    assert SECRET not in contract.render_job(job)  # the path, never the key
    record = ops._load("inflight.json")[RID]
    assert record["key_files"] == [key_files.key_path(RID, 0)]
    await ops._finish(RID, record, 0)
    assert ops.fake.ran("rm", "-f", key_files.key_path(RID, 0))
    for task in list(ops._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_signing_needs_its_key_and_a_restate_that_signs(signing_ops, monkeypatch):
    ops = signing_ops
    monkeypatch.setattr(
        v,
        "check_target",
        lambda role, target, **kw: (
            target["mount_point"],
            target["mount_point"] + "/" + target["repo_dir"],
        ),
    )
    await ops.backup_configure(_storage_policy())
    keyless = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "sign",
                                    "snapshot": "20261102T120000Z"})  # fmt: skip
    assert keyless["success"] is False and keyless["reason"] == "invalid_request"
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: FEATURES))
    old = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "sign",
                                "snapshot": "20261102T120000Z", "needs_key": True})  # fmt: skip
    assert old["reason"] == "tool_outdated"


@pytest.mark.asyncio
async def test_a_host_never_signs(signing_ops):
    ops = signing_ops
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "sign",
                                   "snapshot": "20261102T120000Z", "needs_key": True})  # fmt: skip
    assert answer["success"] is False


@pytest.mark.asyncio
async def test_restores_name_the_signers_key(signing_ops, monkeypatch, tmp_path):
    ops = signing_ops
    monkeypatch.setattr(contract, "KEYS_DIR", str(tmp_path / "keys"))
    await ops.backup_configure(_host_policy(trusted_key=PUBLIC))
    path = contract.trusted_key_path(PID)
    assert ops.fake.ran("install", path)
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / f"{PID}.trusted.asc").write_text(PUBLIC)  # what install made
    await ops.backup_restore({"run_id": RID, "policy_id": PID, "include": ["/etc"],
                              "dry_run": False})  # fmt: skip
    job = ops.rendered[-1]
    assert job["trusted_key"] == [path] and "allow_unverified" not in job
    await ops.backup_restore({"run_id": RID, "policy_id": PID, "include": ["/etc"],
                              "dry_run": False, "allow_unverified": True})  # fmt: skip
    job = ops.rendered[-1]
    # An acknowledged UNSIGNED snapshot: both, so a signed one is still checked.
    assert job["trusted_key"] == [path] and job["allow_unverified"] is True
    for task in list(ops._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_the_storage_host_lists_signatures_against_the_signer(
    signing_ops, monkeypatch, tmp_path
):
    """The storage side's ``signatures`` job is restate ``snapshots`` with
    the signer's key, so the server learns which snapshots are signed from
    the trusted side even after its catalog lost them (lab, t14,
    2026-11-03).  A backed-up host may not run it."""
    ops = signing_ops
    monkeypatch.setattr(contract, "KEYS_DIR", str(tmp_path))
    policy = _storage_policy()
    policy["jobs"]["signatures"] = {}
    answer = await ops.backup_configure(dict(policy, trusted_key=PUBLIC))
    assert answer["success"] is True, answer
    path = contract.trusted_key_path(PID)
    assert ops.fake.ran("install", path)
    listing = [j for j in ops.rendered if j["command"] == "snapshots"][-1]
    assert listing["trusted_key"] == [path] and listing["repository"]
    assert ops.fake.ran("install", contract.job_path(PID, "signatures"))
    answer = await ops.backup_configure(policy)  # signing off: no key named
    listing = [j for j in ops.rendered if j["command"] == "snapshots"][-1]
    assert answer["success"] is True and "trusted_key" not in listing
    host = _host_policy()
    host["jobs"]["signatures"] = {}
    answer = await ops.backup_configure(host)
    assert answer["success"] is False


@pytest.mark.asyncio
async def test_signing_turned_off_removes_the_trusted_key(
    signing_ops, monkeypatch, tmp_path
):
    ops = signing_ops
    monkeypatch.setattr(contract, "KEYS_DIR", str(tmp_path))
    (tmp_path / f"{PID}.trusted.asc").write_text(PUBLIC)
    await ops.backup_configure(_host_policy())
    assert ops.fake.ran("rm", "-f", "--", contract.trusted_key_path(PID))
