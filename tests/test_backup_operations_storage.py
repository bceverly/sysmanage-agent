# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The restate driver: prepare storage, managed mounts, seal retention,
browse and what changed (Phase 24)."""

# pylint: disable=protected-access,redefined-outer-name

import json
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations import backup_operations as ops_module
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401  pylint: disable=unused-import
    FEATURES,
    PID,
    RID,
    STORAGE_TARGET,
    FakeRun,
    _drain,
    _fake_target,
    _host_policy,
    _sent,
    _storage_policy,
    _touch_jobs,
    _write,
    agent,
    job_files,
    ops,
)

# restate is Linux-only; the driver uses POSIX paths and modes throughout.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only feature")


# --- prepare: one host's own filesystem and export -------------------------


@pytest.fixture
def prepare_env(ops, monkeypatch):
    prep = ops_module.storage_prepare
    monkeypatch.setattr(prep.pwd, "getpwnam", lambda n: SimpleNamespace(pw_uid=1002))
    monkeypatch.setattr(prep.grp, "getgrnam", lambda n: SimpleNamespace(gr_gid=1003))
    monkeypatch.setattr(ops_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(ops_module.storage_fs, "describe",
                        lambda *a, **k: {"type": "btrfs"})  # fmt: skip
    monkeypatch.setattr(ops, "_zfs_datasets", AsyncMock(return_value={}))
    monkeypatch.setattr(ops, "_audit", lambda policy: [{"code": "export_own",
                        "level": "ok", "params": {}}])  # fmt: skip
    return ops


def _prepare_policy():
    target = dict(STORAGE_TARGET, client_address="192.168.4.196")
    return {"policy_id": PID, "role": "storage", "target": target,
            "jobs": {"check": {"read_all": True}}}  # fmt: skip


@pytest.mark.asyncio
async def test_prepare_creates_exports_and_protects_in_order(prepare_env, agent):
    ops = prepare_env
    await ops.backup_configure(_prepare_policy())
    ops.fake.calls.clear()
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "prepare"}
    )
    assert answer["status"] == "started"
    await _drain(ops)
    bare = [c[2:] if c[:2] == ["sudo", "-n"] else c for c in ops.fake.calls]
    repo = "/srv/backups/restate/h-1"
    create = next(
        i for i, c in enumerate(bare) if c[1:] == ["subvolume", "create", repo]
    )
    install = next(i for i, c in enumerate(bare)
                   if c[0] == "install" and c[-1].startswith("/etc/exports.d/"))  # fmt: skip
    reload_ = bare.index(["exportfs", "-ra"])
    chown = bare.index(["chown", "root:restate", repo])
    assert create < install < reload_ < chown < bare.index(["chmod", "1770", repo])
    report = _sent(agent, "backup_result")[0]
    assert (report["action"], report["status"]) == ("prepare", "ok")
    assert report["storage_audit"][0]["code"] == "export_own"  # re-audited


@pytest.mark.asyncio
async def test_a_refused_prepare_reports_why(prepare_env, agent, monkeypatch):
    monkeypatch.setattr(ops_module.platform, "system", lambda: "FreeBSD")
    monkeypatch.setattr(ops_module.storage_fs, "describe",
                        lambda *a, **k: {"type": "ufs"})  # fmt: skip
    await prepare_env.backup_configure(_prepare_policy())
    await prepare_env.backup_run({"run_id": RID, "policy_id": PID, "action": "prepare"})
    await _drain(prepare_env)
    report = _sent(agent, "backup_result")[0]
    assert report["status"] == "failed"
    assert report["result"]["reason"] == "zfs_required" and report["result"]["errors"]


@pytest.mark.asyncio
async def test_a_failed_prepare_command_is_reported(prepare_env, agent):
    await prepare_env.backup_configure(_prepare_policy())
    for path in ops_module.BTRFS_PATHS:
        prepare_env.fake.fail[(path,)] = (1, "ERROR: cannot create")
    await prepare_env.backup_run({"run_id": RID, "policy_id": PID, "action": "prepare"})
    await _drain(prepare_env)
    report = _sent(agent, "backup_result")[0]
    assert report["status"] == "failed"
    assert report["result"]["reason"] == "command_failed"
    assert not prepare_env.fake.ran("exportfs")  # stopped at the first failure


@pytest.mark.asyncio
async def test_a_host_policy_cannot_prepare(ops):
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "prepare"}
    )
    assert answer["success"] is False and answer["reason"] == "not_configured"


# --- managed mount: the host's export only while a job runs -----------------

NFS = {"server": "192.168.4.10", "path": "/restate/nas-1"}
WHERE = "/mnt/sysmanage-backup/nas-1"


@pytest.fixture
def mounts(ops, monkeypatch):
    """Fake mount table: mount/umount through FakeRun change it."""
    table = {}
    real = ops.fake.__call__

    async def run(argv):
        bare = argv[2:] if argv[:2] == ["sudo", "-n"] else argv
        if bare[:1] == ["mount"] and ("mount",) not in ops.fake.fail:
            table[bare[-1]] = "nfs4"
        if bare[:1] == ["umount"]:
            table.pop(bare[-1], None)
        return await real(argv)

    monkeypatch.setattr(ops, "_run", run)
    monkeypatch.setattr(BackupOperations, "_mounts", staticmethod(lambda: dict(table)))
    return table


async def _capture_to_the_end(ops, run_id=RID):
    unit = contract.unit_name(PID, "capture")
    answer = await ops.backup_run(
        {"run_id": run_id, "policy_id": PID, "action": "capture"}
    )
    _write(job_builder.result_path(ops.state_dir, PID, "capture"),
           json.dumps({"schema": 1, "exit": 0, "status": "ok"}))  # fmt: skip
    ops.fake.active.discard(unit)
    return answer


@pytest.mark.asyncio
async def test_the_export_is_mounted_for_the_job_and_unmounted_after(
    ops, agent, job_files, mounts
):
    target = {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1", "nfs": NFS}
    await ops.backup_configure(_host_policy(target=target))
    _touch_jobs(job_files, "capture")
    answer = await _capture_to_the_end(ops)
    assert answer["status"] == "started"
    mount = ops.fake.ran("mount", "-t", "nfs4")
    assert mount and mount[0][-2:] == ["192.168.4.10:/restate/nas-1", WHERE]
    assert "hard" in mount[0][mount[0].index("-o") + 1]
    start = ops.fake.calls.index(ops.fake.ran("--no-block", "start")[0])
    assert ops.fake.calls.index(mount[0]) < start  # mounted before restate starts
    await _drain(ops)
    assert ops.fake.ran("umount", WHERE) and WHERE not in mounts
    assert ops._load("mounts.json") == {}
    assert _sent(agent, "backup_result")[0]["status"] == "ok"


@pytest.mark.asyncio
async def test_an_operators_own_mount_is_used_and_left_alone(ops, job_files, mounts):
    mounts[WHERE] = "nfs4"  # fstab / autofs
    target = {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1", "nfs": NFS}
    await ops.backup_configure(_host_policy(target=target))
    _touch_jobs(job_files, "capture")
    await _capture_to_the_end(ops)
    await _drain(ops)
    assert not ops.fake.ran("mount", "-t", "nfs4") and not ops.fake.ran("umount")


@pytest.mark.asyncio
async def test_a_failed_mount_refuses_the_run_and_starts_nothing(
    ops, job_files, mounts
):
    ops.fake.fail[("mount",)] = (32, "mount.nfs4: access denied by server")
    target = {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1", "nfs": NFS}
    await ops.backup_configure(_host_policy(target=target))
    _touch_jobs(job_files, "capture")
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["reason"] == "mount_failed" and "access denied" in answer["error"]
    assert not ops.fake.ran("--no-block", "start")


@pytest.mark.asyncio
async def test_without_an_nfs_source_nothing_is_mounted(ops, job_files, mounts):
    mounts["/mnt/sysmanage-backup"] = "nfs4"
    await ops.backup_configure(_host_policy())
    _touch_jobs(job_files, "capture")
    await _capture_to_the_end(ops)
    await _drain(ops)
    assert not ops.fake.ran("mount", "-t", "nfs4")


@pytest.mark.asyncio
async def test_an_operators_shared_mount_is_used_without_stacking(
    ops, job_files, mounts
):
    mounts["/mnt/sysmanage-backup"] = "nfs4"  # the whole share, mounted by hand
    target = {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1", "nfs": NFS}
    await ops.backup_configure(_host_policy(target=target))
    _touch_jobs(job_files, "capture")
    await _capture_to_the_end(ops)
    await _drain(ops)
    assert not ops.fake.ran("mount", "-t", "nfs4") and not ops.fake.ran("umount")


@pytest.mark.asyncio
async def test_a_host_job_never_runs_against_the_local_disk(ops, job_files, mounts):
    await ops.backup_configure(_host_policy())  # no nfs source sent yet
    _touch_jobs(job_files, "capture")
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["reason"] == "mount_failed" and "not mounted" in answer["error"]
    assert not ops.fake.ran("--no-block", "start")


@pytest.mark.asyncio
async def test_a_host_reports_the_quiesce_hooks_its_restate_finds(ops, monkeypatch):
    features = dict(FEATURES, hooks=["lxd", "docker", "Bad Name", 7])
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: features))
    answer = await ops.backup_configure(_host_policy())
    assert answer["success"] and answer["hooks"] == ["docker", "lxd"]


# --- seal retention -----------------------------------------------------------

DS = "tank/b"


@pytest.mark.asyncio
async def test_a_seal_removes_its_own_seals_past_the_age(ops, agent, monkeypatch):
    now = 1_800_000_000.0
    monkeypatch.setattr(ops_module.time, "time", lambda: now)
    old = f"{DS}@sysmanage-6ed601a3-f093-4506-bc52-7a8ae504f03b"
    recent = f"{DS}@sysmanage-b4f0e030-409e-4861-b743-2e640a04e304"
    real = ops.fake.__call__

    async def run(argv):
        bare = argv[2:] if argv[:2] == ["sudo", "-n"] else argv
        if "list" in bare and "snapshot" in bare:
            ops.fake.calls.append(list(argv))
            return (
                0,
                f"{old}\t{int(now - 30 * 86400)}\n{recent}\t{int(now - 3600)}\n",
                "",
            )
        return await real(argv)

    monkeypatch.setattr(ops, "_run", run)
    await ops.backup_configure(
        _storage_policy({"mode": "zfs_snapshot", "dataset": DS, "keep_days": 14})
    )
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "seal"})
    await _drain(ops)
    destroyed = [c for c in ops.fake.calls if "destroy" in c]
    assert [c[-1] for c in destroyed] == [old]  # never the recent one, nor the new seal
    assert destroyed[0][-2:] == ["-r", old]
    report = _sent(agent, "backup_result")[0]
    assert report["status"] == "ok" and report["result"]["seals_removed"] == 1


@pytest.mark.asyncio
async def test_a_failed_removal_never_fails_the_seal(ops, agent, monkeypatch):
    now = 1_800_000_000.0
    monkeypatch.setattr(ops_module.time, "time", lambda: now)
    old = f"{DS}@sysmanage-6ed601a3-f093-4506-bc52-7a8ae504f03b"
    real = ops.fake.__call__

    async def run(argv):
        bare = argv[2:] if argv[:2] == ["sudo", "-n"] else argv
        if "list" in bare and "snapshot" in bare:
            return (
                0,
                f"{old}\t{int(now - 30 * 86400)}\n{DS}@sysmanage-{RID}\t{int(now)}\n",
                "",
            )
        if "destroy" in bare:
            return 1, "", "dataset is busy"
        return await real(argv)

    monkeypatch.setattr(ops, "_run", run)
    await ops.backup_configure(
        _storage_policy({"mode": "zfs_snapshot", "dataset": DS, "keep_days": 14})
    )
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "seal"})
    await _drain(ops)
    report = _sent(agent, "backup_result")[0]
    assert report["status"] == "ok"
    assert "dataset is busy" in report["result"]["message"]


@pytest.mark.asyncio
async def test_btrfs_seals_are_recorded_and_only_recorded_ones_expire(ops, monkeypatch):
    clock = {"t": 1_800_000_000.0}
    monkeypatch.setattr(ops_module.time, "time", lambda: clock["t"])
    seal = {"mode": "btrfs_snapshot", "subvolume": "/srv/backups/restate",
            "snapshot_dir": "/srv/backups/.snapshots", "keep_days": 1}  # fmt: skip
    await ops.backup_configure(_storage_policy(seal))
    first = "11111111-1111-4111-8111-111111111111"
    await ops.backup_run({"run_id": first, "policy_id": PID, "action": "seal"})
    await _drain(ops)
    assert f"/srv/backups/.snapshots/sysmanage-{first}" in ops._load("seals.json")
    clock["t"] += 3 * 86400
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "seal"})
    await _drain(ops)
    deleted = [c for c in ops.fake.calls if "delete" in c]
    assert [c[-1] for c in deleted] == [f"/srv/backups/.snapshots/sysmanage-{first}"]
    assert list(ops._load("seals.json")) == [f"/srv/backups/.snapshots/sysmanage-{RID}"]


@pytest.mark.asyncio
async def test_a_failed_preflight_refuses_the_capture_and_unmounts(
    ops, job_files, mounts, monkeypatch
):
    monkeypatch.setattr(ops_module.host_mount, "preflight",
                        lambda where, run_id: "The backup storage is nearly full")  # fmt: skip
    target = {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1", "nfs": NFS}
    await ops.backup_configure(_host_policy(target=target))
    _touch_jobs(job_files, "capture")
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["reason"] == "preflight_failed" and "nearly full" in answer["error"]
    assert not ops.fake.ran("--no-block", "start")
    assert ops.fake.ran("umount", WHERE)  # the mount it made for this run is released


@pytest.mark.asyncio
async def test_read_only_jobs_skip_the_preflight(ops, job_files, monkeypatch):
    def never(where, run_id):
        raise AssertionError("preflight must not run for a listing")

    monkeypatch.setattr(ops_module.host_mount, "preflight", never)
    await ops.backup_configure(_host_policy())
    _touch_jobs(job_files, "snapshots")
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "snapshots"}
    )
    assert answer["status"] == "started"


# --- browse / what changed (restate 2.1.0.4) -----------------------------------


@pytest.mark.asyncio
async def test_a_listing_installs_its_job_and_starts_it(ops, monkeypatch):
    features = dict(FEATURES, job_commands=["capture", "list", "status"])
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: features))
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "list",
                                   "snapshot": "20261023T161149Z", "path": "/etc"})  # fmt: skip
    assert answer["status"] == "started", answer
    job = [j for j in rendered if j["command"] == "list"][0]
    assert job["snapshot"].endswith("::20261023T161149Z") and job["path"] == "/etc"
    assert ops.fake.ran(
        "systemctl", "--no-block", "start", contract.unit_name(PID, "list")
    )


@pytest.mark.asyncio
async def test_an_older_restate_cannot_list(ops):
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "list",
                                   "snapshot": "s1"})  # fmt: skip
    assert answer["reason"] == "tool_outdated"


@pytest.mark.asyncio
async def test_a_storage_policy_cannot_list(ops, monkeypatch):
    features = dict(FEATURES, job_commands=["list"])
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: features))
    await ops.backup_configure(_storage_policy({"mode": "none"}))
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "list",
                                   "snapshot": "s1"})  # fmt: skip
    assert answer["reason"] == "not_configured"
