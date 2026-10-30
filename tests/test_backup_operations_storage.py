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
    chmod = bare.index(["chmod", "0770", repo])
    assert (
        create < install < reload_ < chown < chmod < bare.index(["chattr", "+a", repo])
    )
    report = _sent(agent, "backup_result")[0]
    assert (report["action"], report["status"]) == ("prepare", "ok")
    assert report["storage_audit"][0]["code"] == "export_own"  # re-audited


# The zfs the agent runs: /usr/sbin/zfs on Linux, /sbin/zfs on the BSDs
# (where these tests also run, faking Linux).
ZFS = ops_module._first(ops_module.ZFS_PATHS)


def _zfs_prepare(prepare_env, monkeypatch, mounted_after):
    """Linux ZFS under systemd; the host's mount table shows the dataset
    once ``zfs mount`` has run (or never, with mounted_after=None)."""
    repo = "/srv/backups/restate/h-1"
    monkeypatch.setattr(ops_module.storage_fs, "describe",
                        lambda *a, **k: {"type": "zfs"})  # fmt: skip
    monkeypatch.setattr(prepare_env, "_zfs_datasets",
                        AsyncMock(return_value={"/srv/backups/restate": "tank/b"}))  # fmt: skip
    monkeypatch.setattr(ops_module.host_mount, "systemd_running", lambda: True)
    table = f"1 2 0:5 / {repo} rw - zfs tank/b/h-1 rw\n"

    real = ops_module._read_text

    def read_text(path):
        if path != ops_module.host_mount.HOST_MOUNTINFO:
            return real(path)
        ran = prepare_env.fake.ran(mounted_after) if mounted_after else False
        return table if ran else ""

    monkeypatch.setattr(ops_module, "_read_text", read_text)
    return repo


@pytest.mark.asyncio
async def test_linux_zfs_is_created_and_mounted_in_the_hosts_namespace(
    prepare_env, agent, monkeypatch
):
    repo = _zfs_prepare(prepare_env, monkeypatch, mounted_after="nsenter")
    await prepare_env.backup_configure(_prepare_policy())
    await prepare_env.backup_run({"run_id": RID, "policy_id": PID, "action": "prepare"})
    await _drain(prepare_env)
    bare = [c[2:] if c[:2] == ["sudo", "-n"] else c for c in prepare_env.fake.calls]
    host_ns = ["nsenter", "--mount=/proc/1/ns/mnt", "--"]
    create = bare.index([*host_ns, ZFS, "create", "tank/b/h-1"])
    assert create < bare.index(["exportfs", "-ra"]) < bare.index(
        ["chown", "root:restate", repo])  # fmt: skip
    assert [*host_ns, ZFS, "mount", "tank/b/h-1"] not in bare
    assert _sent(agent, "backup_result")[0]["status"] == "ok"


@pytest.mark.asyncio
async def test_a_dataset_not_mounted_host_wide_is_never_prepared_beneath(
    prepare_env, agent, monkeypatch
):
    """The production failure: mounted for the agent alone, NFS exported the
    directory beneath.  Now it is mounted host-wide, or the prepare fails."""
    _zfs_prepare(prepare_env, monkeypatch, mounted_after=None)
    await prepare_env.backup_configure(_prepare_policy())
    await prepare_env.backup_run({"run_id": RID, "policy_id": PID, "action": "prepare"})
    await _drain(prepare_env)
    bare = [c[2:] if c[:2] == ["sudo", "-n"] else c for c in prepare_env.fake.calls]
    assert ["nsenter", "--mount=/proc/1/ns/mnt", "--", ZFS, "mount",
            "tank/b/h-1"] in bare  # fmt: skip
    report = _sent(agent, "backup_result")[0]
    assert (
        report["status"] == "failed" and "not mounted" in report["result"]["errors"][0]
    )
    assert not prepare_env.fake.ran("exportfs") and not prepare_env.fake.ran("chown")


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
    monkeypatch.setattr(ops_module.host_mount, "nfs_client_missing", lambda *a: False)

    async def run(argv):
        bare = argv[2:] if argv[:2] == ["sudo", "-n"] else argv
        if (
            bare[:1] in (["mount"], ["systemd-mount"])
            and ("mount",) not in ops.fake.fail
            and not getattr(ops, "private_namespace", False)
        ):
            table[bare[-1]] = "nfs4"
        if bare[:1] in (["umount"], ["systemd-umount"]):
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
async def test_a_host_without_an_nfs_client_is_told_so_plainly(
    ops, job_files, mounts, monkeypatch
):
    """Not systemd's "Job failed" (nextcloud, 2026-10-29): nothing is tried."""
    monkeypatch.setattr(ops_module.host_mount, "nfs_client_missing", lambda *a: True)
    target = {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1", "nfs": NFS}
    await ops.backup_configure(_host_policy(target=target))
    _touch_jobs(job_files, "capture")
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["success"] is False and "no NFS client" in answer["error"]
    assert "nfs-common" in answer["error"] and not ops.fake.ran("mount", "-t", "nfs4")


def test_the_nfs_client_is_found_by_its_mount_helper():
    from src.sysmanage_agent.backup import (
        host_mount,
    )  # pylint: disable=import-outside-toplevel

    assert host_mount.nfs_client_missing("Linux", lambda path: False)
    assert not host_mount.nfs_client_missing(
        "Linux", lambda p: p == "/usr/sbin/mount.nfs"
    )
    assert not host_mount.nfs_client_missing("FreeBSD", lambda path: False)


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
                        lambda where: "The backup storage is nearly full")  # fmt: skip
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
async def test_a_status_job_leaves_classification_to_restate(ops, monkeypatch):
    """Lab 2026-10-24: restate 2.2.0.1 exits 2 on `rules` in a status job;
    2.2.0.2 uses the capture's recorded rules, which `rules` would replace."""
    features = dict(FEATURES, job_commands=["capture", "list", "status"])
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: features))
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    policy = _host_policy()
    policy["jobs"]["capture"]["skip_paths"] = ["/home/*/Nextcloud"]
    await ops.backup_configure(policy)
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "status"})
    assert answer["status"] == "started", answer
    status = [j for j in rendered if j["command"] == "status"][0]
    assert "rules" not in status and "all" not in status


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


# --- systemd hosts: the mount must exist for restate's unit, not just the agent


@pytest.mark.asyncio
async def test_on_systemd_the_export_is_mounted_by_systemd(
    ops, job_files, mounts, monkeypatch
):
    monkeypatch.setattr(ops_module.host_mount, "systemd_running", lambda: True)
    target = {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1", "nfs": NFS}
    await ops.backup_configure(_host_policy(target=target))
    _touch_jobs(job_files, "capture")
    answer = await _capture_to_the_end(ops)
    assert answer["status"] == "started"
    mount = ops.fake.ran("systemd-mount")
    assert mount and mount[0][-2:] == ["192.168.4.10:/restate/nas-1", WHERE]
    assert "--type=nfs4" in mount[0] and any("hard" in a for a in mount[0])
    assert not ops.fake.ran("mount", "-t", "nfs4")
    await _drain(ops)
    assert ops.fake.ran("systemd-umount", WHERE) and WHERE not in mounts


@pytest.mark.asyncio
async def test_a_mount_only_the_agent_can_see_is_refused_and_taken_down(
    ops, job_files, mounts
):
    """production, ubiquiti, 2026-10-27: the agent's private mount namespace
    hid its mount from restate's unit, and the capture wrote to local disk.
    The host's table is what counts: a mount missing there refuses the run
    and starts nothing."""
    ops.private_namespace = True  # mount(8) "succeeds", but not for the host
    target = {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1", "nfs": NFS}
    await ops.backup_configure(_host_policy(target=target))
    _touch_jobs(job_files, "capture")
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["reason"] == "mount_failed" and "not mounted" in answer["error"]
    assert not ops.fake.ran("--no-block", "start")  # restate never ran
    assert ops.fake.ran("umount", WHERE)  # the private mount is taken down


def test_the_mount_table_is_the_hosts_not_the_agents(monkeypatch):
    read = []

    def fake_read(path):
        read.append(path)
        return (
            "36 25 0:44 / /mnt/b rw - nfs4 nas:/x rw\n"
            if path == "/proc/1/mountinfo"
            else ""
        )

    monkeypatch.setattr("src.sysmanage_agent.backup.mount_mixin._read_text", fake_read)
    assert ops_module.BackupMountMixin._mounts() == {"/mnt/b": "nfs4"}
    assert read == ["/proc/1/mountinfo"]


def test_mount_and_umount_commands():
    from src.sysmanage_agent.backup import host_mount  # noqa: PLC0415

    source = {"server": "192.168.4.10", "path": "/restate/nas-1"}
    assert host_mount.mount_argv(source, WHERE)[:3] == ["mount", "-t", "nfs4"]
    assert host_mount.mount_argv(source, WHERE, systemd=True)[0] == "systemd-mount"
    assert host_mount.umount_argv(WHERE, systemd=True) == ["systemd-umount", WHERE]
    assert host_mount.systemd_running(isdir=lambda p: p == "/run/systemd/system")


@pytest.mark.asyncio
async def test_storage_configure_sweeps_stale_preflight_markers(ops):
    """An older agent's pre-flight check left empty marker files in a host's
    repository directory; the host cannot delete them (append-only) and
    restate will not create a repository there (production, 2026-10-29)."""
    from tests.backup_ops_support import (
        _storage_policy,
    )  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

    await ops.backup_configure(_storage_policy({"mode": "none"}))
    sweep = ops.fake.ran("find")
    assert sweep, "no sweep ran"
    argv = sweep[0]
    assert argv[argv.index("find") + 2 :] == [
        "-maxdepth",
        "1",
        "-type",
        "f",
        "-name",
        ".sysmanage-preflight-*",
        "-size",
        "0",
        "-delete",
    ]
