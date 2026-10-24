# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The restate driver: configure, run, watch, restore, seal (Phase 24).

Every privileged step is a subprocess, so ``_run`` is replaced with a fake
that records argv and answers from a script; no sudo, systemctl or zfs runs.
"""

# pylint: disable=protected-access,redefined-outer-name

import asyncio
import json
import os
import sys

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


# ---------------------------------------------------------------------------
# probe gating
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["missing_tool", "tool_outdated", "wrong_platform"])
@pytest.mark.parametrize(
    "command", ["backup_configure", "backup_run", "backup_restore"]
)
async def test_every_command_refuses_when_restate_is_unusable(
    ops, monkeypatch, reason, command
):
    monkeypatch.setattr(
        ops_module.restate_probe, "unavailable_reason", lambda *a: reason
    )
    answer = await getattr(ops, command)({"policy_id": PID, "run_id": RID})
    assert answer["success"] is False and answer["reason"] == reason
    assert not ops.fake.calls  # nothing privileged was attempted


# ---------------------------------------------------------------------------
# backup_configure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_configure_installs_root_owned_job_files(ops):
    answer = await ops.backup_configure(_host_policy())
    assert answer == {"success": True, "policy_id": PID,
                      "installed": ["capture", "snapshots"], "removed": [],
                      "hooks": [], "abilities": []}  # fmt: skip
    installs = ops.fake.ran("install")
    assert [c[-1] for c in installs] == [
        contract.job_path(PID, "capture"), contract.job_path(PID, "snapshots")
    ]  # fmt: skip
    assert installs[0][:2] == ["sudo", "-n"] or os.geteuid() == 0
    assert ["-m", "644", "-o", "0", "-g", "0"] == installs[0][-9:-3]
    staged = os.listdir(os.path.join(ops.state_dir, "backup"))
    assert not [n for n in staged if n.startswith(".job-")]  # staging cleaned up
    policies = ops._load("policies.json")
    assert policies[PID]["actions"] == ["capture", "snapshots"]


@pytest.mark.asyncio
async def test_configure_installs_the_key_and_points_capture_at_it(ops, monkeypatch):
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----"
    assert (await ops.backup_configure(_host_policy(encrypt_key=key)))["success"]
    assert ops.fake.ran("install")[0][-1] == contract.key_path(PID)
    capture = next(job for job in rendered if job["command"] == "capture")
    assert capture["encrypt_to"] == contract.key_path(PID)
    assert capture["append_only"] is True


@pytest.mark.asyncio
async def test_reconfiguring_removes_actions_the_policy_dropped(ops):
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_configure(_host_policy(jobs={"capture": {}}))
    assert answer["removed"] == ["snapshots"]
    assert ops.fake.ran("rm", contract.job_path(PID, "snapshots"))


@pytest.mark.asyncio
async def test_an_invalid_policy_writes_nothing(ops):
    answer = await ops.backup_configure(_host_policy(jobs={"capture": {}, "prune": {}}))
    assert answer["reason"] == "invalid_policy"
    assert "prune" in answer["error"]
    assert not ops.fake.calls


@pytest.mark.asyncio
async def test_keys_this_restate_lacks_are_refused_as_outdated(ops, monkeypatch):
    old = {"version": "2.0.0.0", "job_keys": ["command", "repository"]}
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: old))
    answer = await ops.backup_configure(_host_policy())
    assert answer["reason"] == "tool_outdated"
    assert "append_only" in answer["error"]
    assert not ops.fake.ran("install")


@pytest.mark.asyncio
@pytest.mark.parametrize("has_create", [True, False], ids=["create", "no-create"])
async def test_capture_creates_its_repository_only_when_restate_can(
    ops, monkeypatch, has_create
):
    # restate's ``create`` key makes the first capture initialize its own
    # repository; a restate without it (2.0.0.1) still gets a job it can run.
    keys = FEATURES["job_keys"] + (["create"] if has_create else [])
    features = {"version": "2.0.0.1", "job_keys": keys}
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: features))
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    answer = await ops.backup_configure(_host_policy())
    assert answer["success"], answer
    capture = next(job for job in rendered if job["command"] == "capture")
    snapshots = next(job for job in rendered if job["command"] == "snapshots")
    assert capture.get("create") is (True if has_create else None)
    assert "create" not in snapshots


@pytest.mark.asyncio
async def test_path_rules_install_a_rules_file_and_remove_it_when_dropped(
    ops, monkeypatch, tmp_path
):
    rules = tmp_path / "rules.d" / f"{PID}.rules"
    monkeypatch.setattr(ops_module.job_builder, "rules_path", lambda _pid: str(rules))
    policy = _host_policy()
    policy["jobs"]["capture"]["skip_paths"] = ["**/previews"]
    assert (await ops.backup_configure(policy))["success"]
    assert str(rules) in [c[-1] for c in ops.fake.ran("install")]
    rules.parent.mkdir()
    rules.write_text("old")  # what the install above would have left
    del policy["jobs"]["capture"]["skip_paths"]
    assert (await ops.backup_configure(policy))["success"]
    assert ops.fake.ran("rm", "-f", "--", str(rules))


@pytest.mark.asyncio
@pytest.mark.parametrize("has_repack", [True, False], ids=["repack", "no-repack"])
async def test_repack_is_installed_only_where_restate_has_it(
    ops, monkeypatch, has_repack
):
    commands = ["capture", "prune", "check", "du"] + (["repack"] if has_repack else [])
    features = dict(FEATURES, commands=commands)
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: features))
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    policy = _storage_policy({"mode": "none"})
    policy["jobs"]["repack"] = {}
    answer = await ops.backup_configure(policy)
    assert answer["success"], answer
    assert ("repack" in answer["installed"]) is has_repack
    repack = [job for job in rendered if job["command"] == "repack"]
    if has_repack:
        assert repack[0]["record"] == job_builder.record_path(ops.state_dir, PID)
        assert repack[0]["repository"].endswith(STORAGE_TARGET["repo_dir"])
    else:
        assert not repack


@pytest.mark.asyncio
@pytest.mark.parametrize("has_protect", [True, False], ids=["protect", "no-protect"])
async def test_protect_is_installed_only_where_restate_has_it(
    ops, monkeypatch, has_protect
):
    commands = ["capture", "prune", "check", "du"] + (
        ["protect"] if has_protect else []
    )
    features = dict(FEATURES, commands=commands,
                    job_keys=FEATURES["job_keys"] + ["group"])  # fmt: skip
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: features))
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    policy = _storage_policy({"mode": "none"})
    policy["jobs"]["protect"] = {}
    policy["target"] = dict(STORAGE_TARGET, service_account="backup_1")
    answer = await ops.backup_configure(policy)
    assert answer["success"], answer
    assert ("protect" in answer["installed"]) is has_protect
    protect = [job for job in rendered if job["command"] == "protect"]
    if has_protect:
        # the hosts' mapped group may add, never change or remove
        assert protect[0]["group"] == "backup_1"
        assert protect[0]["repository"].endswith(STORAGE_TARGET["repo_dir"])
        assert "record" not in protect[0]
    else:
        assert not protect


@pytest.mark.asyncio
async def test_a_failed_install_is_reported(ops):
    ops.fake.fail[("install",)] = (1, "sudo: a password is required")
    answer = await ops.backup_configure(_host_policy())
    assert answer["reason"] == "install_failed"
    assert "password" in answer["error"]
    assert PID not in ops._load("policies.json")


# ---------------------------------------------------------------------------
# backup_run and the watch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_refuses_an_unconfigured_action(ops, job_files):
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "prune"})
    assert answer["reason"] == "not_configured"
    _touch_jobs(job_files)  # configured in state, but the job file is gone
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["reason"] == "not_configured"


@pytest.mark.asyncio
@pytest.mark.parametrize("params", [None, {}, {"run_id": "x", "policy_id": PID},
                                    {"run_id": RID, "policy_id": "../etc"}])  # fmt: skip
async def test_run_refuses_malformed_ids(ops, params):
    answer = await ops.backup_run(params)
    assert answer["reason"] == "invalid_request"


@pytest.mark.asyncio
async def test_run_refuses_while_the_unit_is_already_running(ops, job_files):
    await ops.backup_configure(_host_policy())
    _touch_jobs(job_files, "capture")
    ops.fake.active.add(contract.unit_name(PID, "capture"))
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["reason"] == "busy" and answer["run_id"] == RID
    assert not ops.fake.ran("--no-block")


@pytest.mark.asyncio
async def test_a_unit_that_will_not_start_is_reported(ops, job_files):
    await ops.backup_configure(_host_policy())
    _touch_jobs(job_files, "capture")
    ops.fake.fail[("systemctl", "--no-block")] = (5, "Unit not found.")
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer == {"success": False, "run_id": RID, "reason": "start_failed",
                      "error": "Unit not found."}  # fmt: skip
    assert RID not in ops._load("inflight.json")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,status",
    [(0, "ok"), (1, "different"), (2, "failed"), (3, "incomplete"),
     (4, "untrusted"), (5, "busy")],
)  # fmt: skip
async def test_a_run_reports_its_result_for_every_exit_code(
    ops, agent, job_files, code, status
):
    await ops.backup_configure(_host_policy())
    _touch_jobs(job_files, "capture")
    unit = contract.unit_name(PID, "capture")
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer == {"success": True, "run_id": RID, "status": "started"}
    assert ops.fake.ran("systemctl", "--no-block", "start", unit)
    assert RID in ops._load("inflight.json")

    ops.fake.active.add(unit)
    progress = job_builder.progress_path(ops.state_dir, PID, "capture")
    _write(progress, json.dumps({"phase": "write", "paths": 12}) + "\n")
    await asyncio.sleep(0.01)
    result = {"schema": 1, "exit": code, "status": status, "snapshot": "repo::s1"}
    _write(job_builder.result_path(ops.state_dir, PID, "capture"), json.dumps(result))
    ops.fake.exit_status = str(code)
    ops.fake.active.discard(unit)
    await _drain(ops)

    reports = _sent(agent, "backup_result")
    assert len(reports) == 1
    report = reports[0]
    assert report["run_id"] == RID and report["policy_id"] == PID
    assert report["action"] == "capture" and report["host_id"] == "host-1"
    assert (report["status"], report["exit"]) == (status, code)
    assert report["result"]["snapshot"] == "repo::s1"
    assert report["restate_version"] == "2.0.0.0"
    assert report["started_at"] and report["finished_at"]
    assert {"phase": "write", "paths": 12} in [
        p["progress"] for p in _sent(agent, "backup_progress")
    ]
    assert RID not in ops._load("inflight.json")


@pytest.mark.asyncio
async def test_a_run_without_a_result_file_is_failed(
    ops, agent, job_files, monkeypatch
):
    monkeypatch.setattr(ops_module, "START_GRACE_SECONDS", -1)
    await ops.backup_configure(_host_policy())
    _touch_jobs(job_files, "capture")
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "capture"})
    await _drain(ops)  # never seen active; the grace has passed
    report = _sent(agent, "backup_result")[0]
    assert report["status"] == "failed" and report["result"] is None


@pytest.mark.asyncio
async def test_old_reports_are_cleared_before_a_new_run(ops, job_files):
    await ops.backup_configure(_host_policy())
    _touch_jobs(job_files, "capture")
    stale = job_builder.result_path(ops.state_dir, PID, "capture")
    _write(stale, '{"exit": 0}')
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "capture"})
    assert not os.path.exists(stale)
    for task in list(ops._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_a_restarted_agent_resumes_and_reports_once(ops, agent):
    record = {"policy_id": PID, "action": "capture",
              "unit": contract.unit_name(PID, "capture"), "started_at": "t0", "started": 0}  # fmt: skip
    ops._save("inflight.json", {RID: record, "junk": "not a record"})
    _write(job_builder.result_path(ops.state_dir, PID, "capture"),
           '{"schema": 1, "exit": 0, "status": "ok"}')  # fmt: skip
    await ops.resume_in_flight()
    await ops.resume_in_flight()  # once per process
    await _drain(ops)
    reports = _sent(agent, "backup_result")
    assert [r["run_id"] for r in reports] == [RID]
    assert reports[0]["status"] == "ok" and reports[0]["started_at"] == "t0"
    assert RID not in ops._load("inflight.json")


@pytest.mark.asyncio
async def test_a_report_the_agent_cannot_queue_is_logged(ops, agent, caplog):
    agent.send_message.return_value = False
    agent.registration_manager.get_host_approval_from_db.return_value = None
    await ops._report({"run_id": RID})
    assert "host_id" not in agent.create_message.call_args.args[1]
    assert "Could not queue" in caplog.text


# ---------------------------------------------------------------------------
# seal and restore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seal_snapshots_the_dataset(ops, agent):
    await ops.backup_configure(
        _storage_policy({"mode": "zfs_snapshot", "dataset": "tank/b"})
    )
    assert contract.job_path(PID, "seal") not in [
        c[-1] for c in ops.fake.ran("install")
    ]
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "seal"})
    assert answer["status"] == "started"
    await _drain(ops)
    snap = ops.fake.ran("snapshot")
    assert snap and snap[0][-1] == f"tank/b@sysmanage-{RID}"
    assert "-r" in snap[0]  # each host's repository is a child dataset
    report = _sent(agent, "backup_result")[0]
    assert (report["action"], report["status"], report["exit"]) == ("seal", "ok", 0)


@pytest.mark.asyncio
async def test_seal_takes_a_read_only_btrfs_snapshot(ops, agent):
    await ops.backup_configure(
        _storage_policy({"mode": "btrfs_snapshot", "subvolume": "/srv/backups/restate",
                         "snapshot_dir": "/srv/backups/.snapshots"})
    )  # fmt: skip
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "seal"})
    await _drain(ops)
    snap = ops.fake.ran("snapshot")
    assert snap and snap[0][-5:] == [
        "subvolume", "snapshot", "-r", "/srv/backups/restate",
        f"/srv/backups/.snapshots/sysmanage-{RID}",
    ]  # fmt: skip
    assert snap[0][-6].endswith("/btrfs")
    report = _sent(agent, "backup_result")[0]
    assert (report["action"], report["status"], report["exit"]) == ("seal", "ok", 0)


@pytest.mark.asyncio
async def test_a_failed_btrfs_seal_is_reported(ops, agent):
    await ops.backup_configure(
        _storage_policy({"mode": "btrfs_snapshot", "subvolume": "/srv/backups/restate",
                         "snapshot_dir": "/srv/backups/.snapshots"})
    )  # fmt: skip
    for btrfs in ops_module.BTRFS_PATHS:
        ops.fake.fail[(btrfs, "subvolume")] = (1, "ERROR: not a subvolume")
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "seal"})
    await _drain(ops)
    report = _sent(agent, "backup_result")[0]
    assert report["status"] == "failed"
    assert report["result"] == {"message": "ERROR: not a subvolume"}


def test_btrfs_seal_argv_is_exact():
    argv = ops_module.seal_argv(
        {"mode": "btrfs_snapshot", "subvolume": "/srv/b", "snapshot_dir": "/srv/s"}, RID
    )
    assert argv[1:] == [
        "subvolume",
        "snapshot",
        "-r",
        "/srv/b",
        f"/srv/s/sysmanage-{RID}",
    ]
    assert ops_module.seal_argv({"mode": "none"}, RID) is None


@pytest.mark.asyncio
async def test_a_failed_seal_is_reported(ops, agent):
    await ops.backup_configure(
        _storage_policy({"mode": "zfs_snapshot", "dataset": "tank/b"})
    )
    for zfs in ops_module.ZFS_PATHS:
        ops.fake.fail[(zfs, "snapshot")] = (1, "dataset does not exist")
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "seal"})
    await _drain(ops)
    report = _sent(agent, "backup_result")[0]
    assert report["status"] == "failed"
    assert report["result"] == {"message": "dataset does not exist"}


@pytest.mark.asyncio
async def test_seal_mode_none_succeeds_without_zfs(ops, agent):
    await ops.backup_configure(_storage_policy({"mode": "none"}))
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "seal"})
    await _drain(ops)
    assert not ops.fake.ran("snapshot")
    assert _sent(agent, "backup_result")[0]["status"] == "ok"


@pytest.mark.asyncio
async def test_restore_stages_into_the_agents_directory(ops, monkeypatch):
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_restore(
        {"run_id": RID, "policy_id": PID, "include": ["/etc/**"], "restore_root": "/"}
    )
    assert answer == {"success": True, "run_id": RID, "status": "started"}
    job = rendered[-1]
    root = os.path.join(ops.state_dir, "restore", RID)
    assert job["restore_root"] == root and job["dry_run"] is True
    assert os.path.isdir(root) and oct(os.stat(root).st_mode & 0o777) == "0o700"
    assert ops.fake.ran("install")[-1][-1] == contract.job_path(PID, "restore")
    assert ops.fake.ran("--no-block", contract.unit_name(PID, "restore"))
    for task in list(ops._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_restore_needs_a_host_policy(ops):
    await ops.backup_configure(_storage_policy({"mode": "none"}))
    answer = await ops.backup_restore({"run_id": RID, "policy_id": PID})
    assert answer["reason"] == "not_configured"
    answer = await ops.backup_restore({"run_id": RID, "policy_id": "nope"})
    assert answer["reason"] == "invalid_request"


@pytest.mark.asyncio
async def test_a_hostile_restore_request_is_refused(ops):
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_restore(
        {"run_id": RID, "policy_id": PID, "include": ["a\nrestore_root = /"]}
    )
    assert answer["reason"] == "invalid_request"
    assert not ops.fake.ran("--no-block")


def test_privileged_prefixes_sudo_unless_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert BackupOperations._privileged(["rm"]) == ["sudo", "-n", "rm"]
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert BackupOperations._privileged(["rm"]) == ["rm"]


@pytest.mark.asyncio
async def test_run_really_spawns_a_process():
    code, out, err = await BackupOperations._run(
        ["/bin/sh", "-c", "echo hi; echo no >&2; exit 3"]
    )
    assert (code, out, err) == (3, "hi\n", "no")


@pytest.mark.asyncio
async def test_storage_configure_reports_the_filesystem(ops, monkeypatch):
    seen = []

    def describe(path, **_kw):
        seen.append(path)
        return {"type": "ext4", "mount_point": "/srv", "path": path,
                "btrfs_subvolume": None}  # fmt: skip

    monkeypatch.setattr(ops_module.storage_fs, "describe", describe)
    reply = await ops.backup_configure(_storage_policy({"mode": "none"}))
    assert reply["success"] and reply["storage_fs"]["type"] == "ext4"
    assert seen[0] == "/srv/backups/restate"  # then the audit asks about the repository


@pytest.mark.asyncio
async def test_host_configure_does_not_report_a_filesystem(ops):
    reply = await ops.backup_configure(_host_policy())
    assert reply["success"] and "storage_fs" not in reply
