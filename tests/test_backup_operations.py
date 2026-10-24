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
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations import backup_operations as ops_module
from src.sysmanage_agent.operations.backup_operations import BackupOperations

PID = "3f2a0000-0000-4000-8000-0000000000c1"
RID = "7b1c0000-0000-4000-8000-0000000000aa"
FEATURES = {
    "version": "2.0.0.0",
    "job_keys": sorted(
        {"command", "repository", "result", "progress", "report_group",
         "encrypt_to", "append_only", "quiesce", "keep_last", "restore_root",
         "dry_run", "check_first", "snapshot", "include", "allow_unverified",
         "read_all", "metadata_only", "record", "whole_packs", "rules"}
    ),
}  # fmt: skip
# restate is Linux-only; the driver uses POSIX paths and modes throughout.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only feature")
STORAGE_TARGET = {"mount_point": "/srv/backups/restate", "repo_dir": "h-1"}


class FakeRun:
    """Stands in for ``BackupOperations._run``: records argv, scripted answers."""

    def __init__(self):
        self.calls = []
        self.active = set()  # units systemctl show reports as active
        self.fail = {}  # argv[0..] prefix (tuple) -> (code, err)
        self.exit_status = "0"

    async def __call__(self, argv):
        self.calls.append(list(argv))
        bare = argv[2:] if argv[:2] == ["sudo", "-n"] else argv
        for prefix, answer in self.fail.items():
            if tuple(bare[: len(prefix)]) == prefix:
                return answer[0], "", answer[1]
        if bare[:2] == ["systemctl", "show"]:
            state = "active" if bare[2] in self.active else "inactive"
            return (
                0,
                f"ActiveState={state}\nResult=success\nExecMainStatus={self.exit_status}\n",
                "",
            )
        return 0, "", ""

    def ran(self, *words):
        return [c for c in self.calls if all(w in c for w in words)]


@pytest.fixture
def agent():
    approval = SimpleNamespace(host_id="host-1")
    return SimpleNamespace(
        registration_manager=Mock(
            get_host_approval_from_db=Mock(return_value=approval)
        ),
        create_message=Mock(
            side_effect=lambda kind, data: {"message_type": kind, "data": data}
        ),
        send_message=AsyncMock(return_value=True),
    )


@pytest.fixture
def ops(agent, tmp_path, monkeypatch):
    backup = BackupOperations(agent, state_dir=str(tmp_path))
    # The runner comes from platform.system(); these tests are the Linux
    # (systemd) driver on every CI leg, macOS included.
    backup.runner = job_runner.SYSTEMD
    fake = FakeRun()
    monkeypatch.setattr(backup, "_run", fake)
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: FEATURES))
    monkeypatch.setattr(ops_module.restate_probe, "unavailable_reason", lambda *a: None)
    monkeypatch.setattr(ops_module, "_agent_group", lambda: "sysmanage-agent")
    monkeypatch.setattr(ops_module, "POLL_SECONDS", 0)
    monkeypatch.setattr(ops_module, "PROGRESS_EVERY_SECONDS", 0)
    monkeypatch.setattr(ops_module.validation, "check_target", _fake_target)
    # The storage takes the capture unless a test says otherwise.
    monkeypatch.setattr(ops_module.host_mount, "preflight", lambda where, run_id: None)
    # The host's repository is on NFS unless a test says otherwise.
    monkeypatch.setattr(BackupOperations, "_mounts",
                        staticmethod(lambda: {"/mnt/sysmanage-backup": "nfs4"}))  # fmt: skip
    backup.fake = fake
    return backup


def _fake_target(role, target, **_kw):
    del role
    return target["mount_point"], f"{target['mount_point']}/{target['repo_dir']}"


def _host_policy(**over):
    params = {
        "policy_id": PID,
        "role": "host",
        "target": {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1"},
        "jobs": {"capture": {"quiesce": True}, "snapshots": {}},
    }
    params.update(over)
    return params


def _sent(agent, kind):
    return [c.args[0]["data"] for c in agent.send_message.await_args_list
            if c.args[0]["message_type"] == kind]  # fmt: skip


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


async def _drain(backup):
    while backup._tasks:
        await asyncio.gather(*list(backup._tasks))


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


@pytest.fixture
def job_files(monkeypatch, tmp_path):
    jobs = tmp_path / "jobs.d"
    jobs.mkdir()
    monkeypatch.setattr(contract, "JOBS_DIR", str(jobs))
    return jobs


def _touch_jobs(job_files, *actions):
    for action in actions:
        (job_files / f"{PID}.{action}.conf").write_text("command = x\n")


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


def _storage_policy(seal):
    return {"policy_id": PID, "role": "storage", "target": STORAGE_TARGET,
            "jobs": {"check": {"read_all": True}, "seal": seal}}  # fmt: skip


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
