# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""FreeBSD storage hosts: restate under daemon(8) instead of systemd (Phase 24).

The pidfile lock and log helpers run for real; the driver's subprocesses go
through the same recording fake as ``test_backup_operations``.
"""

# pylint: disable=protected-access,redefined-outer-name,unused-import

import json
import os
import sys

import pytest

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations import backup_operations as ops_module
from tests.test_backup_operations import (  # noqa: F401  # fixtures
    PID,
    RID,
    _drain,
    _host_policy,
    _sent,
    _storage_policy,
    _touch_jobs,
    _write,
    agent,
    job_files,
    ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")
RESTATE = "/usr/local/sbin/restate"


@pytest.fixture
def bsd(ops, monkeypatch):
    """The driver as a FreeBSD storage host's agent, running unprivileged."""
    ops.runner = job_runner.DAEMON
    monkeypatch.setattr(os, "geteuid", lambda: 1001, raising=False)
    monkeypatch.setattr(ops_module.restate_probe, "locate", lambda _w: RESTATE)
    locked = set()
    monkeypatch.setattr(job_runner, "pidfile_locked", lambda path: path in locked)
    ops.locked = locked
    return ops


def _prune_policy():
    policy = _storage_policy({"mode": "zfs_snapshot", "dataset": "zroot/b"})
    policy["jobs"]["prune"] = {"keep_last": 7}
    return policy


# ---------------------------------------------------------------------------
# the helpers, for real
# ---------------------------------------------------------------------------


def test_runners_by_platform():
    assert job_runner.runner_for("Linux") == job_runner.SYSTEMD
    assert job_runner.runner_for("FreeBSD") == job_runner.DAEMON
    for system in ("OpenBSD", "NetBSD", "Darwin", "Windows", "", None):
        assert job_runner.runner_for(system) is None
    assert job_runner.ROLES[job_runner.DAEMON] == ("storage",)


def test_a_pidfile_is_running_only_while_locked(tmp_path):
    import fcntl  # pylint: disable=import-outside-toplevel

    path = str(tmp_path / "job.pid")
    assert not job_runner.pidfile_locked(path)  # no pidfile: done
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("4242\n")
        handle.flush()
        assert not job_runner.pidfile_locked(path)  # stale: done
        fcntl.flock(handle, fcntl.LOCK_EX)  # what pidfile(3) holds
        assert job_runner.pidfile_locked(path)
        fcntl.flock(handle, fcntl.LOCK_UN)
    assert not job_runner.pidfile_locked(path)


def test_log_tail_keeps_the_end(tmp_path):
    path = tmp_path / "job.log"
    assert job_runner.log_tail(str(path)) is None
    path.write_text("x" * 5000 + "restate: run: not run\n")
    tail = job_runner.log_tail(str(path))
    assert tail.endswith("restate: run: not run")
    assert len(tail) <= job_runner.LOG_TAIL_BYTES
    path.write_text("  \n")
    assert job_runner.log_tail(str(path)) is None


def test_daemon_argv_elevates_only_restate():
    def sudo(argv):
        return ["sudo", "-n"] + argv

    argv = job_runner.daemon_argv(RESTATE, "/etc/restate/jobs.d/a.prune.conf",
                                  "/s/a.pid", "/s/a.log", sudo)  # fmt: skip
    assert argv == ["/usr/sbin/daemon", "-f", "-p", "/s/a.pid", "-o", "/s/a.log",
                    "sudo", "-n", RESTATE, "run",
                    "/etc/restate/jobs.d/a.prune.conf"]  # fmt: skip


# ---------------------------------------------------------------------------
# the driver on FreeBSD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_freebsd_host_cannot_take_the_host_role(bsd):
    answer = await bsd.backup_configure(_host_policy())
    assert answer["success"] is False and answer["reason"] == "wrong_platform"
    assert not bsd.fake.ran("install")


@pytest.mark.asyncio
async def test_freebsd_install_makes_the_directory_without_gnu_dash_d(
    bsd, monkeypatch, tmp_path
):
    jobs = tmp_path / "etc" / "restate" / "jobs.d"
    monkeypatch.setattr(contract, "JOBS_DIR", str(jobs))
    answer = await bsd.backup_configure(_prune_policy())
    assert answer["success"], answer
    installs = bsd.fake.ran("install")
    assert all("-D" not in argv for argv in installs)
    assert installs[0] == ["sudo", "-n", "install", "-d", "-m", "755", "-o", "0",
                           "-g", "0", "--", str(jobs)]  # fmt: skip
    dests = [argv[-1] for argv in installs[1:]]
    assert str(jobs / f"{PID}.prune.conf") in dests


@pytest.mark.asyncio
async def test_freebsd_install_leaves_an_existing_directory_alone(bsd, job_files):
    await bsd.backup_configure(_prune_policy())
    assert all("-d" not in argv for argv in bsd.fake.ran("install"))


@pytest.mark.asyncio
async def test_a_freebsd_prune_runs_under_daemon_and_reports(bsd, agent, job_files):
    await bsd.backup_configure(_prune_policy())
    _touch_jobs(job_files, "prune")
    answer = await bsd.backup_run({"run_id": RID, "policy_id": PID, "action": "prune"})
    assert answer == {"success": True, "run_id": RID, "status": "started"}
    name = contract.job_name(PID, "prune")
    pid = job_runner.pidfile(bsd.state_dir, name)
    log = job_runner.logfile(bsd.state_dir, name)
    assert bsd.fake.ran("/usr/sbin/daemon") == [
        ["/usr/sbin/daemon", "-f", "-p", pid, "-o", log, "sudo", "-n", RESTATE,
         "run", str(job_files / f"{name}.conf")]
    ]  # fmt: skip
    assert not bsd.fake.ran("systemctl")
    assert os.path.isdir(job_runner.run_dir(bsd.state_dir))

    bsd.locked.add(pid)
    busy = await bsd.backup_run({"run_id": RID, "policy_id": PID, "action": "prune"})
    assert busy["reason"] == "busy"

    result = {"schema": 1, "exit": 0, "status": "ok"}
    _write(job_builder.result_path(bsd.state_dir, PID, "prune"), json.dumps(result))
    bsd.locked.discard(pid)
    await _drain(bsd)
    report = _sent(agent, "backup_result")[0]
    assert (report["action"], report["status"], report["exit"]) == ("prune", "ok", 0)
    assert RID not in bsd._load("inflight.json")


@pytest.mark.asyncio
async def test_a_run_with_no_result_reports_what_restate_said(
    bsd, agent, job_files, monkeypatch
):
    monkeypatch.setattr(ops_module, "START_GRACE_SECONDS", -1)
    await bsd.backup_configure(_prune_policy())
    _touch_jobs(job_files, "prune")
    log = job_runner.logfile(bsd.state_dir, contract.job_name(PID, "prune"))
    _write(log, "old run's output\n")
    await bsd.backup_run({"run_id": RID, "policy_id": PID, "action": "prune"})
    assert not os.path.exists(log)  # cleared before the run
    _write(log, "restate: run: not run: it has to be root's\n")
    await _drain(bsd)
    report = _sent(agent, "backup_result")[0]
    assert (report["status"], report["exit"]) == ("failed", None)
    assert report["result"] == {"message": "restate: run: not run: it has to be root's"}


@pytest.mark.asyncio
async def test_a_daemon_that_will_not_start_is_reported(bsd, job_files):
    await bsd.backup_configure(_prune_policy())
    _touch_jobs(job_files, "prune")
    bsd.fake.fail[("/usr/sbin/daemon",)] = (1, "daemon: pidfile busy")
    answer = await bsd.backup_run({"run_id": RID, "policy_id": PID, "action": "prune"})
    assert answer["reason"] == "start_failed" and "pidfile" in answer["error"]
    assert RID not in bsd._load("inflight.json")


@pytest.mark.asyncio
async def test_no_restate_means_no_start(bsd, job_files, monkeypatch):
    await bsd.backup_configure(_prune_policy())
    _touch_jobs(job_files, "prune")
    monkeypatch.setattr(ops_module.restate_probe, "locate", lambda _w: None)
    answer = await bsd.backup_run({"run_id": RID, "policy_id": PID, "action": "prune"})
    assert answer["reason"] == "start_failed"
    assert not bsd.fake.ran("/usr/sbin/daemon")


@pytest.mark.asyncio
async def test_a_restarted_freebsd_agent_resumes_a_daemon_run(bsd, agent):
    name = contract.job_name(PID, "check")
    record = {"policy_id": PID, "action": "check", "started_at": "t0", "started": 0,
              "pidfile": job_runner.pidfile(bsd.state_dir, name),
              "log": job_runner.logfile(bsd.state_dir, name)}  # fmt: skip
    bsd._save("inflight.json", {RID: record})
    _write(job_builder.result_path(bsd.state_dir, PID, "check"),
           '{"schema": 1, "exit": 5, "status": "busy"}')  # fmt: skip
    await bsd.resume_in_flight()
    await _drain(bsd)
    report = _sent(agent, "backup_result")[0]
    assert (report["run_id"], report["status"], report["exit"]) == (RID, "busy", 5)


def test_backup_state_lives_beside_the_agents_database(agent, monkeypatch, tmp_path):
    # A fixed /var/lib/sysmanage-agent made a checkout agent switch to a new,
    # empty database there on restart and lose its identity (2026-10-20).
    monkeypatch.delenv("SYSMANAGE_BACKUP_STATE_DIR", raising=False)
    database = tmp_path / "checkout" / "agent.db"
    monkeypatch.setattr(ops_module, "current_database_path", lambda: str(database))
    assert ops_module.BackupOperations(agent).state_dir == str(database.parent)
    monkeypatch.setenv("SYSMANAGE_BACKUP_STATE_DIR", "/srv/state")
    assert ops_module.BackupOperations(agent).state_dir == "/srv/state"


def test_the_state_directory_follows_the_platform(agent, monkeypatch):
    monkeypatch.delenv("SYSMANAGE_BACKUP_STATE_DIR", raising=False)
    monkeypatch.setattr(ops_module, "current_database_path", lambda: None)
    monkeypatch.setattr(ops_module.platform, "system", lambda: "FreeBSD")
    backup = ops_module.BackupOperations(agent)
    assert backup.state_dir == "/var/db/sysmanage-agent"
    assert backup.runner == job_runner.DAEMON
    monkeypatch.setattr(ops_module.platform, "system", lambda: "Linux")
    assert ops_module.BackupOperations(agent).state_dir == "/var/lib/sysmanage-agent"


def test_the_freebsd_sudoers_rule_admits_exactly_the_storage_jobs():
    """The sudoers regex and the agent's job paths must not drift apart."""
    import re  # pylint: disable=import-outside-toplevel

    from src.sysmanage_agent.backup import (  # pylint: disable=import-outside-toplevel
        job_validation,
    )

    here = os.path.dirname(os.path.abspath(__file__))
    sudoers = os.path.join(
        here, "..", "installer", "freebsd", "sysmanage-agent.sudoers"
    )
    with open(sudoers, encoding="utf-8") as handle:
        rules = [line for line in handle if f"{RESTATE} ^run " in line]
    assert len(rules) == 1
    pattern = rules[0].split(f"{RESTATE} ", 1)[1].strip()
    run = [a for a in job_validation.STORAGE_ACTIONS if a != "seal"]
    for action in run:
        assert re.fullmatch(pattern, f"run {contract.job_path(PID, action)}"), action
    for action in job_validation.HOST_ACTIONS:
        assert not re.fullmatch(pattern, f"run {contract.job_path(PID, action)}")
    good = f"run {contract.job_path(PID, 'prune')}"
    for bad in (good + " --result /etc/master.passwd", "--result /x " + good,
                good.replace(PID, "../" + PID), good.replace(".d/", "Xd/")):  # fmt: skip
        assert not re.fullmatch(pattern, bad), bad
