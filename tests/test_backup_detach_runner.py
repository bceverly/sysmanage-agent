# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Backups without systemd or daemon(8): Alpine and macOS (25.8).

detach.py runs for real (it only forks and runs the command it is given);
the driver's subprocesses go through the same recording fake as
``backup_ops_support``.
"""

# pylint: disable=protected-access,redefined-outer-name,unused-import

import os
import subprocess
import sys
import time

import pytest

from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import job_validation as validation
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import self_backup
from src.sysmanage_agent.operations import backup_operations as ops_module
from tests.backup_ops_support import (  # noqa: F401  # fixtures
    PID,
    RID,
    _drain,
    _storage_policy,
    _touch_jobs,
    agent,
    job_files,
    ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")
RESTATE = "/usr/sbin/restate"


def _detach(tmp_path, *command):
    pid, log = str(tmp_path / "job.pid"), str(tmp_path / "job.log")
    started = time.monotonic()
    done = subprocess.run(
        [sys.executable, "-I", job_runner.DETACH_SCRIPT, pid, log, "--", *command],
        capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    return done, pid, log, time.monotonic() - started


def _wait_unlocked(pid, seconds=10.0):
    deadline = time.monotonic() + seconds
    while job_runner.pidfile_locked(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not job_runner.pidfile_locked(pid)


# ---------------------------------------------------------------------------
# detach.py, for real
# ---------------------------------------------------------------------------


def test_it_returns_at_once_and_holds_the_lock_while_the_command_runs(tmp_path):
    done, pid, log, took = _detach(
        tmp_path, "sh", "-c", "echo started; sleep 1; echo ended"
    )
    assert done.returncode == 0 and took < 1.0  # like daemon -f: it does not wait
    assert job_runner.pidfile_locked(pid)
    assert _wait_unlocked(pid)
    with open(log, encoding="utf-8") as handle:
        assert handle.read().split() == ["started", "ended"]


def test_the_pidfile_names_the_command(tmp_path):
    _done, pid, _log, _took = _detach(tmp_path, "sleep", "1")
    deadline, text = time.monotonic() + 5, ""
    while not text.strip() and time.monotonic() < deadline:
        with open(pid, encoding="utf-8") as handle:
            text = handle.read()
        time.sleep(0.02)
    shown = subprocess.run(["ps", "-o", "comm=", "-p", text.strip()],
                           capture_output=True, text=True, check=False).stdout  # fmt: skip
    assert shown.strip().endswith("sleep")
    assert _wait_unlocked(pid)


def test_a_second_start_while_one_runs_is_refused(tmp_path):
    _detach(tmp_path, "sleep", "1")
    again, pid, _log, _took = _detach(tmp_path, "echo", "second")
    assert again.returncode == 3 and "already running" in again.stderr
    assert _wait_unlocked(pid)


def test_sigterm_reaches_the_command(tmp_path):
    marker = tmp_path / "stopped"
    script = f"trap 'touch {marker}; exit 0' TERM; sleep 30 & wait"
    _done, pid, _log, _took = _detach(tmp_path, "sh", "-c", script)
    time.sleep(0.5)
    with open(pid, encoding="utf-8") as handle:
        child = int(handle.read())
    supervisor = int(
        subprocess.run(["ps", "-o", "ppid=", "-p", str(child)], capture_output=True,
                       text=True, check=False).stdout.strip()
    )  # fmt: skip
    os.kill(supervisor, 15)
    assert _wait_unlocked(pid)
    assert marker.exists()


def test_it_refuses_without_the_separator(tmp_path):
    done = subprocess.run(
        [sys.executable, "-I", job_runner.DETACH_SCRIPT, str(tmp_path / "p"),
         str(tmp_path / "l"), "echo"],
        capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    assert done.returncode == 2 and "usage" in done.stderr


def test_the_start_command_elevates_only_restate():
    argv = job_runner.start_argv(
        job_runner.DETACH, RESTATE, "/etc/restate/jobs.d/x.prune.conf", "/r/x.pid",
        "/r/x.log", lambda a: ["sudo", "-n", *a],
    )  # fmt: skip
    assert argv == [sys.executable, "-I", job_runner.DETACH_SCRIPT, "/r/x.pid",
                    "/r/x.log", "--", "sudo", "-n", RESTATE, "run",
                    "/etc/restate/jobs.d/x.prune.conf"]  # fmt: skip


# ---------------------------------------------------------------------------
# the driver on a detach host
# ---------------------------------------------------------------------------


@pytest.fixture
def alpine(ops, monkeypatch):
    """The driver as an Alpine host's agent (no systemd), unprivileged."""
    ops.runner = job_runner.DETACH
    monkeypatch.setattr(os, "geteuid", lambda: 1001, raising=False)
    monkeypatch.setattr(ops_module.restate_probe, "locate", lambda _w: RESTATE)
    monkeypatch.setattr(job_runner, "pidfile_locked", lambda path: False)
    return ops


@pytest.mark.asyncio
async def test_a_job_starts_through_detach_and_is_watched_by_its_pidfile(
    alpine, job_files, monkeypatch
):
    monkeypatch.setattr(ops_module, "START_GRACE_SECONDS", -1)
    policy = _storage_policy({"mode": "zfs_snapshot", "dataset": "tank/b"})
    policy["jobs"]["prune"] = {"keep_last": 7}
    assert (await alpine.backup_configure(policy))["success"]
    _touch_jobs(job_files, "prune")
    answer = await alpine.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "prune"}
    )
    assert answer["success"], answer
    started = [argv for argv in alpine.fake.calls if job_runner.DETACH_SCRIPT in argv]
    assert len(started) == 1
    name = contract.job_name(PID, "prune")
    assert started[0][3:5] == [job_runner.pidfile(alpine.state_dir, name),
                               job_runner.logfile(alpine.state_dir, name)]  # fmt: skip
    assert started[0][-3:] == [RESTATE, "run", contract.job_path(PID, "prune")]
    record = alpine._load("inflight.json")[RID]
    assert record["pidfile"].endswith(".pid") and "unit" not in record
    await _drain(alpine)


# ---------------------------------------------------------------------------
# mounting off Linux
# ---------------------------------------------------------------------------

SOURCE = {"server": "192.168.4.10", "path": "/srv/backups/restate/mac-1234"}


def test_each_platform_mounts_nfsv4_in_its_own_words():
    where = "/Volumes/backups/mac-1234"
    assert host_mount.mount_argv(SOURCE, where, system="FreeBSD") == [
        "mount", "-t", "nfs", "-o", "nfsv4,tcp,hard,nosuid",
        "192.168.4.10:/srv/backups/restate/mac-1234", where]  # fmt: skip
    assert host_mount.mount_argv(SOURCE, where, system="Darwin") == [
        "mount", "-t", "nfs", "-o", "vers=4,tcp,hard,nosuid,nodev,resvport",
        "192.168.4.10:/srv/backups/restate/mac-1234", where]  # fmt: skip
    # Linux without systemd (Alpine): plain mount, as before.
    assert host_mount.mount_argv(SOURCE, where, systemd=False)[:3] == [
        "mount", "-t", "nfs4"]  # fmt: skip


def test_the_mac_mount_table_is_read_from_mount():
    out = (
        "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n"
        "192.168.4.10:/srv/backups/restate/mac-1234 on /Volumes/backups/mac-1234 "
        "(nfs, nodev, nosuid, mounted by root)\n"
        "map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)\n"
    )
    mounts = {m.point: m.fstype for m in self_backup.darwin_mounts(out)}
    assert mounts == {"/": "apfs", "/Volumes/backups/mac-1234": "nfs",
                      "/System/Volumes/Data/home": "autofs"}  # fmt: skip
    assert host_mount.mounted_nfs("/Volumes/backups/mac-1234", mounts)


def test_a_mac_may_mount_under_volumes_and_nobody_else_may():
    target = {"mount_point": "/Volumes/backups", "repo_dir": "mac-1234"}
    point, repository = validation.check_target(
        "host", target, mountinfo=lambda: "", managed=True, system="Darwin",
        realpath=lambda p: p,
    )  # fmt: skip
    assert (point, repository) == ("/Volumes/backups", "/Volumes/backups/mac-1234")
    with pytest.raises(validation.PolicyError):
        validation.check_target(
            "host", target, mountinfo=lambda: "", managed=True, system="Linux",
            realpath=lambda p: p,
        )  # fmt: skip


def test_an_operator_mount_off_linux_is_found_in_the_platform_table():
    target = {"mount_point": "/mnt/backups", "repo_dir": "fbsd-1"}
    point, _repo = validation.check_target(
        "host", target, mountinfo=lambda: "", system="FreeBSD",
        mount_table=lambda: {"/mnt/backups/fbsd-1": "nfs"}, realpath=lambda p: p,
    )  # fmt: skip
    assert point == "/mnt/backups"
    with pytest.raises(validation.PolicyError):
        validation.check_target(
            "host", target, mountinfo=lambda: "", system="FreeBSD",
            mount_table=lambda: {}, realpath=lambda p: p,
        )  # fmt: skip


def test_a_macs_shares_and_automounts_are_left_out_but_not_its_storage():
    from src.sysmanage_agent.backup import (  # pylint: disable=import-outside-toplevel
        network_mounts,
    )

    table = {
        "/": "apfs",
        "/Volumes/backups/mac-1234": "nfs",
        "/Volumes/Team": "smbfs",
        "/Volumes/Old": "afpfs",
        "/System/Volumes/Data/home": "autofs",
    }
    found = network_mounts.scan("", repository_mount="/Volumes/backups", table=table)
    assert found.excluded == [
        "/System/Volumes/Data/home",
        "/Volumes/Old",
        "/Volumes/Team",
    ]
