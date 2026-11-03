# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The storage host backs itself up (server ROADMAP 24.13): the ``self``
role captures this machine into a repository on its own pool, written
locally, and runs that repository's storage jobs; it never records the
backups it keeps or the pool's other data, but keeps a root-on-ZFS system's
own datasets."""

# pylint: disable=redefined-outer-name,protected-access

import sys
from types import SimpleNamespace

import pytest

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import self_backup
from src.sysmanage_agent.backup import storage_prepare
from src.sysmanage_agent.operations import backup_operations as ops_module
from tests.backup_ops_support import (  # noqa: F401  pylint: disable=unused-import
    PID,
    agent,
    job_files,
    ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")

STORAGE = "/srv/backups/restate"
M = self_backup.Mount


def _no(_path):
    return False


def test_with_the_os_off_zfs_every_dataset_and_the_storage_tree_are_left_out():
    """nas (2026-11-01): the OS on ext4, the data on a ZFS pool."""
    mounts = [M("/", "ext4", "/dev/mapper/ubuntu--vg-ubuntu--lv"),
              M("/boot", "ext4", "/dev/nvme0n1p2"),
              M("/zfs-pool", "zfs", "zfs-pool"),
              M("/zfs-pool/casedata", "zfs", "zfs-pool/casedata"),
              M("/srv/backups/restate", "zfs", "zfs-pool/backups/restate"),
              M("/srv/backups/restate/beast-1", "zfs", "zfs-pool/backups/restate/beast-1"),
              M("/proc", "proc", "proc")]  # fmt: skip
    points = self_backup.leave_out(mounts, STORAGE, exists=_no)
    assert points == ["/srv/backups/restate", "/zfs-pool"]


def test_on_root_on_zfs_the_systems_own_datasets_are_kept():
    """FreeBSD's default: /usr/home, /var/log and /tmp are datasets of the
    root pool -- kept; the backups on that pool and another pool's data are
    not."""
    mounts = [M("/", "zfs", "zroot/ROOT/default"),
              M("/usr/home", "zfs", "zroot/usr/home"),
              M("/var/log", "zfs", "zroot/var/log"),
              M("/tmp", "zfs", "zroot/tmp"),
              M("/srv/backups", "zfs", "zroot/sysmanage-backups"),
              M("/srv/backups/restate", "zfs", "zroot/sysmanage-backups/restate"),
              M("/tank/media", "zfs", "tank/media")]  # fmt: skip
    points = self_backup.leave_out(mounts, STORAGE, exists=_no)
    assert points == ["/srv/backups/restate", "/tank/media"]


def test_rebuildable_caches_present_are_left_out():
    mounts = [M("/", "ext4", "/dev/sda1")]
    points = self_backup.leave_out(
        mounts, STORAGE, exists=lambda p: p == "/var/lib/zfs-l2arc"
    )
    assert points == ["/srv/backups/restate", "/var/lib/zfs-l2arc"]


def test_mount_tables_are_read_on_linux_and_the_bsds():
    info = ("36 25 0:30 / /srv/backups\\040x rw - zfs tank/backups rw\n"
            "37 25 8:1 / / rw - ext4 /dev/sda1 rw\n")  # fmt: skip
    assert self_backup.linux_mounts(info) == [
        M("/srv/backups x", "zfs", "tank/backups"), M("/", "ext4", "/dev/sda1"),
    ]  # fmt: skip
    mount_p = (
        "zroot/ROOT/default\t/\tzfs\trw\t0 0\nzroot/usr/home\t/usr/home\tzfs\trw\t0 0\n"
    )
    assert self_backup.bsd_mounts(mount_p) == [
        M("/", "zfs", "zroot/ROOT/default"), M("/usr/home", "zfs", "zroot/usr/home"),
    ]  # fmt: skip


def test_the_rules_file_leaves_each_point_out_literally():
    text, skipped = self_backup.rules_text(["/srv/backups/restate", "/data[1]"])
    assert "ephemeral /srv/backups/restate" in text
    assert "ephemeral /data\\[1]" in text and skipped == []


def _self_params(**over):
    params = {
        "policy_id": PID,
        "role": "self",
        "target": {"mount_point": STORAGE, "repo_dir": "nas-1"},
        "jobs": {"capture": {"quiesce": False}, "snapshots": {}, "prune": {"keep_last": 7},
                 "protect": {}, "seal": {"mode": "none"}},
    }  # fmt: skip
    params.update(over)
    return params


def test_validation_admits_both_sides_on_a_local_target():
    policy = v.check_policy(
        _self_params(),
        mountinfo=lambda: "",
        realpath=lambda p: p,
        isdir=lambda p: True,
        zfs_mounts=lambda: (),
    )
    assert policy["role"] == "self" and policy["nfs"] is None
    assert policy["repository"] == f"{STORAGE}/nas-1"
    assert policy["jobs"]["capture"]["append_only"] is True
    assert set(policy["jobs"]) == {"capture", "snapshots", "prune", "protect", "seal"}


def test_validation_refuses_what_neither_side_runs():
    with pytest.raises(v.PolicyError, match="may not run"):
        v.check_policy(
            _self_params(jobs={"install": {}}), mountinfo=lambda: "",
            realpath=lambda p: p, isdir=lambda p: True, zfs_mounts=lambda: (),
        )  # fmt: skip


def test_both_runners_drive_a_self_backup():
    assert "self" in job_runner.ROLES[job_runner.SYSTEMD]
    assert "self" in job_runner.ROLES[job_runner.DAEMON]


def test_the_self_rules_come_last_so_no_keep_brings_the_backups_back():
    policy = {"policy_id": PID, "role": "self", "repository": f"{STORAGE}/nas-1",
              "jobs": {"capture": {"keep_paths": ["/srv/**"]}}}  # fmt: skip
    jobs = job_builder.build_jobs(
        policy,
        state_dir="/var/lib/x",
        group="g",
        key_installed=False,
        network_rules=True,
    )
    rules = jobs["capture"]["rules"]
    assert rules[-1] == job_builder.self_rules_path(PID)
    assert rules[0] == job_builder.network_rules_path(PID)


def test_prepare_makes_the_dataset_with_no_export_and_no_address(monkeypatch):
    monkeypatch.setattr(
        storage_prepare.pwd, "getpwnam", lambda n: SimpleNamespace(pw_uid=1)
    )
    monkeypatch.setattr(
        storage_prepare.grp, "getgrnam", lambda n: SimpleNamespace(gr_gid=1)
    )
    policy = {"policy_id": PID, "role": "self", "repository": f"{STORAGE}/nas-1",
              "mount_point": STORAGE, "service_account": "restate"}  # fmt: skip

    def missing(path):
        raise FileNotFoundError(path)

    for system in ("FreeBSD", "Linux"):
        steps = storage_prepare.plan(
            policy, system=system, fstype="zfs",
            datasets={STORAGE: "tank/backups/restate"},
            is_subvolume=lambda _p: False, listdir=missing,
        )  # fmt: skip
        assert steps["commands"] == [["zfs", "create", "tank/backups/restate/nas-1"]]
        assert steps["export_file"] is None and steps["reload"] is False


@pytest.mark.asyncio
async def test_a_self_configure_writes_its_rules_and_reports_both_sides(
    ops, monkeypatch, job_files
):
    del job_files
    monkeypatch.setattr(
        ops_module.SelfBackupMixin,
        "_self_points",
        lambda self, policy: _points(),
    )
    reply = await ops.backup_configure(_self_params())
    assert reply["success"], reply
    assert reply["self_left_out"] == ["/srv/backups/restate", "/zfs-pool"]
    assert "abilities" in reply and "storage_abilities" in reply
    assert "storage_audit" not in reply and "nfs_path" not in reply
    installed = [c for c in ops.fake.calls if job_builder.self_rules_path(PID) in c]
    assert installed, "the self rules file was not installed"
    assert ops._policy(PID)["role"] == "self"


async def _points():
    return ["/srv/backups/restate", "/zfs-pool"]
