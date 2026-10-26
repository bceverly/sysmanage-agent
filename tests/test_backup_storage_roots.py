# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Where a storage host may keep repositories, and whether it serves NFSv4.

Production, 2026-10-25: a ZFS NAS keeps pools at /<pool> by default and its
target at /zfs-pool/backups/restate was refused; a non-root agent could not
read /proc/fs/nfsd/versions and reported every Linux NFS server as not
serving NFSv4."""

import pytest

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import storage_audit as audit
from src.sysmanage_agent.backup import storage_fs

ZFS = {"/zfs-pool/backups/restate", "/tank", "/", "/var/lib/docker", "/home"}


@pytest.mark.parametrize("path", ["/srv/backups/restate", "/mnt/nas", "/var/backups/x"])
def test_the_usual_roots_are_accepted(path):
    assert v.storage_mount_point(path, lambda: ()) == path


@pytest.mark.parametrize("path", ["/zfs-pool/backups/restate", "/tank"])
def test_a_zfs_datasets_own_mount_point_is_accepted(path):
    assert v.storage_mount_point(path, lambda: ZFS) == path


@pytest.mark.parametrize(
    "path",
    ["/zfs-pool/backups/restate/sub",  # inside a dataset, not its mount point
     "/zfs-pool/elsewhere",            # not a dataset at all
     "/", "/var/lib/docker", "/home",  # root-on-ZFS system trees
     "/zfs-pool/../etc", "relative", "/a\nb"],
)  # fmt: skip
def test_anything_else_is_refused(path):
    with pytest.raises(v.PolicyError):
        v.storage_mount_point(path, lambda: ZFS)


def test_only_the_storage_role_widens(monkeypatch):
    target = {"mount_point": "/zfs-pool/backups/restate", "repo_dir": "h-1"}
    point, repository = v.check_target(
        "storage", target, mountinfo=lambda: "", realpath=lambda p: p,
        isdir=lambda p: True, zfs_mounts=lambda: ZFS,
    )  # fmt: skip
    assert repository == "/zfs-pool/backups/restate/h-1" and point.startswith("/zfs")
    with pytest.raises(v.PolicyError):
        v.check_target("host", target, mountinfo=lambda: "", realpath=lambda p: p,
                       isdir=lambda p: True, managed=True, zfs_mounts=lambda: ZFS)  # fmt: skip


def test_zfs_mount_points_come_from_the_mount_table():
    mountinfo = (
        "36 25 0:44 / /zfs-pool/backups/restate rw - zfs zfs-pool/backups/restate rw\n"
        "37 25 0:45 / /srv rw - ext4 /dev/sda1 rw\n"
    )
    found = storage_fs.zfs_mount_points(lambda path: mountinfo)
    assert found == {"/zfs-pool/backups/restate"}


def _run(answers):
    return lambda argv: answers.get(tuple(argv))


def test_nfsv4_is_read_from_rpcinfo_when_the_versions_file_is_root_only():
    run = _run({("systemctl", "is-active", "nfs-server"): "active",
                ("rpcinfo", "-p", "localhost"):
                "   100003    3   tcp   2049  nfs\n   100003    4   tcp   2049  nfs\n"})  # fmt: skip
    found = {
        f["code"]: f["level"] for f in audit._linux_baseline(run, lambda path: "")
    }  # pylint: disable=protected-access
    assert found["nfs_v4"] == "ok" and found["nfs_v4_only"] == "warning"


def test_the_versions_file_wins_when_readable():
    run = _run({("systemctl", "is-active", "nfs-server"): "active"})
    found = {
        f["code"]: f["level"]
        for f in audit._linux_baseline(run, lambda path: "-2 -3 +4 +4.1 +4.2")
    }  # pylint: disable=protected-access
    assert found["nfs_v4"] == "ok" and found["nfs_v4_only"] == "ok"


def test_unknown_is_a_warning_never_a_false_no_nfsv4():
    run = _run({("systemctl", "is-active", "nfs-server"): "active"})
    found = [
        f for f in audit._linux_baseline(run, lambda path: "") if f["code"] == "nfs_v4"
    ]  # pylint: disable=protected-access
    assert found[0]["level"] == "warning" and found[0]["params"]["checked"] is False
