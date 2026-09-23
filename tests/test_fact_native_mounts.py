# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""``mounts`` capacity: measured where it is safe, NULL where it is not.

Until 2026-09-23 every block/inode column was NULL, and the Phase 21.2 S0
spike showed the cost: "filesystem more than 90% full" answered "does not
fire" on a real host whose capacity had never been read. The reason they were
NULL still stands -- a statvfs on an unreachable network mount blocks -- so
the property under test is two-sided: local types are measured, network and
FUSE types are NEVER touched.
"""

# pylint: disable=protected-access

import os
from collections import namedtuple
from unittest.mock import patch

from src.sysmanage_agent.collection import fact_native as fn

StatVFS = namedtuple(
    "StatVFS", "f_bsize f_frsize f_blocks f_bfree f_bavail f_files f_ffree"
)
ROOT = StatVFS(4096, 4096, 1000, 400, 300, 5000, 4000)


def test_local_filesystem_is_measured_the_way_osquery_reports_it():
    with patch.object(os, "statvfs", return_value=ROOT, create=True) as statvfs:
        cap = fn._mount_capacity("/", "ext4")
    statvfs.assert_called_once_with("/")
    assert cap == {
        "blocks_size": 4096,
        "blocks": 1000,
        "blocks_free": 400,
        "blocks_available": 300,
        "inodes": 5000,
        "inodes_free": 4000,
    }


def test_blocks_size_is_the_unit_blocks_are_counted_in():
    # BSD/macOS statvfs: f_bsize is the preferred I/O size, f_frsize the unit
    # of f_blocks. blocks * blocks_size must be bytes.
    bsd = StatVFS(32768, 4096, 1000, 400, 300, 5000, 4000)
    with patch.object(os, "statvfs", return_value=bsd, create=True):
        cap = fn._mount_capacity("/", "ufs")
    assert cap["blocks_size"] == 4096


def test_network_and_fuse_mounts_are_never_touched():
    with patch.object(os, "statvfs", create=True) as statvfs:
        for fstype in ("nfs", "nfs4", "cifs", "smbfs", "fuse.sshfs", "autofs", "9p"):
            assert fn._mount_capacity("/mnt/x", fstype) == {}
    statvfs.assert_not_called()


def test_unknown_or_missing_type_is_not_guessed_safe():
    with patch.object(os, "statvfs", create=True) as statvfs:
        assert fn._mount_capacity("/mnt/x", None) == {}
        assert fn._mount_capacity("/mnt/x", "somethingnew") == {}
        assert fn._mount_capacity(None, "ext4") == {}
    statvfs.assert_not_called()


def test_an_unreadable_mount_is_unmeasured_not_zero():
    with patch.object(os, "statvfs", side_effect=PermissionError, create=True):
        assert fn._mount_capacity("/run/user/1000/doc", "tmpfs") == {}


def test_build_mounts_carries_capacity_on_its_rows():
    Part = namedtuple("Part", "device mountpoint fstype opts")
    parts = [
        Part("/dev/sda1", "/", "ext4", "rw"),
        Part("server:/export", "/mnt/nfs", "nfs4", "rw"),
    ]
    with patch("psutil.disk_partitions", return_value=parts), patch.object(
        os, "statvfs", return_value=ROOT, create=True
    ):
        rows = {r["path"]: r for r in fn.build_mounts()}
    assert rows["/"]["blocks"] == 1000
    assert "blocks" not in rows["/mnt/nfs"]  # absent -> NULL in the fact store
