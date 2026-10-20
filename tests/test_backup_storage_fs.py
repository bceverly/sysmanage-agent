# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Which filesystem the storage host keeps repositories on (24.5): the server
warns when it cannot take snapshots, and flags a seal mode that cannot work."""

from types import SimpleNamespace

from src.sysmanage_agent.backup import storage_fs

MOUNTINFO = "\n".join(
    [
        "22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw",
        "40 22 8:17 / /srv rw,relatime - btrfs /dev/sdb1 rw,subvol=/",
        "41 40 0:44 / /srv/zpool rw - zfs tank/backups rw",
    ]
)


def _describe(path, ino=256, text=MOUNTINFO):
    return storage_fs.describe(
        path,
        read_text=lambda p: text if p == "/proc/self/mountinfo" else None,
        stat=lambda p: SimpleNamespace(st_ino=ino),
    )


def test_the_deepest_mount_wins():
    assert _describe("/srv/zpool/restate")["type"] == "zfs"
    assert _describe("/srv/zpool/restate")["mount_point"] == "/srv/zpool"
    assert _describe("/var/backups/restate")["type"] == "ext4"


def test_a_prefix_that_is_not_a_path_component_does_not_match():
    text = (
        "22 1 8:2 / / rw - ext4 /dev/sda2 rw\n40 22 8:17 / /srv rw - btrfs /dev/sdb1 rw"
    )
    assert _describe("/srvx/restate", text=text)["mount_point"] == "/"


def test_btrfs_reports_whether_the_path_is_a_subvolume_root():
    assert _describe("/srv/backups/restate", ino=256)["btrfs_subvolume"] is True
    assert _describe("/srv/backups/restate", ino=8123)["btrfs_subvolume"] is False


def test_btrfs_subvolume_is_false_when_the_path_cannot_be_read():
    def boom(_path):
        raise OSError("gone")

    result = storage_fs.describe(
        "/srv/backups/restate",
        read_text=lambda p: MOUNTINFO if p == "/proc/self/mountinfo" else None,
        stat=boom,
    )
    assert result["btrfs_subvolume"] is False


def test_non_btrfs_does_not_claim_a_subvolume():
    assert _describe("/var/backups/restate")["btrfs_subvolume"] is None


def test_unknown_when_there_is_no_mount_table(monkeypatch):
    monkeypatch.setattr(storage_fs.platform, "system", lambda: "OpenBSD")
    result = storage_fs.describe("/srv/backups", read_text=lambda p: None)
    assert result == {
        "type": None,
        "mount_point": None,
        "path": "/srv/backups",
        "btrfs_subvolume": None,
    }


def test_freebsd_mount_p_is_parsed():
    text = "/dev/ada0p2 / ufs rw 1 1\ntank/backups /srv/backups zfs rw 0 0\n"
    mounts = storage_fs.bsd_mount_types(text)
    assert mounts == {"/": "ufs", "/srv/backups": "zfs"}
    assert storage_fs.deepest_mount("/srv/backups/restate", mounts) == "/srv/backups"
