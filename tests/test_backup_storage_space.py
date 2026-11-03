# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The storage host measures how full its storage path is (24.8, 2026-11-03):
on ZFS the parent dataset holds almost nothing, every repository a child, so
statvfs read 0% while the pool filled."""

from types import SimpleNamespace

from src.sysmanage_agent.backup import storage_audit
from src.sysmanage_agent.backup import storage_space as space

# nas, 2026-11-03: zfs-pool/backups/restate refers 202 KB, used (with its
# children) 851 GB; the pool root used 6.56 TB, available 32.05 TB.
DATASET = "zfs-pool/backups/restate\t850697795904\t32047326434944\t0"
POOL = "6560134588800\t32047326434944"


def _runner(answers):
    calls = []

    def run(argv):
        calls.append(argv)
        for key, out in answers.items():
            if key in argv:
                return out
        return None

    return run, calls


def test_zfs_without_a_quota_is_measured_against_the_pool():
    run, calls = _runner({"/srv/backups/restate": DATASET, "zfs-pool": POOL})
    found = space.zfs_space("/srv/backups/restate", run=run, zfs="/sbin/zfs")
    assert found["total_bytes"] == 6560134588800 + 32047326434944
    assert found["available_bytes"] == 32047326434944
    assert found["backups_bytes"] == 850697795904
    used = (
        100.0 * (found["total_bytes"] - found["available_bytes"]) / found["total_bytes"]
    )
    assert round(used, 1) == 17.0  # not the 0% statvfs of the parent dataset
    assert calls[0] == ["/sbin/zfs", "list", "-Hp", "-o", "name,used,avail,quota",
                        "/srv/backups/restate"]  # fmt: skip


def test_zfs_with_a_quota_is_measured_against_the_quota():
    run, _ = _runner({"/srv/b": "pool/b\t900\t100\t1000"})
    found = space.zfs_space("/srv/b", run=run, zfs="zfs")
    assert (found["total_bytes"], found["available_bytes"]) == (1000, 100)


def test_not_zfs_or_no_zfs_answer_is_none(monkeypatch):
    run, _ = _runner({})
    assert space.zfs_space("/srv/b", run=run, zfs="zfs") is None
    monkeypatch.setattr(space, "zfs_binary", lambda: None)
    assert space.zfs_space("/srv/b", run=run) is None  # no zfs on this host


def test_other_filesystems_use_statvfs():
    st = SimpleNamespace(f_blocks=1000, f_frsize=4096, f_bavail=250)
    found = space.measure("/srv/b", "btrfs", statvfs=lambda p: st)
    assert found == {"filesystem": "btrfs", "total_bytes": 4096000,
                     "available_bytes": 1024000, "backups_bytes": None,
                     "path": "/srv/b"}  # fmt: skip


def test_a_zfs_path_zfs_cannot_measure_falls_back_to_statvfs():
    st = SimpleNamespace(f_blocks=10, f_frsize=1, f_bavail=5)
    run, _ = _runner({})
    found = space.measure("/srv/b", "zfs", run=run, statvfs=lambda p: st)
    assert found["total_bytes"] == 10 and found["filesystem"] == "zfs"


def test_the_audit_reports_the_storage_path_s_space(monkeypatch):
    monkeypatch.setattr(storage_audit.storage_fs, "describe",
                        lambda path, read_text: {"type": "zfs"})  # fmt: skip
    seen = {}

    def measure(path, fstype):
        seen["args"] = (path, fstype)
        return {"total_bytes": 10, "available_bytes": 4, "path": path}

    found = storage_audit.space_findings("/srv/backups/restate/h-1", lambda p: None,
                                         measure=measure)  # fmt: skip
    assert seen["args"] == ("/srv/backups/restate", "zfs")
    assert found == [{"code": "storage_space", "level": "ok",
                      "params": {"total_bytes": 10, "available_bytes": 4,
                                 "path": "/srv/backups/restate"}}]  # fmt: skip
