# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""How full is the storage the backups live on? (24.8, fixed 2026-11-03)

The server used to read it from the host's disk inventory -- ``statvfs`` of
the mount point holding the storage path.  On ZFS that is wrong twice over:
every repository is a CHILD dataset, so the storage path's own dataset holds
almost nothing (202 KB on nas against 851 GB beneath it) and read 0% used,
and nas's inventory carried no sizes for its datasets at all.  A filling
pool could never raise "storage space low" and the forecast read the same.

So the storage host measures the storage path itself, with every storage
audit:

* ZFS: ``zfs list -Hp`` of the dataset at the path.  With a quota, that
  quota is the limit (``used`` counts every child); without one, the limit
  is the pool -- its root dataset's ``used`` + ``available`` -- and what is
  left is this dataset's ``available`` (reservations and the pool's other
  datasets taken into account by ZFS itself).
* anything else (btrfs, ext4, UFS, ...): ``statvfs`` of the path, which is
  what the filesystem itself says is free.
"""

import os
import shutil
import subprocess  # nosec B404 -- fixed argv, no shell
from typing import Any, Callable, Dict, List, Optional

TIMEOUT = 10
_ZFS_CANDIDATES = ("/sbin/zfs", "/usr/sbin/zfs", "/usr/local/sbin/zfs")


def _run(argv: List[str]) -> Optional[str]:
    try:
        done = subprocess.run(  # nosec B603 -- fixed argv
            argv, capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def zfs_binary() -> Optional[str]:
    found = shutil.which("zfs")
    if found:
        return found
    for path in _ZFS_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def _ints(line: str) -> Optional[List[str]]:
    parts = line.split("\t")
    return parts if parts and all(p.strip() for p in parts) else None


def zfs_space(
    path: str, run: Callable = _run, zfs: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """The space for the dataset mounted at ``path``, measured the ZFS way;
    None when ``path`` is not a ZFS dataset or zfs cannot say."""
    zfs = zfs or zfs_binary()
    if not zfs:
        return None
    out = run([zfs, "list", "-Hp", "-o", "name,used,avail,quota", path])
    parts = _ints((out or "").splitlines()[0]) if out else None
    if not parts or len(parts) != 4:
        return None
    try:
        name = parts[0]
        used, avail, quota = int(parts[1]), int(parts[2]), int(parts[3])
    except ValueError:
        return None
    if quota > 0:
        total = quota
    else:
        pool = name.split("/", 1)[0]
        root = run([zfs, "list", "-Hp", "-o", "used,avail", pool])
        rparts = _ints((root or "").splitlines()[0]) if root else None
        try:
            total = (
                int(rparts[0]) + int(rparts[1])
                if rparts and len(rparts) == 2
                else used + avail
            )
        except ValueError:
            total = used + avail
    return {
        "filesystem": "zfs",
        "dataset": name,
        "total_bytes": total,
        "available_bytes": min(avail, total),
        "backups_bytes": used,
    }


def statvfs_space(
    path: str, statvfs: Callable = os.statvfs
) -> Optional[Dict[str, Any]]:
    try:
        st = statvfs(path)
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    if not total:
        return None
    return {
        "filesystem": None,
        "total_bytes": total,
        "available_bytes": st.f_bavail * st.f_frsize,
        "backups_bytes": None,
    }


def measure(path: str, fstype: Optional[str], run: Callable = _run,
            statvfs: Callable = os.statvfs) -> Optional[Dict[str, Any]]:  # fmt: skip
    """The storage path's space: ZFS-aware where it is ZFS, else statvfs."""
    if not path:
        return None
    if fstype == "zfs":
        found = zfs_space(path, run=run)
        if found:
            return dict(found, path=path)
    found = statvfs_space(path, statvfs=statvfs)
    if found:
        found = dict(found, path=path, filesystem=fstype or found["filesystem"])
    return found
