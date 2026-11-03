# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The storage host backs itself up (server ROADMAP 24.13).

Its repository is a path on its own pool, written locally, and its capture
must record the operating system but NEVER the backups it keeps, or the
pool's other data (case files, archives).  restate's ``one_file_system``
cannot say that on its own: on a root-on-ZFS system (FreeBSD's default,
``zroot``) ``/usr/home``, ``/var/log`` and ``/tmp`` are datasets of their own,
and it would leave those out too.  So the agent leaves out, by rule:

* the storage path and everything under it (every host's repository,
  including this one's own);
* every ZFS dataset of a pool other than the one ``/`` is on -- with the OS
  on ext4 (nas, 2026-11-01) that is every dataset; on root-on-ZFS, the data
  pools;
* caches that rebuild themselves, such as an L2ARC backing file
  (``/var/lib/zfs-l2arc``, 120 GB on nas).

The points are written as a rules file of the policy's own (the same shape
as the network-mount rules) and refreshed before each capture.
"""

import posixpath
import subprocess  # nosec B404 - fixed argv, no shell
from typing import Dict, Iterable, List, NamedTuple, Optional, Tuple

from src.sysmanage_agent.backup import network_mounts

# Rebuildable by the system itself, never worth a backup.
REBUILDABLE = ("/var/lib/zfs-l2arc",)
_VIRTUAL = ("/proc", "/sys", "/dev", "/run")


class Mount(NamedTuple):
    point: str
    fstype: str
    source: str


def _unescape(field: str) -> str:
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and field[i + 1 : i + 4].isdigit():
            out.append(chr(int(field[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def linux_mounts(mountinfo: str) -> List[Mount]:
    """``/proc/<pid>/mountinfo``: the point (field 5), and after `` - `` the
    type and source (a ZFS mount's source is its dataset)."""
    found = []
    for line in (mountinfo or "").splitlines():
        before, sep, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if not sep or len(fields) < 5 or len(tail) < 2:
            continue
        found.append(Mount(_unescape(fields[4]), tail[0], _unescape(tail[1])))
    return found


def bsd_mounts(mount_p: str) -> List[Mount]:
    """``mount -p`` (fstab format): ``source point type options ...``."""
    found = []
    for line in (mount_p or "").splitlines():
        fields = line.split()
        if len(fields) >= 3:
            found.append(Mount(fields[1], fields[2], fields[0]))
    return found


def read_mounts(system: str) -> List[Mount]:
    """This machine's mounts: the host's mountinfo on Linux, ``mount -p`` on
    the BSDs (which have no /proc)."""
    if system == "Linux":
        return linux_mounts(network_mounts.read_host_mountinfo())
    try:
        out = subprocess.run(  # nosec B603 B607 - fixed argv
            ["mount", "-p"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return bsd_mounts(out.stdout)


def _under(path: str, root: str) -> bool:
    root = posixpath.normpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _pool(source: str) -> str:
    return source.split("/", 1)[0]


def leave_out(
    mounts: Iterable[Mount],
    storage_path: str,
    exists=posixpath.exists,
) -> List[str]:
    """The paths a self-backup must leave out, sorted (see the module)."""
    mounts = list(mounts)
    by_point: Dict[str, Mount] = {posixpath.normpath(m.point): m for m in mounts}
    root = by_point.get("/")
    root_pool: Optional[str] = (
        _pool(root.source) if root is not None and root.fstype == "zfs" else None
    )
    storage = posixpath.normpath(storage_path)
    points = {storage}
    for point, mount in by_point.items():
        if mount.fstype != "zfs" or point == "/" or _under(point, storage):
            continue
        if any(_under(point, tree) for tree in _VIRTUAL):
            continue
        if root_pool is None or _pool(mount.source) != root_pool:
            points.add(point)
    points.update(p for p in REBUILDABLE if exists(p))
    # Nothing nested under a point already left out.
    kept: List[str] = []
    for point in sorted(points):
        if not any(_under(point, other) for other in kept):
            kept.append(point)
    return kept


def rules_text(points: Iterable[str]) -> Tuple[str, List[str]]:
    """``(rules file, points it could not express)``."""
    text, skipped = network_mounts.rules_text(points)
    header = (
        "# Written by sysmanage-agent: the storage host's own backup leaves out\n"
        "# the backups it keeps, its data pools and rebuildable caches.\n"
        "# Replaced at every configure and before every capture.\n"
    )
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    return header + body + ("\n" if body else ""), skipped
