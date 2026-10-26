# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Which filesystem the storage host keeps the repositories on (24.5).

Sealing a backup against a compromised host needs a filesystem that can take
snapshots -- ZFS or btrfs.  Backups work on anything (a big ext4 volume is
fine), but the server warns when the storage path cannot be sealed, and flags
a seal mode that cannot work there.  So the storage host's agent reports, in
its ``backup_configure`` reply, the filesystem type and mount of the storage
path, and for btrfs whether that path is a subvolume root (only a subvolume
can be snapshotted).

Read-only: the mount table and a ``stat``; nothing here needs root.
"""

import os
import posixpath
import platform
import subprocess  # nosec B404
from typing import Any, Callable, Dict, Optional

from src.sysmanage_agent.backup.job_validation import mount_types

# A btrfs subvolume's root directory always has inode number 256.
BTRFS_SUBVOLUME_ROOT_INODE = 256


def bsd_mount_types(text: str) -> Dict[str, str]:
    """``{mount point: type}`` from FreeBSD's ``mount -p`` (fstab format)."""
    found = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            found[fields[1]] = fields[2]
    return found


def deepest_mount(path: str, mounts: Dict[str, str]) -> Optional[str]:
    """The mount point that contains ``path`` most specifically."""
    best = None
    for point in mounts:
        inside = path == point or path.startswith(point.rstrip("/") + "/")
        if inside and (best is None or len(point) > len(best)):
            best = point
    return best


def _mount_table(read_text: Callable[[str], Optional[str]]) -> Dict[str, str]:
    text = read_text("/proc/self/mountinfo")
    if text:
        return mount_types(text)
    if platform.system() == "FreeBSD":
        try:
            done = subprocess.run(  # nosec B603 B607
                ["mount", "-p"], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        return bsd_mount_types(done.stdout) if done.returncode == 0 else {}
    return {}


def zfs_mount_points(read_text: Callable[[str], Optional[str]]) -> set:
    """Where this host's ZFS datasets are mounted (the mount table only)."""
    return {point for point, kind in _mount_table(read_text).items() if kind == "zfs"}


def describe(
    path: str,
    *,
    read_text: Callable[[str], Optional[str]],
    stat: Callable[[str], Any] = os.stat,
) -> Dict[str, Any]:
    """``{"type", "mount_point", "path", "btrfs_subvolume"}``; None where unknown."""
    path = posixpath.normpath(path)
    mounts = _mount_table(read_text)
    point = deepest_mount(path, mounts)
    fstype = mounts.get(point) if point else None
    subvolume = None
    if fstype == "btrfs":
        try:
            subvolume = stat(path).st_ino == BTRFS_SUBVOLUME_ROOT_INODE
        except OSError:
            subvolume = False
    return {
        "type": fstype,
        "mount_point": point,
        "path": path,
        "btrfs_subvolume": subvolume,
    }


# statx(2) ``stx_attributes`` bits for the inode flags ``chattr`` sets.
ATTR_IMMUTABLE = 0x10
ATTR_APPEND = 0x20
_AT_FDCWD = -100
_AT_SYMLINK_NOFOLLOW = 0x100
_STATX_SIZE = 256
_STX_ATTRIBUTES, _STX_ATTRIBUTES_MASK = 8, 56


def file_attributes(path: str) -> Optional[int]:
    """The inode flags (``ATTR_*``) of ``path`` itself, from statx(2): read
    without opening it, so the agent needs no access to a 0770 directory.
    None off Linux, or when the filesystem does not report them."""
    if platform.system() != "Linux":
        return None
    import ctypes  # pylint: disable=import-outside-toplevel
    import struct  # pylint: disable=import-outside-toplevel

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        buf = ctypes.create_string_buffer(_STATX_SIZE)
        if libc.statx(_AT_FDCWD, os.fsencode(path), _AT_SYMLINK_NOFOLLOW, 0, buf):
            return None
    except (OSError, AttributeError):  # no statx (glibc < 2.28)
        return None
    (attributes,) = struct.unpack_from("=Q", buf, _STX_ATTRIBUTES)
    (supported,) = struct.unpack_from("=Q", buf, _STX_ATTRIBUTES_MASK)
    if not supported & (ATTR_APPEND | ATTR_IMMUTABLE):
        return None
    return attributes & supported
