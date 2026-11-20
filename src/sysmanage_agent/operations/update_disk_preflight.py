# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Refuse an update the disk cannot hold (2026-11-20).

Production: an update of 37 packages started on a host whose root had 1.3 MB
free.  dpkg unpacked part of it, ran out of room, and stopped -- leaving
systemd, libc and a kernel half-configured and the new kernel with no
initramfs, one reboot from not booting.  A failed update must fail BEFORE
it changes anything.

Before any package is touched, each filesystem a package manager writes to
-- the root, ``/var`` (package caches, snaps, the dpkg database), ``/usr``
and ``/usr/local`` (installed files), and ``/boot`` when a kernel is in the
batch (each kernel adds an initramfs) -- must have room.  Where they are one
filesystem it is checked once.  On Windows it is the system drive.  A path
that cannot be checked is skipped, never refused on.
"""

import os
import shutil
from typing import Any, Callable, Dict, List, Optional

from src.i18n import _

MIB = 1024 * 1024
# Free space an update must leave room for on each filesystem it writes to:
# a large batch (a kernel, systemd, a language runtime) needs a few hundred MB
# to download and unpack; the margin keeps the host usable afterwards.
MIN_FREE = 512 * MIB
# A kernel's initramfs and image are 50-100 MB each, and the old ones stay
# until autoremove.
MIN_FREE_BOOT = 256 * MIB
_UNIX_PATHS = ("/", "/var", "/usr", "/usr/local")
_KERNEL_PREFIXES = ("linux-image", "linux-modules", "kernel", "kernel-core")


def _has_kernel(packages: List[Dict[str, Any]]) -> bool:
    return any(
        str(package.get("name") or "").startswith(_KERNEL_PREFIXES)
        for package in packages
    )


def _paths(packages: List[Dict[str, Any]]) -> Dict[str, int]:
    """``{path: free bytes needed}`` for this batch on this platform."""
    if os.name == "nt":
        return {os.environ.get("SystemDrive", "C:") + "\\": MIN_FREE}
    wanted = {path: MIN_FREE for path in _UNIX_PATHS}
    if _has_kernel(packages):
        wanted["/boot"] = MIN_FREE_BOOT
    return wanted


def _human(size: int) -> str:
    if size >= 1024 * MIB:
        return f"{size / (1024 * MIB):.1f} GB"
    return f"{size / MIB:.0f} MB"


def shortage(
    packages: List[Dict[str, Any]],
    usage: Callable = shutil.disk_usage,
    device_of: Optional[Callable] = None,
) -> Optional[str]:
    """Why this batch must not start, or None when every filesystem it
    writes to has room."""
    if not packages:
        return None
    device_of = device_of or (lambda path: os.stat(path).st_dev)
    seen = set()
    for path, need in _paths(packages).items():
        try:
            if not os.path.isdir(path):
                continue
            device = device_of(path)
            free = usage(path).free
        except OSError:
            continue  # cannot check: never refuse on a guess
        if device in seen and path != "/boot":
            continue
        seen.add(device)
        if free < need:
            return _(
                "Not enough disk space: %(path)s has %(free)s free and this "
                "update needs at least %(need)s.  Nothing was changed; free "
                "some space or grow the disk, then update again."
            ) % {"path": path, "free": _human(free), "need": _human(need)}
    return None


def refused(packages: List[Dict[str, Any]], reason: str) -> List[Dict[str, Any]]:
    """Every package of the batch, reported back as failed with ``reason``."""
    return [
        {
            "package_name": package.get("name"),
            "package_manager": package.get("package_manager"),
            "error": reason,
        }
        for package in packages
    ]
