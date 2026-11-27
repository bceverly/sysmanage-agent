# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Which kernel is running, and which ones are installed (ROADMAP 27.8).

The distribution's own "reboot required" flag (``/var/run/reboot-required``
on Debian and Ubuntu) is written by a package hook and removed by whatever
clears ``/run``; production had a host running a kernel twelve builds behind
the newest one installed with no flag at all (2026-11-27).  So the kernels
themselves decide: a newer kernel installed than the one running means the
host needs a reboot to be protected by it.

The running release also goes to the server with every heartbeat, where it
builds the boot history that proves a kernel boots (the old-kernel cleanup
never removes the last proven kernel) and tells the vulnerability scan which
installed kernel is actually in use.
"""

import glob
import os
import platform
import re
from typing import List, Optional, Tuple

# A Linux kernel release starts "major.minor"; anything else in /boot
# (vmlinuz-linux on Arch, vmlinuz.old symlinks) names no version.
_RELEASE = re.compile(r"^\d+\.\d+")
_TOKEN = re.compile(r"\d+|[^\d]+")


def running_release() -> str:
    """The running kernel's release (``uname -r``)."""
    return platform.release()


def version_key(release: str) -> Tuple:
    """Sort key for a kernel release: its numbers in order, so 6.8.0-151
    sorts after 6.8.0-99 and 6.8 after 5.15.  The flavor (``-generic``)
    does not order anything."""
    parts = []
    for token in _TOKEN.findall(release or ""):
        if token.isdigit():
            parts.append(int(token))
        elif parts and any(c.isalpha() for c in token):
            break  # the first word after the numbers is the flavor
    return tuple(parts)


def installed_releases(
    boot_dir: str = "/boot", modules_dir: str = "/usr/lib/modules"
) -> List[str]:
    """Every kernel release with an image installed, newest first.  Reads
    ``/boot/vmlinuz-<release>`` (Debian, Ubuntu, RHEL, SUSE) and
    ``/usr/lib/modules/<release>/vmlinuz`` (Arch, Fedora's packaged copy)."""
    found = set()
    for path in glob.glob(os.path.join(boot_dir, "vmlinuz-*")):
        release = os.path.basename(path)[len("vmlinuz-") :]
        if _RELEASE.match(release) and os.path.isfile(path):
            found.add(release)
    for path in glob.glob(os.path.join(modules_dir, "*", "vmlinuz")):
        release = os.path.basename(os.path.dirname(path))
        if _RELEASE.match(release):
            found.add(release)
    return sorted(found, key=version_key, reverse=True)


def newer_kernel(
    running: Optional[str] = None, installed: Optional[List[str]] = None
) -> Optional[str]:
    """The newest installed kernel when it is newer than the running one,
    else None.  Linux only; elsewhere the kernel is part of the OS update."""
    if platform.system() != "Linux":
        return None
    running = running or running_release()
    installed = installed_releases() if installed is None else installed
    if not installed or not running:
        return None
    newest = installed[0]
    if version_key(newest) > version_key(running):
        return newest
    return None
