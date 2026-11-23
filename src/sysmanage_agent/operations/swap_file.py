# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Give a small host the swap ClamAV needs (antivirus memory floor).

ClamAV's daemon keeps its whole signature database resident and briefly two
copies while it reloads; on a 2 GB host with no swap that took a machine down
(production, 2026-10-15).  So the server deploys it only where memory plus
swap clears a floor -- and, when the operator allows it, first asks this
module to add a swap file that closes the gap.

What it does, and refuses:

* **Where:** Linux and the BSDs only, never inside a container, on a local
  filesystem that takes a swap file: ext2/3/4 or XFS on Linux, UFS on
  FreeBSD, FFS on OpenBSD and NetBSD -- never ZFS or btrfs (their swap-file
  rules are not worth the risk here).  Of the candidate mount points (``/``,
  ``/var``, ``/home``, ``/usr``) the one with the most room is used, and only
  if it keeps a reserve free afterwards (``RESERVE_MB`` or a tenth of the
  filesystem, the larger).
* **How:** ``sysmanage.swap`` at that mount point, written with ``dd`` from
  ``/dev/zero`` (no holes -- a sparse swap file is refused by the kernel or,
  worse, silently unsafe), mode 0600, made swap and turned on at once, and
  listed in ``/etc/fstab`` so it comes back on every boot.  FreeBSD needs it
  through a memory disk (``md99 none swap sw,file=...,late``).
* **Idempotent:** a swap file of ours that is already there and listed is
  only turned on again; nothing is ever resized or replaced.

Every step is a fixed argv run with ``sudo -n`` (``doas -n`` on OpenBSD)
unless the agent is root;
the size is validated as a whole number of MB within bounds first.
"""

from __future__ import annotations

import os
import platform
import posixpath
import re
import subprocess  # nosec B404 -- fixed argvs, no shell
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.i18n import _

SWAP_NAME = "sysmanage.swap"
FSTAB = "/etc/fstab"
CANDIDATES = ("/", "/var", "/home", "/usr")
SUPPORTED_FS = {
    "Linux": {"ext2", "ext3", "ext4", "xfs"},
    "FreeBSD": {"ufs"},
    "OpenBSD": {"ffs"},
    "NetBSD": {"ffs"},
}
RESERVE_MB = 1024
RESERVE_FRACTION = 0.10
# Whole GB, 1 to 8: the sudoers rules spell out each allowed dd exactly.
MIN_SIZE_MB, MAX_SIZE_MB = 1024, 8192
FREEBSD_MD = "md99"


class SwapRefused(Exception):
    """The swap file cannot be added: ``code`` + why."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def check_size(value: Any) -> int:
    try:
        size = int(value)
    except (TypeError, ValueError) as error:
        raise SwapRefused(
            "invalid_request", _("The swap size must be a whole number of MB.")
        ) from error
    if not MIN_SIZE_MB <= size <= MAX_SIZE_MB or size % 1024:
        raise SwapRefused(
            "invalid_request",
            _("The swap size must be a whole number of GB from %(low)d to %(high)d MB.")
            % {"low": MIN_SIZE_MB, "high": MAX_SIZE_MB},
        )
    return size


# --- what the host has -------------------------------------------------------


def parse_linux_mounts(text: str) -> Dict[str, str]:
    """``{mount point: fstype}`` from /proc/self/mounts."""
    found = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            found[fields[1].replace("\\040", " ")] = fields[2]
    return found


_BSD_MOUNT = re.compile(r"^\S+ on (\S+) (?:type (\w+)|\((\w+))")


def parse_bsd_mounts(text: str) -> Dict[str, str]:
    """``{mount point: fstype}`` from ``mount``: ``/dev/sd0a on / type ffs
    (local)`` (OpenBSD, NetBSD) or ``/dev/ada0p2 on / (ufs, local)``
    (FreeBSD)."""
    found = {}
    for line in text.splitlines():
        match = _BSD_MOUNT.match(line.strip())
        if match:
            found[match.group(1)] = match.group(2) or match.group(3)
    return found


def choose_mount(
    system: str,
    size_mb: int,
    mounts: Dict[str, str],
    space: Callable[[str], Tuple[int, int]],
) -> str:
    """The candidate mount point that takes a ``size_mb`` swap file and keeps
    its reserve, with the most room; else SwapRefused saying why.
    ``space(mount)`` -> ``(total_mb, free_mb)``."""
    allowed = SUPPORTED_FS.get(system, set())
    usable = [m for m in CANDIDATES if mounts.get(m) in allowed]
    if not usable:
        kinds = sorted({mounts.get(m) for m in CANDIDATES if m in mounts} - {None})
        raise SwapRefused(
            "unsupported_filesystem",
            _("Swap files are not supported here (%s); add swap by hand.")
            % (", ".join(kinds) or _("no local filesystem")),
        )
    best, best_left = None, None
    for mount in usable:
        total, free = space(mount)
        left = free - size_mb
        reserve = max(RESERVE_MB, int(total * RESERVE_FRACTION))
        if left >= reserve and (best_left is None or left > best_left):
            best, best_left = mount, left
    if best is None:
        raise SwapRefused(
            "no_room",
            _("There is no room for a %d MB swap file that leaves enough space free.")
            % size_mb,
        )
    return best


def swap_path(mount: str) -> str:
    return posixpath.join(mount, SWAP_NAME)


def fstab_line(system: str, path: str) -> str:
    if system == "FreeBSD":
        return f"{FREEBSD_MD}\tnone\tswap\tsw,file={path},late\t0\t0"
    return f"{path}\tnone\tswap\tsw\t0\t0"


def listed(fstab_text: str, path: str) -> bool:
    for line in fstab_text.splitlines():
        if line.strip().startswith("#"):
            continue
        if path in line.split() or f"file={path}" in line:
            return True
    return False


def plan(system: str, path: str, size_mb: int, exists: bool) -> List[List[str]]:
    """The commands that make ``path`` swap and turn it on (``exists``: the
    file is already there -- only turned on)."""
    steps: List[List[str]] = []
    if not exists:
        # if= and of= LAST: dd honors the last of each, so a sudoers rule
        # whose count=* could swallow more arguments still writes only here.
        steps.append(
            ["dd", "bs=1048576", f"count={size_mb}", "if=/dev/zero", f"of={path}"]
        )
        steps.append(["chmod", "600", path])
        if system == "Linux":
            steps.append(["mkswap", path])
    if system == "Linux":
        steps.append(["swapon", path])
    elif system == "FreeBSD":
        steps.append(["swapon", "-aL"])
    else:
        steps.append(["swapctl", "-a", path])
    return steps


# --- running it ----------------------------------------------------------------


def _root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _elevated(argv: List[str]) -> List[str]:
    """sudo -n, or doas -n on OpenBSD (as backup/equip.py does)."""
    if _root():
        return list(argv)
    if platform.system() == "OpenBSD":
        return ["doas", "-n"] + list(argv)
    return ["sudo", "-n"] + list(argv)


def _run(argv: List[str], timeout: int = 1800) -> Tuple[int, str]:
    full = _elevated(argv)
    result = subprocess.run(  # nosec B603 -- fixed argv
        full, capture_output=True, text=True, timeout=timeout, check=False
    )
    return result.returncode, (result.stderr or result.stdout or "").strip()


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def _mounts(system: str) -> Dict[str, str]:
    if system == "Linux":
        return parse_linux_mounts(_read("/proc/self/mounts"))
    code, out = 0, ""
    try:
        result = subprocess.run(  # nosec B603 B607 -- fixed argv
            ["mount"], capture_output=True, text=True, timeout=30, check=False
        )
        code, out = result.returncode, result.stdout
    except (OSError, subprocess.SubprocessError):
        code = 1
    return parse_bsd_mounts(out) if code == 0 else {}


def _space(mount: str) -> Tuple[int, int]:
    stat = os.statvfs(mount)
    return (stat.f_blocks * stat.f_frsize) // 1048576, (
        stat.f_bavail * stat.f_frsize
    ) // 1048576


def in_container() -> bool:
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return True
    try:
        result = subprocess.run(  # nosec B603 B607 -- fixed argv
            ["systemd-detect-virt", "--container", "--quiet"],
            capture_output=True, timeout=10, check=False,
        )  # fmt: skip
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _add_to_fstab(system: str, path: str, install: Callable[[str], None]) -> bool:
    current = _read(FSTAB)
    if listed(current, path):
        return False
    text = current if current.endswith("\n") or not current else current + "\n"
    install(text + "# Added by SysManage for the antivirus memory floor\n"
            + fstab_line(system, path) + "\n")  # fmt: skip
    return True


def _install_fstab(text: str) -> None:
    """Write /etc/fstab root-owned 0644 through ``install`` (a temp file the
    agent owns, then installed in one step)."""
    # pylint: disable=import-outside-toplevel
    import tempfile

    handle, staged = tempfile.mkstemp(prefix=".sysmanage-fstab-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(text)
        code, err = _run(["install", "-m", "644", "-o", "0", "-g", "0", staged, FSTAB])
        if code != 0:
            raise SwapRefused(
                "command_failed", _("Could not update /etc/fstab: %s") % err
            )
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def ensure_swap(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Add (or turn back on) SysManage's swap file of ``size_mb`` MB."""
    system = platform.system()
    try:
        size = check_size((parameters or {}).get("size_mb"))
        if system not in SUPPORTED_FS:
            raise SwapRefused(
                "unsupported_os", _("Swap files are added only on Linux and the BSDs.")
            )
        if system == "OpenBSD" and not _root():
            # doas cannot limit dd's arguments, and an unlimited dd is root.
            raise SwapRefused(
                "needs_root",
                _("On OpenBSD a swap file is added only by an agent running as root."),
            )
        if system == "Linux" and in_container():
            raise SwapRefused(
                "container",
                _("This host is a container; its swap is the host machine's."),
            )
        mounts = _mounts(system)
        existing = next(
            (swap_path(m) for m in CANDIDATES if os.path.exists(swap_path(m))), None
        )
        path = existing or swap_path(choose_mount(system, size, mounts, _space))
        for argv in plan(system, path, size, exists=existing is not None):
            if argv[0] in ("swapon", "swapctl") and system != "Linux":
                _add_to_fstab(system, path, _install_fstab)  # BSD swapon reads it
            code, err = _run(argv)
            if code != 0 and not (existing and "busy" in err.lower()):
                raise SwapRefused("command_failed", f"{' '.join(argv)}: {err or code}")
        added = _add_to_fstab(system, path, _install_fstab)
        return {"success": True, "path": path, "size_mb": size,
                "created": existing is None, "fstab_added": added}  # fmt: skip
    except SwapRefused as refused:
        return {"success": False, "reason": refused.code, "error": str(refused)}
    except (OSError, subprocess.SubprocessError) as error:
        return {"success": False, "reason": "command_failed", "error": str(error)}


def remove_swap(_parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Turn off and remove SysManage's swap file and its fstab line."""
    system = platform.system()
    path = next(
        (swap_path(m) for m in CANDIDATES if os.path.exists(swap_path(m))), None
    )
    if path is None:
        return {"success": True, "removed": False}
    off = (
        ["swapoff", path] if system in ("Linux", "FreeBSD") else ["swapctl", "-d", path]
    )
    if system == "FreeBSD":
        off = ["swapoff", f"/dev/{FREEBSD_MD}"]
    _run(off)
    current = _read(FSTAB)
    kept = [line for line in current.splitlines()
            if path not in line and "Added by SysManage for the antivirus" not in line]  # fmt: skip
    if kept != current.splitlines():
        _install_fstab("\n".join(kept) + "\n")
    if system == "FreeBSD":
        _run(["mdconfig", "-d", "-u", FREEBSD_MD[2:]])
    code, err = _run(["rm", "-f", "--", path])
    if code != 0:
        return {"success": False, "reason": "command_failed", "error": err}
    return {"success": True, "removed": True, "path": path}
