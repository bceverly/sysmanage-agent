# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Would this host come back if it rebooted now?  And get it ready first.

Production, 2026-11-19: an "update all" upgraded the agent in the same apt
run as a new kernel; the agent's restart took its private temporary
directory away mid-run, so the kernel's postinst could not build the
initramfs (mktemp failed there) and three hosts were left with a half-configured kernel and "reboot required" -- one
reboot from booting a kernel with no initramfs.

Two things make a reboot unsafe, and both are read unprivileged:

* a package that is part of booting (the kernel and its modules, the
  initramfs tools, the boot loader) is part-way installed, per the package
  manager's health check (collection/package_manager_health.py);
* an installed kernel has no initramfs, on a system that uses one (some other
  kernel in /boot has one, or the distribution always does) -- this catches a
  broken boot even when the package manager looks finished.

:func:`prepare_for_reboot` is what the agent does before every reboot: refuse
while a package manager is running (its work is not finished, and a reboot
would interrupt it), finish what an earlier run left part-way (the same
repair as "Repair package manager": ``dpkg --configure -a`` then
``apt-get install -f``), check again, and only then let the reboot go ahead.
"""

import os
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from src.i18n import _
from src.sysmanage_agent.collection import package_manager_health as health

BOOT_DIR = "/boot"
# Package names (dpkg and rpm) whose half-finished state can stop a boot.
_BOOT_PACKAGES = re.compile(
    r"^(linux-image-|linux-modules-|linux-signed-|kernel(-core|-modules)?($|-)|"
    r"initramfs-tools|dracut|grub|shim|systemd-boot|mkinitcpio|"
    r"linux-firmware)"
)
# Processes that mean a package manager is at work right now.
_PACKAGE_PROCESSES = frozenset({
    "apt", "apt-get", "aptitude", "dpkg", "unattended-upgr", "unattended-upgrade",
    "dnf", "yum", "rpm", "zypper", "pacman", "pkg", "apk",
})  # fmt: skip
# Distributions whose kernels always boot with an initramfs.
_ALWAYS_INITRAMFS = ("ubuntu", "debian", "rhel", "centos", "fedora", "rocky",
                     "almalinux", "ol", "amzn", "opensuse", "sles")  # fmt: skip


def boot_packages(names: Iterable[str]) -> List[str]:
    """The packages among ``names`` that are part of booting."""
    return [name for name in names if _BOOT_PACKAGES.match(name)]


def _os_ids(path: str = "/etc/os-release") -> List[str]:
    try:
        with open(path, encoding="utf-8") as release:
            text = release.read()
    except OSError:
        return []
    ids = []
    for line in text.splitlines():
        if line.startswith(("ID=", "ID_LIKE=")):
            ids += line.split("=", 1)[1].strip().strip('"').lower().split()
    return ids


def _initramfs_names(version: str) -> List[str]:
    """What an initramfs for kernel ``version`` is called: Debian / Ubuntu,
    Red Hat / Fedora / SUSE, Arch, Alpine."""
    return [
        f"initrd.img-{version}",
        f"initramfs-{version}.img",
        f"initrd-{version}",
        f"initramfs-{version}",
    ]


def kernels_without_initramfs(
    boot_dir: str = BOOT_DIR,
    listdir: Callable[[str], List[str]] = os.listdir,
    os_ids: Optional[List[str]] = None,
) -> List[str]:
    """Kernel versions in ``boot_dir`` that have no initramfs, on a system that
    uses one; empty where /boot cannot be read or nothing uses an initramfs
    (a kernel built with everything in it needs none)."""
    try:
        entries = set(listdir(boot_dir))
    except OSError:
        return []
    versions = sorted(
        name[len("vmlinuz-"):] for name in entries
        if name.startswith("vmlinuz-") and "rescue" not in name
    )  # fmt: skip
    missing, with_one = [], 0
    for version in versions:
        if any(name in entries for name in _initramfs_names(version)):
            with_one += 1
        else:
            missing.append(version)
    ids = _os_ids() if os_ids is None else os_ids
    uses_initramfs = with_one > 0 or any(i in _ALWAYS_INITRAMFS for i in ids)
    return missing if uses_initramfs else []


# Always running and idle: Ubuntu's unattended-upgrade-shutdown waits for a
# shutdown signal all day (its process name is "unattended-upgr" too).
_IDLE_COMMANDS = ("unattended-upgrade-shutdown",)


def package_manager_running(
    processes: Optional[Callable[[], Iterable[Tuple[str, str]]]] = None,
) -> Optional[str]:
    """The name of a package manager process at work now, or None.
    ``processes`` yields ``(name, command line)``."""
    for name, command in processes() if processes else _processes():
        if name in _PACKAGE_PROCESSES and not any(
            idle in command for idle in _IDLE_COMMANDS
        ):
            return name
    return None


def _processes() -> Iterable[Tuple[str, str]]:
    try:
        import psutil  # pylint: disable=import-outside-toplevel
    except ImportError:  # pragma: no cover - psutil is a runtime dependency
        return []
    found = []
    for proc in psutil.process_iter(["name", "cmdline"]):
        try:
            name = (proc.info.get("name") or "").lower()
            command = " ".join(proc.info.get("cmdline") or [])
        except (psutil.Error, AttributeError, TypeError):  # pragma: no cover
            continue
        found.append((name, command))
    return found


def assess(
    pm_health: Optional[Dict[str, Any]] = None,
    unfinished: Optional[List[str]] = None,
    missing: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """``{"reboot_unsafe", "reboot_unsafe_reason"}`` from the package
    manager's health, its part-way packages and the kernels with no
    initramfs."""
    if unfinished is None:
        unfinished = (
            health.unfinished_packages()
            if (pm_health or {}).get("manager") == "dpkg"
            else []
        )
    if missing is None:
        missing = kernels_without_initramfs()
    booting = boot_packages(unfinished)
    reason = None
    if booting:
        reason = _(
            "Not safe to reboot: %s is only partly installed, so the host may "
            "not boot. Repair the package manager first."
        ) % ", ".join(booting[:3])
    elif missing:
        reason = _(
            "Not safe to reboot: kernel %s has no initramfs, so the host may "
            "not boot. Repair the package manager first."
        ) % ", ".join(missing[:3])
    return {"reboot_unsafe": reason is not None, "reboot_unsafe_reason": reason}


def with_reboot_safety(pm_health: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The package manager's health as reported to the server, with whether a
    reboot is safe now; never raises (a failed assessment reports nothing
    about reboots, as an older agent would)."""
    if not isinstance(pm_health, dict):
        return pm_health
    try:
        return {**pm_health, **assess(pm_health)}
    except Exception:  # pylint: disable=broad-except
        return pm_health


def prepare_for_reboot(
    check: Callable[[], Dict[str, Any]] = health.check,
    repair: Callable[[], Dict[str, Any]] = health.repair,
    running: Callable[[], Optional[str]] = package_manager_running,
    judge: Callable[[Dict[str, Any]], Dict[str, Any]] = assess,
) -> Dict[str, Any]:
    """Get the host ready to reboot.  ``{"ok", "reason", "repaired",
    "output"}``: ``ok`` False means do NOT reboot, for ``reason``."""
    busy = running()
    if busy:
        return {
            "ok": False,
            "reason": _(
                "Not rebooting: a package manager (%s) is running. Reboot "
                "when it has finished."
            )
            % busy,
            "repaired": False,
            "output": "",
        }
    state = check()
    repaired, output = False, ""
    if state.get("needs_repair") and state.get("repairable"):
        fixed = repair()
        repaired, output = True, fixed.get("output", "")
        state = fixed.get("health") or check()
    verdict = judge(state)
    if verdict["reboot_unsafe"]:
        return {
            "ok": False,
            "reason": verdict["reboot_unsafe_reason"],
            "repaired": repaired,
            "output": output,
        }
    return {"ok": True, "reason": None, "repaired": repaired, "output": output}
