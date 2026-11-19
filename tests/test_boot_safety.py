# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Would this host come back if it rebooted now (2026-11-19)?  Production:
three hosts were left with a half-configured kernel and no initramfs, one
reboot away from not booting."""

from src.sysmanage_agent.collection import boot_safety


def _boot(*names):
    return lambda _path: list(names)


# --- which packages are part of booting -------------------------------------


def test_boot_packages_are_the_kernel_initramfs_and_loader():
    names = [
        "linux-image-7.0.0-44-generic", "linux-modules-7.0.0-44-generic",
        "kernel-core", "kernel", "initramfs-tools", "dracut", "grub-efi-amd64",
        "shim-signed", "openjdk-25-jre", "linux-headers-generic", "kernelshark",
    ]  # fmt: skip
    assert boot_safety.boot_packages(names) == names[:8]


# --- kernels with no initramfs ----------------------------------------------


def test_a_kernel_with_no_initramfs_is_found():
    boot = _boot(
        "vmlinuz-7.0.0-43-generic", "initrd.img-7.0.0-43-generic",
        "vmlinuz-7.0.0-44-generic",
    )  # fmt: skip
    assert boot_safety.kernels_without_initramfs(listdir=boot, os_ids=[]) == [
        "7.0.0-44-generic"
    ]


def test_red_hat_arch_and_alpine_names_count():
    boot = _boot(
        "vmlinuz-6.12.0-55.el10.x86_64", "initramfs-6.12.0-55.el10.x86_64.img",
        "vmlinuz-linux", "initramfs-linux.img",
        "vmlinuz-lts", "initramfs-lts",
        "vmlinuz-0-rescue-abc",
    )  # fmt: skip
    assert boot_safety.kernels_without_initramfs(listdir=boot, os_ids=[]) == []


def test_a_system_that_boots_without_an_initramfs_is_left_alone():
    """Gentoo-style: no kernel has one, and the distribution needs none."""
    boot = _boot("vmlinuz-6.6.1-gentoo")
    assert boot_safety.kernels_without_initramfs(listdir=boot, os_ids=["gentoo"]) == []


def test_ubuntu_always_needs_one():
    boot = _boot("vmlinuz-7.0.0-44-generic")
    assert boot_safety.kernels_without_initramfs(
        listdir=boot, os_ids=["ubuntu", "debian"]
    ) == ["7.0.0-44-generic"]


def test_an_unreadable_boot_says_nothing():
    def refuse(_path):
        raise PermissionError("no")

    assert (
        boot_safety.kernels_without_initramfs(listdir=refuse, os_ids=["ubuntu"]) == []
    )


# --- the verdict ------------------------------------------------------------


def test_a_half_configured_kernel_is_unsafe():
    verdict = boot_safety.assess(
        {"manager": "dpkg"}, unfinished=["linux-image-7.0.0-44-generic"], missing=[]
    )
    assert verdict["reboot_unsafe"] is True
    assert "linux-image-7.0.0-44-generic" in verdict["reboot_unsafe_reason"]


def test_a_missing_initramfs_is_unsafe_even_when_dpkg_is_done():
    verdict = boot_safety.assess(
        {"manager": "dpkg"}, unfinished=[], missing=["7.0.0-44-generic"]
    )
    assert verdict["reboot_unsafe"] is True
    assert "initramfs" in verdict["reboot_unsafe_reason"]


def test_an_unfinished_ordinary_package_does_not_stop_a_reboot():
    verdict = boot_safety.assess(
        {"manager": "dpkg"}, unfinished=["openjdk-25-jre"], missing=[]
    )
    assert verdict == {"reboot_unsafe": False, "reboot_unsafe_reason": None}


def test_the_report_carries_the_verdict(monkeypatch):
    monkeypatch.setattr(
        boot_safety,
        "assess",
        lambda _h: {"reboot_unsafe": True, "reboot_unsafe_reason": "x"},
    )
    out = boot_safety.with_reboot_safety({"manager": "dpkg", "needs_repair": True})
    assert out == {"manager": "dpkg", "needs_repair": True,
                   "reboot_unsafe": True, "reboot_unsafe_reason": "x"}  # fmt: skip
    assert boot_safety.with_reboot_safety(None) is None


def test_a_failed_assessment_reports_nothing_about_reboots(monkeypatch):
    def boom(_h):
        raise RuntimeError("no /boot")

    monkeypatch.setattr(boot_safety, "assess", boom)
    assert boot_safety.with_reboot_safety({"manager": "dpkg"}) == {"manager": "dpkg"}


# --- getting ready to reboot ------------------------------------------------


def test_a_running_package_manager_stops_the_reboot():
    calls = []
    out = boot_safety.prepare_for_reboot(
        check=lambda: calls.append("check") or {},
        repair=lambda: calls.append("repair") or {},
        running=lambda: "apt-get",
        judge=lambda _s: {"reboot_unsafe": False},
    )
    assert out["ok"] is False and "apt-get" in out["reason"]
    assert calls == []  # nothing touched while it runs


def test_unfinished_packages_are_finished_first():
    fixed = {"manager": "dpkg", "needs_repair": False}
    out = boot_safety.prepare_for_reboot(
        check=lambda: {"manager": "dpkg", "needs_repair": True, "repairable": True},
        repair=lambda: {"success": True, "health": fixed, "output": "$ dpkg --configure -a"},
        running=lambda: None,
        judge=lambda state: {"reboot_unsafe": state["needs_repair"],
                             "reboot_unsafe_reason": None},
    )  # fmt: skip
    assert out == {"ok": True, "reason": None, "repaired": True,
                   "output": "$ dpkg --configure -a"}  # fmt: skip


def test_a_repair_that_does_not_fix_the_boot_refuses():
    out = boot_safety.prepare_for_reboot(
        check=lambda: {"manager": "dpkg", "needs_repair": True, "repairable": True},
        repair=lambda: {"success": False, "health": {"needs_repair": True}, "output": "E"},
        running=lambda: None,
        judge=lambda _s: {"reboot_unsafe": True, "reboot_unsafe_reason": "no initramfs"},
    )  # fmt: skip
    assert out["ok"] is False and out["reason"] == "no initramfs"
    assert out["repaired"] is True


def test_a_healthy_host_reboots_without_a_repair():
    repaired = []
    out = boot_safety.prepare_for_reboot(
        check=lambda: {"manager": "dpkg", "needs_repair": False, "repairable": True},
        repair=lambda: repaired.append(1) or {},
        running=lambda: None,
        judge=lambda _s: {"reboot_unsafe": False, "reboot_unsafe_reason": None},
    )
    assert out["ok"] is True and not repaired


def test_running_finds_package_managers_by_name():
    assert (
        boot_safety.package_manager_running(
            lambda: [("bash", "bash"), ("dpkg", "/usr/bin/dpkg --configure -a")]
        )
        == "dpkg"
    )
    assert boot_safety.package_manager_running(lambda: [("sshd", "sshd")]) is None


def test_the_idle_shutdown_waiter_is_not_a_running_package_manager():
    """Every Ubuntu host runs it all day (found on all eight production
    hosts, 2026-11-19): counting it would refuse every reboot."""
    waiter = ("unattended-upgr",
              "/usr/bin/python3 /usr/share/unattended-upgrades/"
              "unattended-upgrade-shutdown --wait-for-signal")  # fmt: skip
    assert boot_safety.package_manager_running(lambda: [waiter]) is None
    working = ("unattended-upgr", "/usr/bin/python3 /usr/bin/unattended-upgrade")
    assert boot_safety.package_manager_running(lambda: [working]) == "unattended-upgr"


def test_the_real_process_list_is_read():
    """psutil on this machine: a list of (name, command line) pairs."""
    found = list(boot_safety._processes())  # pylint: disable=protected-access
    assert found and all(isinstance(n, str) and isinstance(c, str) for n, c in found)
