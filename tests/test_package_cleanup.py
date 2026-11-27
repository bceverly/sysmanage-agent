# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The old-kernel and unneeded-package cleanup (ROADMAP 27.8)."""

import asyncio
from unittest.mock import patch

from src.sysmanage_agent.operations import package_cleanup as pc

AUTOREMOVE = """NOTE: This is only a simulation!
Purg linux-image-6.8.0-139-generic [6.8.0-139.139]
Purg linux-modules-6.8.0-139-generic [6.8.0-139.139]
Purg linux-image-6.8.0-149-generic [6.8.0-149.149]
Purg libfoo1 [1.2-3]
"""
INSTALLED = [
    "linux-image-6.8.0-94-generic",
    "linux-modules-6.8.0-94-generic",  # manual, old
    "linux-image-6.8.0-139-generic",
    "linux-modules-6.8.0-139-generic",
    "linux-image-6.8.0-149-generic",
    "linux-image-6.8.0-151-generic",
    "linux-headers-6.8.0-151",
    "linux-generic",
    "linux-firmware",
    "linux-libc-dev",
    "bash",
]


def test_abi_and_kernel_package_names():
    assert pc.abi_of("6.8.0-151-generic") == "6.8.0-151"
    assert pc.abi_of("linux-hwe-6.8-headers-6.8.0-151") == "6.8.0-151"
    assert pc.is_kernel_package("linux-modules-extra-6.8.0-139-generic")
    assert pc.is_kernel_package("linux-headers-6.8.0-151")
    for name in (
        "linux-generic",
        "linux-firmware",
        "linux-libc-dev",
        "linux-image-generic-hwe-24.04",
    ):
        assert not pc.is_kernel_package(name), name


def test_simulated_removals():
    assert pc.simulated_removals(AUTOREMOVE) == [
        "linux-image-6.8.0-139-generic",
        "linux-modules-6.8.0-139-generic",
        "linux-image-6.8.0-149-generic",
        "libfoo1",
    ]
    assert pc.simulated_removals("Remv foo:amd64 [1]\nInst bar") == ["foo"]


def test_plan_keeps_the_last_proven_kernel_autoremove_would_drop():
    """After a reboot into 151 (not yet proven), apt would remove 139 -- the
    kernel last booted successfully.  It is protected, so it stays."""
    keep = {"6.8.0-151", "6.8.0-139"}
    remove, kept = pc.build_plan(pc.simulated_removals(AUTOREMOVE), INSTALLED, keep)
    names = [p["name"] for p in remove]
    assert "linux-image-6.8.0-139-generic" not in names
    assert "linux-modules-6.8.0-139-generic" not in names
    assert {
        "linux-image-6.8.0-149-generic",
        "linux-image-6.8.0-94-generic",
        "linux-modules-6.8.0-94-generic",
        "libfoo1",
    } == set(names)
    assert {k["kernel"] for k in kept} == {"6.8.0-139", "6.8.0-151"}
    reasons = {p["name"]: p["reason"] for p in remove}
    assert reasons["libfoo1"] == "unneeded"
    assert reasons["linux-image-6.8.0-94-generic"] == "old_kernel"
    for name in ("linux-generic", "linux-firmware", "linux-libc-dev", "bash"):
        assert name not in names


def test_running_and_newest_always_protected():
    with patch.object(
        pc.kernel_state, "running_release", return_value="6.8.0-139-generic"
    ), patch.object(
        pc.kernel_state,
        "installed_releases",
        return_value=["6.8.0-151-generic", "6.8.0-139-generic"],
    ):
        assert pc.protected_abis([]) == {"6.8.0-139", "6.8.0-151"}
        assert pc.protected_abis(["6.8.0-94-generic"]) == {
            "6.8.0-139",
            "6.8.0-151",
            "6.8.0-94",
        }


def test_boot_path_check(tmp_path):
    (tmp_path / "vmlinuz-6.8.0-151-generic").write_bytes(b"")
    (tmp_path / "initrd.img-6.8.0-151-generic").write_bytes(b"")
    (tmp_path / "vmlinuz-6.8.0-139-generic").write_bytes(b"")  # initramfs gone
    with patch.object(
        pc.kernel_state,
        "installed_releases",
        return_value=["6.8.0-151-generic", "6.8.0-139-generic"],
    ):
        assert pc.boot_path_problems({"6.8.0-151"}, str(tmp_path)) == []
        assert pc.boot_path_problems({"6.8.0-139"}, str(tmp_path)) == [
            "initrd.img-6.8.0-139-generic"
        ]
    with patch.object(pc.kernel_state, "installed_releases", return_value=[]):
        assert pc.boot_path_problems({"6.8.0-151"}, str(tmp_path))


class _Fake(pc.PackageCleanup):
    """apt and dpkg answered from strings; records what really ran."""

    def __init__(self, removal_sim):
        super().__init__(agent_instance=None)
        self.removal_sim = removal_sim
        self.ran = []

    async def _run(self, argv):
        self.ran.append(argv)
        if argv[:3] == ["apt-get", "-s", "autoremove"]:
            return 0, AUTOREMOVE
        if argv[0] == "dpkg-query":
            return 0, "".join(f"{n}\tii \n" for n in INSTALLED)
        if argv[:3] == ["apt-get", "-s", "remove"]:
            return 0, self.removal_sim(argv[4:])
        return 0, ""


def _sim_exact(names):
    return "".join(f"Purg {n} [1]\n" for n in names)


def test_apply_removes_exactly_the_approved_list():
    fake = _Fake(_sim_exact)
    with patch.object(pc, "boot_path_problems", return_value=[]):
        result = asyncio.run(
            fake.apply(
                {"6.8.0-151", "6.8.0-139"},
                ["linux-image-6.8.0-94-generic", "linux-image-6.8.0-139-generic"],
            )
        )
    assert result["status"] == "done"
    real = [argv for argv in fake.ran if argv[0] == "sudo"]
    # the protected 139 was approved by mistake and is still not removed
    assert real == [
        ["sudo", "apt-get", "remove", "--purge", "-y", "linux-image-6.8.0-94-generic"]
    ]


def test_apply_refuses_when_apt_would_take_more():
    fake = _Fake(lambda names: _sim_exact(list(names) + ["linux-generic"]))
    result = asyncio.run(fake.apply({"6.8.0-151"}, ["linux-image-6.8.0-94-generic"]))
    assert result["status"] == "refused"
    assert "linux-generic" in result["error"]
    assert not [argv for argv in fake.ran if argv[0] == "sudo"]


def test_apply_reports_a_broken_boot_path():
    fake = _Fake(_sim_exact)
    with patch.object(
        pc, "boot_path_problems", return_value=["initrd.img-6.8.0-151-generic"]
    ):
        result = asyncio.run(fake.apply({"6.8.0-151"}, ["libfoo1"]))
    assert result["status"] == "boot_path_broken"


def test_unsupported_without_apt():
    with patch.object(pc.shutil, "which", return_value=None):
        result = asyncio.run(pc.PackageCleanup(None).execute({"mode": "plan"}))
    assert result["status"] == "unsupported"
