# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Running vs installed kernels, and the reboot they call for (ROADMAP 27.8)."""

from unittest.mock import patch

from src.sysmanage_agent.collection import kernel_state
from src.sysmanage_agent.operations import update_manager


def _touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")


def test_version_key_orders_builds_numerically():
    releases = [
        "6.8.0-99-generic",
        "6.8.0-151-generic",
        "5.15.0-213-generic",
        "6.8.0-149-generic",
    ]
    assert sorted(releases, key=kernel_state.version_key, reverse=True) == [
        "6.8.0-151-generic",
        "6.8.0-149-generic",
        "6.8.0-99-generic",
        "5.15.0-213-generic",
    ]


def test_version_key_ignores_flavor_and_distro_suffix():
    assert kernel_state.version_key("6.8.0-151-generic") == (6, 8, 0, 151)
    assert kernel_state.version_key("6.11.4-301.fc41.x86_64") == (6, 11, 4, 301)
    assert kernel_state.version_key("6.12.1-arch1-1") == (6, 12, 1)


def test_installed_releases_reads_boot_and_modules(tmp_path):
    boot, modules = tmp_path / "boot", tmp_path / "modules"
    _touch(boot / "vmlinuz-6.8.0-139-generic")
    _touch(boot / "vmlinuz-6.8.0-151-generic")
    _touch(boot / "vmlinuz-linux")  # Arch's unversioned name: not a release
    _touch(modules / "6.12.1-arch1-1" / "vmlinuz")
    (modules / "6.1.0-old").mkdir(parents=True)  # modules left behind, no image
    assert kernel_state.installed_releases(str(boot), str(modules)) == [
        "6.12.1-arch1-1",
        "6.8.0-151-generic",
        "6.8.0-139-generic",
    ]


def test_newer_kernel_when_a_newer_one_is_installed():
    with patch.object(kernel_state.platform, "system", return_value="Linux"):
        installed = ["6.8.0-151-generic", "6.8.0-149-generic", "6.8.0-139-generic"]
        assert (
            kernel_state.newer_kernel("6.8.0-139-generic", installed)
            == "6.8.0-151-generic"
        )
        assert kernel_state.newer_kernel("6.8.0-151-generic", installed) is None
        assert kernel_state.newer_kernel("6.8.0-151-generic", []) is None


def test_newer_kernel_only_on_linux():
    with patch.object(kernel_state.platform, "system", return_value="FreeBSD"):
        assert kernel_state.newer_kernel("14.1-RELEASE", ["14.2-RELEASE"]) is None


def test_reboot_reason_names_both_kernels():
    with patch.object(
        kernel_state, "newer_kernel", return_value="6.8.0-151-generic"
    ), patch.object(kernel_state, "running_release", return_value="6.8.0-139-generic"):
        reason = update_manager._kernel_reason()  # pylint: disable=protected-access
    assert "6.8.0-151-generic" in reason and "6.8.0-139-generic" in reason
    assert len(reason) <= 255


def test_no_reason_when_the_newest_kernel_runs():
    with patch.object(kernel_state, "newer_kernel", return_value=None):
        assert (
            update_manager._kernel_reason() is None
        )  # pylint: disable=protected-access


def test_linux_reboot_required_from_kernels_without_the_flag_file():
    from src.sysmanage_agent.collection.update_detection import UpdateDetector

    detector = UpdateDetector()
    detector.available_updates = []
    with patch("os.path.exists", return_value=False), patch.object(
        kernel_state, "newer_kernel", return_value="6.8.0-151-generic"
    ):
        assert (
            detector._detect_linux_reboot_required() is True
        )  # pylint: disable=protected-access
    with patch("os.path.exists", return_value=False), patch.object(
        kernel_state, "newer_kernel", return_value=None
    ):
        assert (
            detector._detect_linux_reboot_required() is False
        )  # pylint: disable=protected-access
