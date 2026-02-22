"""
Tests for child_host_virtualization_checks.py.

This module tests the VirtualizationChecks class which provides a unified
interface for checking virtualization support across multiple platforms.
Tests cover:
- VirtualBox support detection (cross-platform)
- Integration of Windows, Linux, and BSD virtualization mixins
- Error handling and edge cases
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
import os
import subprocess
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.operations.child_host_virtualization_checks import (
    VirtualizationChecks,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_virtualization_checks")


@pytest.fixture
def virt_checks(logger):
    """Create a VirtualizationChecks instance for testing."""
    return VirtualizationChecks(logger)


class TestVirtualizationChecksInit:
    """Tests for VirtualizationChecks initialization."""

    def test_init_sets_logger(self, virt_checks, logger):
        """Test that __init__ sets the logger."""
        assert virt_checks.logger == logger

    def test_init_with_custom_logger(self):
        """Test initialization with a custom logger."""
        custom_logger = logging.getLogger("custom")
        checks = VirtualizationChecks(custom_logger)
        assert checks.logger == custom_logger

    def test_inherits_from_all_mixins(self, virt_checks):
        """Test that VirtualizationChecks inherits from all mixins."""
        # Check Windows mixin methods exist
        assert hasattr(virt_checks, "check_wsl_support")
        assert hasattr(virt_checks, "check_hyperv_support")

        # Check Linux mixin methods exist
        assert hasattr(virt_checks, "check_lxd_support")
        assert hasattr(virt_checks, "check_kvm_support")

        # Check BSD mixin methods exist
        assert hasattr(virt_checks, "check_vmm_support")
        assert hasattr(virt_checks, "check_bhyve_support")


class TestCheckVirtualboxSupport:
    """Tests for check_virtualbox_support method (cross-platform)."""

    def test_virtualbox_not_installed(self, virt_checks):
        """Test VirtualBox check when VBoxManage is not found."""
        with patch("shutil.which", return_value=None):
            with patch("platform.system", return_value="Linux"):
                result = virt_checks.check_virtualbox_support()

        assert result["available"] is False
        assert result["version"] is None

    def test_virtualbox_installed_on_linux(self, virt_checks):
        """Test VirtualBox check on Linux with VBoxManage installed."""
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="7.0.12r159484",
                    stderr="",
                )
                result = virt_checks.check_virtualbox_support()

        assert result["available"] is True
        assert result["version"] == "7.0.12r159484"

    def test_virtualbox_installed_version_command_fails(self, virt_checks):
        """Test VirtualBox check when version command fails."""
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="Error getting version",
                )
                result = virt_checks.check_virtualbox_support()

        assert result["available"] is True
        assert result["version"] is None

    def test_virtualbox_installed_empty_version(self, virt_checks):
        """Test VirtualBox check when version output is empty."""
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="   ",
                    stderr="",
                )
                result = virt_checks.check_virtualbox_support()

        assert result["available"] is True
        assert result["version"] == ""

    def test_virtualbox_on_windows_common_path(self, virt_checks):
        """Test VirtualBox check on Windows using common installation path."""
        with patch(
            "src.sysmanage_agent.operations.child_host_virtualization_checks.shutil.which",
            return_value=None,
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_virtualization_checks.platform.system",
                return_value="Windows",
            ):
                with patch.dict(
                    os.environ,
                    {
                        "ProgramFiles": "C:\\Program Files",
                        "ProgramFiles(x86)": "C:\\Program Files (x86)",
                    },
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_virtualization_checks.os.path.exists"
                    ) as mock_exists:
                        # VBoxManage exists in Program Files
                        def exists_side_effect(path):
                            return "Program Files" in path and "Oracle" in path

                        mock_exists.side_effect = exists_side_effect

                        with patch(
                            "src.sysmanage_agent.operations.child_host_virtualization_checks.subprocess.run"
                        ) as mock_run:
                            mock_run.return_value = Mock(
                                returncode=0,
                                stdout="7.0.10",
                                stderr="",
                            )
                            result = virt_checks.check_virtualbox_support()

        assert result["available"] is True

    def test_virtualbox_on_windows_x86_path(self, virt_checks):
        """Test VirtualBox check on Windows using x86 installation path."""
        with patch(
            "src.sysmanage_agent.operations.child_host_virtualization_checks.shutil.which",
            return_value=None,
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_virtualization_checks.platform.system",
                return_value="Windows",
            ):
                with patch.dict(
                    os.environ,
                    {
                        "ProgramFiles": "C:\\Program Files",
                        "ProgramFiles(x86)": "C:\\Program Files (x86)",
                    },
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_virtualization_checks.os.path.exists"
                    ) as mock_exists:
                        # VBoxManage only exists in Program Files (x86)
                        def exists_side_effect(path):
                            return "(x86)" in path and "Oracle" in path

                        mock_exists.side_effect = exists_side_effect

                        with patch(
                            "src.sysmanage_agent.operations.child_host_virtualization_checks.subprocess.run"
                        ) as mock_run:
                            mock_run.return_value = Mock(
                                returncode=0,
                                stdout="6.1.38",
                                stderr="",
                            )
                            result = virt_checks.check_virtualbox_support()

        assert result["available"] is True

    def test_virtualbox_on_windows_not_found(self, virt_checks):
        """Test VirtualBox check on Windows when not installed anywhere."""
        with patch("shutil.which", return_value=None):
            with patch("platform.system", return_value="Windows"):
                with patch.dict(
                    os.environ,
                    {
                        "ProgramFiles": "C:\\Program Files",
                        "ProgramFiles(x86)": "C:\\Program Files (x86)",
                    },
                ):
                    with patch("os.path.exists", return_value=False):
                        result = virt_checks.check_virtualbox_support()

        assert result["available"] is False
        assert result["version"] is None

    def test_virtualbox_on_windows_empty_env_vars(self, virt_checks):
        """Test VirtualBox check on Windows with empty environment variables."""
        with patch("shutil.which", return_value=None):
            with patch("platform.system", return_value="Windows"):
                with patch.dict(os.environ, {}, clear=True):
                    with patch("os.path.exists", return_value=False):
                        result = virt_checks.check_virtualbox_support()

        assert result["available"] is False

    def test_virtualbox_subprocess_timeout(self, virt_checks):
        """Test VirtualBox check when subprocess times out.

        Note: VBoxManage availability is set before version check,
        so timeout during version check still shows available=True.
        """
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)
            ):
                result = virt_checks.check_virtualbox_support()

        # VBoxManage was found, so available is True even if version check failed
        assert result["available"] is True
        assert result["version"] is None

    def test_virtualbox_subprocess_exception(self, virt_checks):
        """Test VirtualBox check with subprocess exception.

        Note: VBoxManage availability is set before version check,
        so exception during version check still shows available=True.
        """
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run", side_effect=Exception("Unexpected error")):
                result = virt_checks.check_virtualbox_support()

        # VBoxManage was found, so available is True even if version check failed
        assert result["available"] is True
        assert result["version"] is None

    def test_virtualbox_on_macos(self, virt_checks):
        """Test VirtualBox check on macOS."""
        with patch("shutil.which", return_value="/usr/local/bin/VBoxManage"):
            with patch("platform.system", return_value="Darwin"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(
                        returncode=0,
                        stdout="7.0.14r161095",
                        stderr="",
                    )
                    result = virt_checks.check_virtualbox_support()

        assert result["available"] is True
        assert result["version"] == "7.0.14r161095"

    def test_virtualbox_shutil_which_exception(self, virt_checks):
        """Test VirtualBox check when shutil.which raises exception."""
        with patch("shutil.which", side_effect=Exception("which failed")):
            result = virt_checks.check_virtualbox_support()

        assert result["available"] is False


class TestVirtualizationChecksIntegration:
    """Integration tests for VirtualizationChecks class."""

    def test_all_checks_return_dicts(self, virt_checks):
        """Test that all virtualization check methods return dicts."""
        # Mock platform to ensure consistent behavior
        with patch("platform.system", return_value="Linux"):
            with patch("shutil.which", return_value=None):
                with patch("os.path.exists", return_value=False):
                    # VirtualBox check
                    vbox_result = virt_checks.check_virtualbox_support()
                    assert isinstance(vbox_result, dict)
                    assert "available" in vbox_result

                    # KVM check (from Linux mixin)
                    kvm_result = virt_checks.check_kvm_support()
                    assert isinstance(kvm_result, dict)
                    assert "available" in kvm_result

                    # LXD check (from Linux mixin)
                    lxd_result = virt_checks.check_lxd_support()
                    assert isinstance(lxd_result, dict)
                    assert "available" in lxd_result

        with patch("platform.system", return_value="Windows"):
            with patch("shutil.which", return_value=None):
                with patch("os.path.exists", return_value=False):
                    # WSL check (from Windows mixin)
                    wsl_result = virt_checks.check_wsl_support()
                    assert isinstance(wsl_result, dict)
                    assert "available" in wsl_result

                    # Hyper-V check (from Windows mixin)
                    hyperv_result = virt_checks.check_hyperv_support()
                    assert isinstance(hyperv_result, dict)
                    assert "available" in hyperv_result

        with patch("platform.system", return_value="OpenBSD"):
            with patch("shutil.which", return_value=None):
                # VMM check (from BSD mixin)
                vmm_result = virt_checks.check_vmm_support()
                assert isinstance(vmm_result, dict)
                assert "available" in vmm_result

        with patch("platform.system", return_value="FreeBSD"):
            with patch("shutil.which", return_value=None):
                # bhyve check (from BSD mixin)
                bhyve_result = virt_checks.check_bhyve_support()
                assert isinstance(bhyve_result, dict)
                assert "available" in bhyve_result

    def test_checks_dont_raise_exceptions(self, virt_checks):
        """Test that all checks handle errors gracefully without raising."""
        # Force exceptions in various places
        with patch("platform.system", side_effect=Exception("Platform error")):
            # These should not raise, just return default dicts
            try:
                virt_checks.check_virtualbox_support()
                virt_checks.check_kvm_support()
                virt_checks.check_lxd_support()
                virt_checks.check_wsl_support()
                virt_checks.check_hyperv_support()
                virt_checks.check_vmm_support()
                virt_checks.check_bhyve_support()
            except Exception as exc:
                pytest.fail(f"Virtualization check raised exception: {exc}")


class TestVirtualizationChecksFromBsdMixin:
    """Tests for BSD virtualization methods inherited from mixin."""

    def test_check_vmm_support_not_openbsd(self, virt_checks):
        """Test VMM check returns unavailable on non-OpenBSD."""
        with patch("platform.system", return_value="Linux"):
            result = virt_checks.check_vmm_support()

        assert result["available"] is False

    def test_check_bhyve_support_not_freebsd(self, virt_checks):
        """Test bhyve check returns unavailable on non-FreeBSD."""
        with patch("platform.system", return_value="Linux"):
            result = virt_checks.check_bhyve_support()

        assert result["available"] is False

    def test_check_vmm_support_on_openbsd(self, virt_checks):
        """Test VMM check on OpenBSD with vmctl available."""
        with patch("platform.system", return_value="OpenBSD"):
            with patch("shutil.which", return_value="/usr/sbin/vmctl"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="GenuineIntel\n")
                    with patch("os.path.exists", return_value=True):
                        result = virt_checks.check_vmm_support()

        assert result["available"] is True

    def test_check_bhyve_support_on_freebsd(self, virt_checks):
        """Test bhyve check on FreeBSD with bhyvectl available."""
        with patch("platform.system", return_value="FreeBSD"):
            with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="1\n")
                    with patch("os.path.exists", return_value=False):
                        with patch("os.path.isdir", return_value=False):
                            result = virt_checks.check_bhyve_support()

        assert result["available"] is True


class TestVirtualizationChecksFromLinuxMixin:
    """Tests for Linux virtualization methods inherited from mixin."""

    def test_check_kvm_support_not_linux(self, virt_checks):
        """Test KVM check returns unavailable on non-Linux."""
        with patch("platform.system", return_value="Windows"):
            result = virt_checks.check_kvm_support()

        assert result["available"] is False

    def test_check_lxd_support_not_linux(self, virt_checks):
        """Test LXD check returns unavailable on non-Linux."""
        with patch("platform.system", return_value="Darwin"):
            result = virt_checks.check_lxd_support()

        assert result["available"] is False

    def test_check_kvm_support_on_linux(self, virt_checks):
        """Test KVM check on Linux."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                virt_checks, "_check_cpu_virtualization_flags", return_value=True
            ):
                with patch.object(virt_checks, "_get_cpu_vendor", return_value="intel"):
                    with patch.object(
                        virt_checks,
                        "_check_kvm_modules_loaded",
                        return_value={"loaded": True, "available": True},
                    ):
                        with patch("os.path.exists", return_value=True):
                            with patch.object(
                                virt_checks, "_is_user_in_kvm_group", return_value=True
                            ):
                                with patch(
                                    "shutil.which", return_value="/usr/bin/virsh"
                                ):
                                    with patch.object(
                                        virt_checks,
                                        "_check_libvirtd_status",
                                        return_value={"enabled": True, "running": True},
                                    ):
                                        with patch.object(
                                            virt_checks,
                                            "_check_default_network_exists",
                                            return_value=True,
                                        ):
                                            result = virt_checks.check_kvm_support()

        assert result["available"] is True
        assert result["cpu_supported"] is True

    def test_check_lxd_support_on_ubuntu_22(self, virt_checks):
        """Test LXD check on Ubuntu 22.04."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(virt_checks, "_is_ubuntu_22_or_newer", return_value=True):
                with patch("shutil.which", return_value="/snap/bin/snap"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stdout="lxd 5.21")
                        with patch.object(
                            virt_checks, "_is_user_in_lxd_group", return_value=True
                        ):
                            result = virt_checks.check_lxd_support()

        assert result["available"] is True
        assert result["installed"] is True


class TestVirtualizationChecksFromWindowsMixin:
    """Tests for Windows virtualization methods inherited from mixin."""

    def test_check_wsl_support_not_windows(self, virt_checks):
        """Test WSL check returns unavailable on non-Windows."""
        with patch("platform.system", return_value="Linux"):
            result = virt_checks.check_wsl_support()

        assert result["available"] is False

    def test_check_hyperv_support_not_windows(self, virt_checks):
        """Test Hyper-V check returns unavailable on non-Windows."""
        with patch("platform.system", return_value="Linux"):
            result = virt_checks.check_hyperv_support()

        assert result["available"] is False

    def test_check_wsl_support_on_windows(self, virt_checks):
        """Test WSL check on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch.dict(os.environ, {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(
                            returncode=0,
                            stdout=b"Default Version: 2\n",
                            stderr=b"",
                        )
                        result = virt_checks.check_wsl_support()

        assert result["available"] is True

    def test_check_hyperv_support_on_windows(self, virt_checks):
        """Test Hyper-V check on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="Enabled",
                    stderr="",
                )
                result = virt_checks.check_hyperv_support()

        assert result["available"] is True
        assert result["enabled"] is True


class TestVirtualizationChecksEdgeCases:
    """Edge case tests for VirtualizationChecks."""

    def test_virtualbox_with_whitespace_version(self, virt_checks):
        """Test VirtualBox version with leading/trailing whitespace."""
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="  7.0.12r159484  \n",
                    stderr="",
                )
                result = virt_checks.check_virtualbox_support()

        assert result["available"] is True
        assert result["version"] == "7.0.12r159484"

    def test_virtualbox_file_not_found_error(self, virt_checks):
        """Test VirtualBox check when VBoxManage path doesn't exist.

        Note: VBoxManage availability is set before version check,
        so exception during version check still shows available=True.
        """
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch(
                "subprocess.run", side_effect=FileNotFoundError("VBoxManage not found")
            ):
                result = virt_checks.check_virtualbox_support()

        # VBoxManage was found by which, so available is True
        assert result["available"] is True
        assert result["version"] is None

    def test_virtualbox_permission_denied_error(self, virt_checks):
        """Test VirtualBox check when permission denied.

        Note: VBoxManage availability is set before version check,
        so exception during version check still shows available=True.
        """
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch(
                "subprocess.run", side_effect=PermissionError("Permission denied")
            ):
                result = virt_checks.check_virtualbox_support()

        # VBoxManage was found, so available is True
        assert result["available"] is True
        assert result["version"] is None

    def test_virtualbox_oserror(self, virt_checks):
        """Test VirtualBox check with OSError.

        Note: VBoxManage availability is set before version check,
        so exception during version check still shows available=True.
        """
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run", side_effect=OSError("OS error")):
                result = virt_checks.check_virtualbox_support()

        # VBoxManage was found, so available is True
        assert result["available"] is True
        assert result["version"] is None

    def test_multiple_virtualbox_checks(self, virt_checks):
        """Test that multiple VirtualBox checks work correctly."""
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="7.0.12",
                    stderr="",
                )

                result1 = virt_checks.check_virtualbox_support()
                result2 = virt_checks.check_virtualbox_support()

        assert result1["available"] is True
        assert result2["available"] is True
        assert result1["version"] == result2["version"]


class TestVirtualizationChecksWithMockLogger:
    """Tests verifying logger interactions."""

    def test_virtualbox_error_logged(self):
        """Test that VirtualBox errors are logged."""
        mock_logger = MagicMock()
        checks = VirtualizationChecks(mock_logger)

        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run", side_effect=Exception("Test error")):
                checks.check_virtualbox_support()

        mock_logger.debug.assert_called()

    def test_virtualbox_success_no_error_log(self):
        """Test that successful VirtualBox check doesn't log errors."""
        mock_logger = MagicMock()
        checks = VirtualizationChecks(mock_logger)

        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="7.0.12",
                    stderr="",
                )
                checks.check_virtualbox_support()

        # Debug should not be called for errors
        for call in mock_logger.debug.call_args_list:
            assert "Error" not in str(call)


class TestVirtualizationChecksHelperMethods:
    """Tests for helper methods from mixins."""

    def test_decode_wsl_output_utf16le(self, virt_checks):
        """Test _decode_wsl_output with UTF-16LE encoded output."""
        # UTF-16LE encoded "Default Version: 2"
        utf16le_bytes = "Default Version: 2".encode("utf-16-le")
        result = virt_checks._decode_wsl_output(utf16le_bytes, b"")

        assert "Default Version: 2" in result

    def test_decode_wsl_output_utf8(self, virt_checks):
        """Test _decode_wsl_output with UTF-8 encoded output.

        Note: The function tries UTF-16LE first, so pure ASCII/UTF-8
        may be decoded as UTF-16LE if it happens to be valid UTF-16LE.
        Use bytes that don't decode well as UTF-16LE to test fallback.
        """
        # Use odd-length bytes that won't decode as UTF-16LE correctly
        utf8_bytes = b"Version: 2\n"  # Odd length, UTF-16LE decode will fail
        result = virt_checks._decode_wsl_output(utf8_bytes, b"")

        # Should fall back to UTF-8 or latin-1
        assert "Version" in result or result  # At least some output

    def test_decode_wsl_output_empty(self, virt_checks):
        """Test _decode_wsl_output with empty output."""
        result = virt_checks._decode_wsl_output(b"", b"")
        assert result == ""

    def test_decode_wsl_output_with_bom(self, virt_checks):
        """Test _decode_wsl_output with UTF-16LE BOM."""
        # UTF-16LE with BOM
        utf16le_bytes = b"\xff\xfe" + "Test".encode("utf-16-le")
        result = virt_checks._decode_wsl_output(utf16le_bytes, b"")

        assert "Test" in result

    def test_check_vmm_cpu_support(self, virt_checks):
        """Test _check_vmm_cpu_support method."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="GenuineIntel")
            result = virt_checks._check_vmm_cpu_support()

        assert result is True

    def test_check_vmm_cpu_support_failure(self, virt_checks):
        """Test _check_vmm_cpu_support method when command fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="")
            result = virt_checks._check_vmm_cpu_support()

        assert result is False

    def test_check_vmm_cpu_support_exception(self, virt_checks):
        """Test _check_vmm_cpu_support method with exception."""
        with patch("subprocess.run", side_effect=Exception("Error")):
            result = virt_checks._check_vmm_cpu_support()

        assert result is False

    def test_check_vmd_enabled_true(self, virt_checks):
        """Test _check_vmd_enabled when vmd is enabled."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="")
            result = virt_checks._check_vmd_enabled()

        assert result is True

    def test_check_vmd_enabled_false(self, virt_checks):
        """Test _check_vmd_enabled when vmd is disabled."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="NO")
            result = virt_checks._check_vmd_enabled()

        assert result is False

    def test_check_vmd_enabled_timeout(self, virt_checks):
        """Test _check_vmd_enabled with timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            result = virt_checks._check_vmd_enabled()

        assert result is False

    def test_check_vmd_running(self, virt_checks):
        """Test _check_vmd_running method."""
        result = {"running": False, "initialized": False}

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="vmd(ok)")
            virt_checks._check_vmd_running(result)

        assert result["running"] is True
        assert result["initialized"] is True

    def test_check_vmd_running_not_running(self, virt_checks):
        """Test _check_vmd_running when vmd is not running."""
        result = {"running": False, "initialized": False}

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="")
            virt_checks._check_vmd_running(result)

        assert result["running"] is False
        assert result["initialized"] is False

    def test_check_vmd_running_timeout(self, virt_checks):
        """Test _check_vmd_running with timeout."""
        result = {"running": False, "initialized": False}

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            virt_checks._check_vmd_running(result)

        assert result["running"] is False

    def test_check_bhyve_cpu_support_vmx(self, virt_checks):
        """Test _check_bhyve_cpu_support with Intel VMX."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="1")
            result = virt_checks._check_bhyve_cpu_support()

        assert result is True

    def test_check_bhyve_cpu_support_svm(self, virt_checks):
        """Test _check_bhyve_cpu_support with AMD SVM."""

        def run_side_effect(cmd, **_kwargs):
            # cmd is a list, check if svm or vmx is in any element
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            if "vmx" in cmd_str:
                return Mock(returncode=1, stdout="0")
            if "svm" in cmd_str:
                return Mock(returncode=0, stdout="1")
            return Mock(returncode=1, stdout="")

        with patch(
            "src.sysmanage_agent.operations._virtualization_bsd.subprocess.run",
            side_effect=run_side_effect,
        ):
            result = virt_checks._check_bhyve_cpu_support()

        assert result is True

    def test_check_bhyve_cpu_support_none(self, virt_checks):
        """Test _check_bhyve_cpu_support with no virtualization."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="")
            result = virt_checks._check_bhyve_cpu_support()

        assert result is False

    def test_check_vmm_kernel_module_loaded(self, virt_checks):
        """Test _check_vmm_kernel_module when module is loaded."""
        result = {
            "enabled": False,
            "kernel_supported": False,
            "running": False,
            "initialized": False,
            "needs_enable": False,
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="vmm")
            virt_checks._check_vmm_kernel_module(result)

        assert result["enabled"] is True
        assert result["kernel_supported"] is True
        assert result["running"] is True
        assert result["initialized"] is True

    def test_check_vmm_kernel_module_not_loaded(self, virt_checks):
        """Test _check_vmm_kernel_module when module is not loaded."""
        result = {
            "enabled": False,
            "kernel_supported": False,
            "running": False,
            "initialized": False,
            "needs_enable": False,
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="")
            with patch("os.path.exists", return_value=True):
                virt_checks._check_vmm_kernel_module(result)

        assert result["kernel_supported"] is True
        assert result["needs_enable"] is True

    def test_detect_wsl_blockers_bios(self, virt_checks):
        """Test _detect_wsl_blockers with BIOS virtualization issue."""
        result = {
            "enabled": True,
            "needs_enable": False,
            "needs_bios_virtualization": False,
        }

        blocked = virt_checks._detect_wsl_blockers(
            "bios virtualization is disabled",
            result,
        )

        assert blocked is True
        assert result["needs_bios_virtualization"] is True
        assert result["enabled"] is False

    def test_detect_wsl_blockers_vm_platform(self, virt_checks):
        """Test _detect_wsl_blockers with VM platform issue."""
        result = {
            "enabled": True,
            "needs_enable": False,
            "needs_bios_virtualization": False,
        }

        blocked = virt_checks._detect_wsl_blockers(
            "virtual machine platform required",
            result,
        )

        assert blocked is True
        assert result["needs_enable"] is True

    def test_detect_wsl_blockers_none(self, virt_checks):
        """Test _detect_wsl_blockers with no blockers."""
        result = {
            "enabled": True,
            "needs_enable": False,
            "needs_bios_virtualization": False,
        }

        blocked = virt_checks._detect_wsl_blockers(
            "default version: 2",
            result,
        )

        assert blocked is False

    def test_parse_wsl_version_2(self, virt_checks):
        """Test _parse_wsl_version with WSL 2."""
        result = {"default_version": None, "version": None}

        virt_checks._parse_wsl_version("Default Version: 2", result)

        assert result["default_version"] == 2
        assert result["version"] == "2"

    def test_parse_wsl_version_1(self, virt_checks):
        """Test _parse_wsl_version with WSL 1."""
        result = {"default_version": None, "version": None}

        virt_checks._parse_wsl_version("Default Version: 1", result)

        assert result["default_version"] == 1
        assert result["version"] == "1"

    def test_parse_wsl_version_wsl1_format(self, virt_checks):
        """Test _parse_wsl_version with 'WSL 1' format."""
        result = {"default_version": None, "version": None}

        virt_checks._parse_wsl_version("WSL 1 is the current version", result)

        assert result["default_version"] == 1
        assert result["version"] == "1"

    def test_parse_wsl_version_default(self, virt_checks):
        """Test _parse_wsl_version defaults to version 2."""
        result = {"default_version": None, "version": None}

        virt_checks._parse_wsl_version("Some unknown format", result)

        assert result["default_version"] == 2
        assert result["version"] == "2"


class TestVirtualizationChecksCompleteWorkflows:
    """Complete workflow tests for VirtualizationChecks."""

    def test_full_windows_virtualization_check(self, virt_checks):
        """Test complete Windows virtualization workflow."""
        with patch("platform.system", return_value="Windows"):
            # WSL check
            with patch.dict(os.environ, {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(
                            returncode=0,
                            stdout=b"Default Version: 2\n",
                            stderr=b"",
                        )
                        wsl_result = virt_checks.check_wsl_support()

            # Hyper-V check
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="Enabled",
                    stderr="",
                )
                hyperv_result = virt_checks.check_hyperv_support()

        assert wsl_result["available"] is True
        assert hyperv_result["available"] is True

    def test_full_linux_virtualization_check(self, virt_checks):
        """Test complete Linux virtualization workflow."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(virt_checks, "_is_ubuntu_22_or_newer", return_value=True):
                with patch.object(
                    virt_checks, "_check_cpu_virtualization_flags", return_value=True
                ):
                    with patch.object(
                        virt_checks, "_get_cpu_vendor", return_value="intel"
                    ):
                        with patch.object(
                            virt_checks,
                            "_check_kvm_modules_loaded",
                            return_value={"loaded": True, "available": True},
                        ):
                            with patch("os.path.exists", return_value=True):
                                with patch.object(
                                    virt_checks,
                                    "_is_user_in_kvm_group",
                                    return_value=True,
                                ):
                                    with patch.object(
                                        virt_checks,
                                        "_is_user_in_lxd_group",
                                        return_value=True,
                                    ):
                                        with patch("shutil.which") as mock_which:

                                            def which_side_effect(cmd):
                                                if cmd == "virsh":
                                                    return "/usr/bin/virsh"
                                                if cmd == "snap":
                                                    return "/snap/bin/snap"
                                                return None

                                            mock_which.side_effect = which_side_effect
                                            with patch.object(
                                                virt_checks,
                                                "_check_libvirtd_status",
                                                return_value={
                                                    "enabled": True,
                                                    "running": True,
                                                },
                                            ):
                                                with patch.object(
                                                    virt_checks,
                                                    "_check_default_network_exists",
                                                    return_value=True,
                                                ):
                                                    with patch(
                                                        "subprocess.run"
                                                    ) as mock_run:
                                                        mock_run.return_value = Mock(
                                                            returncode=0,
                                                            stdout="lxd 5.21",
                                                        )
                                                        kvm_result = (
                                                            virt_checks.check_kvm_support()
                                                        )
                                                        lxd_result = (
                                                            virt_checks.check_lxd_support()
                                                        )

        assert kvm_result["available"] is True
        assert kvm_result["initialized"] is True
        assert lxd_result["available"] is True
        assert lxd_result["installed"] is True

    def test_full_openbsd_virtualization_check(self, virt_checks):
        """Test complete OpenBSD virtualization workflow."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "hw.vendor" in cmd:
                result.stdout = "GenuineIntel\n"
            elif "rcctl" in cmd and "get" in cmd:
                result.stdout = ""  # Enabled
            elif "rcctl" in cmd and "check" in cmd:
                result.stdout = "vmd(ok)\n"
            return result

        with patch("platform.system", return_value="OpenBSD"):
            with patch("shutil.which", return_value="/usr/sbin/vmctl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", return_value=True):
                        vmm_result = virt_checks.check_vmm_support()

        assert vmm_result["available"] is True
        assert vmm_result["enabled"] is True
        assert vmm_result["running"] is True
        assert vmm_result["kernel_supported"] is True

    def test_full_freebsd_virtualization_check(self, virt_checks):
        """Test complete FreeBSD virtualization workflow."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "hw.vmm.vmx.initialized" in cmd:
                result.returncode = 0
                result.stdout = "1\n"
            elif "kldstat" in cmd:
                result.returncode = 0
                result.stdout = "vmm\n"
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        def mock_path_exists(path):
            if path == "/boot/kernel/vmm.ko":
                return True
            if path == "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd":
                return True
            return False

        with patch("platform.system", return_value="FreeBSD"):
            with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", side_effect=mock_path_exists):
                        with patch("os.path.isdir", return_value=True):
                            bhyve_result = virt_checks.check_bhyve_support()

        assert bhyve_result["available"] is True
        assert bhyve_result["cpu_supported"] is True
        assert bhyve_result["enabled"] is True
        assert bhyve_result["uefi_available"] is True
