"""
Tests for BSD virtualization support check methods.
Tests VMM/vmd (OpenBSD) and bhyve (FreeBSD) detection.
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations._virtualization_bsd import BsdVirtualizationMixin


class VirtHelper(BsdVirtualizationMixin):
    """Helper class that implements the mixin (not prefixed with Test)."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)


@pytest.fixture
def virt_helper():
    """Create a virtualization helper for testing."""
    return VirtHelper()


class TestCheckVmmSupport:
    """Tests for check_vmm_support method (OpenBSD)."""

    def test_vmm_not_openbsd(self, virt_helper):
        """Test VMM check on non-OpenBSD system."""
        with patch("platform.system", return_value="Linux"):
            result = virt_helper.check_vmm_support()

        assert result["available"] is False
        assert result["enabled"] is False
        assert result["running"] is False

    def test_vmm_no_vmctl(self, virt_helper):
        """Test VMM check when vmctl is not available."""
        with patch("platform.system", return_value="OpenBSD"):
            with patch("shutil.which", return_value=None):
                result = virt_helper.check_vmm_support()

        assert result["available"] is False

    def test_vmm_no_dev_vmm(self, virt_helper):
        """Test VMM check when /dev/vmm doesn't exist."""
        with patch("platform.system", return_value="OpenBSD"):
            with patch("shutil.which", return_value="/usr/sbin/vmctl"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="GenuineIntel\n")
                    with patch("os.path.exists", return_value=False):
                        result = virt_helper.check_vmm_support()

        assert result["available"] is True
        assert result["kernel_supported"] is False
        assert result["needs_enable"] is True

    def test_vmm_fully_available(self, virt_helper):
        """Test VMM check when fully available and running."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "hw.vendor" in cmd:
                result.stdout = "GenuineIntel\n"
            elif "rcctl" in cmd and "get" in cmd:
                result.stdout = "\n"  # Not "NO", means enabled
            elif "rcctl" in cmd and "check" in cmd:
                result.stdout = "vmd(ok)\n"
            return result

        with patch("platform.system", return_value="OpenBSD"):
            with patch("shutil.which", return_value="/usr/sbin/vmctl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", return_value=True):
                        result = virt_helper.check_vmm_support()

        assert result["available"] is True
        assert result["kernel_supported"] is True
        assert result["enabled"] is True
        assert result["running"] is True
        assert result["initialized"] is True

    def test_vmm_enabled_not_running(self, virt_helper):
        """Test VMM check when enabled but not running."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "hw.vendor" in cmd:
                result.returncode = 0
                result.stdout = "GenuineIntel\n"
            elif "rcctl" in cmd and "get" in cmd:
                result.returncode = 0
                result.stdout = "\n"  # Enabled
            elif "rcctl" in cmd and "check" in cmd:
                result.returncode = 1  # Not running
                result.stdout = ""
            else:
                result.returncode = 1
            return result

        with patch("platform.system", return_value="OpenBSD"):
            with patch("shutil.which", return_value="/usr/sbin/vmctl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", return_value=True):
                        result = virt_helper.check_vmm_support()

        assert result["available"] is True
        assert result["enabled"] is True
        assert result["running"] is False

    def test_vmm_disabled(self, virt_helper):
        """Test VMM check when disabled."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "hw.vendor" in cmd:
                result.returncode = 0
                result.stdout = "GenuineIntel\n"
            elif "rcctl" in cmd and "get" in cmd:
                result.returncode = 0
                result.stdout = "NO\n"  # Disabled
            elif "rcctl" in cmd and "check" in cmd:
                result.returncode = 1  # Not running
                result.stdout = ""
            else:
                result.returncode = 1
            return result

        with patch("platform.system", return_value="OpenBSD"):
            with patch("shutil.which", return_value="/usr/sbin/vmctl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", return_value=True):
                        result = virt_helper.check_vmm_support()

        assert result["available"] is True
        assert result["enabled"] is False
        assert result["needs_enable"] is True

    def test_vmm_exception_handling(self, virt_helper):
        """Test VMM check with exception."""
        with patch("platform.system", side_effect=Exception("test error")):
            result = virt_helper.check_vmm_support()

        assert result["available"] is False


class TestCheckBhyveSupport:
    """Tests for check_bhyve_support method (FreeBSD)."""

    def test_bhyve_not_freebsd(self, virt_helper):
        """Test bhyve check on non-FreeBSD system."""
        with patch("platform.system", return_value="Linux"):
            result = virt_helper.check_bhyve_support()

        assert result["available"] is False
        assert result["enabled"] is False
        assert result["running"] is False

    def test_bhyve_no_bhyvectl(self, virt_helper):
        """Test bhyve check when bhyvectl is not available."""
        with patch("platform.system", return_value="FreeBSD"):
            with patch("shutil.which", return_value=None):
                result = virt_helper.check_bhyve_support()

        assert result["available"] is False

    def test_bhyve_fully_available_intel(self, virt_helper):
        """Test bhyve check when fully available with Intel VT-x."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "hw.vmm.vmx.initialized" in cmd:
                result.stdout = "1\n"
            elif "kldstat" in cmd:
                result.stdout = "vmm\n"
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
                            result = virt_helper.check_bhyve_support()

        assert result["available"] is True
        assert result["cpu_supported"] is True
        assert result["enabled"] is True
        assert result["running"] is True
        assert result["uefi_available"] is True

    def test_bhyve_fully_available_amd(self, virt_helper):
        """Test bhyve check when fully available with AMD-V."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "hw.vmm.vmx.initialized" in cmd:
                result.returncode = 1
                result.stdout = ""
            elif "hw.vmm.svm.initialized" in cmd:
                result.returncode = 0
                result.stdout = "1\n"
            elif "kldstat" in cmd:
                result.returncode = 0
                result.stdout = "vmm\n"
            else:
                result.returncode = 1
            return result

        def mock_path_exists(path):
            if path == "/boot/kernel/vmm.ko":
                return True
            return False

        with patch("platform.system", return_value="FreeBSD"):
            with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", side_effect=mock_path_exists):
                        with patch("os.path.isdir", return_value=True):
                            result = virt_helper.check_bhyve_support()

        assert result["available"] is True
        assert result["cpu_supported"] is True

    def test_bhyve_vmm_not_loaded(self, virt_helper):
        """Test bhyve check when vmm.ko is not loaded."""

        def mock_run(_cmd, **_kwargs):
            result = Mock()
            result.returncode = 1
            result.stdout = ""
            return result

        def mock_path_exists(path):
            if path == "/boot/kernel/vmm.ko":
                return True
            return False

        with patch("platform.system", return_value="FreeBSD"):
            with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", side_effect=mock_path_exists):
                        with patch("os.path.isdir", return_value=False):
                            result = virt_helper.check_bhyve_support()

        assert result["available"] is True
        assert result["kernel_supported"] is True
        assert result["enabled"] is False
        assert result["needs_enable"] is True

    def test_bhyve_no_cpu_support(self, virt_helper):
        """Test bhyve check when CPU doesn't support virtualization."""

        def mock_run(_cmd, **_kwargs):
            result = Mock()
            result.returncode = 1  # All sysctl checks fail
            result.stdout = ""
            return result

        with patch("platform.system", return_value="FreeBSD"):
            with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", return_value=False):
                        with patch("os.path.isdir", return_value=False):
                            result = virt_helper.check_bhyve_support()

        assert result["available"] is True
        assert result["cpu_supported"] is False

    def test_bhyve_uefi_alternative_path(self, virt_helper):
        """Test bhyve UEFI detection with alternative path."""

        def mock_run(_cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            result.stdout = "1\n"
            return result

        def mock_path_exists(path):
            if path == "/usr/local/share/bhyve-firmware/BHYVE_UEFI.fd":
                return True
            return False

        with patch("platform.system", return_value="FreeBSD"):
            with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
                with patch("subprocess.run", side_effect=mock_run):
                    with patch("os.path.exists", side_effect=mock_path_exists):
                        with patch("os.path.isdir", return_value=True):
                            result = virt_helper.check_bhyve_support()

        assert result["uefi_available"] is True

    def test_bhyve_exception_handling(self, virt_helper):
        """Test bhyve check with exception."""
        with patch("platform.system", side_effect=Exception("test error")):
            result = virt_helper.check_bhyve_support()

        assert result["available"] is False
