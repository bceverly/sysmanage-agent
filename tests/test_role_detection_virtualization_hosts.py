"""
Tests for virtualization host detection utilities.
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.role_detection_virtualization_hosts import (
    VirtualizationHostDetector,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def service_detector():
    """Create a mock service status detector."""
    mock = Mock()
    mock.get_service_status = Mock(return_value="running")
    return mock


@pytest.fixture
def detector(logger, service_detector):
    """Create a VirtualizationHostDetector for testing."""
    return VirtualizationHostDetector("linux", logger, service_detector)


class TestVirtualizationHostDetectorInit:
    """Tests for VirtualizationHostDetector initialization."""

    def test_init_sets_system(self, logger, service_detector):
        """Test that __init__ sets system."""
        detector = VirtualizationHostDetector("linux", logger, service_detector)
        assert detector.system == "linux"

    def test_init_sets_logger(self, logger, service_detector):
        """Test that __init__ sets logger."""
        detector = VirtualizationHostDetector("linux", logger, service_detector)
        assert detector.logger == logger

    def test_init_sets_service_status_detector(self, logger, service_detector):
        """Test that __init__ sets service_status_detector."""
        detector = VirtualizationHostDetector("linux", logger, service_detector)
        assert detector.service_status_detector == service_detector


class TestDetectLxdHostRole:
    """Tests for detect_lxd_host_role method."""

    def test_lxd_not_installed(self, detector):
        """Test when LXD is not installed."""
        with patch("shutil.which", return_value=None):
            with patch("os.path.exists", return_value=False):
                result = detector.detect_lxd_host_role()

        assert result is None

    def test_lxd_installed_not_initialized(self, detector):
        """Test when LXD is installed but not initialized."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("shutil.which", return_value="/snap/bin/lxc"):
            with patch("os.path.exists", return_value=True):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector.detect_lxd_host_role()

        assert result is None

    def test_lxd_fully_configured(self, detector):
        """Test when LXD is fully configured and running."""
        mock_lxc_info = Mock()
        mock_lxc_info.returncode = 0

        mock_snap_list = Mock()
        mock_snap_list.returncode = 0
        mock_snap_list.stdout = "Name  Version  Rev  Tracking  Publisher  Notes\nlxd  5.21.4  36579  5.21/stable  canonical**  -\n"

        def mock_run(cmd, **_kwargs):
            if "lxc" in cmd and "info" in cmd:
                return mock_lxc_info
            if "snap" in cmd and "list" in cmd:
                return mock_snap_list
            return mock_lxc_info

        with patch("shutil.which", return_value="/snap/bin/lxc"):
            with patch("os.path.exists", return_value=True):
                with patch("subprocess.run", side_effect=mock_run):
                    result = detector.detect_lxd_host_role()

        assert result is not None
        assert result["role"] == "LXD Host"
        assert result["package_name"] == "lxd"
        assert result["is_active"] is True

    def test_lxd_exception_handling(self, detector):
        """Test exception handling in LXD detection."""
        with patch("shutil.which", side_effect=Exception("test error")):
            result = detector.detect_lxd_host_role()

        assert result is None


class TestDetectWslHostRole:
    """Tests for detect_wsl_host_role method."""

    def test_wsl_not_installed(self, detector):
        """Test when WSL is not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = detector.detect_wsl_host_role()

        assert result is None

    def test_wsl_not_enabled(self, detector):
        """Test when WSL is not enabled."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            result = detector.detect_wsl_host_role()

        assert result is None

    def test_wsl_fully_enabled(self, detector):
        """Test when WSL is fully enabled and running."""
        mock_status = Mock()
        mock_status.returncode = 0

        mock_version = Mock()
        mock_version.returncode = 0
        mock_version.stdout = "WSL version: 2.0.9.0\nKernel version: 5.15.133\n"

        def mock_run(cmd, **_kwargs):
            if "--status" in cmd:
                return mock_status
            if "--version" in cmd:
                return mock_version
            return mock_status

        with patch("subprocess.run", side_effect=mock_run):
            result = detector.detect_wsl_host_role()

        assert result is not None
        assert result["role"] == "WSL Host"
        assert result["package_name"] == "wsl"
        assert result["is_active"] is True

    def test_wsl_exception_handling(self, detector):
        """Test exception handling in WSL detection."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = detector.detect_wsl_host_role()

        assert result is None


class TestDetectVmmHostRole:
    """Tests for detect_vmm_host_role method."""

    def test_vmm_vmctl_not_installed(self, detector):
        """Test when vmctl is not installed."""
        with patch("shutil.which", return_value=None):
            result = detector.detect_vmm_host_role()

        assert result is None

    def test_vmm_no_dev_vmm(self, detector):
        """Test when /dev/vmm doesn't exist."""
        with patch("shutil.which", return_value="/usr/sbin/vmctl"):
            with patch("os.path.exists", return_value=False):
                result = detector.detect_vmm_host_role()

        assert result is None

    def test_vmm_vmd_not_running(self, detector):
        """Test when vmd is not running."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("shutil.which", return_value="/usr/sbin/vmctl"):
            with patch("os.path.exists", return_value=True):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector.detect_vmm_host_role()

        assert result is None

    def test_vmm_fully_configured(self, detector):
        """Test when VMM is fully configured and running."""
        mock_check = Mock()
        mock_check.returncode = 0

        mock_uname = Mock()
        mock_uname.returncode = 0
        mock_uname.stdout = "7.5\n"

        mock_status = Mock()
        mock_status.returncode = 0
        mock_status.stdout = "NAME  STATE  OWNER  VNCS\ntest  running  -  -\n"

        def mock_run(cmd, **_kwargs):
            if "rcctl" in cmd and "check" in cmd:
                return mock_check
            if "uname" in cmd:
                return mock_uname
            if "vmctl" in cmd and "status" in cmd:
                return mock_status
            return mock_check

        with patch("shutil.which", return_value="/usr/sbin/vmctl"):
            with patch("os.path.exists", return_value=True):
                with patch("subprocess.run", side_effect=mock_run):
                    result = detector.detect_vmm_host_role()

        assert result is not None
        assert result["role"] == "VMM Host"
        assert result["package_name"] == "vmd"
        assert result["is_active"] is True
        assert result["vm_count"] == 1

    def test_vmm_exception_handling(self, detector):
        """Test exception handling in VMM detection."""
        with patch("shutil.which", side_effect=Exception("test error")):
            result = detector.detect_vmm_host_role()

        assert result is None


class TestDetectKvmHostRole:
    """Tests for detect_kvm_host_role method."""

    def test_kvm_no_dev_kvm(self, detector):
        """Test when /dev/kvm doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = detector.detect_kvm_host_role()

        assert result is None

    def test_kvm_virsh_not_installed(self, detector):
        """Test when virsh is not installed."""
        with patch("os.path.exists", return_value=True):
            with patch("shutil.which", return_value=None):
                result = detector.detect_kvm_host_role()

        assert result is None

    def test_kvm_libvirtd_not_running(self, detector):
        """Test when libvirtd is not running."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = "inactive"

        with patch("os.path.exists", return_value=True):
            with patch("shutil.which", return_value="/usr/bin/virsh"):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector.detect_kvm_host_role()

        assert result is None

    def test_kvm_fully_configured(self, detector):
        """Test when KVM is fully configured and running."""
        mock_active = Mock()
        mock_active.returncode = 0
        mock_active.stdout = "active"

        mock_version = Mock()
        mock_version.returncode = 0
        mock_version.stdout = "9.0.0"

        mock_list = Mock()
        mock_list.returncode = 0
        mock_list.stdout = "vm1\nvm2\n"

        def mock_run(cmd, **_kwargs):
            if "is-active" in cmd:
                return mock_active
            if "--version" in cmd:
                return mock_version
            if "list" in cmd:
                return mock_list
            return mock_active

        with patch("os.path.exists", return_value=True):
            with patch("shutil.which", return_value="/usr/bin/virsh"):
                with patch("subprocess.run", side_effect=mock_run):
                    result = detector.detect_kvm_host_role()

        assert result is not None
        assert result["role"] == "KVM Host"
        assert result["package_name"] == "libvirt"
        assert result["is_active"] is True
        assert result["vm_count"] == 2

    def test_kvm_exception_handling(self, detector):
        """Test exception handling in KVM detection."""
        with patch("os.path.exists", side_effect=Exception("test error")):
            result = detector.detect_kvm_host_role()

        assert result is None


class TestDetectBhyveHostRole:
    """Tests for detect_bhyve_host_role method."""

    def test_bhyve_not_installed(self, detector):
        """Test when bhyvectl is not installed."""
        with patch("shutil.which", return_value=None):
            result = detector.detect_bhyve_host_role()

        assert result is None

    def test_bhyve_vmm_not_loaded(self, detector):
        """Test when vmm.ko is not loaded."""
        with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
            with patch("os.path.isdir", return_value=False):
                result = detector.detect_bhyve_host_role()

        assert result is None

    def test_bhyve_fully_configured(self, detector):
        """Test when bhyve is fully configured."""
        mock_uname = Mock()
        mock_uname.returncode = 0
        mock_uname.stdout = "14.0-RELEASE"

        def mock_isdir(path):
            return path == "/dev/vmm"

        def mock_listdir(path):
            if path == "/dev/vmm":
                return ["vm1", "vm2"]
            return []

        def mock_exists(path):
            if path == "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd":
                return True
            return False

        with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
            with patch("os.path.isdir", side_effect=mock_isdir):
                with patch("os.listdir", side_effect=mock_listdir):
                    with patch("os.path.exists", side_effect=mock_exists):
                        with patch("subprocess.run", return_value=mock_uname):
                            result = detector.detect_bhyve_host_role()

        assert result is not None
        assert result["role"] == "bhyve Host"
        assert result["package_name"] == "bhyve"
        assert result["is_active"] is True
        assert result["vm_count"] == 2
        assert result["uefi_available"] is True

    def test_bhyve_no_uefi(self, detector):
        """Test when bhyve is configured but UEFI is not available."""
        mock_uname = Mock()
        mock_uname.returncode = 0
        mock_uname.stdout = "14.0-RELEASE"

        def mock_isdir(path):
            return path == "/dev/vmm"

        def mock_listdir(_path):
            return []

        with patch("shutil.which", return_value="/usr/sbin/bhyvectl"):
            with patch("os.path.isdir", side_effect=mock_isdir):
                with patch("os.listdir", side_effect=mock_listdir):
                    with patch("os.path.exists", return_value=False):
                        with patch("subprocess.run", return_value=mock_uname):
                            result = detector.detect_bhyve_host_role()

        assert result is not None
        assert result["uefi_available"] is False

    def test_bhyve_exception_handling(self, detector):
        """Test exception handling in bhyve detection."""
        with patch("shutil.which", side_effect=Exception("test error")):
            result = detector.detect_bhyve_host_role()

        assert result is None
