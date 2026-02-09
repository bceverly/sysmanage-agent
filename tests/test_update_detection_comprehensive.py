"""
Comprehensive unit tests for update detection module.

This module covers:
- Reboot required detection
- Security update detection
- Multi-distro support
- Update orchestration
- Error handling
- Package manager detection
- Update detector facade

Note: Linux-specific package manager tests (APT, DNF, Pacman, Zypper, Snap, Flatpak)
are in test_update_detection_linux.py

Note: BSD-specific package manager tests (pkg, pkgin, OpenBSD syspatch)
are in test_update_detection_bsd.py
"""

# pylint: disable=protected-access,redefined-outer-name,too-many-public-methods

from unittest.mock import Mock, patch, mock_open

import pytest

from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.sysmanage_agent.collection.update_detection_linux import LinuxUpdateDetector
from src.sysmanage_agent.collection.update_detection_bsd import BSDUpdateDetector
from src.sysmanage_agent.collection.update_detection_base import UpdateDetectorBase


@pytest.fixture
def linux_detector():
    """Create a LinuxUpdateDetector for testing."""
    return LinuxUpdateDetector()


@pytest.fixture
def bsd_detector():
    """Create a BSDUpdateDetector for testing."""
    return BSDUpdateDetector()


@pytest.fixture
def base_detector():
    """Create an UpdateDetectorBase for testing."""
    return UpdateDetectorBase()


# =============================================================================
# Reboot Required Detection Tests
# =============================================================================


class TestRebootRequiredDetection:
    """Tests for reboot required detection."""

    def test_linux_reboot_required_file_exists(self, base_detector):
        """Test Linux reboot detection when file exists."""
        base_detector.platform = "linux"

        with patch("os.path.exists", return_value=True):
            result = base_detector.check_reboot_required()

        assert result is True

    def test_linux_reboot_required_kernel_update(self, base_detector):
        """Test Linux reboot detection with kernel update."""
        base_detector.platform = "linux"
        base_detector.available_updates = [
            {"package_name": "linux-image-5.15.0-150", "package_manager": "apt"}
        ]

        with patch("os.path.exists", return_value=False):
            result = base_detector.check_reboot_required()

        assert result is True

    def test_linux_reboot_required_firmware_update(self, base_detector):
        """Test Linux reboot detection with firmware update."""
        base_detector.platform = "linux"
        base_detector.available_updates = [
            {"package_name": "BIOS Update", "package_manager": "fwupd"}
        ]

        with patch("os.path.exists", return_value=False):
            result = base_detector.check_reboot_required()

        assert result is True

    def test_linux_reboot_not_required(self, base_detector):
        """Test Linux reboot not required for regular packages."""
        base_detector.platform = "linux"
        base_detector.available_updates = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "nginx", "package_manager": "apt"},
        ]

        with patch("os.path.exists", return_value=False):
            result = base_detector.check_reboot_required()

        assert result is False

    def test_macos_reboot_required_system_update(self, base_detector):
        """Test macOS reboot detection with system update."""
        base_detector.platform = "darwin"
        base_detector.available_updates = [
            {"package_name": "macOS Sonoma 14.3", "is_system_update": True}
        ]

        result = base_detector.check_reboot_required()

        assert result is True

    def test_macos_reboot_not_required(self, base_detector):
        """Test macOS reboot not required for app updates."""
        base_detector.platform = "darwin"
        base_detector.available_updates = [
            {"package_name": "Firefox", "is_system_update": False}
        ]

        result = base_detector.check_reboot_required()

        assert result is False

    def test_windows_reboot_always_required(self, base_detector):
        """Test Windows reboot detection (always required with updates)."""
        base_detector.platform = "windows"
        base_detector.available_updates = [{"package_name": "KB12345"}]

        result = base_detector.check_reboot_required()

        assert result is True

    def test_windows_reboot_not_required_no_updates(self, base_detector):
        """Test Windows reboot not required when no updates."""
        base_detector.platform = "windows"
        base_detector.available_updates = []

        result = base_detector.check_reboot_required()

        assert result is False


# =============================================================================
# Security Update Detection Tests
# =============================================================================


class TestSecurityUpdateDetection:
    """Tests for security update detection."""

    def test_apt_security_from_repository(self, linux_detector):
        """Test APT security detection from repository name."""
        mock_update = Mock(returncode=0)
        mock_list = Mock(
            returncode=0,
            stdout="""Listing...
openssl/focal-security 1.1.1f-1ubuntu2.21 amd64 [upgradable from: 1.1.1f-1ubuntu2.20]
""",
        )

        def mock_run(cmd, **_kwargs):
            if "apt-get" in cmd:
                return mock_update
            if "apt-cache" in cmd:
                return Mock(returncode=0, stdout="-security")
            return mock_list

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 1
        assert linux_detector.available_updates[0]["is_security_update"] is True

    def test_dnf_security_from_updateinfo(self, linux_detector):
        """Test DNF security detection from updateinfo."""
        mock_result = Mock(returncode=0, stdout="RHSA-2024:0001 Critical security")

        with patch("subprocess.run", return_value=mock_result):
            is_security = linux_detector._is_dnf_security_update("openssl")

        assert is_security is True

    def test_openbsd_syspatch_always_security(self, bsd_detector):
        """Test that OpenBSD syspatches are always security updates."""
        mock_result = Mock(returncode=0, stdout="001_patch\n")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._detect_openbsd_system_updates()

        if bsd_detector.available_updates:
            assert bsd_detector.available_updates[0]["is_security_update"] is True


# =============================================================================
# Multi-Distro Support Tests
# =============================================================================


class TestMultiDistroSupport:
    """Tests for multi-distribution support."""

    def test_detect_distro_ubuntu(self, linux_detector):
        """Test detection of Ubuntu distribution."""
        os_release_content = """NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
"""
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            linux_detector._detect_linux_system_updates()
        # Should complete without error

    def test_detect_distro_fedora(self, linux_detector):
        """Test detection of Fedora distribution."""
        os_release_content = """NAME="Fedora Linux"
VERSION="39 (Workstation Edition)"
ID=fedora
VERSION_ID=39
"""
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            with patch("subprocess.run", return_value=Mock(returncode=0, stdout="")):
                linux_detector._detect_linux_system_updates()
        # Should complete without error

    def test_detect_distro_arch(self, linux_detector):
        """Test detection of Arch Linux distribution."""
        os_release_content = """NAME="Arch Linux"
ID=arch
"""
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            with patch("subprocess.run", return_value=Mock(returncode=0, stdout="")):
                linux_detector._detect_linux_system_updates()
        # Should complete without error

    def test_detect_distro_opensuse(self, linux_detector):
        """Test detection of openSUSE distribution."""
        os_release_content = """NAME="openSUSE Leap"
VERSION="15.5"
ID=opensuse-leap
VERSION_ID="15.5"
"""
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            with patch("subprocess.run", return_value=Mock(returncode=0, stdout="")):
                linux_detector._detect_linux_system_updates()
        # Should complete without error


# =============================================================================
# Update Orchestration Tests
# =============================================================================


class TestUpdateOrchestration:
    """Tests for update detection orchestration."""

    def test_detect_updates_calls_all_managers(self, linux_detector):
        """Test that detect_updates calls all available package managers."""
        with patch.object(
            linux_detector,
            "_detect_package_managers",
            return_value=["apt", "snap", "flatpak"],
        ):
            with patch.object(linux_detector, "_detect_apt_updates") as mock_apt:
                with patch.object(linux_detector, "_detect_snap_updates") as mock_snap:
                    with patch.object(
                        linux_detector, "_detect_flatpak_updates"
                    ) as mock_flatpak:
                        with patch.object(
                            linux_detector, "_detect_linux_system_updates"
                        ):
                            with patch.object(
                                linux_detector, "_detect_linux_version_upgrades"
                            ):
                                linux_detector.detect_updates()

        mock_apt.assert_called_once()
        mock_snap.assert_called_once()
        mock_flatpak.assert_called_once()

    def test_detect_updates_respects_available_managers(self, linux_detector):
        """Test that detect_updates only calls available package managers."""
        with patch.object(
            linux_detector, "_detect_package_managers", return_value=["apt"]
        ):  # Only apt available
            with patch.object(linux_detector, "_detect_apt_updates") as mock_apt:
                with patch.object(linux_detector, "_detect_snap_updates") as mock_snap:
                    with patch.object(linux_detector, "_detect_linux_system_updates"):
                        with patch.object(
                            linux_detector, "_detect_linux_version_upgrades"
                        ):
                            linux_detector.detect_updates()

        mock_apt.assert_called_once()
        mock_snap.assert_not_called()


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in update detection."""

    def test_handle_permission_denied(self, linux_detector):
        """Test handling of permission denied errors."""
        with patch("subprocess.run", side_effect=PermissionError("Permission denied")):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 0

    def test_handle_file_not_found(self, linux_detector):
        """Test handling of command not found errors."""
        with patch("subprocess.run", side_effect=FileNotFoundError("apt not found")):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 0

    def test_handle_general_exception(self, linux_detector):
        """Test handling of general exceptions."""
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 0

    def test_partial_failure_recovery(self, linux_detector):
        """Test that partial failures don't stop other detections."""
        call_count = 0

        def mock_run(cmd, **_kwargs):
            nonlocal call_count
            call_count += 1
            if "apt" in " ".join(cmd):
                raise RuntimeError("APT failed")
            return Mock(returncode=0, stdout="")

        with patch("subprocess.run", side_effect=mock_run):
            with patch.object(
                linux_detector, "_detect_package_managers", return_value=["apt", "snap"]
            ):
                with patch.object(linux_detector, "_detect_linux_system_updates"):
                    with patch.object(linux_detector, "_detect_linux_version_upgrades"):
                        linux_detector.detect_updates()

        # Should have attempted both apt and snap
        assert call_count >= 2


# =============================================================================
# Package Manager Detection Tests
# =============================================================================


class TestPackageManagerDetection:
    """Tests for package manager detection."""

    def test_detect_package_managers_caching(self, base_detector):
        """Test that package manager detection is cached."""
        base_detector._package_managers = ["apt", "snap"]

        result = base_detector._detect_package_managers()

        assert result == ["apt", "snap"]

    def test_detect_best_package_manager_linux(self, base_detector):
        """Test best package manager selection on Linux."""
        base_detector.platform = "linux"

        with patch.object(
            base_detector,
            "_detect_package_managers",
            return_value=["apt", "snap", "flatpak"],
        ):
            result = base_detector._detect_best_package_manager()

        assert result == "apt"

    def test_detect_best_package_manager_linux_dnf(self, base_detector):
        """Test best package manager selection preferring dnf."""
        base_detector.platform = "linux"

        with patch.object(
            base_detector, "_detect_package_managers", return_value=["dnf", "snap"]
        ):
            result = base_detector._detect_best_package_manager()

        assert result == "dnf"

    def test_detect_best_package_manager_bsd(self, base_detector):
        """Test best package manager selection on BSD."""
        base_detector.platform = "freebsd"

        with patch.object(
            base_detector, "_detect_package_managers", return_value=["pkg", "pkgin"]
        ):
            result = base_detector._detect_best_package_manager()

        assert result == "pkg"


# =============================================================================
# Update Facade Tests
# =============================================================================


class TestUpdateDetectorFacade:
    """Tests for the UpdateDetector facade class."""

    @patch("platform.system")
    def test_facade_linux_initialization(self, mock_system):
        """Test facade initializes Linux detector."""
        mock_system.return_value = "Linux"
        detector = UpdateDetector()

        assert detector.platform == "linux"
        assert isinstance(detector.detector, LinuxUpdateDetector)

    @patch("platform.system")
    def test_facade_bsd_initialization(self, mock_system):
        """Test facade initializes BSD detector."""
        mock_system.return_value = "FreeBSD"
        detector = UpdateDetector()

        assert detector.platform == "freebsd"
        assert isinstance(detector.detector, BSDUpdateDetector)

    @patch("platform.system")
    def test_facade_unsupported_platform(self, mock_system):
        """Test facade handles unsupported platform."""
        mock_system.return_value = "UnknownOS"
        detector = UpdateDetector()

        result = detector.get_available_updates()

        assert "error" in result
        assert result["total_updates"] == 0

    @patch("platform.system")
    def test_facade_attribute_delegation(self, mock_system):
        """Test facade delegates attributes to platform detector."""
        mock_system.return_value = "Linux"
        detector = UpdateDetector()

        # Should delegate to LinuxUpdateDetector
        assert hasattr(detector, "available_updates")
        assert hasattr(detector, "_detect_package_managers")

    @patch("platform.system")
    def test_facade_get_available_updates_categorization(self, mock_system):
        """Test that get_available_updates correctly categorizes updates."""
        mock_system.return_value = "Linux"
        detector = UpdateDetector()

        # Mock the detect_updates to add test updates
        def mock_detect_updates():
            detector.detector.available_updates = [
                {
                    "package_name": "openssl",
                    "is_security_update": True,
                    "is_system_update": False,
                },
                {
                    "package_name": "linux-image",
                    "is_security_update": False,
                    "is_system_update": True,
                },
                {
                    "package_name": "firefox",
                    "is_security_update": False,
                    "is_system_update": False,
                },
            ]

        with patch.object(detector.detector, "detect_updates", mock_detect_updates):
            with patch.object(
                detector.detector, "check_reboot_required", return_value=False
            ):
                result = detector.get_available_updates()

        assert result["total_updates"] == 3
        assert result["security_updates"] == 1
        assert result["system_updates"] == 1
        assert result["application_updates"] == 1
