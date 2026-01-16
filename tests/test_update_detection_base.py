"""
Tests for base update detection module.
"""

# pylint: disable=redefined-outer-name,protected-access

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_base import (
    UpdateDetectorBase,
)


@pytest.fixture
def detector():
    """Create an UpdateDetectorBase for testing."""
    return UpdateDetectorBase()


class TestUpdateDetectorBaseInit:
    """Tests for UpdateDetectorBase initialization."""

    def test_init_sets_platform(self, detector):
        """Test that __init__ sets platform."""
        with patch("platform.system", return_value="Linux"):
            detector = UpdateDetectorBase()
            assert detector.platform == "linux"

    def test_init_sets_empty_available_updates(self, detector):
        """Test that __init__ sets empty available_updates list."""
        assert detector.available_updates == []

    def test_init_sets_package_managers_to_none(self, detector):
        """Test that __init__ sets _package_managers to None."""
        assert detector._package_managers is None


class TestCommandExists:
    """Tests for _command_exists method."""

    def test_command_exists_returns_true(self, detector):
        """Test _command_exists returns True for existing command."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = detector._command_exists("test_cmd")

        assert result is True

    def test_command_exists_returns_false_file_not_found(self, detector):
        """Test _command_exists returns False for non-existent command."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = detector._command_exists("nonexistent")

        assert result is False

    def test_command_exists_returns_false_timeout(self, detector):
        """Test _command_exists returns False on timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            result = detector._command_exists("slow_cmd")

        assert result is False


class TestFormatSizeMb:
    """Tests for _format_size_mb method."""

    def test_format_size_mb_basic(self, detector):
        """Test basic size formatting to MB."""
        result = detector._format_size_mb(1048576)  # 1 MB in bytes
        assert result == 1.0

    def test_format_size_mb_decimal(self, detector):
        """Test size formatting with decimal result."""
        result = detector._format_size_mb(1572864)  # 1.5 MB
        assert result == 1.5

    def test_format_size_mb_none_input(self, detector):
        """Test formatting None input returns None."""
        result = detector._format_size_mb(None)
        assert result is None

    def test_format_size_mb_zero(self, detector):
        """Test formatting zero returns 0."""
        result = detector._format_size_mb(0)
        assert result == 0

    def test_format_size_mb_invalid_type(self, detector):
        """Test formatting invalid type returns None."""
        result = detector._format_size_mb("invalid")
        assert result is None


class TestDetectPackageManagers:
    """Tests for _detect_package_managers method."""

    def test_detect_package_managers_apt(self, detector):
        """Test detection of apt package manager."""
        with patch.object(detector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "apt"
            with patch.object(detector, "_is_homebrew_available", return_value=False):
                result = detector._detect_package_managers()

        assert "apt" in result

    def test_detect_package_managers_snap(self, detector):
        """Test detection of snap package manager."""
        with patch.object(detector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "snap"
            with patch.object(detector, "_is_homebrew_available", return_value=False):
                result = detector._detect_package_managers()

        assert "snap" in result

    def test_detect_package_managers_homebrew(self, detector):
        """Test detection of Homebrew package manager."""
        with patch.object(detector, "_command_exists", return_value=False):
            with patch.object(detector, "_is_homebrew_available", return_value=True):
                result = detector._detect_package_managers()

        assert "homebrew" in result

    def test_detect_package_managers_cached(self, detector):
        """Test that package managers are cached."""
        detector._package_managers = ["apt", "snap"]
        result = detector._detect_package_managers()

        assert result == ["apt", "snap"]

    def test_detect_package_managers_bsd_pkg(self, detector):
        """Test detection of BSD pkg package manager."""
        with patch.object(detector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "pkg"
            with patch.object(detector, "_is_homebrew_available", return_value=False):
                result = detector._detect_package_managers()

        assert "pkg" in result


class TestIsHomebrewAvailable:
    """Tests for _is_homebrew_available method."""

    def test_homebrew_available_apple_silicon(self, detector):
        """Test Homebrew detection on Apple Silicon."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._is_homebrew_available()

        assert result is True

    def test_homebrew_not_available(self, detector):
        """Test when Homebrew is not available."""
        with patch("os.path.exists", return_value=False):
            result = detector._is_homebrew_available()

        assert result is False

    def test_homebrew_available_but_fails(self, detector):
        """Test when Homebrew exists but fails to run."""
        mock_result = Mock()
        mock_result.returncode = 1

        def mock_exists(path):
            return path == "/opt/homebrew/bin/brew"

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._is_homebrew_available()

        assert result is False


class TestGetHomebrewOwner:
    """Tests for _get_homebrew_owner method."""

    def test_get_homebrew_owner_success(self, detector):
        """Test getting Homebrew owner successfully."""
        mock_stat = Mock()
        mock_stat.st_uid = 1000

        mock_pwd = Mock()
        mock_pwd.pw_name = "testuser"

        with patch("os.path.exists", return_value=True):
            with patch("os.stat", return_value=mock_stat):
                with patch("pwd.getpwuid", return_value=mock_pwd):
                    result = detector._get_homebrew_owner()

        assert result == "testuser"

    def test_get_homebrew_owner_not_found(self, detector):
        """Test getting Homebrew owner when not found."""
        with patch("os.path.exists", return_value=False):
            result = detector._get_homebrew_owner()

        assert result == ""


class TestGetBrewCommand:
    """Tests for _get_brew_command method."""

    def test_get_brew_command_not_root(self, detector):
        """Test getting brew command when not running as root."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            with patch("os.geteuid", return_value=1000):  # Non-root
                result = detector._get_brew_command()

        assert result in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew", "brew"]

    def test_get_brew_command_as_root(self, detector):
        """Test getting brew command when running as root."""
        mock_result = Mock()
        mock_result.returncode = 0

        def mock_exists(path):
            return path == "/opt/homebrew/bin/brew"

        with patch("subprocess.run", return_value=mock_result):
            with patch("os.geteuid", return_value=0):  # Root
                with patch("os.path.exists", side_effect=mock_exists):
                    with patch.object(
                        detector, "_get_homebrew_owner", return_value="testuser"
                    ):
                        result = detector._get_brew_command()

        assert "sudo -u testuser" in result or result == "/opt/homebrew/bin/brew"

    def test_get_brew_command_fallback(self, detector):
        """Test brew command fallback."""
        with patch("subprocess.run", side_effect=Exception("test")):
            result = detector._get_brew_command()

        assert result == "brew"


class TestCheckRebootRequired:
    """Tests for check_reboot_required method."""

    def test_reboot_required_file_exists(self, detector):
        """Test reboot required when file exists on Linux."""
        detector.platform = "linux"

        with patch("os.path.exists", return_value=True):
            result = detector.check_reboot_required()

        assert result is True

    def test_reboot_required_kernel_update(self, detector):
        """Test reboot required for kernel update."""
        detector.platform = "linux"
        detector.available_updates = [
            {"package_name": "linux-image-5.15", "package_manager": "apt"}
        ]

        with patch("os.path.exists", return_value=False):
            result = detector.check_reboot_required()

        assert result is True

    def test_reboot_required_firmware_update(self, detector):
        """Test reboot required for firmware update."""
        detector.platform = "linux"
        detector.available_updates = [
            {"package_name": "firmware-update", "package_manager": "fwupd"}
        ]

        with patch("os.path.exists", return_value=False):
            result = detector.check_reboot_required()

        assert result is True

    def test_reboot_required_macos_system_update(self, detector):
        """Test reboot required for macOS system update."""
        detector.platform = "darwin"
        detector.available_updates = [
            {"package_name": "macOS Sequoia", "is_system_update": True}
        ]

        result = detector.check_reboot_required()

        assert result is True

    def test_reboot_required_windows(self, detector):
        """Test reboot required for Windows with any update."""
        detector.platform = "windows"
        detector.available_updates = [{"package_name": "KB12345"}]

        result = detector.check_reboot_required()

        assert result is True

    def test_reboot_not_required(self, detector):
        """Test reboot not required when no conditions match."""
        detector.platform = "linux"
        detector.available_updates = [{"package_name": "vim", "package_manager": "apt"}]

        with patch("os.path.exists", return_value=False):
            result = detector.check_reboot_required()

        assert result is False


class TestDetectBestPackageManager:
    """Tests for _detect_best_package_manager method."""

    def test_detect_best_linux_apt(self, detector):
        """Test detecting best package manager on Linux (apt)."""
        detector.platform = "linux"

        with patch.object(
            detector, "_detect_package_managers", return_value=["apt", "snap"]
        ):
            result = detector._detect_best_package_manager()

        assert result == "apt"

    def test_detect_best_linux_dnf(self, detector):
        """Test detecting best package manager on Linux (dnf)."""
        detector.platform = "linux"

        with patch.object(
            detector, "_detect_package_managers", return_value=["dnf", "snap"]
        ):
            result = detector._detect_best_package_manager()

        assert result == "dnf"

    def test_detect_best_macos_homebrew(self, detector):
        """Test detecting best package manager on macOS."""
        detector.platform = "darwin"

        with patch.object(
            detector, "_detect_package_managers", return_value=["homebrew", "macports"]
        ):
            result = detector._detect_best_package_manager()

        assert result == "homebrew"

    def test_detect_best_windows_winget(self, detector):
        """Test detecting best package manager on Windows."""
        detector.platform = "windows"

        with patch.object(
            detector, "_detect_package_managers", return_value=["winget", "chocolatey"]
        ):
            result = detector._detect_best_package_manager()

        assert result == "winget"

    def test_detect_best_bsd_pkg(self, detector):
        """Test detecting best package manager on BSD."""
        detector.platform = "freebsd"

        with patch.object(
            detector, "_detect_package_managers", return_value=["pkg", "pkgin"]
        ):
            result = detector._detect_best_package_manager()

        assert result == "pkg"

    def test_detect_best_no_managers(self, detector):
        """Test when no package managers are available."""
        detector.platform = "linux"

        with patch.object(detector, "_detect_package_managers", return_value=[]):
            result = detector._detect_best_package_manager()

        assert result == ""

    def test_detect_best_fallback(self, detector):
        """Test fallback to first available manager."""
        detector.platform = "unknown"

        with patch.object(
            detector, "_detect_package_managers", return_value=["custom_pm"]
        ):
            result = detector._detect_best_package_manager()

        assert result == "custom_pm"
