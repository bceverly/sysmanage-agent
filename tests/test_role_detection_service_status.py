"""
Tests for service status detection utilities.
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.role_detection_service_status import (
    is_valid_unix_username,
    ServiceStatusDetector,
)


class TestIsValidUnixUsername:
    """Tests for is_valid_unix_username function."""

    def test_valid_username(self):
        """Test valid username."""
        assert is_valid_unix_username("testuser") is True

    def test_invalid_empty(self):
        """Test empty username is invalid."""
        assert is_valid_unix_username("") is False


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def detector(logger):
    """Create a ServiceStatusDetector for testing."""
    return ServiceStatusDetector("linux", logger)


class TestServiceStatusDetectorInit:
    """Tests for ServiceStatusDetector initialization."""

    def test_init_sets_system(self, logger):
        """Test that __init__ sets system."""
        detector = ServiceStatusDetector("linux", logger)
        assert detector.system == "linux"

    def test_init_sets_logger(self, logger):
        """Test that __init__ sets logger."""
        detector = ServiceStatusDetector("linux", logger)
        assert detector.logger == logger


class TestGetServiceStatus:
    """Tests for get_service_status method."""

    def test_get_service_status_linux(self, logger):
        """Test getting service status on Linux."""
        detector = ServiceStatusDetector("linux", logger)

        with patch.object(
            detector, "_get_linux_service_status", return_value="running"
        ):
            result = detector.get_service_status("nginx")

        assert result == "running"

    def test_get_service_status_macos(self, logger):
        """Test getting service status on macOS."""
        detector = ServiceStatusDetector("darwin", logger)

        with patch.object(
            detector, "_get_macos_service_status", return_value="running"
        ):
            result = detector.get_service_status("nginx")

        assert result == "running"

    def test_get_service_status_bsd(self, logger):
        """Test getting service status on BSD."""
        detector = ServiceStatusDetector("freebsd", logger)

        with patch.object(detector, "_get_bsd_service_status", return_value="running"):
            result = detector.get_service_status("nginx")

        assert result == "running"

    def test_get_service_status_windows(self, logger):
        """Test getting service status on Windows."""
        detector = ServiceStatusDetector("windows", logger)

        with patch.object(
            detector, "_get_windows_service_status", return_value="running"
        ):
            result = detector.get_service_status("nginx")

        assert result == "running"

    def test_get_service_status_unknown_system(self, logger):
        """Test getting service status on unknown system."""
        detector = ServiceStatusDetector("unknown", logger)
        result = detector.get_service_status("nginx")

        assert result == "unknown"

    def test_get_service_status_exception(self, logger):
        """Test getting service status with exception."""
        detector = ServiceStatusDetector("linux", logger)

        with patch.object(
            detector, "_get_linux_service_status", side_effect=Exception("test")
        ):
            result = detector.get_service_status("nginx")

        assert result == "unknown"


class TestGetLinuxServiceStatus:
    """Tests for _get_linux_service_status method."""

    def test_linux_service_running_systemctl(self, detector):
        """Test Linux service running via systemctl."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "active\n"

        with patch.object(detector, "_command_exists", return_value=False):
            with patch.object(
                detector, "_get_command_path", return_value="/usr/bin/systemctl"
            ):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector._get_linux_service_status("nginx")

        assert result == "running"

    def test_linux_service_stopped_systemctl(self, detector):
        """Test Linux service stopped via systemctl."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = "inactive\n"

        with patch.object(detector, "_command_exists", return_value=False):
            with patch.object(
                detector, "_get_command_path", return_value="/usr/bin/systemctl"
            ):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector._get_linux_service_status("nginx")

        assert result == "stopped"

    def test_linux_service_snap(self, detector):
        """Test Linux service via snap."""
        with patch.object(detector, "_command_exists", return_value=True):
            with patch.object(
                detector, "_get_snap_service_status", return_value="running"
            ):
                result = detector._get_linux_service_status("charmed-mysql")

        assert result == "running"


class TestGetMacosServiceStatus:
    """Tests for _get_macos_service_status method."""

    def test_macos_service_via_brew(self, logger):
        """Test macOS service via brew services."""
        detector = ServiceStatusDetector("darwin", logger)

        with patch.object(detector, "_check_brew_services", return_value="running"):
            result = detector._get_macos_service_status("nginx")

        assert result == "running"

    def test_macos_service_via_process(self, logger):
        """Test macOS service via process check."""
        detector = ServiceStatusDetector("darwin", logger)

        with patch.object(detector, "_check_brew_services", return_value="unknown"):
            with patch.object(
                detector, "_check_process_status", return_value="running"
            ):
                result = detector._get_macos_service_status("nginx")

        assert result == "running"


class TestCheckBrewServices:
    """Tests for _check_brew_services method."""

    def test_check_brew_services_running(self, logger):
        """Test brew services shows service running."""
        detector = ServiceStatusDetector("darwin", logger)

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Name      Status  User   File
nginx     started bcuser ~/Library/LaunchAgents/homebrew.mxcl.nginx.plist
"""

        with patch.object(
            detector, "_get_command_path", return_value="/opt/homebrew/bin/brew"
        ):
            with patch("os.getuid", return_value=1000):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector._check_brew_services("nginx")

        assert result == "running"

    def test_check_brew_services_stopped(self, logger):
        """Test brew services shows service stopped."""
        detector = ServiceStatusDetector("darwin", logger)

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Name      Status  User   File
nginx     stopped
"""

        with patch.object(
            detector, "_get_command_path", return_value="/opt/homebrew/bin/brew"
        ):
            with patch("os.getuid", return_value=1000):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector._check_brew_services("nginx")

        assert result == "stopped"

    def test_check_brew_services_no_brew(self, logger):
        """Test brew services when brew not found."""
        detector = ServiceStatusDetector("darwin", logger)

        with patch.object(detector, "_get_command_path", return_value=None):
            result = detector._check_brew_services("nginx")

        assert result == "unknown"


class TestCheckProcessStatus:
    """Tests for _check_process_status method."""

    def test_process_running(self, detector):
        """Test process is running."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "root  12345  nginx: master process\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._check_process_status("nginx")

        assert result == "running"

    def test_process_not_running(self, detector):
        """Test process is not running."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "user  12345  bash\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._check_process_status("nginx")

        assert result == "stopped"

    def test_postgres_process_running(self, detector):
        """Test PostgreSQL process detection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "postgres 12345 postgres: checkpointer\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._check_process_status("postgresql")

        assert result == "running"


class TestGetBsdServiceStatus:
    """Tests for _get_bsd_service_status method."""

    def test_bsd_service_running_via_process(self, logger):
        """Test BSD service running via process check."""
        detector = ServiceStatusDetector("freebsd", logger)

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "root  12345  nginx: master process\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._get_bsd_service_status("nginx")

        assert result == "running"

    def test_bsd_service_stopped(self, logger):
        """Test BSD service stopped."""
        detector = ServiceStatusDetector("freebsd", logger)

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "user  12345  bash\n"

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(detector, "_get_command_path", return_value=None):
                result = detector._get_bsd_service_status("nginx")

        assert result == "stopped"


class TestGetSnapServiceStatus:
    """Tests for _get_snap_service_status method."""

    def test_snap_service_running(self, detector):
        """Test snap service running."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Service                    Startup  Current  Notes
charmed-mysql.mysqld       enabled  active   -
"""

        with patch.object(detector, "_get_command_path", return_value="/usr/bin/snap"):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._get_snap_service_status("charmed-mysql.mysqld")

        assert result == "running"

    def test_snap_service_stopped(self, detector):
        """Test snap service stopped."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Service                    Startup  Current  Notes
charmed-mysql.mysqld       enabled  inactive -
"""

        with patch.object(detector, "_get_command_path", return_value="/usr/bin/snap"):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._get_snap_service_status("charmed-mysql.mysqld")

        assert result == "stopped"


class TestGetWindowsServiceStatus:
    """Tests for _get_windows_service_status method."""

    def test_windows_service_running(self, logger):
        """Test Windows service running."""
        detector = ServiceStatusDetector("windows", logger)

        with patch.object(
            detector, "_check_single_service_pattern", return_value="running"
        ):
            result = detector._get_windows_service_status("postgresql")

        assert result == "running"

    def test_windows_service_unknown(self, logger):
        """Test Windows service unknown."""
        detector = ServiceStatusDetector("windows", logger)

        with patch.object(
            detector, "_check_single_service_pattern", return_value="unknown"
        ):
            result = detector._get_windows_service_status("postgresql")

        assert result == "unknown"


class TestMatchesServicePattern:
    """Tests for _matches_service_pattern method."""

    def test_exact_match(self, detector):
        """Test exact match."""
        result = detector._matches_service_pattern("nginx", "nginx")
        assert result is True

    def test_case_insensitive_match(self, detector):
        """Test case insensitive match."""
        result = detector._matches_service_pattern("NGINX", "nginx")
        assert result is True

    def test_wildcard_match(self, detector):
        """Test wildcard match."""
        result = detector._matches_service_pattern(
            "postgresql-x64-14", "postgresql-x64-*"
        )
        assert result is True

    def test_substring_match(self, detector):
        """Test substring match."""
        result = detector._matches_service_pattern("postgresql-server", "postgresql")
        assert result is True

    def test_no_match(self, detector):
        """Test no match."""
        result = detector._matches_service_pattern("mysql", "postgresql")
        assert result is False


class TestCommandHelpers:
    """Tests for command helper methods."""

    def test_command_exists_true(self, detector):
        """Test command exists returns True."""
        with patch("shutil.which", return_value="/usr/bin/test"):
            result = detector._command_exists("test")
        assert result is True

    def test_command_exists_false(self, detector):
        """Test command exists returns False."""
        with patch("shutil.which", return_value=None):
            result = detector._command_exists("nonexistent")
        assert result is False

    def test_get_command_path(self, detector):
        """Test getting command path."""
        with patch("shutil.which", return_value="/usr/bin/test"):
            result = detector._get_command_path("test")
        assert result == "/usr/bin/test"
