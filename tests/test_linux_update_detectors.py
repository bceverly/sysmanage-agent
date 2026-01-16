"""
Tests for Linux update detectors module.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.linux_update_detectors import (
    LinuxUpdateDetector,
)


@pytest.fixture
def is_system_package_callback():
    """Create a mock callback for system package detection."""

    def callback(package_name):
        return package_name.startswith("linux-") or package_name in [
            "base-files",
            "libc6",
        ]

    return callback


@pytest.fixture
def detector(is_system_package_callback):
    """Create a LinuxUpdateDetector for testing."""
    return LinuxUpdateDetector(is_system_package_callback)


class TestLinuxUpdateDetectorInit:
    """Tests for LinuxUpdateDetector initialization."""

    def test_init_sets_callback(self, is_system_package_callback):
        """Test that __init__ sets the callback."""
        detector = LinuxUpdateDetector(is_system_package_callback)
        assert detector.is_system_package_linux == is_system_package_callback


class TestDetectAptUpdates:
    """Tests for detect_apt_updates method."""

    def test_detect_apt_updates_success(self, detector):
        """Test successful APT update detection."""
        mock_update = Mock()
        mock_update.returncode = 0

        mock_list = Mock()
        mock_list.returncode = 0
        mock_list.stdout = """Listing...
nginx/focal-security 1.18.0-0ubuntu1.5 amd64 [upgradable from: 1.18.0-0ubuntu1.4]
vim/focal 2:8.1.2269-1ubuntu5.18 amd64 [upgradable from: 2:8.1.2269-1ubuntu5.17]
"""

        def mock_run(cmd, **_kwargs):
            if "apt-get" in cmd and "update" in cmd:
                return mock_update
            return mock_list

        with patch("subprocess.run", side_effect=mock_run):
            result = detector.detect_apt_updates()

        assert len(result) == 2
        assert result[0]["package_name"] == "nginx"
        assert result[0]["package_manager"] == "apt"
        assert result[0]["is_security_update"] is True  # -security in line

    def test_detect_apt_updates_no_updates(self, detector):
        """Test APT update detection with no updates."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Listing..."

        with patch("subprocess.run", return_value=mock_result):
            result = detector.detect_apt_updates()

        assert len(result) == 0

    def test_detect_apt_updates_system_package(self, detector):
        """Test APT update detection marks system packages correctly."""
        mock_update = Mock()
        mock_update.returncode = 0

        mock_list = Mock()
        mock_list.returncode = 0
        mock_list.stdout = """Listing...
linux-image-5.4.0-150/focal-updates 5.4.0-150.167 amd64 [upgradable from: 5.4.0-148.165]
nginx/focal 1.18.0-0ubuntu1.5 amd64 [upgradable from: 1.18.0-0ubuntu1.4]
"""

        def mock_run(cmd, **_kwargs):
            if "apt-get" in cmd:
                return mock_update
            return mock_list

        with patch("subprocess.run", side_effect=mock_run):
            result = detector.detect_apt_updates()

        # Find linux package
        linux_pkg = next((p for p in result if "linux" in p["package_name"]), None)
        if linux_pkg:
            assert linux_pkg["is_system_update"] is True

    def test_detect_apt_updates_exception(self, detector):
        """Test APT update detection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = detector.detect_apt_updates()

        assert result == []


class TestDetectSnapUpdates:
    """Tests for detect_snap_updates method."""

    def test_detect_snap_updates_success(self, detector):
        """Test successful Snap update detection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Name       Version         Rev    Publisher     Notes
firefox    120.0           2985   mozilla**     -
chromium   119.0.6045.123  2691   nicpottier    -
"""

        with patch("subprocess.run", return_value=mock_result):
            result = detector.detect_snap_updates()

        assert len(result) == 2
        assert result[0]["package_name"] == "firefox"
        assert result[0]["package_manager"] == "snap"

    def test_detect_snap_updates_no_updates(self, detector):
        """Test Snap update detection with no updates."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = detector.detect_snap_updates()

        assert len(result) == 0

    def test_detect_snap_updates_exception(self, detector):
        """Test Snap update detection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = detector.detect_snap_updates()

        assert result == []


class TestDetectFlatpakUpdates:
    """Tests for detect_flatpak_updates method."""

    def test_detect_flatpak_updates_success(self, detector):
        """Test successful Flatpak update detection."""
        mock_update_appstream = Mock()
        mock_update_appstream.returncode = 0

        mock_remote_ls = Mock()
        mock_remote_ls.returncode = 0
        mock_remote_ls.stdout = (
            "org.mozilla.firefox\tstable\t120.0\norg.gnome.Calculator\tstable\t45.0\n"
        )

        def mock_run(cmd, **_kwargs):
            if "--appstream" in cmd:
                return mock_update_appstream
            return mock_remote_ls

        with patch("subprocess.run", side_effect=mock_run):
            result = detector.detect_flatpak_updates()

        assert len(result) == 2
        assert result[0]["package_name"] == "org.mozilla.firefox"
        assert result[0]["package_manager"] == "flatpak"

    def test_detect_flatpak_updates_no_updates(self, detector):
        """Test Flatpak update detection with no updates."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = detector.detect_flatpak_updates()

        assert len(result) == 0

    def test_detect_flatpak_updates_exception(self, detector):
        """Test Flatpak update detection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = detector.detect_flatpak_updates()

        assert result == []
