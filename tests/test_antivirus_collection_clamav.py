"""
Tests for ClamAV-specific antivirus detection methods.
Tests ClamAV detection on Unix-like systems and Windows.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector


@pytest.fixture
def collector():
    """Create an AntivirusCollector instance for testing."""
    return AntivirusCollector()


class TestCheckClamav:
    """Tests for _check_clamav method."""

    def test_check_clamav_installed_and_running(self, collector):
        """Test ClamAV check when installed and running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0/26853/Mon Jan 1 00:00:00 2024\n"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(collector, "_is_service_running", return_value=True):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["version"] == "1.0.0"
        assert result["enabled"] is True

    def test_check_clamav_installed_not_running(self, collector):
        """Test ClamAV check when installed but not running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0/26853/Mon Jan 1 00:00:00 2024\n"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(collector, "_is_service_running", return_value=False):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is False

    def test_check_clamav_not_installed(self, collector):
        """Test ClamAV check when not installed."""
        which_result = Mock()
        which_result.returncode = 1
        which_result.stdout = ""

        with patch("subprocess.run", return_value=which_result):
            result = collector._check_clamav()

        assert result["software_name"] is None

    def test_check_clamav_version_parsing_error(self, collector):
        """Test ClamAV check with version parsing error."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 1
        version_result.stdout = ""

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(collector, "_is_service_running", return_value=False):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["version"] is None

    def test_check_clamav_exception(self, collector):
        """Test ClamAV check handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = collector._check_clamav()

        assert result["software_name"] is None


class TestCheckClamavWindows:
    """Tests for _check_clamav_windows method."""

    def test_check_clamav_windows_installed(self, collector):
        """Test ClamAV check on Windows when installed."""
        with patch("os.path.exists", side_effect=[True]):
            with patch.object(
                collector,
                "_get_clamav_windows_version",
                return_value="1.0.0",
            ):
                with patch.object(
                    collector,
                    "_is_windows_service_running",
                    return_value=True,
                ):
                    result = collector._check_clamav_windows()

        assert result["software_name"] == "clamav"
        assert result["version"] == "1.0.0"
        assert result["enabled"] is True

    def test_check_clamav_windows_second_path(self, collector):
        """Test ClamAV check on Windows in x86 path."""
        with patch("os.path.exists", side_effect=[False, True]):
            with patch.object(
                collector,
                "_get_clamav_windows_version",
                return_value="1.0.0",
            ):
                with patch.object(
                    collector,
                    "_is_windows_service_running",
                    return_value=False,
                ):
                    result = collector._check_clamav_windows()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is False

    def test_check_clamav_windows_not_installed(self, collector):
        """Test ClamAV check on Windows when not installed."""
        with patch("os.path.exists", return_value=False):
            result = collector._check_clamav_windows()

        assert result["software_name"] is None

    def test_check_clamav_windows_exception(self, collector):
        """Test ClamAV check on Windows handles exceptions."""
        with patch("os.path.exists", side_effect=Exception("Access denied")):
            result = collector._check_clamav_windows()

        assert result["software_name"] is None
