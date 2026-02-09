"""
Tests for antivirus platform-specific detection methods.
Tests detection of antivirus software on Linux, macOS, Windows, and BSD platforms.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector


@pytest.fixture
def collector():
    """Create an AntivirusCollector instance for testing."""
    return AntivirusCollector()


class TestDetectLinuxAntivirus:
    """Tests for _detect_linux_antivirus method."""

    def test_detect_linux_clamav(self, collector):
        """Test detection of ClamAV on Linux."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": "clamav",
                "install_path": "/usr/bin/clamscan",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector._detect_linux_antivirus()

        assert result["software_name"] == "clamav"

    def test_detect_linux_chkrootkit(self, collector):
        """Test detection of chkrootkit on Linux."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_chkrootkit",
                return_value={
                    "software_name": "chkrootkit",
                    "install_path": "/usr/bin/chkrootkit",
                    "version": "0.55",
                    "enabled": True,
                },
            ):
                result = collector._detect_linux_antivirus()

        assert result["software_name"] == "chkrootkit"

    def test_detect_linux_rkhunter(self, collector):
        """Test detection of rkhunter on Linux."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_chkrootkit",
                return_value={
                    "software_name": None,
                    "install_path": None,
                    "version": None,
                    "enabled": None,
                },
            ):
                with patch.object(
                    collector,
                    "_check_rkhunter",
                    return_value={
                        "software_name": "rkhunter",
                        "install_path": "/usr/bin/rkhunter",
                        "version": "1.4.6",
                        "enabled": True,
                    },
                ):
                    result = collector._detect_linux_antivirus()

        assert result["software_name"] == "rkhunter"

    def test_detect_linux_none_found(self, collector):
        """Test detection when no antivirus is found on Linux."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_chkrootkit",
                return_value={
                    "software_name": None,
                    "install_path": None,
                    "version": None,
                    "enabled": None,
                },
            ):
                with patch.object(
                    collector,
                    "_check_rkhunter",
                    return_value={
                        "software_name": None,
                        "install_path": None,
                        "version": None,
                        "enabled": None,
                    },
                ):
                    result = collector._detect_linux_antivirus()

        assert result["software_name"] is None


class TestDetectMacosAntivirus:
    """Tests for _detect_macos_antivirus method."""

    def test_detect_macos_clamav_with_brew_service(self, collector):
        """Test detection of ClamAV on macOS with brew service running."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": "clamav",
                "install_path": "/opt/homebrew/bin/clamscan",
                "version": "1.0.0",
                "enabled": False,
            },
        ):
            with patch.object(
                collector,
                "_is_brew_service_running",
                return_value=True,
            ):
                result = collector._detect_macos_antivirus()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is True

    def test_detect_macos_clamav_without_brew_service(self, collector):
        """Test detection of ClamAV on macOS without brew service running."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": "clamav",
                "install_path": "/opt/homebrew/bin/clamscan",
                "version": "1.0.0",
                "enabled": False,
            },
        ):
            with patch.object(
                collector,
                "_is_brew_service_running",
                return_value=False,
            ):
                result = collector._detect_macos_antivirus()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is False

    def test_detect_macos_none_found(self, collector):
        """Test detection when no antivirus is found on macOS."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            result = collector._detect_macos_antivirus()

        assert result["software_name"] is None


class TestDetectWindowsAntivirus:
    """Tests for _detect_windows_antivirus method."""

    def test_detect_windows_clamav(self, collector):
        """Test detection of ClamAV on Windows."""
        with patch.object(
            collector,
            "_check_clamav_windows",
            return_value={
                "software_name": "clamav",
                "install_path": "C:\\Program Files\\ClamAV\\clamscan.exe",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector._detect_windows_antivirus()

        assert result["software_name"] == "clamav"

    def test_detect_windows_none_found(self, collector):
        """Test detection when no antivirus is found on Windows."""
        with patch.object(
            collector,
            "_check_clamav_windows",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            result = collector._detect_windows_antivirus()

        assert result["software_name"] is None


class TestDetectBsdAntivirus:
    """Tests for _detect_bsd_antivirus method."""

    def test_detect_bsd_clamav(self, collector):
        """Test detection of ClamAV on BSD."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": "clamav",
                "install_path": "/usr/local/bin/clamscan",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector._detect_bsd_antivirus()

        assert result["software_name"] == "clamav"

    def test_detect_freebsd_rkhunter(self, collector):
        """Test detection of rkhunter on FreeBSD."""
        collector.system = "FreeBSD"

        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_rkhunter",
                return_value={
                    "software_name": "rkhunter",
                    "install_path": "/usr/local/bin/rkhunter",
                    "version": "1.4.6",
                    "enabled": True,
                },
            ):
                result = collector._detect_bsd_antivirus()

        assert result["software_name"] == "rkhunter"

    def test_detect_netbsd_rkhunter(self, collector):
        """Test detection of rkhunter on NetBSD."""
        collector.system = "NetBSD"

        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_rkhunter",
                return_value={
                    "software_name": "rkhunter",
                    "install_path": "/usr/pkg/bin/rkhunter",
                    "version": "1.4.6",
                    "enabled": True,
                },
            ):
                result = collector._detect_bsd_antivirus()

        assert result["software_name"] == "rkhunter"

    def test_detect_openbsd_no_rkhunter_check(self, collector):
        """Test that rkhunter is not checked on OpenBSD."""
        collector.system = "OpenBSD"

        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            result = collector._detect_bsd_antivirus()

        # OpenBSD doesn't check rkhunter, so should return empty
        assert result["software_name"] is None
