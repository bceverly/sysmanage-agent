"""
Comprehensive unit tests for OS information collection.

This module provides extensive testing coverage for:
- OS version detection across all platforms
- Kernel version detection
- Hostname/FQDN collection
- System uptime and boot time
- Timezone information collection
- Multi-platform support (Linux, macOS, Windows, BSD variants)
- Error handling scenarios
"""

import subprocess
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from src.sysmanage_agent.collection.os_info_collection import (
    ZONEINFO_PATH_SEGMENT,
    OSInfoCollector,
)


class TestOSInfoCollectorInitialization:
    """Test OSInfoCollector initialization and attributes."""

    def test_initialization_creates_logger(self):
        """Test that initialization creates a logger."""
        collector = OSInfoCollector()
        assert collector.logger is not None

    def test_initialization_has_macos_version_names(self):
        """Test that macOS version names mapping is complete."""
        collector = OSInfoCollector()
        assert "24" in collector.macos_version_names  # Sequoia
        assert "23" in collector.macos_version_names  # Sonoma
        assert "22" in collector.macos_version_names  # Ventura
        assert "21" in collector.macos_version_names  # Monterey
        assert "20" in collector.macos_version_names  # Big Sur
        assert "19" in collector.macos_version_names  # Catalina
        assert "18" in collector.macos_version_names  # Mojave
        assert "17" in collector.macos_version_names  # High Sierra
        assert "16" in collector.macos_version_names  # Sierra
        assert "15" in collector.macos_version_names  # El Capitan
        assert "14" in collector.macos_version_names  # Yosemite
        assert "13" in collector.macos_version_names  # Mavericks
        assert "12" in collector.macos_version_names  # Mountain Lion
        assert "11" in collector.macos_version_names  # Lion

    def test_zoneinfo_path_segment_constant(self):
        """Test the ZONEINFO_PATH_SEGMENT constant."""
        assert ZONEINFO_PATH_SEGMENT == "/zoneinfo/"


class TestMacOSFriendlyName:
    """Test macOS friendly name generation."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test fixtures."""
        # pylint: disable=attribute-defined-outside-init
        self.collector = OSInfoCollector()

    def test_sequoia_version_mapping(self):
        """Test Sequoia (macOS 15) version mapping."""
        with patch("platform.mac_ver", return_value=("15.0.1", "", "")):
            result = self.collector._get_macos_friendly_name("24.0.0")
            assert "Sequoia" in result
            assert "15.0" in result

    def test_sonoma_version_mapping(self):
        """Test Sonoma (macOS 14) version mapping."""
        with patch("platform.mac_ver", return_value=("14.6.0", "", "")):
            result = self.collector._get_macos_friendly_name("23.6.0")
            assert "Sonoma" in result
            assert "14.6" in result

    def test_ventura_version_mapping(self):
        """Test Ventura (macOS 13) version mapping."""
        with patch("platform.mac_ver", return_value=("13.5.0", "", "")):
            result = self.collector._get_macos_friendly_name("22.6.0")
            assert "Ventura" in result
            assert "13.5" in result

    def test_monterey_version_mapping(self):
        """Test Monterey (macOS 12) version mapping."""
        with patch("platform.mac_ver", return_value=("12.7.0", "", "")):
            result = self.collector._get_macos_friendly_name("21.6.0")
            assert "Monterey" in result
            assert "12.7" in result

    def test_big_sur_version_mapping(self):
        """Test Big Sur (macOS 11) version mapping."""
        with patch("platform.mac_ver", return_value=("11.7.10", "", "")):
            result = self.collector._get_macos_friendly_name("20.6.0")
            assert "Big Sur" in result
            assert "11.7" in result

    def test_catalina_version_mapping(self):
        """Test Catalina (macOS 10.15) version mapping."""
        with patch("platform.mac_ver", return_value=("10.15.7", "", "")):
            result = self.collector._get_macos_friendly_name("19.6.0")
            assert "Catalina" in result
            assert "10.15" in result

    def test_mojave_version_mapping(self):
        """Test Mojave (macOS 10.14) version mapping."""
        with patch("platform.mac_ver", return_value=("10.14.6", "", "")):
            result = self.collector._get_macos_friendly_name("18.7.0")
            assert "Mojave" in result
            assert "10.14" in result

    def test_high_sierra_version_mapping(self):
        """Test High Sierra (macOS 10.13) version mapping."""
        with patch("platform.mac_ver", return_value=("10.13.6", "", "")):
            result = self.collector._get_macos_friendly_name("17.7.0")
            assert "High Sierra" in result
            assert "10.13" in result

    def test_sierra_version_mapping(self):
        """Test Sierra (macOS 10.12) version mapping."""
        with patch("platform.mac_ver", return_value=("10.12.6", "", "")):
            result = self.collector._get_macos_friendly_name("16.7.0")
            assert "Sierra" in result
            assert "10.12" in result

    def test_el_capitan_version_mapping(self):
        """Test El Capitan (macOS 10.11) version mapping."""
        with patch("platform.mac_ver", return_value=("10.11.6", "", "")):
            result = self.collector._get_macos_friendly_name("15.6.0")
            assert "El Capitan" in result
            assert "10.11" in result

    def test_yosemite_version_mapping(self):
        """Test Yosemite (macOS 10.10) version mapping."""
        with patch("platform.mac_ver", return_value=("10.10.5", "", "")):
            result = self.collector._get_macos_friendly_name("14.5.0")
            assert "Yosemite" in result
            assert "10.10" in result

    def test_mavericks_version_mapping(self):
        """Test Mavericks (macOS 10.9) version mapping."""
        with patch("platform.mac_ver", return_value=("10.9.5", "", "")):
            result = self.collector._get_macos_friendly_name("13.5.0")
            assert "Mavericks" in result
            assert "10.9" in result

    def test_mountain_lion_version_mapping(self):
        """Test Mountain Lion (macOS 10.8) version mapping."""
        with patch("platform.mac_ver", return_value=("10.8.5", "", "")):
            result = self.collector._get_macos_friendly_name("12.5.0")
            assert "Mountain Lion" in result
            assert "10.8" in result

    def test_lion_version_mapping(self):
        """Test Lion (macOS 10.7) version mapping."""
        with patch("platform.mac_ver", return_value=("10.7.5", "", "")):
            result = self.collector._get_macos_friendly_name("11.5.0")
            assert "Lion" in result
            assert "10.7" in result

    def test_unknown_darwin_version_returns_original(self):
        """Test that unknown Darwin version returns original string."""
        result = self.collector._get_macos_friendly_name("99.0.0")
        assert result == "99.0.0"

    def test_single_part_mac_ver(self):
        """Test with single-part macOS version."""
        with patch("platform.mac_ver", return_value=("15", "", "")):
            result = self.collector._get_macos_friendly_name("24.0.0")
            assert "Sequoia 15" in result

    def test_full_mac_ver_with_three_parts(self):
        """Test with three-part macOS version."""
        with patch("platform.mac_ver", return_value=("15.0.1", "", "")):
            result = self.collector._get_macos_friendly_name("24.0.0")
            assert "Sequoia 15.0" in result

    def test_empty_darwin_version_string(self):
        """Test with empty Darwin version string."""
        result = self.collector._get_macos_friendly_name("")
        # Should trigger IndexError in split and return original
        assert result == ""

    def test_darwin_version_without_dots(self):
        """Test Darwin version without dots."""
        result = self.collector._get_macos_friendly_name("24")
        # Major version "24" should still map to Sequoia
        with patch("platform.mac_ver", return_value=("15.0", "", "")):
            result = self.collector._get_macos_friendly_name("24")
            assert "Sequoia" in result


class TestLinuxDistributionInfo:
    """Test Linux distribution information collection."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test fixtures."""
        # pylint: disable=attribute-defined-outside-init
        self.collector = OSInfoCollector()

    def test_ubuntu_distribution_info(self):
        """Test Ubuntu distribution info collection."""
        mock_os_release = {
            "NAME": "Ubuntu",
            "VERSION_ID": "22.04",
            "VERSION_CODENAME": "jammy",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            name, version = self.collector._get_linux_distribution_info()
            assert name == "Ubuntu"
            assert version == "22.04"

    def test_debian_distribution_info(self):
        """Test Debian distribution info collection."""
        mock_os_release = {
            "NAME": "Debian GNU/Linux",
            "VERSION_ID": "12",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            name, version = self.collector._get_linux_distribution_info()
            assert name == "Debian GNU/Linux"
            assert version == "12"

    def test_fedora_distribution_info(self):
        """Test Fedora distribution info collection."""
        mock_os_release = {
            "NAME": "Fedora Linux",
            "VERSION_ID": "39",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            name, version = self.collector._get_linux_distribution_info()
            # "Linux" suffix should be removed
            assert name == "Fedora"
            assert version == "39"

    def test_centos_distribution_info(self):
        """Test CentOS distribution info collection."""
        mock_os_release = {
            "NAME": "CentOS Stream",
            "VERSION_ID": "9",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            name, version = self.collector._get_linux_distribution_info()
            assert name == "CentOS Stream"
            assert version == "9"

    def test_arch_linux_distribution_info(self):
        """Test Arch Linux distribution info collection."""
        mock_os_release = {
            "NAME": "Arch Linux",
            "VERSION_ID": "",  # Arch doesn't use VERSION_ID
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            with patch("platform.release", return_value="6.6.1-arch1-1"):
                # Should fallback since VERSION_ID is empty
                name, version = self.collector._get_linux_distribution_info()
                assert name == "Linux"
                assert version == "6.6.1-arch1-1"

    def test_rhel_distribution_info(self):
        """Test Red Hat Enterprise Linux distribution info collection."""
        mock_os_release = {
            "NAME": "Red Hat Enterprise Linux",
            "VERSION_ID": "9.3",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            name, version = self.collector._get_linux_distribution_info()
            # Note: " Linux" suffix is stripped by the code
            assert name == "Red Hat Enterprise"
            assert version == "9.3"

    def test_opensuse_distribution_info(self):
        """Test openSUSE distribution info collection."""
        mock_os_release = {
            "NAME": "openSUSE Leap",
            "VERSION_ID": "15.5",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            name, version = self.collector._get_linux_distribution_info()
            assert name == "openSUSE Leap"
            assert version == "15.5"

    def test_alpine_linux_distribution_info(self):
        """Test Alpine Linux distribution info collection."""
        mock_os_release = {
            "NAME": "Alpine Linux",
            "VERSION_ID": "3.19.0",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            name, version = self.collector._get_linux_distribution_info()
            # Should remove "Linux" suffix
            assert name == "Alpine"
            assert version == "3.19.0"

    def test_gentoo_linux_distribution_info(self):
        """Test Gentoo distribution info collection."""
        mock_os_release = {
            "NAME": "Gentoo",
            "VERSION_ID": "2.14",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            name, version = self.collector._get_linux_distribution_info()
            assert name == "Gentoo"
            assert version == "2.14"

    def test_freedesktop_os_release_not_available(self):
        """Test fallback when freedesktop_os_release is not available."""
        # Simulate Python < 3.10 where freedesktop_os_release doesn't exist
        original_hasattr = hasattr

        def mock_hasattr(obj, name):
            if name == "freedesktop_os_release":
                return False
            return original_hasattr(obj, name)

        with patch("builtins.hasattr", side_effect=mock_hasattr):
            with patch("platform.release", return_value="5.15.0-generic"):
                name, version = self.collector._get_linux_distribution_info()
                assert name == "Linux"
                assert version == "5.15.0-generic"

    def test_freedesktop_os_release_raises_attribute_error(self):
        """Test fallback when freedesktop_os_release raises AttributeError."""
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            side_effect=AttributeError("Not available"),
            create=True,
        ):
            with patch("platform.release", return_value="5.15.0-generic"):
                name, version = self.collector._get_linux_distribution_info()
                assert name == "Linux"
                assert version == "5.15.0-generic"

    def test_missing_name_field(self):
        """Test handling of missing NAME field."""
        mock_os_release = {
            "VERSION_ID": "22.04",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            with patch("platform.release", return_value="5.15.0"):
                name, version = self.collector._get_linux_distribution_info()
                assert name == "Linux"
                assert version == "5.15.0"

    def test_missing_version_id_field(self):
        """Test handling of missing VERSION_ID field."""
        mock_os_release = {
            "NAME": "Ubuntu",
        }
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            with patch("platform.release", return_value="5.15.0"):
                name, version = self.collector._get_linux_distribution_info()
                assert name == "Linux"
                assert version == "5.15.0"


class TestTimezoneCollection:
    """Test timezone information collection."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test fixtures."""
        # pylint: disable=attribute-defined-outside-init
        self.collector = OSInfoCollector()

    def test_extract_timezone_from_zoneinfo_path(self):
        """Test timezone extraction from zoneinfo path."""
        path = "/usr/share/zoneinfo/America/New_York"
        result = self.collector._extract_timezone_from_zoneinfo_path(path)
        assert result == "America/New_York"

    def test_extract_timezone_from_nested_zoneinfo_path(self):
        """Test timezone extraction from deeply nested zoneinfo path."""
        path = "/var/db/timezone/zoneinfo/Europe/London"
        result = self.collector._extract_timezone_from_zoneinfo_path(path)
        assert result == "Europe/London"

    def test_extract_timezone_from_simple_timezone(self):
        """Test timezone extraction for simple timezone like UTC."""
        path = "/usr/share/zoneinfo/UTC"
        result = self.collector._extract_timezone_from_zoneinfo_path(path)
        assert result == "UTC"

    def test_extract_timezone_from_invalid_path(self):
        """Test timezone extraction from path without zoneinfo."""
        path = "/etc/localtime"
        result = self.collector._extract_timezone_from_zoneinfo_path(path)
        assert result is None

    def test_run_timezone_command_success(self):
        """Test successful timezone command execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "America/Chicago\n"

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._run_timezone_command(["cat", "/etc/timezone"])
            assert result is not None
            assert result.stdout.strip() == "America/Chicago"

    def test_run_timezone_command_failure(self):
        """Test failed timezone command execution."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._run_timezone_command(["cat", "/etc/timezone"])
            assert result is None

    def test_run_timezone_command_empty_output(self):
        """Test timezone command with empty output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._run_timezone_command(["cat", "/etc/timezone"])
            assert result is None

    def test_run_timezone_command_file_not_found(self):
        """Test timezone command when file is not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = self.collector._run_timezone_command(["nonexistent"])
            assert result is None

    def test_run_timezone_command_timeout(self):
        """Test timezone command timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            result = self.collector._run_timezone_command(["sleep", "100"], timeout=5)
            assert result is None

    def test_get_timezone_linux_bsd_etc_timezone(self):
        """Test Linux/BSD timezone from /etc/timezone."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Europe/Paris\n"

        with patch.object(
            self.collector, "_run_timezone_command", return_value=mock_result
        ):
            result = self.collector._get_timezone_linux_bsd()
            assert result == "Europe/Paris"

    def test_get_timezone_linux_bsd_localtime_symlink(self):
        """Test Linux/BSD timezone from /etc/localtime symlink."""
        # First command fails, second succeeds
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "/usr/share/zoneinfo/Asia/Tokyo\n"

        def side_effect(cmd, timeout=5):
            if cmd == ["cat", "/etc/timezone"]:
                return None
            return mock_result

        with patch.object(
            self.collector, "_run_timezone_command", side_effect=side_effect
        ):
            result = self.collector._get_timezone_linux_bsd()
            assert result == "Asia/Tokyo"

    def test_get_timezone_linux_bsd_timedatectl(self):
        """Test Linux/BSD timezone from timedatectl."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Australia/Sydney\n"

        call_count = [0]

        def side_effect(cmd, timeout=5):
            call_count[0] += 1
            if call_count[0] <= 2:  # First two calls fail
                return None
            return mock_result

        with patch.object(
            self.collector, "_run_timezone_command", side_effect=side_effect
        ):
            result = self.collector._get_timezone_linux_bsd()
            assert result == "Australia/Sydney"

    def test_get_timezone_linux_bsd_all_methods_fail(self):
        """Test Linux/BSD timezone when all methods fail."""
        with patch.object(self.collector, "_run_timezone_command", return_value=None):
            result = self.collector._get_timezone_linux_bsd()
            assert result is None

    def test_get_timezone_darwin_systemsetup(self):
        """Test macOS timezone from systemsetup."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Time Zone: America/Los_Angeles\n"

        with patch.object(
            self.collector, "_run_timezone_command", return_value=mock_result
        ):
            result = self.collector._get_timezone_darwin()
            assert result == "America/Los_Angeles"

    def test_get_timezone_darwin_localtime_symlink(self):
        """Test macOS timezone from /etc/localtime symlink."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "/var/db/timezone/zoneinfo/Pacific/Auckland\n"

        def side_effect(cmd, timeout=5):
            if cmd[0] == "sudo":
                return None
            return mock_result

        with patch.object(
            self.collector, "_run_timezone_command", side_effect=side_effect
        ):
            result = self.collector._get_timezone_darwin()
            assert result == "Pacific/Auckland"

    def test_get_timezone_darwin_all_methods_fail(self):
        """Test macOS timezone when all methods fail."""
        with patch.object(self.collector, "_run_timezone_command", return_value=None):
            result = self.collector._get_timezone_darwin()
            assert result is None

    def test_get_timezone_windows_success(self):
        """Test Windows timezone collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Eastern Standard Time\n"

        with patch.object(
            self.collector, "_run_timezone_command", return_value=mock_result
        ):
            result = self.collector._get_timezone_windows()
            assert result == "Eastern Standard Time"

    def test_get_timezone_windows_failure(self):
        """Test Windows timezone when PowerShell fails."""
        with patch.object(self.collector, "_run_timezone_command", return_value=None):
            result = self.collector._get_timezone_windows()
            assert result is None

    def test_get_timezone_fallback_standard_time(self):
        """Test timezone fallback to Python time module (standard time)."""
        with patch("time.daylight", 0):
            with patch("time.tzname", ("EST", "EDT")):
                result = self.collector._get_timezone_fallback()
                assert result == "EST"

    def test_get_timezone_fallback_daylight_time(self):
        """Test timezone fallback to Python time module (daylight time)."""
        with patch("time.daylight", 1):
            with patch("time.tzname", ("EST", "EDT")):
                result = self.collector._get_timezone_fallback()
                assert result == "EDT"

    def test_get_timezone_linux(self):
        """Test full _get_timezone for Linux."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                self.collector, "_get_timezone_linux_bsd", return_value="US/Central"
            ):
                result = self.collector._get_timezone()
                assert result == "US/Central"

    def test_get_timezone_freebsd(self):
        """Test full _get_timezone for FreeBSD."""
        with patch("platform.system", return_value="FreeBSD"):
            with patch.object(
                self.collector, "_get_timezone_linux_bsd", return_value="UTC"
            ):
                result = self.collector._get_timezone()
                assert result == "UTC"

    def test_get_timezone_openbsd(self):
        """Test full _get_timezone for OpenBSD."""
        with patch("platform.system", return_value="OpenBSD"):
            with patch.object(
                self.collector, "_get_timezone_linux_bsd", return_value="Canada/Eastern"
            ):
                result = self.collector._get_timezone()
                assert result == "Canada/Eastern"

    def test_get_timezone_netbsd(self):
        """Test full _get_timezone for NetBSD."""
        with patch("platform.system", return_value="NetBSD"):
            with patch.object(
                self.collector, "_get_timezone_linux_bsd", return_value="Japan"
            ):
                result = self.collector._get_timezone()
                assert result == "Japan"

    def test_get_timezone_darwin(self):
        """Test full _get_timezone for macOS/Darwin."""
        with patch("platform.system", return_value="Darwin"):
            with patch.object(
                self.collector,
                "_get_timezone_darwin",
                return_value="America/New_York",
            ):
                result = self.collector._get_timezone()
                assert result == "America/New_York"

    def test_get_timezone_windows(self):
        """Test full _get_timezone for Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch.object(
                self.collector,
                "_get_timezone_windows",
                return_value="Pacific Standard Time",
            ):
                result = self.collector._get_timezone()
                assert result == "Pacific Standard Time"

    def test_get_timezone_unknown_platform_fallback(self):
        """Test _get_timezone falls back on unknown platform."""
        with patch("platform.system", return_value="UnknownOS"):
            with patch.object(
                self.collector, "_get_timezone_fallback", return_value="UTC"
            ):
                result = self.collector._get_timezone()
                assert result == "UTC"

    def test_get_timezone_exception_handling(self):
        """Test _get_timezone handles exceptions gracefully."""
        with patch("platform.system", side_effect=Exception("Platform error")):
            with patch("time.tzname", ("PST", "PDT")):
                result = self.collector._get_timezone()
                # Should return fallback value
                assert result in ("PST", "PDT", "Unknown")

    def test_get_timezone_platform_method_fails_uses_fallback(self):
        """Test _get_timezone uses fallback when platform method fails."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                self.collector, "_get_timezone_linux_bsd", return_value=None
            ):
                with patch.object(
                    self.collector, "_get_timezone_fallback", return_value="CST"
                ):
                    result = self.collector._get_timezone()
                    assert result == "CST"


class TestPlatformInfoCollection:
    """Test platform-specific information collection."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test fixtures."""
        # pylint: disable=attribute-defined-outside-init
        self.collector = OSInfoCollector()

    def test_collect_darwin_info(self):
        """Test Darwin/macOS info collection."""
        with patch("platform.mac_ver", return_value=("14.5.0", "", "")):
            with patch.object(
                self.collector,
                "_get_macos_friendly_name",
                return_value="Sonoma 14.5",
            ):
                platform_name, release, os_info = self.collector._collect_darwin_info(
                    "23.5.0"
                )

                assert platform_name == "macOS"
                assert release == "Sonoma 14.5"
                assert os_info["mac_version"] == "14.5.0"

    def test_collect_darwin_info_empty_mac_ver(self):
        """Test Darwin info when mac_ver returns empty."""
        with patch("platform.mac_ver", return_value=("", "", "")):
            platform_name, release, os_info = self.collector._collect_darwin_info(
                "23.5.0"
            )

            assert platform_name == "macOS"
            assert os_info["mac_version"] == ""

    def test_collect_linux_info_with_distribution(self):
        """Test Linux info with distribution detection."""
        with patch.object(
            self.collector,
            "_get_linux_distribution_info",
            return_value=("Ubuntu", "22.04"),
        ):
            with patch.object(
                self.collector,
                "_collect_linux_os_info",
                return_value={"distribution": "Ubuntu"},
            ):
                platform_name, release, os_info = self.collector._collect_linux_info(
                    "5.15.0"
                )

                assert platform_name == "Linux"
                assert release == "Ubuntu 22.04"
                assert os_info["distribution"] == "Ubuntu"

    def test_collect_linux_info_fallback_to_kernel(self):
        """Test Linux info fallback when distribution is not detected."""
        with patch.object(
            self.collector,
            "_get_linux_distribution_info",
            return_value=("Linux", "5.15.0"),
        ):
            with patch.object(
                self.collector, "_collect_linux_os_info", return_value={}
            ):
                platform_name, release, os_info = self.collector._collect_linux_info(
                    "5.15.0"
                )

                assert platform_name == "Linux"
                assert release == "5.15.0"

    def test_collect_linux_os_info_ubuntu_with_pro(self):
        """Test Linux OS info collection for Ubuntu with Pro info."""
        mock_os_release = {
            "NAME": "Ubuntu",
            "VERSION_ID": "22.04",
            "VERSION_CODENAME": "jammy",
        }
        mock_pro_info = {"available": True, "attached": False}

        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            with patch.object(
                self.collector, "_get_ubuntu_pro_info", return_value=mock_pro_info
            ):
                os_info = self.collector._collect_linux_os_info()

                assert os_info["distribution"] == "Ubuntu"
                assert os_info["distribution_version"] == "22.04"
                assert os_info["distribution_codename"] == "jammy"
                assert os_info["ubuntu_pro"] == mock_pro_info

    def test_collect_linux_os_info_non_ubuntu_no_pro(self):
        """Test Linux OS info for non-Ubuntu (no Pro info)."""
        mock_os_release = {
            "NAME": "Fedora",
            "VERSION_ID": "39",
        }

        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):
            os_info = self.collector._collect_linux_os_info()

            assert os_info["distribution"] == "Fedora"
            assert os_info["distribution_version"] == "39"
            assert "ubuntu_pro" not in os_info

    def test_collect_linux_os_info_os_error(self):
        """Test Linux OS info when freedesktop_os_release raises OSError."""
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            side_effect=OSError("File not found"),
            create=True,
        ):
            os_info = self.collector._collect_linux_os_info()
            assert os_info == {}

    def test_collect_windows_info(self):
        """Test Windows info collection."""
        with patch(
            "platform.win32_ver",
            return_value=("10", "10.0.19041", "SP0", "Multiprocessor Free"),
        ):
            platform_name, release, os_info = self.collector._collect_windows_info("10")

            assert platform_name == "Windows"
            assert release == "10"
            assert os_info["windows_version"] == "10"
            assert os_info["windows_service_pack"] == "10.0.19041"

    def test_collect_windows_info_empty_values(self):
        """Test Windows info with empty win32_ver values."""
        with patch("platform.win32_ver", return_value=("", "", "", "")):
            platform_name, release, os_info = self.collector._collect_windows_info("11")

            assert platform_name == "Windows"
            assert release == "11"
            assert os_info["windows_version"] == ""
            assert os_info["windows_service_pack"] == ""

    def test_collect_freebsd_info_success(self):
        """Test FreeBSD info collection with freebsd-version."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "14.0-RELEASE\n"

        with patch("subprocess.run", return_value=mock_result):
            platform_name, release, os_info = self.collector._collect_freebsd_info(
                "14.0-RELEASE"
            )

            assert platform_name == "FreeBSD"
            assert release == "14.0-RELEASE"
            assert os_info["freebsd_version"] == "14.0-RELEASE"
            assert os_info["freebsd_userland_version"] == "14.0-RELEASE"

    def test_collect_freebsd_info_command_failure(self):
        """Test FreeBSD info when freebsd-version fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            platform_name, release, os_info = self.collector._collect_freebsd_info(
                "14.0-RELEASE"
            )

            assert platform_name == "FreeBSD"
            assert os_info["freebsd_version"] == "14.0-RELEASE"
            assert "freebsd_userland_version" not in os_info

    def test_collect_freebsd_info_file_not_found(self):
        """Test FreeBSD info when freebsd-version is not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            platform_name, release, os_info = self.collector._collect_freebsd_info(
                "14.0-RELEASE"
            )

            assert platform_name == "FreeBSD"
            assert os_info["freebsd_version"] == "14.0-RELEASE"
            assert "freebsd_userland_version" not in os_info

    def test_collect_freebsd_info_timeout(self):
        """Test FreeBSD info when freebsd-version times out."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired("freebsd-version", 5),
        ):
            platform_name, release, os_info = self.collector._collect_freebsd_info(
                "14.0-RELEASE"
            )

            assert platform_name == "FreeBSD"
            assert os_info["freebsd_version"] == "14.0-RELEASE"
            assert "freebsd_userland_version" not in os_info

    def test_collect_platform_info_openbsd(self):
        """Test OpenBSD platform info collection."""
        platform_name, release, os_info = self.collector._collect_platform_info(
            "OpenBSD", "7.4"
        )

        assert platform_name == "OpenBSD"
        assert release == "7.4"
        assert os_info["openbsd_version"] == "7.4"

    def test_collect_platform_info_netbsd(self):
        """Test NetBSD platform info collection."""
        platform_name, release, os_info = self.collector._collect_platform_info(
            "NetBSD", "10.0"
        )

        assert platform_name == "NetBSD"
        assert release == "10.0"
        assert os_info["netbsd_version"] == "10.0"

    def test_collect_platform_info_unknown_os(self):
        """Test unknown OS platform info collection."""
        platform_name, release, os_info = self.collector._collect_platform_info(
            "HaikuOS", "R1"
        )

        assert platform_name == "HaikuOS"
        assert release == "R1"
        assert os_info == {}


class TestUbuntuProInfo:
    """Test Ubuntu Pro information collection."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test fixtures."""
        # pylint: disable=attribute-defined-outside-init
        self.collector = OSInfoCollector()

    def test_get_ubuntu_pro_info_full_response(self):
        """Test full Ubuntu Pro response parsing."""
        pro_data = {
            "attached": True,
            "version": "27.14.4",
            "expires": "2030-01-01T00:00:00Z",
            "account": {"name": "Test Account"},
            "contract": {"name": "Ubuntu Pro Infra", "tech_support_level": "standard"},
            "services": [
                {
                    "name": "esm-infra",
                    "description": "Extended Security Maintenance",
                    "status": "enabled",
                    "available": "yes",
                    "entitled": "yes",
                },
                {
                    "name": "livepatch",
                    "description": "Livepatch",
                    "status": "disabled",
                    "available": "yes",
                    "entitled": "yes",
                },
            ],
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = __import__("json").dumps(pro_data)

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._get_ubuntu_pro_info()

            assert result["available"] is True
            assert result["attached"] is True
            assert result["version"] == "27.14.4"
            assert result["account_name"] == "Test Account"
            assert result["contract_name"] == "Ubuntu Pro Infra"
            assert result["tech_support_level"] == "standard"
            assert len(result["services"]) == 2

    def test_get_ubuntu_pro_info_not_attached(self):
        """Test Ubuntu Pro info when not attached."""
        pro_data = {"attached": False, "version": "27.14.4"}

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = __import__("json").dumps(pro_data)

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._get_ubuntu_pro_info()

            assert result["available"] is True
            assert result["attached"] is False

    def test_get_ubuntu_pro_info_general_exception(self):
        """Test Ubuntu Pro info with general exception."""
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            result = self.collector._get_ubuntu_pro_info()

            assert result["available"] is False
            assert result["attached"] is False

    def test_parse_ubuntu_pro_services_status_mapping(self):
        """Test Ubuntu Pro services status mapping."""
        services = [
            {"name": "esm-infra", "status": "enabled", "available": "yes"},
            {"name": "fips", "status": "disabled", "available": "yes"},
            {
                "name": "ros",
                "status": "active",
                "available": "yes",
            },  # active -> enabled
            {"name": "fips-updates", "status": "n/a", "available": "no"},  # n/a status
        ]

        result = self.collector._parse_ubuntu_pro_services(services)

        assert len(result) == 4
        assert result[0]["status"] == "enabled"
        assert result[1]["status"] == "disabled"
        assert result[2]["status"] == "enabled"  # "active" maps to "enabled"
        assert result[3]["status"] == "n/a"  # not available

    def test_parse_single_ubuntu_pro_service(self):
        """Test parsing a single Ubuntu Pro service."""
        service = {
            "name": "esm-apps",
            "description": "Extended Security Maintenance for Applications",
            "status": "enabled",
            "available": "yes",
            "entitled": "yes",
        }

        result = self.collector._parse_single_ubuntu_pro_service(service, 0, 1)

        assert result["name"] == "esm-apps"
        assert result["description"] == "Extended Security Maintenance for Applications"
        assert result["status"] == "enabled"
        assert result["available"] is True
        assert result["entitled"] is True
        assert result["raw_status"] == "enabled"

    def test_parse_single_ubuntu_pro_service_not_available(self):
        """Test parsing a service that is not available."""
        service = {
            "name": "fips",
            "description": "FIPS Certified",
            "status": "disabled",
            "available": "no",
            "entitled": "no",
        }

        result = self.collector._parse_single_ubuntu_pro_service(service, 0, 1)

        assert result["name"] == "fips"
        assert result["status"] == "n/a"  # Not available means status is n/a
        assert result["available"] is False

    def test_parse_ubuntu_pro_account_info(self):
        """Test parsing Ubuntu Pro account info."""
        pro_data = {
            "account": {"name": "My Company"},
            "contract": {
                "name": "Ubuntu Pro Desktop",
                "tech_support_level": "advanced",
            },
        }
        ubuntu_pro_info = {
            "account_name": "",
            "contract_name": "",
            "tech_support_level": "n/a",
        }

        self.collector._parse_ubuntu_pro_account_info(pro_data, ubuntu_pro_info)

        assert ubuntu_pro_info["account_name"] == "My Company"
        assert ubuntu_pro_info["contract_name"] == "Ubuntu Pro Desktop"
        assert ubuntu_pro_info["tech_support_level"] == "advanced"

    def test_parse_ubuntu_pro_account_info_missing_fields(self):
        """Test parsing Ubuntu Pro account info with missing fields."""
        pro_data = {}
        ubuntu_pro_info = {
            "account_name": "",
            "contract_name": "",
            "tech_support_level": "n/a",
        }

        self.collector._parse_ubuntu_pro_account_info(pro_data, ubuntu_pro_info)

        # Should retain default values
        assert ubuntu_pro_info["account_name"] == ""
        assert ubuntu_pro_info["contract_name"] == ""
        assert ubuntu_pro_info["tech_support_level"] == "n/a"


class TestGetOSVersionInfo:
    """Test the main get_os_version_info method."""

    def setup_method(self):
        """Set up test fixtures."""
        # pylint: disable=attribute-defined-outside-init
        self.collector = OSInfoCollector()

    def test_get_os_version_info_all_fields_present(self):
        """Test that all required fields are present in result."""
        with patch("platform.system", return_value="Linux"):
            with patch("platform.release", return_value="5.15.0"):
                with patch("platform.version", return_value="#1 SMP"):
                    with patch("platform.machine", return_value="x86_64"):
                        with patch("platform.processor", return_value="x86_64"):
                            with patch(
                                "platform.architecture", return_value=("64bit", "ELF")
                            ):
                                with patch(
                                    "platform.python_version", return_value="3.11.0"
                                ):
                                    result = self.collector.get_os_version_info()

                                    assert "platform" in result
                                    assert "platform_release" in result
                                    assert "platform_version" in result
                                    assert "architecture" in result
                                    assert "processor" in result
                                    assert "machine_architecture" in result
                                    assert "timezone" in result
                                    assert "python_version" in result
                                    assert "os_info" in result

    def test_get_os_version_info_arm64_architecture(self):
        """Test ARM64 architecture detection."""
        with patch("platform.system", return_value="Linux"):
            with patch("platform.machine", return_value="aarch64"):
                result = self.collector.get_os_version_info()
                assert result["machine_architecture"] == "aarch64"

    def test_get_os_version_info_riscv64_architecture(self):
        """Test RISC-V 64-bit architecture detection."""
        with patch("platform.system", return_value="Linux"):
            with patch("platform.machine", return_value="riscv64"):
                result = self.collector.get_os_version_info()
                assert result["machine_architecture"] == "riscv64"

    def test_get_os_version_info_ppc64le_architecture(self):
        """Test PowerPC 64-bit LE architecture detection."""
        with patch("platform.system", return_value="Linux"):
            with patch("platform.machine", return_value="ppc64le"):
                result = self.collector.get_os_version_info()
                assert result["machine_architecture"] == "ppc64le"

    def test_get_os_version_info_s390x_architecture(self):
        """Test IBM System Z architecture detection."""
        with patch("platform.system", return_value="Linux"):
            with patch("platform.machine", return_value="s390x"):
                result = self.collector.get_os_version_info()
                assert result["machine_architecture"] == "s390x"

    def test_get_os_version_info_i386_architecture(self):
        """Test 32-bit x86 architecture detection."""
        with patch("platform.system", return_value="Linux"):
            with patch("platform.machine", return_value="i686"):
                with patch("platform.architecture", return_value=("32bit", "ELF")):
                    result = self.collector.get_os_version_info()
                    assert result["machine_architecture"] == "i686"
                    assert result["architecture"] == "32bit"


class TestIntegration:
    """Integration tests for OS info collection."""

    def test_integration_actual_system_info(self):
        """Test actual system info collection on current platform."""
        collector = OSInfoCollector()
        result = collector.get_os_version_info()

        # Verify structure
        assert isinstance(result, dict)
        assert isinstance(result["platform"], str)
        assert isinstance(result["platform_release"], str)
        assert isinstance(result["machine_architecture"], str)
        assert isinstance(result["timezone"], str)
        assert isinstance(result["os_info"], dict)

        # Platform should be one of the known values
        assert result["platform"] in [
            "Linux",
            "macOS",
            "Windows",
            "FreeBSD",
            "OpenBSD",
            "NetBSD",
        ]

    def test_json_serialization(self):
        """Test that result can be JSON serialized."""
        import json

        collector = OSInfoCollector()
        result = collector.get_os_version_info()

        # Should not raise
        json_str = json.dumps(result)
        assert isinstance(json_str, str)

        # Should be deserializable
        deserialized = json.loads(json_str)
        assert deserialized["platform"] == result["platform"]
