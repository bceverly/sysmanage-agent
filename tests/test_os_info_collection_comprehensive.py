# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

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

# pylint: disable=protected-access,import-outside-toplevel

from unittest.mock import patch

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
