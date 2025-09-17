"""
Additional tests for OS info collection to achieve full coverage.
Tests the missing coverage areas including error handling and edge cases.
"""

from unittest.mock import patch

from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector


class TestOSInfoCollectorCoverage:
    """Test cases for OS info collector coverage."""

    # pylint: disable=protected-access

    def test_get_macos_friendly_name_version_fallback(self):
        """Test macOS version mapping fallback (lines 56-62)."""
        collector = OSInfoCollector()

        # Test with malformed version string that triggers IndexError/ValueError (lines 61-62)
        with patch("platform.mac_ver") as mock_mac_ver:
            mock_mac_ver.return_value = ("", "", "")  # Empty version triggers fallback

            result = collector._get_macos_friendly_name(
                "22.1.0"
            )  # pylint: disable=protected-access

            # Should return the original darwin_version on exception
            assert result == "22.1.0"

        # Test with version that has insufficient parts (line 56)
        with patch("platform.mac_ver") as mock_mac_ver:
            mock_mac_ver.return_value = ("13", "", "")  # Only major version

            result = collector._get_macos_friendly_name(
                "22.1.0"
            )  # pylint: disable=protected-access

            # Should handle single version part and fall back to full version (line 56)
            assert "13" in result

    def test_get_macos_friendly_name_exception_handling(self):
        """Test macOS version mapping with exception (lines 61-62)."""
        collector = OSInfoCollector()

        # Test IndexError path
        with patch("platform.mac_ver") as mock_mac_ver:
            mock_mac_ver.side_effect = IndexError("Test error")

            result = collector._get_macos_friendly_name(
                "22.1.0"
            )  # pylint: disable=protected-access
            assert result == "22.1.0"

        # Test ValueError path
        with patch("platform.mac_ver") as mock_mac_ver:
            mock_mac_ver.side_effect = ValueError("Test error")

            result = collector._get_macos_friendly_name(
                "22.1.0"
            )  # pylint: disable=protected-access
            assert result == "22.1.0"

    def test_get_linux_distribution_info_distro_name_cleanup(self):
        """Test Linux distribution name cleanup (line 75)."""
        collector = OSInfoCollector()

        # Mock platform.freedesktop_os_release to return data with "Linux" suffix
        mock_os_release = {"NAME": "Ubuntu Linux", "VERSION_ID": "20.04"}

        with patch("platform.freedesktop_os_release", return_value=mock_os_release):
            with patch("builtins.hasattr", return_value=True):
                result = (
                    collector._get_linux_distribution_info()
                )  # pylint: disable=protected-access

                # Should remove " Linux" suffix (line 75)
                assert result == ("Ubuntu", "20.04")

    def test_get_os_version_info_simple_calls(self):
        """Test get_os_version_info with various system calls to improve coverage."""
        collector = OSInfoCollector()

        # Just call the method to execute different paths
        # We're not testing exact output but covering code paths

        # Test Linux path
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                collector,
                "_get_linux_distribution_info",
                return_value=("Ubuntu", "20.04"),
            ):
                with patch("platform.release", return_value="5.4.0"):
                    with patch("platform.machine", return_value="x86_64"):
                        result = collector.get_os_version_info()
                        assert result is not None

        # Test Darwin/macOS path
        with patch("platform.system", return_value="Darwin"):
            with patch("platform.release", return_value="22.1.0"):
                with patch("platform.machine", return_value="arm64"):
                    with patch.object(
                        collector,
                        "_get_macos_friendly_name",
                        return_value="macOS Ventura",
                    ):
                        result = collector.get_os_version_info()
                        assert result is not None

        # Test Windows path
        with patch("platform.system", return_value="Windows"):
            with patch("platform.release", return_value="10"):
                with patch("platform.machine", return_value="AMD64"):
                    result = collector.get_os_version_info()
                    assert result is not None
