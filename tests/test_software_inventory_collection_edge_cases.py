"""
Test edge cases and error handling for software_inventory_collection.py.
Focused on improving test coverage by targeting uncovered paths.
"""

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.software_inventory_collection import (
    SoftwareInventoryCollector,
)


class TestSoftwareInventoryCollectorEdgeCases:  # pylint: disable=too-many-public-methods
    """Test edge cases and error handling for SoftwareInventoryCollector."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test environment."""
        # pylint: disable=attribute-defined-outside-init
        self.collector = SoftwareInventoryCollector()

    def test_command_exists_timeout_exception(self):
        """Test command_exists with timeout exception."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("test", 5)):
            result = self.collector._command_exists("fake_command")
            assert result is False

    def test_command_exists_file_not_found(self):
        """Test command_exists with FileNotFoundError."""
        with patch(
            "subprocess.run", side_effect=FileNotFoundError("Command not found")
        ):
            result = self.collector._command_exists("fake_command")
            assert result is False

    def test_command_exists_os_error(self):
        """Test command_exists with OSError."""
        with patch("subprocess.run", side_effect=OSError("OS error")):
            result = self.collector._command_exists("fake_command")
            assert result is False

    def test_command_exists_pkg_info_special_case(self):
        """Test special case handling for pkg_info command."""
        mock_result = Mock()
        mock_result.returncode = 1  # Usage error - acceptable for pkg_info

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = self.collector._command_exists("pkg_info")

            assert result is True
            mock_run.assert_called_once_with(
                ["pkg_info"],
                capture_output=True,
                timeout=5,
                check=False,
            )

    def test_collect_linux_packages_unsupported_platform(self):
        """Test collecting packages on unsupported platform."""
        # Mock platform to return unsupported system
        with patch.object(self.collector, "platform", "unsupported"):
            result = self.collector.get_software_inventory()

            assert result["total_packages"] == 0
            assert result["platform"] == "unsupported"

    def test_collect_apt_packages_subprocess_error(self):
        """Test apt package collection with subprocess error."""
        # Mock platform detection to return apt available
        with patch.object(
            self.collector, "_detect_package_managers", return_value=["apt"]
        ):
            with patch("subprocess.run", side_effect=Exception("Subprocess error")):
                # Should not raise exception, should handle gracefully
                self.collector._collect_apt_packages()
                assert len(self.collector.collected_packages) == 0

    def test_collect_snap_packages_malformed_output(self):
        """Test snap package collection with malformed output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Name\tVersion\tRev\tTracking\nmalformed line"

        with patch("subprocess.run", return_value=mock_result):
            self.collector._collect_snap_packages()
            # Should handle malformed lines gracefully
            assert len(self.collector.collected_packages) == 0

    def test_collect_flatpak_packages_empty_output(self):
        """Test flatpak package collection with empty output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Name\tApp ID\tVersion\tSize\tOrigin\n"  # Header only

        with patch("subprocess.run", return_value=mock_result):
            self.collector._collect_flatpak_packages()
            assert len(self.collector.collected_packages) == 0

    def test_parse_size_string_edge_cases(self):
        """Test _parse_size_string with various edge cases."""
        # Test None input
        assert self.collector._parse_size_string(None) is None

        # Test empty string
        assert self.collector._parse_size_string("") is None

        # Test whitespace only
        assert self.collector._parse_size_string("   ") is None

        # Test invalid format
        assert self.collector._parse_size_string("invalid") is None

        # Test with valid formats
        assert self.collector._parse_size_string("1.5 MB") == 1572864
        assert self.collector._parse_size_string("2 GB") == 2147483648
        assert self.collector._parse_size_string("100") == 100  # No unit

        # Test exception handling
        with patch("re.match", side_effect=AttributeError("Regex error")):
            assert self.collector._parse_size_string("1 MB") is None

    def test_collect_homebrew_packages_error_handling(self):
        """Test homebrew package collection error handling."""
        with patch("subprocess.run", side_effect=Exception("Homebrew error")):
            # Should not raise exception
            self.collector._collect_homebrew_packages()
            assert len(self.collector.collected_packages) == 0

    def test_collect_macos_applications_file_operations_error(self):
        """Test macOS applications collection with file operation errors."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", side_effect=OSError("Permission denied")):
                # Should handle OS errors gracefully
                self.collector._collect_macos_applications()
                assert len(self.collector.collected_packages) == 0

    def test_collect_macos_app_store_json_decode_error(self):
        """Test Mac App Store collection with JSON decode error."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json"

        with patch("subprocess.run", return_value=mock_result):
            # Should handle JSON decode error gracefully
            self.collector._collect_macos_app_store()
            assert len(self.collector.collected_packages) == 0

    def test_collect_dnf_packages_no_packages_section(self):
        """Test DNF package collection with output missing packages section."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Some header\nBut no Installed Packages line"

        with patch("subprocess.run", return_value=mock_result):
            self.collector._collect_dnf_packages()
            assert len(self.collector.collected_packages) == 0

    def test_collect_winget_packages_no_header_found(self):
        """Test winget package collection when header line is not found."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Some output\nWithout proper headers\nMore data"

        with patch("subprocess.run", return_value=mock_result):
            self.collector._collect_winget_packages()
            assert len(self.collector.collected_packages) == 0

    def test_collect_pkg_packages_both_commands_fail(self):
        """Test pkg package collection when both FreeBSD and OpenBSD commands fail."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            self.collector._collect_pkg_packages()
            assert len(self.collector.collected_packages) == 0

    def test_is_system_package_linux_edge_cases(self):
        """Test Linux system package detection with edge cases."""
        # Test empty string
        assert not self.collector._is_system_package_linux("")

        # Test None (should handle gracefully)
        with pytest.raises(AttributeError):
            self.collector._is_system_package_linux(None)

        # Test system packages
        assert self.collector._is_system_package_linux("libssl1.1")
        assert self.collector._is_system_package_linux("python3-pip")
        assert self.collector._is_system_package_linux("linux-headers")

        # Test non-system packages
        assert not self.collector._is_system_package_linux("firefox")
        assert not self.collector._is_system_package_linux("user-application")

    def test_is_bsd_system_package_edge_cases(self):
        """Test BSD system package detection with edge cases."""
        # Test case sensitivity
        assert self.collector._is_bsd_system_package("LIB-something")  # Mixed case
        assert self.collector._is_bsd_system_package("Python-module")  # Capital P

        # Test non-system packages
        assert not self.collector._is_bsd_system_package("firefox")
        assert not self.collector._is_bsd_system_package("user-app")

    def test_package_manager_cache_functionality(self):
        """Test package manager detection caching."""
        # First call should populate cache
        with patch.object(
            self.collector, "_command_exists", return_value=True
        ) as mock_cmd:
            managers1 = self.collector._detect_package_managers()
            # Store call count for comparison
            _ = mock_cmd.call_count

        # Second call should use cache
        with patch.object(
            self.collector, "_command_exists", return_value=True
        ) as mock_cmd:
            managers2 = self.collector._detect_package_managers()
            call_count2 = mock_cmd.call_count

        assert managers1 == managers2
        assert call_count2 == 0  # No new calls made due to caching

    def test_collect_apt_packages_partial_data(self):
        """Test apt package collection with incomplete data."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """package1\t1.0\tarch\tdesc\t1024
package2\t2.0\tarch
package3\t3.0"""

        with patch("subprocess.run", return_value=mock_result):
            self.collector._collect_apt_packages()

            # Should handle lines with different numbers of fields
            packages = self.collector.collected_packages
            assert len(packages) == 1  # Only first line has >= 4 fields
            assert packages[0]["package_name"] == "package1"
            assert packages[0]["size_bytes"] == 1024 * 1024  # Converted to bytes

    def test_platform_specific_collection_methods(self):
        """Test platform-specific collection method routing."""
        # Test BSD platform variants
        for bsd_platform in ["freebsd", "openbsd", "netbsd"]:
            collector = SoftwareInventoryCollector()
            collector.platform = bsd_platform

            with patch.object(collector, "_collect_bsd_packages") as mock_bsd:
                collector.get_software_inventory()
                mock_bsd.assert_called_once()

    def test_collect_pkg_info_packages_error_handling(self):
        """Test OpenBSD pkg_info collection error handling."""
        with patch("subprocess.run", side_effect=Exception("pkg_info error")):
            # Should handle exception gracefully
            self.collector._collect_pkg_info_packages()
            assert len(self.collector.collected_packages) == 0

    def test_stub_methods_coverage(self):
        """Test coverage of stub methods that are not yet implemented."""
        # These methods should not raise exceptions
        self.collector._collect_yum_packages()
        self.collector._collect_zypper_packages()
        self.collector._collect_portage_packages()
        self.collector._collect_apk_packages()
        self.collector._collect_macports_packages()
        self.collector._collect_windows_registry_programs()
        self.collector._collect_microsoft_store_apps()
        self.collector._collect_chocolatey_packages()
        self.collector._collect_scoop_packages()
        self.collector._collect_ports_packages()

        # Verify no packages were added by stub methods
        assert len(self.collector.collected_packages) == 0

    def test_package_managers_detection_partial_availability(self):
        """Test package manager detection with some commands available."""

        def mock_command_exists(cmd):
            # Only some commands exist
            return cmd in ["apt", "snap", "brew"]

        with patch.object(
            self.collector, "_command_exists", side_effect=mock_command_exists
        ):
            managers = self.collector._detect_package_managers()

            # Should detect multiple managers
            assert "apt" in managers
            assert "snap" in managers

            # Platform-specific homebrew detection
            if self.collector.platform == "darwin":
                # On macOS, homebrew should be detected if brew command exists
                # Reset cache and mock homebrew availability
                self.collector._package_managers = None
                with patch.object(
                    self.collector, "_is_homebrew_available", return_value=True
                ):
                    managers = self.collector._detect_package_managers()
                    assert "homebrew" in managers
            else:
                # On non-macOS platforms, homebrew should not be detected even if brew exists
                assert "homebrew" not in managers

            assert "flatpak" not in managers
            assert "yum" not in managers
