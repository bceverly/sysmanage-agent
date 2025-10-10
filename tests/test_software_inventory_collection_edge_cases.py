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
from src.sysmanage_agent.collection.software_inventory_windows import (
    WindowsSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_bsd import (
    BSDSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_macos import (
    MacOSSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_linux import (
    LinuxSoftwareInventoryCollector,
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
        # Mock platform.system to return unsupported OS
        with patch("platform.system", return_value="UnknownOS"):
            unsupported_collector = SoftwareInventoryCollector()
            result = unsupported_collector.get_software_inventory()

            assert result["total_packages"] == 0
            assert result["platform"] == "unknownos"
            assert result["error"] == "Unsupported platform"

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
            macos_collector = MacOSSoftwareInventoryCollector()
            macos_collector._collect_homebrew_packages()
            assert len(macos_collector.collected_packages) == 0

    def test_collect_macos_applications_file_operations_error(self):
        """Test macOS applications collection with file operation errors."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", side_effect=OSError("Permission denied")):
                # Should handle OS errors gracefully
                macos_collector = MacOSSoftwareInventoryCollector()
                macos_collector._collect_macos_applications()
                assert len(macos_collector.collected_packages) == 0

    def test_collect_macos_app_store_json_decode_error(self):
        """Test Mac App Store collection with JSON decode error."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json"

        with patch("subprocess.run", return_value=mock_result):
            # Should handle JSON decode error gracefully
            macos_collector = MacOSSoftwareInventoryCollector()
            macos_collector._collect_macos_app_store()
            assert len(macos_collector.collected_packages) == 0

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
            windows_collector = WindowsSoftwareInventoryCollector()
            windows_collector._collect_winget_packages()
            assert len(windows_collector.collected_packages) == 0

    def test_collect_pkg_packages_both_commands_fail(self):
        """Test pkg package collection when both FreeBSD and OpenBSD commands fail."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            bsd_collector = BSDSoftwareInventoryCollector()
            bsd_collector._collect_pkg_packages()
            assert len(bsd_collector.collected_packages) == 0

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
        bsd_collector = BSDSoftwareInventoryCollector()

        # Test case sensitivity
        assert bsd_collector._is_bsd_system_package("LIB-something")  # Mixed case
        assert bsd_collector._is_bsd_system_package("Python-module")  # Capital P

        # Test non-system packages
        assert not bsd_collector._is_bsd_system_package("firefox")
        assert not bsd_collector._is_bsd_system_package("user-app")

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

            with patch.object(collector.collector, "collect_packages") as mock_collect:

                def mock_collect_side_effect(
                    coll=collector,
                ):  # pylint: disable=cell-var-from-loop
                    coll.collector.collected_packages = []

                mock_collect.side_effect = mock_collect_side_effect

                collector.get_software_inventory()
                mock_collect.assert_called_once()

    def test_collect_pkg_info_packages_error_handling(self):
        """Test OpenBSD pkg_info collection error handling."""
        with patch("subprocess.run", side_effect=Exception("pkg_info error")):
            # Should handle exception gracefully
            bsd_collector = BSDSoftwareInventoryCollector()
            bsd_collector._collect_pkg_info_packages()
            assert len(bsd_collector.collected_packages) == 0

    def test_stub_methods_coverage(self):
        """Test coverage of stub methods that are not yet implemented."""
        # Test Linux stub methods
        linux_collector = LinuxSoftwareInventoryCollector()
        linux_collector._collect_yum_packages()
        linux_collector._collect_portage_packages()
        linux_collector._collect_apk_packages()

        # Test macOS stub methods
        macos_collector = MacOSSoftwareInventoryCollector()
        macos_collector._collect_macports_packages()

        # Test Windows stub methods
        windows_collector = WindowsSoftwareInventoryCollector()
        windows_collector._collect_windows_registry_programs()
        windows_collector._collect_microsoft_store_apps()
        windows_collector._collect_chocolatey_packages()
        windows_collector._collect_scoop_packages()

        # Test BSD stub methods
        bsd_collector = BSDSoftwareInventoryCollector()
        bsd_collector._collect_ports_packages()

        # Verify no packages were added by stub methods
        assert len(linux_collector.collected_packages) == 0
        assert len(macos_collector.collected_packages) == 0
        assert len(windows_collector.collected_packages) == 0
        assert len(bsd_collector.collected_packages) == 0

    def test_package_managers_detection_partial_availability(self):
        """Test package manager detection with some commands available."""

        # Test Linux package manager detection
        linux_collector = LinuxSoftwareInventoryCollector()

        def mock_command_exists_linux(cmd):
            return cmd in ["apt", "snap"]

        with patch.object(
            linux_collector, "_command_exists", side_effect=mock_command_exists_linux
        ):
            managers = linux_collector.detect_package_managers()

            # Should detect multiple managers
            assert "apt" in managers
            assert "snap" in managers
            assert "flatpak" not in managers
            assert "yum" not in managers

        # Test macOS package manager detection
        macos_collector = MacOSSoftwareInventoryCollector()

        with patch.object(macos_collector, "_is_homebrew_available", return_value=True):
            managers = macos_collector.detect_package_managers()
            assert "homebrew" in managers

        with patch.object(
            macos_collector, "_is_homebrew_available", return_value=False
        ):
            macos_collector._package_managers = None  # Reset cache
            managers = macos_collector.detect_package_managers()
            assert "homebrew" not in managers
