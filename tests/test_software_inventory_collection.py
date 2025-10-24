#!/usr/bin/env python3
# pylint: disable=protected-access
"""
Tests for Software Inventory Collection Module

Comprehensive test suite covering all package managers and platforms
with 100% test coverage for software inventory functionality.
"""

import json
import subprocess
import unittest
from unittest.mock import Mock, patch

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


class TestSoftwareInventoryCollector(
    unittest.TestCase
):  # pylint: disable=too-many-public-methods
    """Test suite for SoftwareInventoryCollector class."""

    def setUp(self):
        """Set up test fixtures."""
        self.collector = SoftwareInventoryCollector()
        # Create Linux-specific collector for Linux-specific tests
        self.linux_collector = LinuxSoftwareInventoryCollector()

    def test_init(self):
        """Test collector initialization."""
        self.assertIsNotNone(self.collector.platform)
        self.assertEqual(self.collector.collected_packages, [])
        self.assertIsNone(
            self.collector._package_managers
        )  # pylint: disable=protected-access

    @patch("subprocess.run")
    def test_command_exists_true(self, mock_run):
        """Test _command_exists returns True when command exists."""
        mock_run.return_value = Mock(returncode=0)
        result = self.collector._command_exists(
            "test-command"
        )  # pylint: disable=protected-access
        self.assertTrue(result)

    @patch("subprocess.run")
    def test_command_exists_false(self, mock_run):
        """Test _command_exists returns False when command doesn't exist."""
        mock_run.side_effect = FileNotFoundError()
        result = self.collector._command_exists(
            "nonexistent-command"
        )  # pylint: disable=protected-access
        self.assertFalse(result)

    @patch("subprocess.run")
    def test_command_exists_timeout(self, mock_run):
        """Test _command_exists handles timeout gracefully."""
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 5)
        result = self.collector._command_exists(
            "slow-command"
        )  # pylint: disable=protected-access
        self.assertFalse(result)

    def test_parse_size_string_valid_sizes(self):
        """Test _parse_size_string with valid size strings."""
        test_cases = [
            ("1024 B", 1024),
            ("1 KB", 1024),
            ("1.5 MB", 1572864),
            ("2 GB", 2147483648),
            ("1 TB", 1099511627776),
            ("100", 100),
            ("", None),
            ("invalid", None),
        ]

        for size_str, expected in test_cases:
            with self.subTest(size_str=size_str):
                result = self.collector._parse_size_string(
                    size_str
                )  # pylint: disable=protected-access
                self.assertEqual(result, expected)

    def test_is_system_package_linux(self):
        """Test _is_system_package_linux classification."""
        test_cases = [
            ("libc6", True),
            ("python3-dev", True),
            ("linux-headers", True),
            ("systemd", True),
            ("base-files", True),
            ("firefox", False),
            ("user-app", False),
        ]

        for package_name, expected in test_cases:
            with self.subTest(package_name=package_name):
                result = self.linux_collector._is_system_package_linux(
                    package_name
                )  # pylint: disable=protected-access
                self.assertEqual(result, expected)

    @patch.object(SoftwareInventoryCollector, "_command_exists")
    def test_detect_package_managers(self, mock_command_exists):
        """Test package manager detection."""
        # Mock some package managers as available
        available_commands = {"apt", "snap", "brew"}
        mock_command_exists.side_effect = lambda cmd: any(
            cmd in executables
            for manager, executables in {
                "apt": ["apt", "apt-get", "dpkg"],
                "snap": ["snap"],
                "homebrew": ["brew"],
            }.items()
            if manager in ["apt", "snap", "homebrew"] and cmd in available_commands
        )

        managers = (
            self.collector._detect_package_managers()
        )  # pylint: disable=protected-access

        # Should cache the result
        cached_managers = (
            self.collector._detect_package_managers()
        )  # pylint: disable=protected-access
        self.assertEqual(managers, cached_managers)

    @patch("platform.system")
    def test_get_software_inventory_linux(self, mock_platform):
        """Test get_software_inventory for Linux platform."""
        mock_platform.return_value = "Linux"
        self.collector.platform = "linux"

        # Mock the collect method to add packages to the platform collector
        with patch.object(self.collector.collector, "collect_packages") as mock_collect:

            def mock_collect_side_effect():
                self.collector.collector.collected_packages = [
                    {"package_name": "test-package", "version": "1.0.0"}
                ]

            mock_collect.side_effect = mock_collect_side_effect

            result = self.collector.get_software_inventory()

            mock_collect.assert_called_once()
            self.assertEqual(result["platform"], "linux")
            self.assertEqual(result["total_packages"], 1)
            self.assertIn("collection_timestamp", result)
            self.assertEqual(len(result["software_packages"]), 1)

    @patch("platform.system")
    def test_get_software_inventory_macos(self, mock_platform):
        """Test get_software_inventory for macOS platform."""
        mock_platform.return_value = "Darwin"
        self.collector.platform = "darwin"

        with patch.object(self.collector.collector, "collect_packages") as mock_collect:

            def mock_collect_side_effect():
                self.collector.collector.collected_packages = []

            mock_collect.side_effect = mock_collect_side_effect

            result = self.collector.get_software_inventory()

            mock_collect.assert_called_once()
            self.assertEqual(result["platform"], "darwin")

    @patch("platform.system")
    def test_get_software_inventory_windows(self, mock_platform):
        """Test get_software_inventory for Windows platform."""
        mock_platform.return_value = "Windows"
        self.collector.platform = "windows"

        with patch.object(self.collector.collector, "collect_packages") as mock_collect:

            def mock_collect_side_effect():
                self.collector.collector.collected_packages = []

            mock_collect.side_effect = mock_collect_side_effect

            result = self.collector.get_software_inventory()

            mock_collect.assert_called_once()
            self.assertEqual(result["platform"], "windows")

    @patch("platform.system")
    def test_get_software_inventory_bsd(self, mock_platform):
        """Test get_software_inventory for BSD platform."""
        mock_platform.return_value = "FreeBSD"
        self.collector.platform = "freebsd"

        with patch.object(self.collector.collector, "collect_packages") as mock_collect:

            def mock_collect_side_effect():
                self.collector.collector.collected_packages = []

            mock_collect.side_effect = mock_collect_side_effect

            result = self.collector.get_software_inventory()

            mock_collect.assert_called_once()
            self.assertEqual(result["platform"], "freebsd")

    @patch("platform.system")
    def test_get_software_inventory_unsupported_platform(self, mock_platform):
        """Test get_software_inventory for unsupported platform."""
        mock_platform.return_value = "UnknownOS"

        # Create a new collector with unsupported platform
        unsupported_collector = SoftwareInventoryCollector()

        result = unsupported_collector.get_software_inventory()

        self.assertEqual(result["platform"], "unknownos")
        self.assertEqual(result["total_packages"], 0)
        self.assertEqual(result["error"], "Unsupported platform")

    @patch("subprocess.run")
    def test_collect_apt_packages_success(self, mock_run):
        """Test _collect_apt_packages with successful execution."""
        mock_output = "firefox\t75.0-1ubuntu1\tamd64\tWeb browser\t200000\nlibc6\t2.31-0ubuntu9.2\tamd64\tGNU C Library\t12000"
        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        self.linux_collector._collect_apt_packages()  # pylint: disable=protected-access

        self.assertEqual(len(self.linux_collector.collected_packages), 2)

        firefox_package = self.linux_collector.collected_packages[0]
        self.assertEqual(firefox_package["package_name"], "firefox")
        self.assertEqual(firefox_package["version"], "75.0-1ubuntu1")
        self.assertEqual(firefox_package["package_manager"], "apt")
        self.assertEqual(firefox_package["size_bytes"], 200000 * 1024)

    @patch("subprocess.run")
    def test_collect_snap_packages_success(self, mock_run):
        """Test _collect_snap_packages with successful execution."""
        mock_output = "Name      Version    Rev   Tracking       Publisher   Notes\ncode      1.52.1     54    latest/stable  vscode*     classic\n"
        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        self.linux_collector._collect_snap_packages()  # pylint: disable=protected-access

        self.assertEqual(len(self.linux_collector.collected_packages), 1)

        package = self.linux_collector.collected_packages[0]
        self.assertEqual(package["package_name"], "code")
        self.assertEqual(package["version"], "1.52.1")
        self.assertEqual(package["package_manager"], "snap")

    @patch("subprocess.run")
    def test_collect_flatpak_packages_success(self, mock_run):
        """Test _collect_flatpak_packages with successful execution."""
        mock_output = "Name\tApplication ID\tVersion\tInstalled size\tOrigin\nVSCode\tcom.visualstudio.code\t1.52.1\t200 MB\tflathub\n"
        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        self.linux_collector._collect_flatpak_packages()  # pylint: disable=protected-access

        self.assertEqual(len(self.linux_collector.collected_packages), 1)

        package = self.linux_collector.collected_packages[0]
        self.assertEqual(package["package_name"], "VSCode")
        self.assertEqual(package["bundle_id"], "com.visualstudio.code")
        self.assertEqual(package["package_manager"], "flatpak")

    @patch("subprocess.run")
    def test_collect_dnf_packages_success(self, mock_run):
        """Test _collect_dnf_packages with successful execution."""
        mock_output = "Installed Packages\nfirefox.x86_64      75.0-1.fc32     @anaconda\nvim.x86_64          8.2.0-1.fc32    @anaconda"
        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        self.linux_collector._collect_dnf_packages()  # pylint: disable=protected-access

        self.assertEqual(len(self.linux_collector.collected_packages), 2)

        firefox_package = self.linux_collector.collected_packages[0]
        self.assertEqual(firefox_package["package_name"], "firefox")
        self.assertEqual(firefox_package["version"], "75.0-1.fc32")
        self.assertEqual(firefox_package["package_manager"], "dnf")
        self.assertEqual(firefox_package["source"], "@anaconda")

    @patch("subprocess.run")
    def test_collect_pacman_packages_success(self, mock_run):
        """Test _collect_pacman_packages with successful execution."""
        mock_output = "firefox 75.0-1\nvim 8.2.0-1"
        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        self.linux_collector._collect_pacman_packages()  # pylint: disable=protected-access

        self.assertEqual(len(self.linux_collector.collected_packages), 2)

        firefox_package = self.linux_collector.collected_packages[0]
        self.assertEqual(firefox_package["package_name"], "firefox")
        self.assertEqual(firefox_package["version"], "75.0-1")
        self.assertEqual(firefox_package["package_manager"], "pacman")

    @patch("subprocess.run")
    def test_collect_homebrew_packages_success(self, mock_run):
        """Test _collect_homebrew_packages with successful execution."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Homebrew 4.0.0"),  # brew --version check
            Mock(returncode=0, stdout="git 2.30.0\nvim 8.2"),  # formula
            Mock(returncode=0, stdout="visual-studio-code 1.52.1"),  # cask
        ]

        # Test macOS-specific method directly
        macos_collector = MacOSSoftwareInventoryCollector()
        macos_collector._collect_homebrew_packages()  # pylint: disable=protected-access

        self.assertEqual(len(macos_collector.collected_packages), 3)

        # Check formula package
        git_package = macos_collector.collected_packages[0]
        self.assertEqual(git_package["package_name"], "git")
        self.assertEqual(git_package["source"], "homebrew_core")

        # Check cask package
        vscode_package = macos_collector.collected_packages[2]
        self.assertEqual(vscode_package["package_name"], "visual-studio-code")
        self.assertEqual(vscode_package["source"], "homebrew_cask")

    @patch("os.path.exists")
    @patch("os.listdir")
    @patch("subprocess.run")
    def test_collect_macos_applications_success(
        self, mock_run, mock_listdir, mock_exists
    ):
        """Test _collect_macos_applications with successful execution."""
        mock_exists.return_value = True
        mock_listdir.return_value = ["Firefox.app", "TextEdit.app"]

        # Mock plutil output for bundle info
        mock_run.return_value = Mock(
            returncode=0,
            stdout='"CFBundleIdentifier" => "org.mozilla.firefox"\n"CFBundleShortVersionString" => "75.0"',
        )

        # Test macOS-specific method directly
        macos_collector = MacOSSoftwareInventoryCollector()
        macos_collector._collect_macos_applications()  # pylint: disable=protected-access

        self.assertEqual(
            len(macos_collector.collected_packages), 4
        )  # 2 apps x 2 directories

        app_package = macos_collector.collected_packages[0]
        self.assertEqual(app_package["package_name"], "Firefox")
        self.assertEqual(app_package["package_manager"], "macos_applications")

    @patch("subprocess.run")
    def test_collect_winget_packages_success(self, mock_run):
        """Test _collect_winget_packages with successful execution."""
        mock_output = "Name               Id                           Version\n---------------------------------------------------------\nFirefox            Mozilla.Firefox                75.0.0\nVSCode             Microsoft.VisualStudioCode    1.52.1"
        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        # Test Windows-specific method directly
        windows_collector = WindowsSoftwareInventoryCollector()
        windows_collector._collect_winget_packages()  # pylint: disable=protected-access

        self.assertEqual(len(windows_collector.collected_packages), 2)

        firefox_package = windows_collector.collected_packages[0]
        self.assertEqual(firefox_package["package_name"], "Firefox")
        self.assertEqual(firefox_package["bundle_id"], "Mozilla.Firefox")
        self.assertEqual(firefox_package["package_manager"], "winget")

    @patch("subprocess.run")
    def test_collect_pkg_packages_success(self, mock_run):
        """Test _collect_pkg_packages with successful execution."""
        mock_output = "git-2.30.0                     Version control system\nvim-8.2.0                      Vi IMproved text editor"
        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        # Test BSD-specific method directly
        bsd_collector = BSDSoftwareInventoryCollector()
        bsd_collector._collect_pkg_packages()  # pylint: disable=protected-access

        self.assertEqual(len(bsd_collector.collected_packages), 2)

        git_package = bsd_collector.collected_packages[0]
        self.assertEqual(git_package["package_name"], "git")
        self.assertEqual(git_package["version"], "2.30.0")
        self.assertEqual(git_package["package_manager"], "pkg")

    @patch("subprocess.run")
    def test_collect_macos_app_store_success(self, mock_run):
        """Test _collect_macos_app_store with successful execution."""
        mock_json_data = {
            "SPApplicationsDataType": [
                {
                    "_name": "TestApp",
                    "version": "1.0.0",
                    "info": "com.test.app",
                    "source_kind": "Mac App Store",
                    "kind": "Universal, 100 MB",
                }
            ]
        }
        mock_run.return_value = Mock(returncode=0, stdout=json.dumps(mock_json_data))

        # Test macOS-specific method directly
        macos_collector = MacOSSoftwareInventoryCollector()
        macos_collector._collect_macos_app_store()  # pylint: disable=protected-access

        self.assertEqual(len(macos_collector.collected_packages), 1)

        app_package = macos_collector.collected_packages[0]
        self.assertEqual(app_package["package_name"], "TestApp")
        self.assertEqual(app_package["package_manager"], "mac_app_store")

    @patch("subprocess.run")
    def test_package_collection_error_handling(self, mock_run):
        """Test error handling in package collection methods."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "command")

        # Test that errors don't crash the collector for each platform-specific collector
        # pylint: disable=protected-access

        # Test Linux methods
        linux_collector = LinuxSoftwareInventoryCollector()
        linux_methods = [
            linux_collector._collect_apt_packages,
            linux_collector._collect_snap_packages,
            linux_collector._collect_flatpak_packages,
            linux_collector._collect_dnf_packages,
            linux_collector._collect_pacman_packages,
        ]

        # Test macOS methods
        macos_collector = MacOSSoftwareInventoryCollector()
        macos_methods = [
            macos_collector._collect_homebrew_packages,
        ]

        # Test Windows methods
        windows_collector = WindowsSoftwareInventoryCollector()
        windows_methods = [
            windows_collector._collect_winget_packages,
        ]

        # Test BSD methods
        bsd_collector = BSDSoftwareInventoryCollector()
        bsd_methods = [
            bsd_collector._collect_pkg_packages,
        ]

        all_methods = linux_methods + macos_methods + windows_methods + bsd_methods

        for method in all_methods:
            with self.subTest(method=method.__name__):
                try:
                    method()
                    # Should not raise an exception
                except Exception as error:
                    self.fail(f"Method {method.__name__} raised an exception: {error}")

    def test_get_software_inventory_with_exception(self):
        """Test get_software_inventory handles exceptions gracefully."""
        with patch.object(
            self.collector.collector,
            "collect_packages",
            side_effect=Exception("Test error"),
        ):
            self.collector.platform = "linux"
            result = self.collector.get_software_inventory()

            self.assertEqual(result["total_packages"], 0)
            self.assertEqual(result["software_packages"], [])
            self.assertIn("error", result)
            self.assertEqual(result["error"], "Test error")

    def test_collect_linux_packages_calls_detected_managers(self):
        """Test _collect_linux_packages calls methods for detected managers."""
        # Test Linux-specific method directly
        linux_collector = LinuxSoftwareInventoryCollector()

        with (
            patch.object(
                linux_collector, "detect_package_managers", return_value=["apt", "snap"]
            ),
            patch.object(linux_collector, "_collect_apt_packages") as mock_apt,
            patch.object(linux_collector, "_collect_snap_packages") as mock_snap,
            patch.object(linux_collector, "_collect_flatpak_packages") as mock_flatpak,
        ):

            linux_collector.collect_packages()  # pylint: disable=protected-access

            mock_apt.assert_called_once()
            mock_snap.assert_called_once()
            mock_flatpak.assert_not_called()

    def test_collect_macos_packages_calls_detected_managers(self):
        """Test _collect_macos_packages calls methods for detected managers."""
        # Test macOS-specific method directly
        macos_collector = MacOSSoftwareInventoryCollector()

        with (
            patch.object(
                macos_collector, "detect_package_managers", return_value=["homebrew"]
            ),
            patch.object(macos_collector, "_collect_homebrew_packages") as mock_brew,
            patch.object(macos_collector, "_collect_macos_applications") as mock_apps,
            patch.object(macos_collector, "_collect_macos_app_store") as mock_store,
            patch.object(macos_collector, "_collect_macports_packages") as mock_ports,
        ):

            macos_collector.collect_packages()  # pylint: disable=protected-access

            mock_apps.assert_called_once()
            mock_store.assert_called_once()
            mock_brew.assert_called_once()
            mock_ports.assert_not_called()


if __name__ == "__main__":
    unittest.main()
