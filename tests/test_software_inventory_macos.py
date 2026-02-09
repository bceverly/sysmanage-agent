#!/usr/bin/env python3
"""
Comprehensive tests for macOS software inventory collection module.

Tests macOS package managers: Homebrew, MacPorts, Applications folder, Mac App Store.
Covers installed package listing, version parsing, error handling, and edge cases.
"""

# pylint: disable=redefined-outer-name,protected-access

import json
import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.software_inventory_macos import (
    MacOSSoftwareInventoryCollector,
    APPLICATIONS_DIR,
)


@pytest.fixture
def collector():
    """Create a MacOSSoftwareInventoryCollector for testing."""
    return MacOSSoftwareInventoryCollector()


class TestMacOSSoftwareInventoryCollectorInit:
    """Tests for MacOSSoftwareInventoryCollector initialization."""

    def test_init_sets_empty_collected_packages(self, collector):
        """Test that __init__ sets empty collected_packages list."""
        assert collector.collected_packages == []

    def test_init_sets_package_managers_to_none(self, collector):
        """Test that __init__ sets _package_managers to None."""
        assert collector._package_managers is None


class TestDetectPackageManagers:
    """Tests for detect_package_managers method."""

    def test_detect_homebrew_available(self, collector):
        """Test detection when Homebrew is available."""
        with patch.object(collector, "_is_homebrew_available", return_value=True):
            with patch.object(collector, "_command_exists", return_value=False):
                result = collector.detect_package_managers()

        assert "homebrew" in result

    def test_detect_macports_available(self, collector):
        """Test detection when MacPorts is available."""
        with patch.object(collector, "_is_homebrew_available", return_value=False):
            with patch.object(collector, "_command_exists") as mock_exists:
                mock_exists.side_effect = lambda cmd: cmd == "port"
                result = collector.detect_package_managers()

        assert "macports" in result

    def test_detect_both_managers(self, collector):
        """Test detection when both managers available."""
        with patch.object(collector, "_is_homebrew_available", return_value=True):
            with patch.object(collector, "_command_exists") as mock_exists:
                mock_exists.side_effect = lambda cmd: cmd == "port"
                result = collector.detect_package_managers()

        assert "homebrew" in result
        assert "macports" in result

    def test_detect_no_managers(self, collector):
        """Test detection when no managers available."""
        with patch.object(collector, "_is_homebrew_available", return_value=False):
            with patch.object(collector, "_command_exists", return_value=False):
                result = collector.detect_package_managers()

        assert result == []

    def test_detect_managers_cached(self, collector):
        """Test that package managers are cached after first detection."""
        collector._package_managers = ["homebrew"]
        result = collector.detect_package_managers()

        assert result == ["homebrew"]


class TestIsHomebrewAvailable:
    """Tests for _is_homebrew_available method."""

    def test_homebrew_apple_silicon(self, collector):
        """Test Homebrew detection on Apple Silicon."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = collector._is_homebrew_available()

        assert result is True
        # Should try /opt/homebrew/bin/brew first (Apple Silicon path)
        first_call_args = mock_run.call_args_list[0][0][0]
        assert first_call_args[0] == "/opt/homebrew/bin/brew"

    def test_homebrew_intel_mac(self, collector):
        """Test Homebrew detection on Intel Mac."""
        mock_result_fail = Mock()
        mock_result_fail.returncode = 1
        mock_result_success = Mock()
        mock_result_success.returncode = 0

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                FileNotFoundError(),  # Apple Silicon path fails
                mock_result_success,  # Intel path succeeds
            ]
            result = collector._is_homebrew_available()

        assert result is True

    def test_homebrew_not_installed(self, collector):
        """Test Homebrew detection when not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = collector._is_homebrew_available()

        assert result is False

    def test_homebrew_timeout(self, collector):
        """Test Homebrew detection with timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("brew", 10)):
            result = collector._is_homebrew_available()

        assert result is False


class TestGetBrewCommand:
    """Tests for _get_brew_command method."""

    def test_get_brew_apple_silicon(self, collector):
        """Test getting brew command on Apple Silicon."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = collector._get_brew_command()

        assert result == "/opt/homebrew/bin/brew"

    def test_get_brew_intel_mac(self, collector):
        """Test getting brew command on Intel Mac."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                FileNotFoundError(),  # Apple Silicon path fails
                Mock(returncode=0),  # Intel path succeeds
            ]
            result = collector._get_brew_command()

        assert result == "/usr/local/bin/brew"

    def test_get_brew_fallback(self, collector):
        """Test getting brew command fallback."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = collector._get_brew_command()

        assert result == "brew"


class TestCollectPackages:
    """Tests for collect_packages method."""

    def test_collect_packages_calls_all_sources(self, collector):
        """Test that collect_packages calls all macOS sources."""
        with patch.object(
            collector, "detect_package_managers", return_value=["homebrew"]
        ):
            with patch.object(collector, "_collect_macos_applications") as mock_apps:
                with patch.object(collector, "_collect_macos_app_store") as mock_store:
                    with patch.object(
                        collector, "_collect_homebrew_packages"
                    ) as mock_brew:
                        collector.collect_packages()

        mock_apps.assert_called_once()
        mock_store.assert_called_once()
        mock_brew.assert_called_once()

    def test_collect_packages_with_macports(self, collector):
        """Test that collect_packages calls MacPorts when available."""
        with patch.object(
            collector, "detect_package_managers", return_value=["macports"]
        ):
            with patch.object(collector, "_collect_macos_applications"):
                with patch.object(collector, "_collect_macos_app_store"):
                    with patch.object(
                        collector, "_collect_macports_packages"
                    ) as mock_ports:
                        collector.collect_packages()

        mock_ports.assert_called_once()


class TestCollectHomebrewPackages:
    """Tests for _collect_homebrew_packages method."""

    def test_collect_homebrew_formulas(self, collector):
        """Test successful Homebrew formula collection."""
        with patch.object(
            collector, "_get_brew_command", return_value="/opt/homebrew/bin/brew"
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    Mock(returncode=0, stdout="git 2.33.0\nvim 8.2.3456\n"),  # formulas
                    Mock(returncode=0, stdout=""),  # casks (empty)
                ]
                collector._collect_homebrew_packages()

        assert len(collector.collected_packages) == 2
        git = collector.collected_packages[0]
        assert git["package_name"] == "git"
        assert git["version"] == "2.33.0"
        assert git["package_manager"] == "homebrew"
        assert git["source"] == "homebrew_core"

    def test_collect_homebrew_casks(self, collector):
        """Test successful Homebrew cask collection."""
        with patch.object(
            collector, "_get_brew_command", return_value="/opt/homebrew/bin/brew"
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    Mock(returncode=0, stdout=""),  # formulas (empty)
                    Mock(returncode=0, stdout="firefox 91.0\nvscode 1.60.0\n"),  # casks
                ]
                collector._collect_homebrew_packages()

        assert len(collector.collected_packages) == 2
        firefox = collector.collected_packages[0]
        assert firefox["package_name"] == "firefox"
        assert firefox["source"] == "homebrew_cask"
        assert firefox["category"] == "application"

    def test_collect_homebrew_mixed(self, collector):
        """Test Homebrew collection with formulas and casks."""
        with patch.object(
            collector, "_get_brew_command", return_value="/opt/homebrew/bin/brew"
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    Mock(returncode=0, stdout="git 2.33.0\n"),  # formulas
                    Mock(returncode=0, stdout="firefox 91.0\n"),  # casks
                ]
                collector._collect_homebrew_packages()

        assert len(collector.collected_packages) == 2

    def test_collect_homebrew_failure(self, collector):
        """Test Homebrew collection with command failure."""
        with patch.object(collector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=1, stdout="")
                collector._collect_homebrew_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_homebrew_exception(self, collector):
        """Test Homebrew collection with exception."""
        with patch.object(collector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", side_effect=Exception("brew error")):
                collector._collect_homebrew_packages()

        assert len(collector.collected_packages) == 0


class TestCollectHomebrewList:
    """Tests for _collect_homebrew_list method."""

    def test_collect_formulas(self, collector):
        """Test collecting Homebrew formulas."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "git 2.33.0\nvim 8.2.3456\ncurl 7.79.1\n"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_homebrew_list(
                "/opt/homebrew/bin/brew", "--formula", "homebrew_core"
            )

        assert len(collector.collected_packages) == 3
        git = collector.collected_packages[0]
        assert git["package_name"] == "git"
        assert git["source"] == "homebrew_core"
        assert "category" not in git

    def test_collect_casks(self, collector):
        """Test collecting Homebrew casks."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "firefox 91.0\nvscode 1.60.0\n"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_homebrew_list(
                "/opt/homebrew/bin/brew", "--cask", "homebrew_cask"
            )

        assert len(collector.collected_packages) == 2
        firefox = collector.collected_packages[0]
        assert firefox["package_name"] == "firefox"
        assert firefox["source"] == "homebrew_cask"
        assert firefox["category"] == "application"

    def test_collect_failure(self, collector):
        """Test collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_homebrew_list(
                "/opt/homebrew/bin/brew", "--formula", "homebrew_core"
            )

        assert len(collector.collected_packages) == 0

    def test_collect_malformed_lines(self, collector):
        """Test collection with malformed lines."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "git 2.33.0\nmalformed\nvim 8.2\n"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_homebrew_list(
                "/opt/homebrew/bin/brew", "--formula", "homebrew_core"
            )

        # Only valid lines with >= 2 parts should be collected
        assert len(collector.collected_packages) == 2


class TestCollectMacOSApplications:
    """Tests for _collect_macos_applications method."""

    def test_collect_applications_success(self, collector):
        """Test successful application collection."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir") as mock_listdir:
                mock_listdir.side_effect = [
                    ["Firefox.app", "Safari.app", "TextEdit.txt"],  # /Applications
                    ["MyApp.app"],  # ~/Applications
                ]
                with patch.object(collector, "_detect_plist_metadata", return_value={}):
                    collector._collect_macos_applications()

        # Should collect .app files only
        assert len(collector.collected_packages) == 3
        firefox = collector.collected_packages[0]
        assert firefox["package_name"] == "Firefox"
        assert firefox["package_manager"] == "macos_applications"
        assert firefox["category"] == "application"

    def test_collect_applications_with_plist(self, collector):
        """Test application collection with plist metadata."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", return_value=["Firefox.app"]):
                with patch.object(
                    collector,
                    "_detect_plist_metadata",
                    return_value={
                        "bundle_id": "org.mozilla.firefox",
                        "version": "91.0",
                    },
                ):
                    collector._collect_macos_applications()

        firefox = collector.collected_packages[0]
        assert firefox["bundle_id"] == "org.mozilla.firefox"
        assert firefox["version"] == "91.0"

    def test_collect_applications_dir_not_exists(self, collector):
        """Test application collection when directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            collector._collect_macos_applications()

        assert len(collector.collected_packages) == 0

    def test_collect_applications_permission_error(self, collector):
        """Test application collection with permission error."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", side_effect=PermissionError("Access denied")):
                collector._collect_macos_applications()

        assert len(collector.collected_packages) == 0

    def test_collect_applications_system_vs_user(self, collector):
        """Test correct system vs user app classification."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir") as mock_listdir:
                mock_listdir.side_effect = [
                    ["SystemApp.app"],  # /Applications
                    ["UserApp.app"],  # ~/Applications
                ]
                with patch.object(collector, "_detect_plist_metadata", return_value={}):
                    collector._collect_macos_applications()

        system_app = collector.collected_packages[0]
        user_app = collector.collected_packages[1]

        assert system_app["is_system_package"] is True
        assert system_app["is_user_installed"] is False
        assert user_app["is_system_package"] is False
        assert user_app["is_user_installed"] is True


class TestDetectPlistMetadata:
    """Tests for _detect_plist_metadata method."""

    def test_detect_plist_success(self, collector):
        """Test successful plist metadata detection."""
        plist_output = (
            '"CFBundleIdentifier" => "org.mozilla.firefox"\n'
            '"CFBundleShortVersionString" => "91.0"\n'
        )

        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout=plist_output)
                result = collector._detect_plist_metadata("/path/to/Info.plist")

        assert result["bundle_id"] == "org.mozilla.firefox"
        assert result["version"] == "91.0"

    def test_detect_plist_not_found(self, collector):
        """Test plist detection when file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = collector._detect_plist_metadata("/path/to/nonexistent.plist")

        assert result == {}

    def test_detect_plist_failure(self, collector):
        """Test plist detection with command failure."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=1, stdout="")
                result = collector._detect_plist_metadata("/path/to/Info.plist")

        assert result == {}

    def test_detect_plist_timeout(self, collector):
        """Test plist detection with timeout."""
        with patch("os.path.exists", return_value=True):
            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired("plutil", 5),
            ):
                result = collector._detect_plist_metadata("/path/to/Info.plist")

        assert result == {}

    def test_detect_plist_partial_data(self, collector):
        """Test plist detection with partial metadata."""
        plist_output = '"CFBundleIdentifier" => "org.mozilla.firefox"\n'

        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout=plist_output)
                result = collector._detect_plist_metadata("/path/to/Info.plist")

        assert result["bundle_id"] == "org.mozilla.firefox"
        assert "version" not in result


class TestParsePlistField:
    """Tests for _parse_plist_field method."""

    def test_parse_field_success(self, collector):
        """Test successful field parsing."""
        output = '"CFBundleIdentifier" => "org.mozilla.firefox"'
        result = collector._parse_plist_field(output, "CFBundleIdentifier")

        assert result == "org.mozilla.firefox"

    def test_parse_field_not_found(self, collector):
        """Test field parsing when field not found."""
        output = '"OtherField" => "value"'
        result = collector._parse_plist_field(output, "CFBundleIdentifier")

        assert result is None

    def test_parse_field_malformed(self, collector):
        """Test field parsing with malformed data."""
        output = "CFBundleIdentifier without proper format"
        result = collector._parse_plist_field(output, "CFBundleIdentifier")

        assert result is None


class TestCollectMacOSAppStore:
    """Tests for _collect_macos_app_store method."""

    def test_collect_app_store_success(self, collector):
        """Test successful App Store collection."""
        apps_data = {
            "SPApplicationsDataType": [
                {
                    "_name": "Pages",
                    "version": "11.2",
                    "info": "com.apple.iWork.Pages",
                    "source_kind": "Mac App Store",
                },
                {
                    "_name": "Keynote",
                    "version": "11.2",
                    "info": "com.apple.iWork.Keynote",
                    "obtained_from": "mac_app_store",
                },
            ]
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(apps_data)

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_macos_app_store()

        assert len(collector.collected_packages) == 2
        pages = collector.collected_packages[0]
        assert pages["package_name"] == "Pages"
        assert pages["package_manager"] == "mac_app_store"
        assert pages["source"] == "app_store"

    def test_collect_app_store_filters_non_store_apps(self, collector):
        """Test that non-App Store apps are filtered."""
        apps_data = {
            "SPApplicationsDataType": [
                {
                    "_name": "Pages",
                    "version": "11.2",
                    "source_kind": "Mac App Store",
                },
                {
                    "_name": "Firefox",
                    "version": "91.0",
                    "source_kind": "Identified Developer",
                },
            ]
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(apps_data)

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_macos_app_store()

        assert len(collector.collected_packages) == 1
        assert collector.collected_packages[0]["package_name"] == "Pages"

    def test_collect_app_store_empty(self, collector):
        """Test App Store collection with no apps."""
        apps_data = {"SPApplicationsDataType": []}

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(apps_data)

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_macos_app_store()

        assert len(collector.collected_packages) == 0

    def test_collect_app_store_invalid_json(self, collector):
        """Test App Store collection with invalid JSON."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json {"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_macos_app_store()

        assert len(collector.collected_packages) == 0

    def test_collect_app_store_failure(self, collector):
        """Test App Store collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_macos_app_store()

        assert len(collector.collected_packages) == 0

    def test_collect_app_store_exception(self, collector):
        """Test App Store collection with exception."""
        with patch("subprocess.run", side_effect=Exception("system_profiler error")):
            collector._collect_macos_app_store()

        assert len(collector.collected_packages) == 0


class TestProcessAppStoreEntry:
    """Tests for _process_app_store_entry method."""

    def test_process_app_store_app(self, collector):
        """Test processing App Store app entry."""
        app = {
            "_name": "Pages",
            "version": "11.2",
            "info": "com.apple.iWork.Pages",
            "source_kind": "Mac App Store",
        }
        result = collector._process_app_store_entry(app)

        assert result is not None
        assert result["package_name"] == "Pages"
        assert result["version"] == "11.2"
        assert result["bundle_id"] == "com.apple.iWork.Pages"

    def test_process_non_app_store_app(self, collector):
        """Test processing non-App Store app entry."""
        app = {
            "_name": "Firefox",
            "version": "91.0",
            "source_kind": "Identified Developer",
        }
        result = collector._process_app_store_entry(app)

        assert result is None

    def test_process_app_obtained_from_store(self, collector):
        """Test processing app with obtained_from field."""
        app = {
            "_name": "Keynote",
            "version": "11.2",
            "obtained_from": "mac_app_store",
        }
        result = collector._process_app_store_entry(app)

        assert result is not None
        assert result["package_name"] == "Keynote"


class TestDetectAppStoreSize:
    """Tests for _detect_app_store_size method."""

    def test_detect_size_success(self, collector):
        """Test successful size detection."""
        # The method checks for "bytes" in the string (case sensitive check)
        app = {"kind": "Universal, 500 MB, 524288000 bytes"}
        package = {}
        collector._detect_app_store_size(app, package)

        assert package["size_bytes"] == 500 * 1024 * 1024

    def test_detect_size_no_kind(self, collector):
        """Test size detection without kind field."""
        app = {}
        package = {}
        collector._detect_app_store_size(app, package)

        assert "size_bytes" not in package

    def test_detect_size_no_bytes_string(self, collector):
        """Test size detection without 'bytes' in kind field."""
        # The method only processes if "bytes" is in the kind string
        app = {"kind": "Universal, 500 MB"}
        package = {}
        collector._detect_app_store_size(app, package)

        assert "size_bytes" not in package

    def test_detect_size_no_size_info(self, collector):
        """Test size detection without size info."""
        app = {"kind": "Universal"}
        package = {}
        collector._detect_app_store_size(app, package)

        assert "size_bytes" not in package


class TestCollectMacPortsPackages:
    """Tests for _collect_macports_packages method."""

    def test_collect_macports_not_implemented(self, collector):
        """Test that MacPorts collection logs but doesn't fail."""
        # Should not raise any exception
        collector._collect_macports_packages()

        # Should not add any packages (not implemented)
        assert len(collector.collected_packages) == 0


class TestApplicationsDir:
    """Tests for APPLICATIONS_DIR constant."""

    def test_applications_dir_value(self):
        """Test APPLICATIONS_DIR is set correctly."""
        assert APPLICATIONS_DIR == "/Applications"


class TestErrorRecovery:
    """Tests for error recovery and graceful degradation."""

    def test_subprocess_timeout(self, collector):
        """Test handling of subprocess timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 120)):
            collector._collect_macos_app_store()

        assert len(collector.collected_packages) == 0

    def test_multiple_source_partial_failure(self, collector):
        """Test that internal exception handling works for each source."""
        # Each collection method should handle its own exceptions
        # Test that methods handle subprocess failures gracefully
        with patch("subprocess.run", side_effect=Exception("Error")):
            # These should not raise, just log errors
            collector._collect_macos_app_store()
            collector._collect_homebrew_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_applications_handles_errors(self, collector):
        """Test that application collection handles file system errors."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", side_effect=OSError("Permission denied")):
                # Should not raise
                collector._collect_macos_applications()

        assert len(collector.collected_packages) == 0


class TestIntegrationScenarios:
    """Integration-style tests for realistic scenarios."""

    def test_full_macos_collection_flow(self, collector):
        """Test complete macOS collection with all sources."""
        # Mock all sources returning packages
        brew_formula_output = "git 2.33.0\n"
        brew_cask_output = "firefox 91.0\n"

        apps_data = {
            "SPApplicationsDataType": [
                {
                    "_name": "Pages",
                    "version": "11.2",
                    "source_kind": "Mac App Store",
                }
            ]
        }

        with patch.object(
            collector, "detect_package_managers", return_value=["homebrew"]
        ):
            with patch("os.path.exists", return_value=True):
                with patch("os.listdir", return_value=["Safari.app"]):
                    with patch.object(
                        collector, "_detect_plist_metadata", return_value={}
                    ):
                        with patch("subprocess.run") as mock_run:
                            # Configure different outputs for different commands
                            def run_side_effect(*args, **_kwargs):
                                cmd = args[0]
                                result = Mock()
                                result.returncode = 0

                                if "brew" in str(cmd):
                                    if "--formula" in cmd:
                                        result.stdout = brew_formula_output
                                    else:
                                        result.stdout = brew_cask_output
                                elif "system_profiler" in str(cmd):
                                    result.stdout = json.dumps(apps_data)
                                else:
                                    result.stdout = ""

                                return result

                            mock_run.side_effect = run_side_effect
                            collector.collect_packages()

        # Should have collected from multiple sources
        assert len(collector.collected_packages) >= 1

    def test_empty_system(self, collector):
        """Test collection on system with no packages."""
        with patch.object(collector, "detect_package_managers", return_value=[]):
            with patch("os.path.exists", return_value=False):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(
                        returncode=0, stdout=json.dumps({"SPApplicationsDataType": []})
                    )
                    collector.collect_packages()

        assert len(collector.collected_packages) == 0
