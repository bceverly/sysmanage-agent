#!/usr/bin/env python3
"""
Comprehensive tests for Windows software inventory collection module.

Tests Windows package managers: winget, chocolatey, scoop, Windows Registry, Microsoft Store.
Covers installed package listing, version parsing, error handling, and edge cases.
"""

# pylint: disable=redefined-outer-name,protected-access

import json
import subprocess
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.collection.software_inventory_windows import (
    WindowsSoftwareInventoryCollector,
)


@pytest.fixture
def collector():
    """Create a WindowsSoftwareInventoryCollector for testing."""
    return WindowsSoftwareInventoryCollector()


class TestWindowsSoftwareInventoryCollectorInit:
    """Tests for WindowsSoftwareInventoryCollector initialization."""

    def test_init_sets_empty_collected_packages(self, collector):
        """Test that __init__ sets empty collected_packages list."""
        assert collector.collected_packages == []

    def test_init_sets_package_managers_to_none(self, collector):
        """Test that __init__ sets _package_managers to None."""
        assert collector._package_managers is None


class TestDetectPackageManagers:
    """Tests for detect_package_managers method."""

    def test_detect_winget_available(self, collector):
        """Test detection when winget is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "winget"
            result = collector.detect_package_managers()

        assert "winget" in result

    def test_detect_chocolatey_available(self, collector):
        """Test detection when chocolatey is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "choco"
            result = collector.detect_package_managers()

        assert "chocolatey" in result

    def test_detect_scoop_available(self, collector):
        """Test detection when scoop is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "scoop"
            result = collector.detect_package_managers()

        assert "scoop" in result

    def test_detect_multiple_managers(self, collector):
        """Test detection when multiple managers available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd in ["winget", "choco"]
            result = collector.detect_package_managers()

        assert "winget" in result
        assert "chocolatey" in result

    def test_detect_no_managers(self, collector):
        """Test detection when no managers available."""
        with patch.object(collector, "_command_exists", return_value=False):
            result = collector.detect_package_managers()

        assert result == []

    def test_detect_managers_cached(self, collector):
        """Test that package managers are cached after first detection."""
        collector._package_managers = ["winget", "chocolatey"]
        result = collector.detect_package_managers()

        assert result == ["winget", "chocolatey"]


class TestCollectPackages:
    """Tests for collect_packages method."""

    def test_collect_packages_calls_all_sources(self, collector):
        """Test that collect_packages calls all Windows sources."""
        with patch.object(
            collector, "detect_package_managers", return_value=["winget", "chocolatey"]
        ):
            with patch.object(
                collector, "_collect_windows_registry_programs"
            ) as mock_reg:
                with patch.object(
                    collector, "_collect_microsoft_store_apps"
                ) as mock_store:
                    with patch.object(
                        collector, "_collect_winget_packages"
                    ) as mock_winget:
                        with patch.object(
                            collector, "_collect_chocolatey_packages"
                        ) as mock_choco:
                            collector.collect_packages()

        mock_reg.assert_called_once()
        mock_store.assert_called_once()
        mock_winget.assert_called_once()
        mock_choco.assert_called_once()

    def test_collect_packages_without_winget(self, collector):
        """Test that collect_packages skips winget when not available."""
        with patch.object(collector, "detect_package_managers", return_value=[]):
            with patch.object(
                collector, "_collect_windows_registry_programs"
            ) as mock_reg:
                with patch.object(
                    collector, "_collect_microsoft_store_apps"
                ) as mock_store:
                    with patch.object(
                        collector, "_collect_winget_packages"
                    ) as mock_winget:
                        collector.collect_packages()

        mock_reg.assert_called_once()
        mock_store.assert_called_once()
        mock_winget.assert_not_called()


class TestCollectWingetPackages:
    """Tests for _collect_winget_packages method."""

    def test_collect_winget_packages_success(self, collector):
        """Test successful winget package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Name               Id                           Version\n"
            "---------------------------------------------------------\n"
            "Firefox            Mozilla.Firefox              91.0.0\n"
            "VSCode             Microsoft.VisualStudioCode   1.60.0\n"
            "Git                Git.Git                      2.33.0\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_winget_packages()

        assert len(collector.collected_packages) == 3
        firefox = collector.collected_packages[0]
        assert firefox["package_name"] == "Firefox"
        assert firefox["bundle_id"] == "Mozilla.Firefox"
        assert firefox["version"] == "91.0.0"
        assert firefox["package_manager"] == "winget"

    def test_collect_winget_packages_empty(self, collector):
        """Test winget package collection with no packages."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Name               Id                           Version\n"
            "---------------------------------------------------------\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_winget_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_winget_packages_failure(self, collector):
        """Test winget package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_winget_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_winget_packages_no_header(self, collector):
        """Test winget package collection without proper header."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Some unexpected output\nNo header line here"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_winget_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_winget_packages_exception(self, collector):
        """Test winget package collection with exception."""
        with patch("subprocess.run", side_effect=Exception("winget error")):
            collector._collect_winget_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_winget_packages_msstore_source(self, collector):
        """Test winget package collection detects Microsoft Store source."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Name               Id                           Version\n"
            "---------------------------------------------------------\n"
            "Calculator         msstore.Calculator           11.0.0\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_winget_packages()

        assert len(collector.collected_packages) == 1
        calc = collector.collected_packages[0]
        assert calc["source"] == "microsoft_store"


class TestDetectWingetHeader:
    """Tests for _detect_winget_header method."""

    def test_detect_header_success(self, collector):
        """Test successful header detection."""
        lines = [
            "Name               Id                           Version",
            "---------------------------------------------------------",
            "Firefox            Mozilla.Firefox              91.0.0",
        ]
        header_line, data_start = collector._detect_winget_header(lines)

        assert header_line is not None
        assert "Name" in header_line
        assert "Id" in header_line
        assert "Version" in header_line
        assert data_start == 2

    def test_detect_header_not_found(self, collector):
        """Test header detection when not found."""
        lines = ["Some other output", "No header here"]
        header_line, data_start = collector._detect_winget_header(lines)

        assert header_line is None
        assert data_start == 0


class TestParseWingetDataLine:
    """Tests for _parse_winget_data_line method."""

    def test_parse_valid_line(self, collector):
        """Test parsing valid winget data line."""
        line = "Firefox            Mozilla.Firefox              91.0.0"
        result = collector._parse_winget_data_line(line, 0, 19, 48)

        assert result is not None
        assert result["package_name"] == "Firefox"
        assert result["bundle_id"] == "Mozilla.Firefox"
        assert result["version"] == "91.0.0"

    def test_parse_empty_line(self, collector):
        """Test parsing empty line."""
        result = collector._parse_winget_data_line("", 0, 19, 48)

        assert result is None

    def test_parse_separator_line(self, collector):
        """Test parsing separator line."""
        result = collector._parse_winget_data_line("-" * 60, 0, 19, 48)

        assert result is None

    def test_parse_short_line(self, collector):
        """Test parsing line that's too short."""
        result = collector._parse_winget_data_line("short", 0, 19, 48)

        assert result is None


class TestCollectMicrosoftStoreApps:
    """Tests for _collect_microsoft_store_apps method."""

    def test_collect_store_apps_success(self, collector):
        """Test successful Microsoft Store app collection."""
        apps_data = [
            {
                "Name": "Microsoft.WindowsCalculator",
                "Version": "11.2009.4.0",
                "Publisher": "CN=Microsoft Corporation",
                "PackageFullName": "Microsoft.WindowsCalculator_11.2009.4.0_x64__8wekyb3d8bbwe",
            },
            {
                "Name": "Microsoft.WindowsNotepad",
                "Version": "11.0.0.0",
                "Publisher": "CN=Microsoft Corporation",
                "PackageFullName": "Microsoft.WindowsNotepad_11.0.0.0_x64__8wekyb3d8bbwe",
            },
        ]

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(apps_data)

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_microsoft_store_apps()

        assert len(collector.collected_packages) == 2
        calc = collector.collected_packages[0]
        assert calc["package_name"] == "Microsoft.WindowsCalculator"
        assert calc["version"] == "11.2009.4.0"
        assert calc["package_manager"] == "microsoft_store"
        assert calc["source"] == "microsoft_store"

    def test_collect_store_apps_single_app(self, collector):
        """Test Microsoft Store collection with single app (dict not list)."""
        app_data = {
            "Name": "Microsoft.WindowsCalculator",
            "Version": "11.2009.4.0",
            "Publisher": "CN=Microsoft Corporation",
            "PackageFullName": "Microsoft.WindowsCalculator_11.2009.4.0_x64__8wekyb3d8bbwe",
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(app_data)

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_microsoft_store_apps()

        assert len(collector.collected_packages) == 1

    def test_collect_store_apps_empty(self, collector):
        """Test Microsoft Store collection with no apps."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_microsoft_store_apps()

        assert len(collector.collected_packages) == 0

    def test_collect_store_apps_invalid_json(self, collector):
        """Test Microsoft Store collection with invalid JSON."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json {"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_microsoft_store_apps()

        assert len(collector.collected_packages) == 0

    def test_collect_store_apps_failure(self, collector):
        """Test Microsoft Store collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_microsoft_store_apps()

        assert len(collector.collected_packages) == 0

    def test_collect_store_apps_powershell_not_found(self, collector):
        """Test Microsoft Store collection when PowerShell not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError("powershell")):
            collector._collect_microsoft_store_apps()

        assert len(collector.collected_packages) == 0

    def test_collect_store_apps_exception(self, collector):
        """Test Microsoft Store collection with exception."""
        with patch("subprocess.run", side_effect=Exception("PowerShell error")):
            collector._collect_microsoft_store_apps()

        assert len(collector.collected_packages) == 0


class TestProcessMicrosoftStoreEntry:
    """Tests for _process_microsoft_store_entry method."""

    def test_process_valid_entry(self, collector):
        """Test processing valid Microsoft Store entry."""
        app = {
            "Name": "Calculator",
            "Version": "11.0.0",
            "Publisher": "Microsoft",
            "PackageFullName": "Calculator_11.0.0_x64__abc123",
        }
        result = collector._process_microsoft_store_entry(app)

        assert result is not None
        assert result["package_name"] == "Calculator"
        assert result["version"] == "11.0.0"
        assert result["publisher"] == "Microsoft"

    def test_process_entry_without_name(self, collector):
        """Test processing entry without name."""
        app = {
            "Version": "11.0.0",
            "Publisher": "Microsoft",
        }
        result = collector._process_microsoft_store_entry(app)

        assert result is None

    def test_process_entry_empty_name(self, collector):
        """Test processing entry with empty name."""
        app = {
            "Name": "",
            "Version": "11.0.0",
        }
        result = collector._process_microsoft_store_entry(app)

        assert result is None


class TestCollectWindowsRegistryPrograms:
    """Tests for _collect_windows_registry_programs method."""

    def test_collect_registry_winreg_not_available(self, collector):
        """Test registry collection when winreg not available."""
        with patch.dict("sys.modules", {"winreg": None}):
            with patch(
                "builtins.__import__",
                side_effect=ImportError("No module named 'winreg'"),
            ):
                collector._collect_windows_registry_programs()

        # Should not crash
        assert len(collector.collected_packages) == 0

    def test_collect_registry_permission_error(self, collector):
        """Test registry collection with permission error."""
        mock_winreg = MagicMock()
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
        mock_winreg.HKEY_CURRENT_USER = 0x80000001
        mock_winreg.OpenKey.side_effect = PermissionError("Access denied")

        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            # Re-import to use mocked winreg
            collector._collect_windows_registry_programs()

        # Should handle permission error gracefully
        assert len(collector.collected_packages) == 0

    def test_collect_registry_file_not_found(self, collector):
        """Test registry collection when key not found."""
        mock_winreg = MagicMock()
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
        mock_winreg.HKEY_CURRENT_USER = 0x80000001
        mock_winreg.OpenKey.side_effect = FileNotFoundError("Key not found")

        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            collector._collect_windows_registry_programs()

        # Should handle missing key gracefully
        assert len(collector.collected_packages) == 0


class TestParseRegistrySubkey:
    """Tests for _parse_registry_subkey method."""

    def test_parse_valid_subkey(self, collector):
        """Test parsing valid registry subkey."""
        mock_winreg = MagicMock()

        def query_value(_key, name):
            values = {
                "DisplayName": ("Firefox", 1),
                "DisplayVersion": ("91.0", 1),
                "Publisher": ("Mozilla", 1),
            }
            if name in values:
                return values[name]
            raise FileNotFoundError(f"Value {name} not found")

        mock_winreg.QueryValueEx = query_value
        mock_subkey = MagicMock()

        result = collector._parse_registry_subkey(mock_winreg, mock_subkey, "{ABC-123}")

        assert result is not None
        assert result["package_name"] == "Firefox"
        assert result["version"] == "91.0"
        assert result["publisher"] == "Mozilla"
        assert result["bundle_id"] == "{ABC-123}"

    def test_parse_subkey_no_display_name(self, collector):
        """Test parsing subkey without DisplayName."""
        mock_winreg = MagicMock()
        mock_winreg.QueryValueEx.side_effect = FileNotFoundError("Not found")
        mock_subkey = MagicMock()

        result = collector._parse_registry_subkey(mock_winreg, mock_subkey, "{ABC-123}")

        assert result is None

    def test_parse_subkey_empty_display_name(self, collector):
        """Test parsing subkey with empty DisplayName."""
        mock_winreg = MagicMock()
        mock_winreg.QueryValueEx.return_value = ("", 1)
        mock_subkey = MagicMock()

        result = collector._parse_registry_subkey(mock_winreg, mock_subkey, "{ABC-123}")

        assert result is None

    def test_parse_subkey_whitespace_display_name(self, collector):
        """Test parsing subkey with whitespace-only DisplayName."""
        mock_winreg = MagicMock()
        mock_winreg.QueryValueEx.return_value = ("   ", 1)
        mock_subkey = MagicMock()

        result = collector._parse_registry_subkey(mock_winreg, mock_subkey, "{ABC-123}")

        assert result is None

    def test_parse_subkey_no_version(self, collector):
        """Test parsing subkey without version."""
        mock_winreg = MagicMock()

        def query_value(_key, name):
            if name == "DisplayName":
                return ("Firefox", 1)
            raise FileNotFoundError(f"Value {name} not found")

        mock_winreg.QueryValueEx = query_value
        mock_subkey = MagicMock()

        result = collector._parse_registry_subkey(mock_winreg, mock_subkey, "{ABC-123}")

        assert result is not None
        assert result["version"] == "Unknown"


class TestCollectRegistryKeyPrograms:
    """Tests for _collect_registry_key_programs method."""

    def test_collect_programs_success(self, collector):
        """Test successful registry key program collection."""
        mock_winreg = MagicMock()
        mock_key = MagicMock()
        _mock_subkey = MagicMock()

        mock_winreg.OpenKey.return_value.__enter__ = Mock(return_value=mock_key)
        mock_winreg.OpenKey.return_value.__exit__ = Mock(return_value=False)
        mock_winreg.QueryInfoKey.return_value = (2, 0, 0)  # 2 subkeys
        mock_winreg.EnumKey.side_effect = ["Firefox", "VSCode"]

        def query_value(_key, name):
            if name == "DisplayName":
                return ("Test App", 1)
            if name == "DisplayVersion":
                return ("1.0", 1)
            raise FileNotFoundError()

        mock_winreg.QueryValueEx = query_value

        seen = set()
        collector._collect_registry_key_programs(
            mock_winreg, mock_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Test", seen
        )

        # Should have attempted to collect programs
        assert mock_winreg.QueryInfoKey.called

    def test_collect_programs_key_not_found(self, collector):
        """Test collection when registry key not found."""
        mock_winreg = MagicMock()
        mock_winreg.OpenKey.side_effect = FileNotFoundError()

        seen = set()
        collector._collect_registry_key_programs(
            mock_winreg, mock_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\NotFound", seen
        )

        # Should handle gracefully
        assert len(collector.collected_packages) == 0

    def test_collect_programs_permission_denied(self, collector):
        """Test collection when permission denied."""
        mock_winreg = MagicMock()
        mock_winreg.OpenKey.side_effect = PermissionError()

        seen = set()
        collector._collect_registry_key_programs(
            mock_winreg, mock_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Protected", seen
        )

        # Should handle gracefully
        assert len(collector.collected_packages) == 0

    def test_collect_programs_deduplication(self, collector):
        """Test that duplicate programs are not added."""
        # Pre-populate seen set
        seen = {"Test App_1.0"}

        mock_winreg = MagicMock()
        mock_key = MagicMock()

        mock_winreg.OpenKey.return_value.__enter__ = Mock(return_value=mock_key)
        mock_winreg.OpenKey.return_value.__exit__ = Mock(return_value=False)
        mock_winreg.QueryInfoKey.return_value = (1, 0, 0)
        mock_winreg.EnumKey.return_value = "TestApp"

        def query_value(_key, name):
            if name == "DisplayName":
                return ("Test App", 1)
            if name == "DisplayVersion":
                return ("1.0", 1)
            raise FileNotFoundError()

        mock_winreg.QueryValueEx = query_value

        collector._collect_registry_key_programs(
            mock_winreg, mock_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Test", seen
        )

        # Should not add duplicate
        assert len(collector.collected_packages) == 0


class TestCollectChocolateyPackages:
    """Tests for _collect_chocolatey_packages method."""

    def test_collect_chocolatey_not_implemented(self, collector):
        """Test that chocolatey collection logs but doesn't fail."""
        # Should not raise any exception
        collector._collect_chocolatey_packages()

        # Should not add any packages (not implemented)
        assert len(collector.collected_packages) == 0


class TestCollectScoopPackages:
    """Tests for _collect_scoop_packages method."""

    def test_collect_scoop_not_implemented(self, collector):
        """Test that scoop collection logs but doesn't fail."""
        # Should not raise any exception
        collector._collect_scoop_packages()

        # Should not add any packages (not implemented)
        assert len(collector.collected_packages) == 0


class TestErrorRecovery:
    """Tests for error recovery and graceful degradation."""

    def test_subprocess_timeout(self, collector):
        """Test handling of subprocess timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 60)):
            collector._collect_winget_packages()

        assert len(collector.collected_packages) == 0

    def test_multiple_source_failures(self, collector):
        """Test that failures in one source don't affect others."""
        call_count = 0

        def run_side_effect(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # First two calls fail
                raise RuntimeError("Error")
            # Third call succeeds (winget)
            return Mock(
                returncode=0,
                stdout=(
                    "Name    Id         Version\n"
                    "----------------------------\n"
                    "App     App.Id     1.0\n"
                ),
            )

        with patch.object(
            collector, "detect_package_managers", return_value=["winget"]
        ):
            with patch("subprocess.run", side_effect=run_side_effect):
                collector.collect_packages()

        # At least some packages should be collected
        # (depending on which sources succeeded)

    def test_json_decode_error_recovery(self, collector):
        """Test recovery from JSON decode errors."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "{invalid json"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_microsoft_store_apps()

        # Should recover and not crash
        assert len(collector.collected_packages) == 0


class TestIntegrationScenarios:
    """Integration-style tests for realistic scenarios."""

    def test_full_windows_collection_flow(self, collector):
        """Test complete Windows collection with all sources."""
        # Mock all sources returning packages
        winget_output = (
            "Name    Id         Version\n"
            "----------------------------\n"
            "Firefox Mozilla.Firefox 91.0\n"
        )

        store_output = json.dumps([{"Name": "Calculator", "Version": "11.0"}])

        with patch.object(
            collector, "detect_package_managers", return_value=["winget"]
        ):
            with patch.object(collector, "_collect_windows_registry_programs"):
                with patch("subprocess.run") as mock_run:
                    # Return different outputs for different commands
                    def run_side_effect(*args, **_kwargs):
                        cmd = args[0]
                        result = Mock()
                        result.returncode = 0
                        if "winget" in cmd:
                            result.stdout = winget_output
                        elif "powershell" in cmd:
                            result.stdout = store_output
                        else:
                            result.stdout = ""
                        return result

                    mock_run.side_effect = run_side_effect
                    collector.collect_packages()

        # Should have collected from multiple sources
        assert len(collector.collected_packages) >= 1

    def test_internal_error_handling(self, collector):
        """Test that each collection method handles its own errors."""
        # Each collection method should handle subprocess errors gracefully
        with patch("subprocess.run", side_effect=Exception("Error")):
            # These should not raise, just log errors
            collector._collect_winget_packages()
            collector._collect_microsoft_store_apps()

        assert len(collector.collected_packages) == 0

    def test_partial_collection_success(self, collector):
        """Test collection succeeds when winget works."""
        winget_output = (
            "Name    Id         Version\n"
            "----------------------------\n"
            "App     App.Id     1.0\n"
        )

        with patch.object(
            collector, "detect_package_managers", return_value=["winget"]
        ):
            with patch.object(collector, "_collect_windows_registry_programs"):
                with patch.object(collector, "_collect_microsoft_store_apps"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stdout=winget_output)
                        collector.collect_packages()

        # Package collected from winget
        assert len(collector.collected_packages) == 1
        assert collector.collected_packages[0]["package_name"] == "App"
