"""
Tests for Windows update application functionality.

This module covers:
- WindowsUpdateApplierMixin methods
- Winget update application
- Chocolatey update application
- Windows system updates
- Windows version upgrades
- Package collection and routing
"""

# pylint: disable=protected-access,redefined-outer-name

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_windows import (
    WindowsUpdateDetector,
)
from src.sysmanage_agent.collection.update_detection_windows_apply import (
    WINDOWS_UPDATE_LABEL,
)

# On non-Windows platforms, CREATE_NO_WINDOW doesn't exist, so we need to set it
if not hasattr(subprocess, "CREATE_NO_WINDOW"):
    subprocess.CREATE_NO_WINDOW = 0x08000000


@pytest.fixture
def windows_detector():
    """Create a WindowsUpdateDetector for testing."""
    with patch("platform.system", return_value="Windows"):
        detector = WindowsUpdateDetector()
        detector.available_updates = []
        return detector


# =============================================================================
# _detect_winget_process_timeout Tests
# =============================================================================


class TestDetectWingetProcessTimeout:
    """Tests for _detect_winget_process_timeout method."""

    def test_process_completes_immediately(self, windows_detector):
        """Test when process completes immediately."""
        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Success output", "")

        package = {"package_name": "test-package"}
        results = {"failed_packages": []}

        returncode, stdout, stderr = windows_detector._detect_winget_process_timeout(
            mock_process, package, 1200, results
        )

        assert returncode == 0
        assert stdout == "Success output"
        assert stderr == ""
        assert len(results["failed_packages"]) == 0

    def test_process_completes_after_polling(self, windows_detector):
        """Test when process completes after a few poll cycles."""
        mock_process = Mock()
        # Return None twice (still running), then return 0 (completed)
        mock_process.poll.side_effect = [None, None, 0]
        mock_process.communicate.return_value = ("Output after polling", "")

        package = {"package_name": "test-package"}
        results = {"failed_packages": []}

        with patch("time.sleep"):
            returncode, stdout, _stderr = (
                windows_detector._detect_winget_process_timeout(
                    mock_process, package, 1200, results
                )
            )

        assert returncode == 0
        assert stdout == "Output after polling"
        assert len(results["failed_packages"]) == 0

    def test_process_timeout(self, windows_detector):
        """Test when process times out."""
        mock_process = Mock()
        mock_process.poll.return_value = None  # Always returns None (still running)
        mock_process.communicate.return_value = ("Partial output", "")
        mock_process.kill = Mock()

        package = {"package_name": "slow-package"}
        results = {"failed_packages": []}

        # Mock time to simulate timeout - need enough values for the loop
        # Loop: start_time, last_log_time, then check elapsed > timeout
        time_values = [0, 0]  # start_time, last_log_time
        time_values.extend([1300] * 10)  # multiple calls for elapsed checks

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.time.time"
        ) as mock_time:
            mock_time.side_effect = time_values
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.time.sleep"
            ):
                returncode, _stdout, _stderr = (
                    windows_detector._detect_winget_process_timeout(
                        mock_process, package, 1200, results
                    )
                )

        assert returncode is None
        mock_process.kill.assert_called_once()
        assert len(results["failed_packages"]) == 1
        assert results["failed_packages"][0]["package_name"] == "slow-package"
        assert results["failed_packages"][0]["package_manager"] == "winget"
        assert "timed out" in results["failed_packages"][0]["error"]

    def test_progress_logging(self, windows_detector):
        """Test progress logging every 30 seconds."""
        mock_process = Mock()
        # Process completes on 4th poll
        mock_process.poll.side_effect = [None, None, None, 0]
        mock_process.communicate.return_value = ("Done", "")

        package = {"package_name": "long-running-package"}
        results = {"failed_packages": []}

        # Time progression: start=0, then 35s elapsed (triggers log), then completes
        with patch("time.time") as mock_time:
            mock_time.side_effect = [
                0,  # start_time
                0,  # last_log_time
                35,  # elapsed (first check, > 30s triggers log)
                35,  # for progress log
                35,  # new last_log_time
                40,  # second poll
                40,  # elapsed check
                50,  # third poll  - completed
            ]
            with patch("time.sleep"):
                windows_detector._detect_winget_process_timeout(
                    mock_process, package, 1200, results
                )

        # Verify no failures since process completed
        assert len(results["failed_packages"]) == 0


# =============================================================================
# _process_winget_result Tests
# =============================================================================


class TestProcessWingetResult:
    """Tests for _process_winget_result method."""

    def test_success_with_zero_returncode(self, windows_detector):
        """Test successful update with returncode 0."""
        package = {
            "package_name": "test-package",
            "current_version": "1.0.0",
            "available_version": "2.0.0",
        }
        results = {"updated_packages": [], "failed_packages": []}

        windows_detector._process_winget_result(
            0, "Successfully installed", "", package, results
        )

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_name"] == "test-package"
        assert results["updated_packages"][0]["old_version"] == "1.0.0"
        assert results["updated_packages"][0]["new_version"] == "2.0.0"
        assert results["updated_packages"][0]["package_manager"] == "winget"
        assert len(results["failed_packages"]) == 0

    def test_failure_with_nonzero_returncode(self, windows_detector):
        """Test failed update with non-zero returncode."""
        package = {
            "package_name": "broken-package",
            "current_version": "1.0.0",
            "available_version": "2.0.0",
        }
        results = {"updated_packages": [], "failed_packages": []}

        windows_detector._process_winget_result(
            1, "", "Installation failed", package, results
        )

        assert len(results["updated_packages"]) == 0
        assert len(results["failed_packages"]) == 1
        assert results["failed_packages"][0]["package_name"] == "broken-package"
        assert "Installation failed" in results["failed_packages"][0]["error"]

    def test_failure_with_stdout_error(self, windows_detector):
        """Test failed update with error in stdout."""
        package = {"package_name": "test-package"}
        results = {"updated_packages": [], "failed_packages": []}

        windows_detector._process_winget_result(
            1, "Error: package not found", "", package, results
        )

        assert len(results["failed_packages"]) == 1
        assert "Error: package not found" in results["failed_packages"][0]["error"]

    def test_failure_with_default_error_message(self, windows_detector):
        """Test failed update with default error message."""
        package = {"package_name": "test-package"}
        results = {"updated_packages": [], "failed_packages": []}

        windows_detector._process_winget_result(1, "", "", package, results)

        assert len(results["failed_packages"]) == 1
        assert "exit code 1" in results["failed_packages"][0]["error"]

    def test_error_message_truncation(self, windows_detector):
        """Test that long error messages are truncated."""
        package = {"package_name": "test-package"}
        results = {"updated_packages": [], "failed_packages": []}

        long_error = "E" * 2000  # Very long error message
        windows_detector._process_winget_result(1, "", long_error, package, results)

        assert len(results["failed_packages"][0]["error"]) <= 1000


# =============================================================================
# _apply_winget_updates Tests
# =============================================================================


class TestApplyWingetUpdates:
    """Tests for _apply_winget_updates method."""

    def test_apply_single_package_success(self, windows_detector):
        """Test applying a single winget update successfully."""
        packages = [
            {
                "package_name": "Git",
                "bundle_id": "Git.Git",
                "current_version": "2.42.0",
                "available_version": "2.43.0",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Successfully installed", "")

        with patch("subprocess.Popen", return_value=mock_process):
            windows_detector._apply_winget_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_name"] == "Git"

    def test_apply_multiple_packages(self, windows_detector):
        """Test applying multiple winget updates."""
        packages = [
            {"package_name": "Git", "bundle_id": "Git.Git"},
            {"package_name": "VSCode", "bundle_id": "Microsoft.VisualStudioCode"},
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Success", "")

        with patch("subprocess.Popen", return_value=mock_process):
            windows_detector._apply_winget_updates(packages, results)

        assert len(results["updated_packages"]) == 2

    def test_apply_package_without_bundle_id(self, windows_detector):
        """Test applying update when bundle_id is not present."""
        packages = [{"package_name": "SomePackage"}]
        results = {"updated_packages": [], "failed_packages": []}

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Success", "")

        with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
            windows_detector._apply_winget_updates(packages, results)

        # Verify that package_name was used as the package_id
        call_args = mock_popen.call_args[0][0]
        assert "SomePackage" in call_args

    def test_apply_package_exception(self, windows_detector):
        """Test handling exception during package update."""
        packages = [{"package_name": "test-package"}]
        results = {"updated_packages": [], "failed_packages": []}

        with patch("subprocess.Popen", side_effect=Exception("Popen failed")):
            windows_detector._apply_winget_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Popen failed" in results["failed_packages"][0]["error"]

    def test_apply_package_timeout(self, windows_detector):
        """Test handling timeout during package update."""
        packages = [{"package_name": "slow-package"}]
        results = {"updated_packages": [], "failed_packages": []}

        mock_process = Mock()
        mock_process.poll.return_value = None
        mock_process.communicate.return_value = ("Partial", "")
        mock_process.kill = Mock()

        # Need enough time values for the loop
        time_values = [0, 0]  # start_time, last_log_time
        time_values.extend([1300] * 10)  # multiple calls for elapsed checks

        with patch("subprocess.Popen", return_value=mock_process):
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.time.time"
            ) as mock_time:
                mock_time.side_effect = time_values
                with patch(
                    "src.sysmanage_agent.collection.update_detection_windows_apply.time.sleep"
                ):
                    windows_detector._apply_winget_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "timed out" in results["failed_packages"][0]["error"]


# =============================================================================
# _apply_chocolatey_updates Tests
# =============================================================================


class TestApplyChocolateyUpdates:
    """Tests for _apply_chocolatey_updates method."""

    def test_apply_single_package_success(self, windows_detector):
        """Test applying a single Chocolatey update successfully."""
        packages = [
            {
                "package_name": "git",
                "current_version": "2.42.0",
                "available_version": "2.43.0",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=0, stdout="Chocolatey upgraded 1 package")
        mock_result.stderr = ""
        mock_result.stdout = mock_result.stdout

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._apply_chocolatey_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_name"] == "git"
        assert results["updated_packages"][0]["package_manager"] == "chocolatey"

    def test_apply_multiple_packages(self, windows_detector):
        """Test applying multiple Chocolatey updates."""
        packages = [
            {"package_name": "git"},
            {"package_name": "nodejs"},
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=0)
        mock_result.stderr = ""
        mock_result.stdout = "Success"

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._apply_chocolatey_updates(packages, results)

        assert len(results["updated_packages"]) == 2

    def test_apply_package_failure(self, windows_detector):
        """Test handling Chocolatey update failure."""
        packages = [{"package_name": "broken-package"}]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=1)
        mock_result.stderr = "Package not found"
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._apply_chocolatey_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Package not found" in results["failed_packages"][0]["error"]

    def test_apply_package_failure_stdout_error(self, windows_detector):
        """Test handling failure with error in stdout."""
        packages = [{"package_name": "test-package"}]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=1)
        mock_result.stderr = ""
        mock_result.stdout = "Error during installation"

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._apply_chocolatey_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Error during installation" in results["failed_packages"][0]["error"]

    def test_apply_package_exception(self, windows_detector):
        """Test handling exception during Chocolatey update."""
        packages = [{"package_name": "test-package"}]
        results = {"updated_packages": [], "failed_packages": []}

        with patch("subprocess.run", side_effect=Exception("Subprocess failed")):
            windows_detector._apply_chocolatey_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Subprocess failed" in results["failed_packages"][0]["error"]


# =============================================================================
# _collect_windows_update_powershell_cmd Tests
# =============================================================================


class TestCollectWindowsUpdatePowershellCmd:
    """Tests for _collect_windows_update_powershell_cmd method."""

    def test_command_with_update_id(self, windows_detector):
        """Test PowerShell command generation with update_id."""
        cmd = windows_detector._collect_windows_update_powershell_cmd(
            "KB12345", "Security Update"
        )

        assert "Identity.UpdateID" in cmd
        assert "KB12345" in cmd
        assert '-KBArticleID "KB12345"' in cmd
        assert "Update not found with UpdateID 'KB12345'" in cmd

    def test_command_without_update_id(self, windows_detector):
        """Test PowerShell command generation without update_id."""
        cmd = windows_detector._collect_windows_update_powershell_cmd(
            None, "Windows Security Update"
        )

        assert "Title" in cmd
        assert "Windows Security Update" in cmd
        assert '-Title "Windows Security Update"' in cmd
        assert "Update not found with title 'Windows Security Update'" in cmd

    def test_command_contains_pswindowsupdate_check(self, windows_detector):
        """Test that command checks for PSWindowsUpdate module."""
        cmd = windows_detector._collect_windows_update_powershell_cmd(
            "KB12345", "Test Update"
        )

        assert "Get-Module -ListAvailable -Name PSWindowsUpdate" in cmd
        assert "Import-Module PSWindowsUpdate" in cmd
        assert "Install-WindowsUpdate" in cmd

    def test_command_contains_com_fallback(self, windows_detector):
        """Test that command contains COM object fallback."""
        cmd = windows_detector._collect_windows_update_powershell_cmd(
            "KB12345", "Test Update"
        )

        assert "Microsoft.Update.Session" in cmd
        assert "CreateUpdateSearcher" in cmd
        assert "CreateUpdateDownloader" in cmd
        assert "CreateUpdateInstaller" in cmd


# =============================================================================
# _process_windows_update_result Tests
# =============================================================================


class TestProcessWindowsUpdateResult:
    """Tests for _process_windows_update_result method."""

    def test_success_with_success_output(self, windows_detector):
        """Test successful update with SUCCESS in output."""
        mock_result = Mock(returncode=0, stdout="SUCCESS", stderr="")
        package = {
            "package_name": "KB12345",
            "current_version": "",
            "available_version": "KB12345",
        }
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        windows_detector._process_windows_update_result(
            mock_result, "KB12345", package, results
        )

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_manager"] == WINDOWS_UPDATE_LABEL
        assert results["requires_reboot"] is True

    def test_success_with_resultcode_2(self, windows_detector):
        """Test successful update with ResultCode=2 in output."""
        mock_result = Mock(returncode=0, stdout="ResultCode=2", stderr="")
        package = {"package_name": "KB12345"}
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        windows_detector._process_windows_update_result(
            mock_result, "KB12345", package, results
        )

        assert len(results["updated_packages"]) == 1
        assert results["requires_reboot"] is True

    def test_failure_with_error_in_output(self, windows_detector):
        """Test failure when ERROR: is in output."""
        mock_result = Mock(returncode=0, stdout="ERROR: Update not found", stderr="")
        package = {"package_name": "KB12345"}
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        windows_detector._process_windows_update_result(
            mock_result, "KB12345", package, results
        )

        assert len(results["failed_packages"]) == 1
        assert "ERROR: Update not found" in results["failed_packages"][0]["error"]

    def test_failure_with_failed_in_output(self, windows_detector):
        """Test failure when FAILED: is in output."""
        mock_result = Mock(
            returncode=0, stdout="FAILED: ResultCode=3, HResult=0x80070005", stderr=""
        )
        package = {"package_name": "KB12345"}
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        windows_detector._process_windows_update_result(
            mock_result, "KB12345", package, results
        )

        assert len(results["failed_packages"]) == 1
        assert "FAILED" in results["failed_packages"][0]["error"]

    def test_failure_with_nonzero_returncode(self, windows_detector):
        """Test failure with non-zero returncode."""
        mock_result = Mock(returncode=1, stdout="", stderr="PowerShell error")
        package = {"package_name": "KB12345"}
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        windows_detector._process_windows_update_result(
            mock_result, "KB12345", package, results
        )

        assert len(results["failed_packages"]) == 1
        assert "PowerShell error" in results["failed_packages"][0]["error"]

    def test_failure_default_message(self, windows_detector):
        """Test failure with default error message."""
        mock_result = Mock(returncode=1, stdout="", stderr="")
        package = {"package_name": "KB12345"}
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        windows_detector._process_windows_update_result(
            mock_result, "KB12345", package, results
        )

        assert len(results["failed_packages"]) == 1
        # Default message should be set


# =============================================================================
# _apply_windows_system_updates Tests
# =============================================================================


class TestApplyWindowsSystemUpdates:
    """Tests for _apply_windows_system_updates method."""

    def test_apply_single_update_success(self, windows_detector):
        """Test applying a single Windows system update successfully."""
        packages = [
            {
                "package_name": "Security Update KB12345",
                "update_id": "12345-67890",
                "current_version": "",
                "available_version": "KB12345",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="SUCCESS", stderr="")

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.subprocess.run",
            return_value=mock_result,
        ):
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.platform.system",
                return_value="Windows",
            ):
                windows_detector._apply_windows_system_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["requires_reboot"] is True

    def test_apply_update_with_bundle_id(self, windows_detector):
        """Test applying update using bundle_id when update_id is not present."""
        packages = [
            {
                "package_name": "KB12345",
                "bundle_id": "bundle-12345",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="SUCCESS", stderr="")

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.subprocess.run",
            return_value=mock_result,
        ):
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.platform.system",
                return_value="Windows",
            ):
                windows_detector._apply_windows_system_updates(packages, results)

        assert len(results["updated_packages"]) == 1

    def test_apply_update_timeout(self, windows_detector):
        """Test handling timeout during Windows update."""
        packages = [{"package_name": "KB12345"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.subprocess.run",
            side_effect=subprocess.TimeoutExpired("powershell", 1800),
        ):
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.platform.system",
                return_value="Windows",
            ):
                windows_detector._apply_windows_system_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "30 minutes" in results["failed_packages"][0]["error"]

    def test_apply_update_exception(self, windows_detector):
        """Test handling exception during Windows update."""
        packages = [{"package_name": "KB12345"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.subprocess.run",
            side_effect=Exception("Unexpected error"),
        ):
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.platform.system",
                return_value="Windows",
            ):
                windows_detector._apply_windows_system_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Unexpected error" in results["failed_packages"][0]["error"]

    def test_apply_multiple_updates(self, windows_detector):
        """Test applying multiple Windows system updates."""
        packages = [
            {"package_name": "KB12345", "update_id": "12345"},
            {"package_name": "KB67890", "update_id": "67890"},
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="SUCCESS", stderr="")

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.subprocess.run",
            return_value=mock_result,
        ):
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.platform.system",
                return_value="Windows",
            ):
                windows_detector._apply_windows_system_updates(packages, results)

        assert len(results["updated_packages"]) == 2


# =============================================================================
# _apply_windows_upgrade_updates Tests
# =============================================================================


class TestApplyWindowsUpgradeUpdates:
    """Tests for _apply_windows_upgrade_updates method."""

    def test_apply_upgrade_success(self, windows_detector):
        """Test applying Windows upgrade successfully."""
        packages = [
            {
                "package_name": "Windows 11 Version 23H2",
                "current_version": "22H2",
                "available_version": "23H2",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="Success", stderr="")

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._apply_windows_upgrade_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_manager"] == "windows-upgrade"
        assert results["requires_reboot"] is True

    def test_apply_upgrade_failure(self, windows_detector):
        """Test handling Windows upgrade failure."""
        packages = [
            {
                "package_name": "Windows 11 Version 23H2",
                "available_version": "23H2",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=1, stdout="", stderr="Upgrade failed")

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._apply_windows_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Upgrade failed" in results["failed_packages"][0]["error"]

    def test_apply_upgrade_timeout(self, windows_detector):
        """Test handling timeout during Windows upgrade."""
        packages = [
            {
                "package_name": "Windows 11 Version 23H2",
                "available_version": "23H2",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("powershell", 7200)
        ):
            windows_detector._apply_windows_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "2 hours" in results["failed_packages"][0]["error"]

    def test_apply_upgrade_exception(self, windows_detector):
        """Test handling exception during Windows upgrade."""
        packages = [
            {
                "package_name": "Windows 11 Version 23H2",
                "available_version": "23H2",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            windows_detector._apply_windows_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Unexpected error" in results["failed_packages"][0]["error"]

    def test_apply_upgrade_failure_no_stderr(self, windows_detector):
        """Test handling upgrade failure without stderr."""
        packages = [
            {
                "package_name": "Windows 11 Version 23H2",
                "available_version": "23H2",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=1, stdout="", stderr="")

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._apply_windows_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1


# =============================================================================
# _collect_windows_packages_to_update Tests
# =============================================================================


class TestCollectWindowsPackagesToUpdate:
    """Tests for _collect_windows_packages_to_update method."""

    def test_with_packages_list(self, windows_detector):
        """Test with packages list (new format)."""
        packages = [
            {"name": "git", "package_manager": "winget"},
            {"name": "nodejs", "package_manager": "chocolatey"},
        ]

        result = windows_detector._collect_windows_packages_to_update(packages=packages)

        assert len(result) == 2
        assert result[0]["name"] == "git"
        assert result[1]["name"] == "nodejs"

    def test_with_package_names_list(self, windows_detector):
        """Test with package_names list (legacy format)."""
        package_names = ["git", "nodejs"]
        package_managers = ["winget", "chocolatey"]

        result = windows_detector._collect_windows_packages_to_update(
            package_names=package_names, package_managers=package_managers
        )

        assert len(result) == 2
        assert result[0]["name"] == "git"
        assert result[0]["package_manager"] == "winget"
        assert result[1]["name"] == "nodejs"
        assert result[1]["package_manager"] == "chocolatey"

    def test_with_package_names_no_managers(self, windows_detector):
        """Test with package_names but no package_managers."""
        package_names = ["git", "nodejs"]

        result = windows_detector._collect_windows_packages_to_update(
            package_names=package_names
        )

        assert len(result) == 2
        assert result[0]["package_manager"] == "unknown"
        assert result[1]["package_manager"] == "unknown"

    def test_with_package_names_fewer_managers(self, windows_detector):
        """Test with more package_names than package_managers."""
        package_names = ["git", "nodejs", "python"]
        package_managers = ["winget"]

        result = windows_detector._collect_windows_packages_to_update(
            package_names=package_names, package_managers=package_managers
        )

        assert len(result) == 3
        assert result[0]["package_manager"] == "winget"
        assert result[1]["package_manager"] == "unknown"
        assert result[2]["package_manager"] == "unknown"

    def test_empty_input(self, windows_detector):
        """Test with no input."""
        result = windows_detector._collect_windows_packages_to_update()

        assert result == []

    def test_packages_takes_precedence(self, windows_detector):
        """Test that packages parameter takes precedence over package_names."""
        packages = [{"name": "git", "package_manager": "winget"}]
        package_names = ["nodejs"]

        result = windows_detector._collect_windows_packages_to_update(
            package_names=package_names, packages=packages
        )

        assert len(result) == 1
        assert result[0]["name"] == "git"


# =============================================================================
# _find_windows_matching_update Tests
# =============================================================================


class TestFindWindowsMatchingUpdate:
    """Tests for _find_windows_matching_update method."""

    def test_find_matching_update(self, windows_detector):
        """Test finding a matching update."""
        windows_detector.available_updates = [
            {
                "package_name": "git",
                "package_manager": "winget",
                "available_version": "2.43.0",
            },
            {
                "package_name": "nodejs",
                "package_manager": "chocolatey",
                "available_version": "20.0.0",
            },
        ]

        result = windows_detector._find_windows_matching_update("git", "winget")

        assert result is not None
        assert result["package_name"] == "git"
        assert result["available_version"] == "2.43.0"

    def test_find_no_matching_update(self, windows_detector):
        """Test when no matching update is found."""
        windows_detector.available_updates = [
            {"package_name": "git", "package_manager": "winget"},
        ]

        result = windows_detector._find_windows_matching_update("nodejs", "chocolatey")

        assert result is None

    def test_find_matching_requires_both_name_and_manager(self, windows_detector):
        """Test that both name and package_manager must match."""
        windows_detector.available_updates = [
            {"package_name": "git", "package_manager": "winget"},
            {"package_name": "git", "package_manager": "chocolatey"},
        ]

        result = windows_detector._find_windows_matching_update("git", "chocolatey")

        assert result is not None
        assert result["package_manager"] == "chocolatey"


# =============================================================================
# _enrich_windows_package_info Tests
# =============================================================================


class TestEnrichWindowsPackageInfo:
    """Tests for _enrich_windows_package_info method."""

    def test_enrich_with_matching_update(self, windows_detector):
        """Test enriching package info with matching update."""
        windows_detector.available_updates = [
            {
                "package_name": "git",
                "package_manager": "winget",
                "available_version": "2.43.0",
                "current_version": "2.42.0",
                "bundle_id": "Git.Git",
            }
        ]

        pkg = {"name": "git", "package_manager": "winget"}
        result = windows_detector._enrich_windows_package_info(pkg)

        assert result["available_version"] == "2.43.0"
        assert result["current_version"] == "2.42.0"
        assert result["bundle_id"] == "Git.Git"
        assert result["package_name"] == "git"

    def test_enrich_without_matching_update(self, windows_detector):
        """Test enriching package info without matching update."""
        windows_detector.available_updates = []

        pkg = {"name": "git", "package_manager": "winget"}
        result = windows_detector._enrich_windows_package_info(pkg)

        assert result["package_name"] == "git"
        assert "available_version" not in result

    def test_enrich_preserves_existing_values(self, windows_detector):
        """Test that existing values in pkg are preserved."""
        windows_detector.available_updates = [
            {
                "package_name": "git",
                "package_manager": "winget",
                "available_version": "2.43.0",
            }
        ]

        pkg = {
            "name": "git",
            "package_manager": "winget",
            "available_version": "2.44.0",
        }
        result = windows_detector._enrich_windows_package_info(pkg)

        # Original value should be preserved
        assert result["available_version"] == "2.44.0"

    def test_enrich_creates_copy(self, windows_detector):
        """Test that enrichment creates a copy and doesn't modify original."""
        windows_detector.available_updates = []

        pkg = {"name": "git", "package_manager": "winget"}
        result = windows_detector._enrich_windows_package_info(pkg)

        assert result is not pkg


# =============================================================================
# _collect_windows_packages_by_manager Tests
# =============================================================================


class TestCollectWindowsPackagesByManager:
    """Tests for _collect_windows_packages_by_manager method."""

    def test_group_by_single_manager(self, windows_detector):
        """Test grouping packages by single manager."""
        packages = [
            {"name": "git", "package_manager": "winget"},
            {"name": "nodejs", "package_manager": "winget"},
        ]

        result = windows_detector._collect_windows_packages_by_manager(packages)

        assert "winget" in result
        assert len(result["winget"]) == 2

    def test_group_by_multiple_managers(self, windows_detector):
        """Test grouping packages by multiple managers."""
        packages = [
            {"name": "git", "package_manager": "winget"},
            {"name": "nodejs", "package_manager": "chocolatey"},
            {"name": "python", "package_manager": "winget"},
        ]

        result = windows_detector._collect_windows_packages_by_manager(packages)

        assert "winget" in result
        assert "chocolatey" in result
        assert len(result["winget"]) == 2
        assert len(result["chocolatey"]) == 1

    def test_group_includes_enriched_info(self, windows_detector):
        """Test that grouped packages include enriched info."""
        windows_detector.available_updates = [
            {
                "package_name": "git",
                "package_manager": "winget",
                "available_version": "2.43.0",
            }
        ]

        packages = [{"name": "git", "package_manager": "winget"}]

        result = windows_detector._collect_windows_packages_by_manager(packages)

        assert result["winget"][0]["available_version"] == "2.43.0"

    def test_group_default_manager(self, windows_detector):
        """Test packages with no manager go to 'unknown'."""
        packages = [{"name": "git"}]

        result = windows_detector._collect_windows_packages_by_manager(packages)

        assert "unknown" in result


# =============================================================================
# _process_windows_manager_updates Tests
# =============================================================================


class TestProcessWindowsManagerUpdates:
    """Tests for _process_windows_manager_updates method."""

    def test_dispatch_to_winget(self, windows_detector):
        """Test dispatching to winget handler."""
        pkg_list = [{"package_name": "git"}]
        results = {"updated_packages": [], "failed_packages": []}

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Success", "")

        with patch("subprocess.Popen", return_value=mock_process):
            windows_detector._process_windows_manager_updates(
                "winget", pkg_list, results
            )

        assert len(results["updated_packages"]) == 1

    def test_dispatch_to_chocolatey(self, windows_detector):
        """Test dispatching to chocolatey handler."""
        pkg_list = [{"package_name": "git"}]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=0)
        mock_result.stderr = ""
        mock_result.stdout = "Success"

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._process_windows_manager_updates(
                "chocolatey", pkg_list, results
            )

        assert len(results["updated_packages"]) == 1

    def test_dispatch_to_windows_update(self, windows_detector):
        """Test dispatching to Windows Update handler."""
        pkg_list = [{"package_name": "KB12345"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="SUCCESS", stderr="")

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.subprocess.run",
            return_value=mock_result,
        ):
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.platform.system",
                return_value="Windows",
            ):
                windows_detector._process_windows_manager_updates(
                    WINDOWS_UPDATE_LABEL, pkg_list, results
                )

        assert len(results["updated_packages"]) == 1

    def test_dispatch_to_windows_upgrade(self, windows_detector):
        """Test dispatching to Windows upgrade handler."""
        pkg_list = [{"package_name": "Windows 11", "available_version": "23H2"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="Success", stderr="")

        with patch("subprocess.run", return_value=mock_result):
            windows_detector._process_windows_manager_updates(
                "windows-upgrade", pkg_list, results
            )

        assert len(results["updated_packages"]) == 1

    def test_dispatch_unsupported_manager(self, windows_detector):
        """Test handling unsupported package manager."""
        pkg_list = [{"package_name": "test-package"}]
        results = {"updated_packages": [], "failed_packages": []}

        windows_detector._process_windows_manager_updates(
            "unsupported-manager", pkg_list, results
        )

        assert len(results["failed_packages"]) == 1
        assert "Unsupported package manager" in results["failed_packages"][0]["error"]


# =============================================================================
# apply_updates Tests (Main Orchestration Method)
# =============================================================================


class TestApplyUpdates:
    """Tests for apply_updates orchestration method."""

    def test_apply_updates_empty_packages(self, windows_detector):
        """Test apply_updates with no packages."""
        result = windows_detector.apply_updates()

        assert result["updated_packages"] == []
        assert result["failed_packages"] == []
        assert result["requires_reboot"] is False
        assert "timestamp" in result

    def test_apply_updates_with_packages_list(self, windows_detector):
        """Test apply_updates with packages list."""
        windows_detector.available_updates = [
            {
                "package_name": "git",
                "package_manager": "winget",
                "current_version": "2.42.0",
                "available_version": "2.43.0",
            }
        ]

        packages = [{"name": "git", "package_manager": "winget"}]

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Success", "")

        with patch("subprocess.Popen", return_value=mock_process):
            result = windows_detector.apply_updates(packages=packages)

        assert len(result["updated_packages"]) == 1

    def test_apply_updates_legacy_format(self, windows_detector):
        """Test apply_updates with legacy format."""
        windows_detector.available_updates = [
            {
                "package_name": "git",
                "package_manager": "winget",
                "available_version": "2.43.0",
            }
        ]

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Success", "")

        with patch("subprocess.Popen", return_value=mock_process):
            result = windows_detector.apply_updates(
                package_names=["git"], package_managers=["winget"]
            )

        assert len(result["updated_packages"]) == 1

    def test_apply_updates_mixed_managers(self, windows_detector):
        """Test apply_updates with multiple package managers."""
        windows_detector.available_updates = [
            {
                "package_name": "git",
                "package_manager": "winget",
                "available_version": "2.43.0",
            },
            {
                "package_name": "nodejs",
                "package_manager": "chocolatey",
                "available_version": "20.0.0",
            },
        ]

        packages = [
            {"name": "git", "package_manager": "winget"},
            {"name": "nodejs", "package_manager": "chocolatey"},
        ]

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Success", "")

        mock_result = Mock(returncode=0)
        mock_result.stderr = ""
        mock_result.stdout = "Success"

        with patch("subprocess.Popen", return_value=mock_process):
            with patch("subprocess.run", return_value=mock_result):
                result = windows_detector.apply_updates(packages=packages)

        assert len(result["updated_packages"]) == 2

    def test_apply_updates_exception_handling(self, windows_detector):
        """Test apply_updates handles exceptions gracefully."""
        packages = [{"name": "test", "package_manager": "winget"}]

        with patch.object(
            windows_detector,
            "_collect_windows_packages_by_manager",
            side_effect=Exception("Unexpected error"),
        ):
            result = windows_detector.apply_updates(packages=packages)

        assert len(result["failed_packages"]) == 1
        assert "Unexpected error" in result["failed_packages"][0]["error"]

    def test_apply_updates_partial_failure(self, windows_detector):
        """Test apply_updates with some packages failing."""
        windows_detector.available_updates = [
            {
                "package_name": "git",
                "package_manager": "winget",
                "available_version": "2.43.0",
            },
            {
                "package_name": "broken",
                "package_manager": "winget",
                "available_version": "1.0.0",
            },
        ]

        packages = [
            {"name": "git", "package_manager": "winget"},
            {"name": "broken", "package_manager": "winget"},
        ]

        # First package succeeds, second fails
        mock_process_success = Mock()
        mock_process_success.poll.return_value = 0
        mock_process_success.communicate.return_value = ("Success", "")

        mock_process_fail = Mock()
        mock_process_fail.poll.return_value = 1
        mock_process_fail.communicate.return_value = ("", "Error")

        with patch(
            "subprocess.Popen", side_effect=[mock_process_success, mock_process_fail]
        ):
            result = windows_detector.apply_updates(packages=packages)

        assert len(result["updated_packages"]) == 1
        assert len(result["failed_packages"]) == 1


# =============================================================================
# Edge Cases and Integration Tests
# =============================================================================


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_winget_command_arguments(self, windows_detector):
        """Test that winget command uses correct arguments."""
        packages = [{"package_name": "test", "bundle_id": "Test.Package"}]
        results = {"updated_packages": [], "failed_packages": []}

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("", "")

        with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
            windows_detector._apply_winget_updates(packages, results)

        # Verify the command arguments
        call_args = mock_popen.call_args[0][0]
        assert "winget" in call_args
        assert "upgrade" in call_args
        assert "--id" in call_args
        assert "Test.Package" in call_args
        assert "--silent" in call_args
        assert "--accept-package-agreements" in call_args
        assert "--accept-source-agreements" in call_args

    def test_chocolatey_command_arguments(self, windows_detector):
        """Test that chocolatey command uses correct arguments."""
        packages = [{"package_name": "test-package"}]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=0)
        mock_result.stderr = ""
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            windows_detector._apply_chocolatey_updates(packages, results)

        # Verify the command arguments
        call_args = mock_run.call_args[0][0]
        assert "choco" in call_args
        assert "upgrade" in call_args
        assert "test-package" in call_args
        assert "-y" in call_args

    def test_windows_update_with_creation_flags(self, windows_detector):
        """Test Windows update uses CREATE_NO_WINDOW on Windows."""
        packages = [{"package_name": "KB12345"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="SUCCESS", stderr="")

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.platform.system",
                return_value="Windows",
            ):
                windows_detector._apply_windows_system_updates(packages, results)

        # Verify creationflags was set
        call_kwargs = mock_run.call_args[1]
        assert "creationflags" in call_kwargs
        assert call_kwargs["creationflags"] == subprocess.CREATE_NO_WINDOW

    def test_windows_update_without_creation_flags_on_non_windows(
        self, windows_detector
    ):
        """Test Windows update does not use CREATE_NO_WINDOW on non-Windows."""
        packages = [{"package_name": "KB12345"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="SUCCESS", stderr="")

        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.platform.system",
                return_value="Linux",
            ):
                windows_detector._apply_windows_system_updates(packages, results)

        # Verify creationflags is 0 on non-Windows
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["creationflags"] == 0

    def test_empty_package_name_handling(self, windows_detector):
        """Test handling packages with missing package_name."""
        packages = [{"name": ""}]

        # Should handle gracefully
        result = windows_detector._enrich_windows_package_info(packages[0])
        assert result.get("package_name") == ""

    def test_none_values_in_package_info(self, windows_detector):
        """Test handling None values in package info."""
        packages = [
            {
                "package_name": "test",
                "current_version": None,
                "available_version": None,
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = ("Success", "")

        with patch("subprocess.Popen", return_value=mock_process):
            windows_detector._apply_winget_updates(packages, results)

        # Verify that None values don't cause issues
        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0].get("old_version") is None
        assert results["updated_packages"][0].get("new_version") is None


# =============================================================================
# Constants Tests
# =============================================================================


class TestConstants:
    """Test module constants."""

    def test_windows_update_label(self):
        """Test WINDOWS_UPDATE_LABEL constant."""
        assert WINDOWS_UPDATE_LABEL == "Windows Update"
