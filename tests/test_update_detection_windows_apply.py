# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

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

import itertools
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
        # Patch the module's time reference so logging's internal time.time() is unaffected
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_apply.time"
        ) as mock_time_mod:
            mock_time_mod.time.side_effect = [
                0,  # start_time
                0,  # elapsed check (loop 1)
                35,  # log time check (loop 1, > 30s triggers log)
                35,  # last_log_time assignment (loop 1)
                35,  # elapsed check (loop 2)
                40,  # log time check (loop 2)
                40,  # elapsed check (loop 3)
                50,  # log time check (loop 3)
            ]
            mock_time_mod.sleep = Mock()
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

        # This patches the shared `time` module's time() GLOBALLY, so every
        # time.time() call draws from side_effect — including the ones inside
        # logging.makeRecord() when the code logs (line 143, and again in the
        # timeout branch).  How many such calls precede `start_time` varies by
        # Python version, so a fixed/repeating VALUE list is unusable: it either
        # runs dry (StopIteration) or, if `start_time` lands on the "elapsed"
        # value, makes `elapsed` == 0 forever → the sleep-free poll loop spins
        # and the runner OOM-kills it (exit 137).
        #
        # Use a MONOTONICALLY INCREASING clock instead: consecutive time.time()
        # calls always differ by a fixed step, so `elapsed = time.time() -
        # start_time` on the first loop iteration is that step regardless of how
        # many logging calls came before start_time.  A step far larger than the
        # 1200s timeout guarantees the loop exits on iteration 1, and the counter
        # is infinite so it can never raise StopIteration.
        mock_clock = itertools.count(0, 1_000_000)  # 0, 1e6, 2e6, … (>> 1200s)

        with patch("subprocess.Popen", return_value=mock_process):
            with patch(
                "src.sysmanage_agent.collection.update_detection_windows_apply.time.time"
            ) as mock_time:
                mock_time.side_effect = mock_clock
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
