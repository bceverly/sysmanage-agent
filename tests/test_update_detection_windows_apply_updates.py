# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for Windows update application orchestration and edge cases.

This module covers:
- apply_updates main orchestration method
- Edge cases and error handling
- Module constants
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
