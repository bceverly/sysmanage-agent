# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for Windows update application functionality.

This module covers Windows system updates, version upgrades, package
collection/routing, and per-manager update processing.
"""

# pylint: disable=protected-access,redefined-outer-name

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_windows import (
    WindowsUpdateDetector,
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
