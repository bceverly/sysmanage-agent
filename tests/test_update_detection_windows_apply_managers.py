# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for Windows update package collection and manager routing.

This module covers:
- Package collection and routing
- Package manager grouping
- Per-manager update processing
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
