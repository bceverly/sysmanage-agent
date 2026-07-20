# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for macOS update detection module (apply/upgrade operations).
"""

# pylint: disable=redefined-outer-name,protected-access

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_macos import (
    MacOSUpdateDetector,
)


@pytest.fixture
def detector():
    """Create a MacOSUpdateDetector for testing."""
    return MacOSUpdateDetector()


class TestApplyHomebrewUpdates:
    """Tests for _apply_homebrew_updates method."""

    def test_apply_formula_updates_success(self, detector):
        """Test successful Homebrew formula update."""
        packages = [
            {
                "package_name": "git",
                "current_version": "2.40.0",
                "available_version": "2.41.0",
                "source": "homebrew_core",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Updated 1 formula"
        mock_result.stderr = ""

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", return_value=mock_result):
                detector._apply_homebrew_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_name"] == "git"
        assert results["updated_packages"][0]["old_version"] == "2.40.0"
        assert results["updated_packages"][0]["new_version"] == "2.41.0"

    def test_apply_cask_updates_success(self, detector):
        """Test successful Homebrew cask update."""
        packages = [
            {
                "package_name": "visual-studio-code",
                "current_version": "1.80.0",
                "available_version": "1.81.0",
                "source": "homebrew_cask",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Updated 1 cask"
        mock_result.stderr = ""

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", return_value=mock_result):
                detector._apply_homebrew_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_manager"] == "homebrew"

    def test_apply_updates_failure(self, detector):
        """Test Homebrew update failure."""
        packages = [
            {
                "package_name": "failing-package",
                "current_version": "1.0.0",
                "available_version": "2.0.0",
                "source": "homebrew_core",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Error: Package not found"

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", return_value=mock_result):
                detector._apply_homebrew_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert results["failed_packages"][0]["package_name"] == "failing-package"
        assert "Error: Package not found" in results["failed_packages"][0]["error"]

    def test_apply_updates_exception(self, detector):
        """Test Homebrew update with exception."""
        packages = [
            {
                "package_name": "exception-package",
                "current_version": "1.0.0",
                "available_version": "2.0.0",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", side_effect=Exception("Network error")):
                detector._apply_homebrew_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Network error" in results["failed_packages"][0]["error"]


class TestApplyMacosUpgradeUpdates:
    """Tests for _apply_macos_upgrade_updates method."""

    def test_apply_upgrade_success(self, detector):
        """Test successful macOS upgrade."""
        packages = [
            {
                "package_name": "macOS Tahoe",
                "current_version": "15.3",
                "available_version": "26.0",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            detector._apply_macos_upgrade_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_manager"] == "macos-upgrade"
        assert results["requires_reboot"] is True

    def test_apply_upgrade_failure(self, detector):
        """Test macOS upgrade failure."""
        packages = [
            {
                "package_name": "macOS Tahoe",
                "current_version": "15.3",
                "available_version": "26.0",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Installation failed"

        with patch("subprocess.run", return_value=mock_result):
            detector._apply_macos_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Installation failed" in results["failed_packages"][0]["error"]

    def test_apply_upgrade_timeout(self, detector):
        """Test macOS upgrade timeout."""
        packages = [
            {
                "package_name": "macOS Tahoe",
                "current_version": "15.3",
                "available_version": "26.0",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 7200)
        ):
            detector._apply_macos_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "timed out" in results["failed_packages"][0]["error"]

    def test_apply_upgrade_exception(self, detector):
        """Test macOS upgrade with general exception."""
        packages = [
            {
                "package_name": "macOS Tahoe",
                "current_version": "15.3",
                "available_version": "26.0",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            detector._apply_macos_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Unexpected error" in results["failed_packages"][0]["error"]

    def test_apply_upgrade_failure_no_stderr(self, detector):
        """Test macOS upgrade failure with no stderr."""
        packages = [
            {
                "package_name": "macOS Tahoe",
                "current_version": "15.3",
                "available_version": "26.0",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            detector._apply_macos_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1


class TestIsMacosUpgradeLine:
    """Tests for _is_macos_upgrade_line method."""

    def test_is_upgrade_line_installer(self, detector):
        """Test detection of macOS Installer line."""
        line = "* macOS Tahoe Installer-26A5326a"
        result = detector._is_macos_upgrade_line(line)
        assert result is True

    def test_is_upgrade_line_upgrade(self, detector):
        """Test detection of macOS Upgrade line."""
        line = "* macOS Sequoia Upgrade-15.3.1"
        result = detector._is_macos_upgrade_line(line)
        assert result is True

    def test_is_not_upgrade_line_regular_update(self, detector):
        """Test non-upgrade lines return False."""
        line = "* Security Update 2024-001"
        result = detector._is_macos_upgrade_line(line)
        assert result is False

    def test_is_not_upgrade_line_safari(self, detector):
        """Test Safari update is not an upgrade."""
        line = "* Safari 17.4"
        result = detector._is_macos_upgrade_line(line)
        assert result is False

    def test_is_not_upgrade_line_empty(self, detector):
        """Test empty line returns False."""
        line = ""
        result = detector._is_macos_upgrade_line(line)
        assert result is False


class TestGetCurrentMacosVersion:
    """Tests for _get_current_macos_version method."""

    def test_get_version_success(self, detector):
        """Test successful version retrieval."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "15.3.1\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._get_current_macos_version()

        assert result == "15.3.1"

    def test_get_version_failure(self, detector):
        """Test version retrieval failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = detector._get_current_macos_version()

        assert result == "Unknown"


class TestParseMacosUpgradeLine:
    """Tests for _parse_macos_upgrade_line method."""

    def test_parse_upgrade_line_success(self, detector):
        """Test successful upgrade line parsing."""
        line = "* macOS Tahoe 26.0-26A5326a"
        result = detector._parse_macos_upgrade_line(line)
        assert result == "macOS Tahoe 26.0-26A5326a"

    def test_parse_upgrade_line_minimal(self, detector):
        """Test parsing minimal line."""
        line = "* Version"
        result = detector._parse_macos_upgrade_line(line)
        assert result == "Version"

    def test_parse_upgrade_line_too_short(self, detector):
        """Test parsing line that's too short."""
        line = "*"
        result = detector._parse_macos_upgrade_line(line)
        assert result is None

    def test_parse_upgrade_line_empty(self, detector):
        """Test parsing empty line."""
        line = ""
        result = detector._parse_macos_upgrade_line(line)
        assert result is None


class TestAddMacosUpgradeUpdate:
    """Tests for _add_macos_upgrade_update method."""

    def test_add_upgrade_update(self, detector):
        """Test adding macOS upgrade update."""
        with patch.object(detector, "_get_current_macos_version", return_value="15.3"):
            detector._add_macos_upgrade_update("macOS Tahoe 26.0")

        assert len(detector.available_updates) == 1
        update = detector.available_updates[0]
        assert update["package_name"] == "macos-upgrade"
        assert update["current_version"] == "15.3"
        assert update["available_version"] == "macOS Tahoe 26.0"
        assert update["package_manager"] == "macos-upgrade"
        assert update["is_security_update"] is True
        assert update["is_system_update"] is True
        assert update["requires_reboot"] is True
        assert update["update_size"] == 8000000000


class TestDetectMacosVersionUpgrades:
    """Tests for _detect_macos_version_upgrades method."""

    def test_detect_upgrades_success(self, detector):
        """Test successful macOS version upgrade detection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Software Update Tool

Finding available software
Software Update found the following new or updated software:
* macOS Tahoe Installer-26A5326a
    Title: macOS Tahoe, Version: 26.0
"""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                detector, "_get_current_macos_version", return_value="15.3"
            ):
                detector._detect_macos_version_upgrades()

        assert len(detector.available_updates) == 1
        assert detector.available_updates[0]["package_name"] == "macos-upgrade"

    def test_detect_upgrades_no_upgrades(self, detector):
        """Test upgrade detection with no upgrades available."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Software Update Tool

Finding available software
No new software available.
"""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macos_version_upgrades()

        assert len(detector.available_updates) == 0

    def test_detect_upgrades_command_fails(self, detector):
        """Test upgrade detection when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macos_version_upgrades()

        assert len(detector.available_updates) == 0

    def test_detect_upgrades_exception(self, detector):
        """Test upgrade detection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            detector._detect_macos_version_upgrades()

        assert len(detector.available_updates) == 0


class TestInstallWithBrew:
    """Tests for _install_with_brew method."""

    def test_install_success(self, detector):
        """Test successful Homebrew package installation."""
        mock_install_result = Mock()
        mock_install_result.returncode = 0
        mock_install_result.stdout = "Package installed successfully"

        mock_link_result = Mock()
        mock_link_result.returncode = 0

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [mock_install_result, mock_link_result]
                result = detector._install_with_brew("test-package")

        assert result["success"] is True
        assert result["version"] == "unknown"
        assert "Package installed successfully" in result["output"]

    def test_install_failure(self, detector):
        """Test Homebrew package installation failure."""
        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch(
                "subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, "brew install", stderr="Package not found"
                ),
            ):
                result = detector._install_with_brew("nonexistent-package")

        assert result["success"] is False
        assert "Failed to install" in result["error"]


class TestDetectUpdates:
    """Tests for detect_updates method."""

    def test_detect_updates_all_sources(self, detector):
        """Test that detect_updates calls all detection methods."""
        with patch.object(detector, "_detect_macos_app_store_updates") as mock_appstore:
            with patch.object(
                detector,
                "_detect_package_managers",
                return_value=["homebrew", "macports"],
            ):
                with patch.object(
                    detector, "_detect_homebrew_updates"
                ) as mock_homebrew:
                    with patch.object(
                        detector, "_detect_macports_updates"
                    ) as mock_macports:
                        detector.detect_updates()

        mock_appstore.assert_called_once()
        mock_homebrew.assert_called_once()
        mock_macports.assert_called_once()

    def test_detect_updates_only_homebrew(self, detector):
        """Test detect_updates with only Homebrew available."""
        with patch.object(detector, "_detect_macos_app_store_updates"):
            with patch.object(
                detector, "_detect_package_managers", return_value=["homebrew"]
            ):
                with patch.object(
                    detector, "_detect_homebrew_updates"
                ) as mock_homebrew:
                    with patch.object(
                        detector, "_detect_macports_updates"
                    ) as mock_macports:
                        detector.detect_updates()

        mock_homebrew.assert_called_once()
        mock_macports.assert_not_called()

    def test_detect_updates_only_macports(self, detector):
        """Test detect_updates with only MacPorts available."""
        with patch.object(detector, "_detect_macos_app_store_updates"):
            with patch.object(
                detector, "_detect_package_managers", return_value=["macports"]
            ):
                with patch.object(
                    detector, "_detect_homebrew_updates"
                ) as mock_homebrew:
                    with patch.object(
                        detector, "_detect_macports_updates"
                    ) as mock_macports:
                        detector.detect_updates()

        mock_homebrew.assert_not_called()
        mock_macports.assert_called_once()

    def test_detect_updates_no_package_managers(self, detector):
        """Test detect_updates with no package managers available."""
        with patch.object(detector, "_detect_macos_app_store_updates") as mock_appstore:
            with patch.object(detector, "_detect_package_managers", return_value=[]):
                with patch.object(
                    detector, "_detect_homebrew_updates"
                ) as mock_homebrew:
                    with patch.object(
                        detector, "_detect_macports_updates"
                    ) as mock_macports:
                        detector.detect_updates()

        mock_appstore.assert_called_once()
        mock_homebrew.assert_not_called()
        mock_macports.assert_not_called()


class TestMajorUpgradeCodenameFallback:
    """Tests for codename-based major upgrade detection fallback."""

    def test_major_upgrade_via_ventura_codename(self, detector):
        """Test detecting Ventura as major upgrade via codename."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "12.0\n"  # Running Monterey (12)

        with patch("subprocess.run", return_value=mock_result):
            # Force ValueError to trigger codename check
            result = detector._is_macos_major_upgrade(
                "macOS Ventura", "invalid.version"
            )

        assert result is True

    def test_major_upgrade_via_monterey_codename(self, detector):
        """Test detecting Monterey as major upgrade via codename."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "11.0\n"  # Running Big Sur (11)

        with patch("subprocess.run", return_value=mock_result):
            result = detector._is_macos_major_upgrade("macOS Monterey", "invalid")

        assert result is True

    def test_major_upgrade_via_big_sur_codename(self, detector):
        """Test detecting Big Sur as major upgrade via codename."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "10.15\n"  # Running Catalina

        with patch("subprocess.run", return_value=mock_result):
            result = detector._is_macos_major_upgrade("macOS Big Sur", "invalid")

        assert result is True

    def test_major_upgrade_via_catalina_codename(self, detector):
        """Test detecting Catalina as major upgrade via codename."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "10.14\n"  # Running Mojave

        with patch("subprocess.run", return_value=mock_result):
            result = detector._is_macos_major_upgrade("macOS Catalina", "invalid")

        assert result is True

    def test_no_major_upgrade_same_codename(self, detector):
        """Test that same codename doesn't trigger major upgrade."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "15.0\n"  # Running Sequoia

        with patch("subprocess.run", return_value=mock_result):
            # If running Sequoia and seeing a Sequoia update, not a major upgrade
            result = detector._is_macos_major_upgrade("macOS Sequoia 15.1", "invalid")

        # Should return False - no codename match in major_upgrade_patterns
        assert result is False
