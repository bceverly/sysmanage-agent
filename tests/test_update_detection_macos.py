# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for macOS update detection module.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_macos import (
    MacOSUpdateDetector,
)


@pytest.fixture
def detector():
    """Create a MacOSUpdateDetector for testing."""
    return MacOSUpdateDetector()


class TestMacOSUpdateDetectorInit:
    """Tests for MacOSUpdateDetector initialization."""

    def test_init_creates_instance(self, detector):
        """Test that __init__ creates a valid detector instance."""
        assert detector is not None
        assert hasattr(detector, "available_updates")
        assert detector.available_updates == []


class TestIsMacosMajorUpgrade:
    """Tests for _is_macos_major_upgrade method."""

    def test_is_major_upgrade_true(self, detector):
        """Test detecting a major macOS upgrade."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "15.3\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._is_macos_major_upgrade("macOS Tahoe 26", "26.0")

        assert result is True

    def test_is_major_upgrade_false_same_major(self, detector):
        """Test detecting a patch update (same major version)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "15.3\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._is_macos_major_upgrade("macOS Sequoia 15.4", "15.4")

        assert result is False

    def test_is_major_upgrade_command_fails(self, detector):
        """Test when sw_vers command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = detector._is_macos_major_upgrade("macOS Tahoe 26", "26.0")

        assert result is False

    def test_is_major_upgrade_no_dot_in_version(self, detector):
        """Test version parsing when version has no dot."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "15.3\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._is_macos_major_upgrade("macOS Tahoe 26", "26")

        assert result is True

    def test_is_major_upgrade_exception_handling(self, detector):
        """Test exception handling in major upgrade detection."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = detector._is_macos_major_upgrade("macOS Test", "1.0")

        assert result is False

    def test_is_major_upgrade_invalid_version_with_codename_detection(self, detector):
        """Test codename-based detection when version parsing fails."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "15.3\n"

        with patch("subprocess.run", return_value=mock_result):
            # Use an invalid version format that will trigger codename detection
            result = detector._is_macos_major_upgrade("macOS Tahoe", "invalid")

        # Should fall through to codename check and return True for Tahoe
        assert result is True

    def test_is_major_upgrade_current_version_parse_error(self, detector):
        """Test when current version cannot be parsed."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid.version\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._is_macos_major_upgrade("macOS Test", "15.0")

        # Should handle the error gracefully
        assert result is False


class TestGetMacosCodename:
    """Tests for _get_macos_codename method."""

    def test_get_codename_sequoia(self, detector):
        """Test getting Sequoia codename for version 15."""
        result = detector._get_macos_codename(15)
        assert result == "Sequoia"

    def test_get_codename_sonoma(self, detector):
        """Test getting Sonoma codename for version 14."""
        result = detector._get_macos_codename(14)
        assert result == "Sonoma"

    def test_get_codename_ventura(self, detector):
        """Test getting Ventura codename for version 13."""
        result = detector._get_macos_codename(13)
        assert result == "Ventura"

    def test_get_codename_monterey(self, detector):
        """Test getting Monterey codename for version 12."""
        result = detector._get_macos_codename(12)
        assert result == "Monterey"

    def test_get_codename_big_sur(self, detector):
        """Test getting Big Sur codename for version 11."""
        result = detector._get_macos_codename(11)
        assert result == "Big Sur"

    def test_get_codename_tahoe(self, detector):
        """Test getting Tahoe codename for version 26."""
        result = detector._get_macos_codename(26)
        assert result == "Tahoe"

    def test_get_codename_unknown(self, detector):
        """Test getting empty string for unknown version."""
        result = detector._get_macos_codename(99)
        assert result == ""


class TestDetectHomebrewUpdates:
    """Tests for _detect_homebrew_updates method."""

    def test_detect_homebrew_updates_success(self, detector):
        """Test successful Homebrew update detection."""
        mock_update_result = Mock()
        mock_update_result.returncode = 0
        mock_update_result.stderr = ""

        mock_outdated_result = Mock()
        mock_outdated_result.returncode = 0
        mock_outdated_result.stdout = """{
            "formulae": [
                {
                    "name": "git",
                    "installed_versions": ["2.40.0"],
                    "current_version": "2.41.0"
                },
                {
                    "name": "node",
                    "installed_versions": ["18.0.0"],
                    "current_version": "20.0.0"
                }
            ],
            "casks": [
                {
                    "name": "visual-studio-code",
                    "installed_versions": ["1.80.0"],
                    "current_version": "1.81.0"
                }
            ]
        }"""

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update_result
            return mock_outdated_result

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", side_effect=mock_run):
                detector._detect_homebrew_updates()

        assert len(detector.available_updates) == 3

        # Check formula updates
        git_update = next(
            (u for u in detector.available_updates if u["package_name"] == "git"), None
        )
        assert git_update is not None
        assert git_update["current_version"] == "2.40.0"
        assert git_update["available_version"] == "2.41.0"
        assert git_update["package_manager"] == "homebrew"
        assert git_update["source"] == "homebrew_core"

        # Check cask updates
        vscode_update = next(
            (
                u
                for u in detector.available_updates
                if u["package_name"] == "visual-studio-code"
            ),
            None,
        )
        assert vscode_update is not None
        assert vscode_update["source"] == "homebrew_cask"

    def test_detect_homebrew_updates_update_fails(self, detector):
        """Test Homebrew detection when update command fails."""
        mock_update_result = Mock()
        mock_update_result.returncode = 1
        mock_update_result.stderr = "Network error"

        mock_outdated_result = Mock()
        mock_outdated_result.returncode = 0
        mock_outdated_result.stdout = '{"formulae": [], "casks": []}'

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update_result
            return mock_outdated_result

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", side_effect=mock_run):
                detector._detect_homebrew_updates()

        # Should still work, just logs a warning
        assert detector.available_updates == []

    def test_detect_homebrew_updates_invalid_json(self, detector):
        """Test Homebrew detection with invalid JSON output."""
        mock_update_result = Mock()
        mock_update_result.returncode = 0

        mock_outdated_result = Mock()
        mock_outdated_result.returncode = 0
        mock_outdated_result.stdout = "invalid json"

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update_result
            return mock_outdated_result

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", side_effect=mock_run):
                detector._detect_homebrew_updates()

        assert detector.available_updates == []

    def test_detect_homebrew_updates_exception(self, detector):
        """Test Homebrew detection with exception."""
        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", side_effect=Exception("test error")):
                detector._detect_homebrew_updates()

        assert detector.available_updates == []

    def test_detect_homebrew_updates_outdated_fails(self, detector):
        """Test Homebrew detection when outdated command fails."""
        mock_update_result = Mock()
        mock_update_result.returncode = 0

        mock_outdated_result = Mock()
        mock_outdated_result.returncode = 1
        mock_outdated_result.stderr = "Error"

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update_result
            return mock_outdated_result

        with patch.object(detector, "_get_brew_command", return_value="brew"):
            with patch("subprocess.run", side_effect=mock_run):
                detector._detect_homebrew_updates()

        assert detector.available_updates == []


class TestParseSoftwareupdateDetails:
    """Tests for _parse_softwareupdate_details method."""

    def test_parse_full_details_line(self, detector):
        """Test parsing a complete details line."""
        details = (
            "Title: macOS Sequoia 15.3, Version: 15.3, Size: 12345678KiB, "
            "Recommended: YES, Action: restart"
        )
        result = detector._parse_softwareupdate_details(details)

        assert result["title"] == "macOS Sequoia 15.3"
        assert result["version"] == "15.3"
        assert result["size_kb"] == 12345678
        assert result["is_recommended"] is True
        assert result["requires_restart"] is True

    def test_parse_partial_details_line(self, detector):
        """Test parsing a partial details line."""
        details = "Title: Safari Update, Version: 17.0"
        result = detector._parse_softwareupdate_details(details)

        assert result["title"] == "Safari Update"
        assert result["version"] == "17.0"
        assert result["size_kb"] is None
        assert result["is_recommended"] is False
        assert result["requires_restart"] is False

    def test_parse_empty_details_line(self, detector):
        """Test parsing an empty details line."""
        result = detector._parse_softwareupdate_details("")

        assert result["title"] is None
        assert result["version"] == "unknown"
        assert result["size_kb"] is None
        assert result["is_recommended"] is False
        assert result["requires_restart"] is False

    def test_parse_none_details_line(self, detector):
        """Test parsing None as details line."""
        result = detector._parse_softwareupdate_details(None)

        assert result["title"] is None
        assert result["version"] == "unknown"

    def test_parse_details_not_recommended(self, detector):
        """Test parsing a details line without recommended flag."""
        details = "Title: Test Update, Version: 1.0, Recommended: NO"
        result = detector._parse_softwareupdate_details(details)

        assert result["is_recommended"] is False

    def test_parse_details_no_restart(self, detector):
        """Test parsing a details line without restart action."""
        details = "Title: Test Update, Version: 1.0, Action: none"
        result = detector._parse_softwareupdate_details(details)

        assert result["requires_restart"] is False


class TestCollectCurrentMacosVersion:
    """Tests for _collect_current_macos_version method."""

    def test_collect_version_success(self, detector):
        """Test successful version collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "15.3.1\n"

        with patch("subprocess.run", return_value=mock_result):
            result = detector._collect_current_macos_version()

        assert result == "15.3.1"

    def test_collect_version_failure(self, detector):
        """Test version collection when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = detector._collect_current_macos_version()

        assert result == "unknown"

    def test_collect_version_exception(self, detector):
        """Test version collection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = detector._collect_current_macos_version()

        assert result == "unknown"


class TestProcessSoftwareupdateEntry:
    """Tests for _process_softwareupdate_entry method."""

    def test_process_entry_with_details(self, detector):
        """Test processing entry with full details."""
        label = "macOS Sequoia 15.3-24E5228c"
        details = (
            "Title: macOS Sequoia 15.3, Version: 15.3, Size: 1234KiB, "
            "Recommended: YES, Action: restart"
        )

        with patch.object(detector, "_is_macos_major_upgrade", return_value=False):
            with patch.object(
                detector, "_collect_current_macos_version", return_value="15.2"
            ):
                result = detector._process_softwareupdate_entry(label, details)

        assert result["package_name"] == "macOS Sequoia 15.3"
        assert result["current_version"] == "15.2"
        assert result["available_version"] == "15.3"
        assert result["package_manager"] == "mac_app_store"
        assert result["label"] == label
        assert result["size_kb"] == 1234
        assert result["is_system_update"] is True
        assert result["is_recommended"] is True
        assert result["requires_restart"] is True

    def test_process_entry_security_update(self, detector):
        """Test processing a security update entry."""
        label = "Security Update 2024-001"
        details = "Title: Security Update, Version: 2024.1"

        with patch.object(detector, "_is_macos_major_upgrade", return_value=False):
            with patch.object(
                detector, "_collect_current_macos_version", return_value="15.2"
            ):
                result = detector._process_softwareupdate_entry(label, details)

        assert result["is_security_update"] is True

    def test_process_entry_major_upgrade(self, detector):
        """Test processing a major OS upgrade entry."""
        label = "macOS Tahoe 26-26A5326a"
        details = "Title: macOS Tahoe, Version: 26.0"

        with patch.object(detector, "_is_macos_major_upgrade", return_value=True):
            with patch.object(
                detector, "_collect_current_macos_version", return_value="15.3"
            ):
                result = detector._process_softwareupdate_entry(label, details)

        assert result["package_manager"] == "macos-upgrade"
        assert result["is_system_update"] is False

    def test_process_entry_safari_update(self, detector):
        """Test processing a Safari update entry."""
        label = "Safari 17.4"
        details = "Title: Safari 17.4, Version: 17.4"

        with patch.object(detector, "_is_macos_major_upgrade", return_value=False):
            with patch.object(
                detector, "_collect_current_macos_version", return_value="15.2"
            ):
                result = detector._process_softwareupdate_entry(label, details)

        assert result["is_system_update"] is True

    def test_process_entry_no_details_title(self, detector):
        """Test processing entry when details has no title."""
        label = "Test Package Update"
        details = ""

        with patch.object(detector, "_is_macos_major_upgrade", return_value=False):
            with patch.object(
                detector, "_collect_current_macos_version", return_value="15.2"
            ):
                result = detector._process_softwareupdate_entry(label, details)

        # Should fallback to using label as package_name
        assert result["package_name"] == label


class TestDetectMacosAppStoreUpdates:
    """Tests for _detect_macos_app_store_updates method."""

    def test_detect_updates_success(self, detector):
        """Test successful App Store update detection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Software Update found the following new or updated software:
* Label: macOS Sequoia 15.3-24E5228c
    Title: macOS Sequoia 15.3, Version: 15.3, Size: 1234KiB, Recommended: YES, Action: restart
* Label: Safari 17.4
    Title: Safari 17.4, Version: 17.4, Size: 567KiB, Recommended: YES, Action: none
"""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(detector, "_is_macos_major_upgrade", return_value=False):
                with patch.object(
                    detector, "_collect_current_macos_version", return_value="15.2"
                ):
                    detector._detect_macos_app_store_updates()

        assert len(detector.available_updates) == 2

    def test_detect_updates_no_updates(self, detector):
        """Test App Store detection with no updates available."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "No new software available."

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macos_app_store_updates()

        assert len(detector.available_updates) == 0

    def test_detect_updates_command_fails(self, detector):
        """Test App Store detection when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macos_app_store_updates()

        assert len(detector.available_updates) == 0

    def test_detect_updates_empty_stdout(self, detector):
        """Test App Store detection with empty stdout."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macos_app_store_updates()

        assert len(detector.available_updates) == 0

    def test_detect_updates_exception(self, detector):
        """Test App Store detection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            detector._detect_macos_app_store_updates()

        assert len(detector.available_updates) == 0

    def test_detect_updates_label_without_details(self, detector):
        """Test App Store detection with label but no details line."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Software Update found the following new or updated software:
* Label: Some Update
Some other unrelated line
"""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(detector, "_is_macos_major_upgrade", return_value=False):
                with patch.object(
                    detector, "_collect_current_macos_version", return_value="15.2"
                ):
                    detector._detect_macos_app_store_updates()

        assert len(detector.available_updates) == 1


class TestDetectMacportsUpdates:
    """Tests for _detect_macports_updates method."""

    def test_detect_updates_success(self, detector):
        """Test successful MacPorts update detection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """The following installed ports are outdated:
python39              3.9.17_0 < 3.9.18_0
vim                   9.0.1500_0 < 9.0.1600_0
git                   2.40.0_0 < 2.41.0_0
"""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macports_updates()

        assert len(detector.available_updates) == 3

        python_update = next(
            (u for u in detector.available_updates if u["package_name"] == "python39"),
            None,
        )
        assert python_update is not None
        assert python_update["current_version"] == "3.9.17_0"
        assert python_update["available_version"] == "3.9.18_0"
        assert python_update["package_manager"] == "macports"

    def test_detect_updates_no_updates(self, detector):
        """Test MacPorts detection with no updates."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macports_updates()

        assert len(detector.available_updates) == 0

    def test_detect_updates_command_fails(self, detector):
        """Test MacPorts detection when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macports_updates()

        assert len(detector.available_updates) == 0

    def test_detect_updates_exception(self, detector):
        """Test MacPorts detection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            detector._detect_macports_updates()

        assert len(detector.available_updates) == 0

    def test_detect_updates_malformed_line(self, detector):
        """Test MacPorts detection with malformed output line."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """The following installed ports are outdated:
python39              3.9.17_0 < 3.9.18_0
incomplete_line
vim                   9.0.1500_0 < 9.0.1600_0
"""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_macports_updates()

        # Should skip the malformed line
        assert len(detector.available_updates) == 2
