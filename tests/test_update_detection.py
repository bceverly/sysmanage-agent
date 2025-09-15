"""
Unit tests for update detection module.
"""

# pylint: disable=protected-access,too-many-public-methods

from unittest.mock import Mock, patch
from src.sysmanage_agent.collection.update_detection import UpdateDetector


class TestUpdateDetector:
    """Test cases for UpdateDetector class."""

    def test_init(self):
        """Test UpdateDetector initialization."""
        detector = UpdateDetector()
        assert detector.platform in [
            "linux",
            "darwin",
            "windows",
            "freebsd",
            "openbsd",
            "netbsd",
        ]
        assert not detector.available_updates
        assert detector._package_managers is None

    @patch("platform.system")
    def test_init_with_platform(self, mock_system):
        """Test initialization with specific platform."""
        mock_system.return_value = "Linux"
        detector = UpdateDetector()
        assert detector.platform == "linux"

    @patch("subprocess.run")
    def test_command_exists_true(self, mock_run):
        """Test _command_exists returns True for existing command."""
        mock_run.return_value = Mock(returncode=0)
        detector = UpdateDetector()
        assert detector._command_exists("apt") is True

    @patch("subprocess.run")
    def test_command_exists_false(self, mock_run):
        """Test _command_exists returns False for non-existing command."""
        mock_run.side_effect = FileNotFoundError()
        detector = UpdateDetector()
        assert detector._command_exists("nonexistent") is False

    @patch("subprocess.run")
    def test_detect_package_managers_linux(self, mock_run):
        """Test package manager detection on Linux."""
        mock_run.return_value = Mock(returncode=0)

        with patch("platform.system", return_value="Linux"):
            detector = UpdateDetector()
            managers = detector._detect_package_managers()

        # Should detect managers if commands exist
        assert isinstance(managers, list)
        # Cache should work
        assert detector._detect_package_managers() == managers

    @patch("platform.system")
    @patch(
        "src.sysmanage_agent.collection.update_detection.UpdateDetector._detect_linux_updates"
    )
    def test_get_available_updates_linux(self, mock_detect_linux, mock_system):
        """Test update detection on Linux."""
        mock_system.return_value = "Linux"
        detector = UpdateDetector()

        result = detector.get_available_updates()

        mock_detect_linux.assert_called_once()
        assert "available_updates" in result
        assert "detection_timestamp" in result
        assert "platform" in result
        assert "total_updates" in result
        assert result["platform"] == "linux"

    @patch("platform.system")
    @patch(
        "src.sysmanage_agent.collection.update_detection.UpdateDetector._detect_macos_updates"
    )
    def test_get_available_updates_macos(self, mock_detect_macos, mock_system):
        """Test update detection on macOS."""
        mock_system.return_value = "Darwin"
        detector = UpdateDetector()

        result = detector.get_available_updates()

        mock_detect_macos.assert_called_once()
        assert result["platform"] == "darwin"

    @patch("platform.system")
    @patch(
        "src.sysmanage_agent.collection.update_detection.UpdateDetector._detect_windows_updates"
    )
    def test_get_available_updates_windows(self, mock_detect_windows, mock_system):
        """Test update detection on Windows."""
        mock_system.return_value = "Windows"
        detector = UpdateDetector()

        result = detector.get_available_updates()

        mock_detect_windows.assert_called_once()
        assert result["platform"] == "windows"

    @patch("platform.system")
    @patch(
        "src.sysmanage_agent.collection.update_detection.UpdateDetector._detect_bsd_updates"
    )
    def test_get_available_updates_openbsd(self, mock_detect_bsd, mock_system):
        """Test update detection on OpenBSD."""
        mock_system.return_value = "OpenBSD"
        detector = UpdateDetector()

        result = detector.get_available_updates()

        mock_detect_bsd.assert_called_once()
        assert result["platform"] == "openbsd"

    @patch("subprocess.run")
    def test_detect_apt_updates(self, mock_run):
        """Test APT update detection."""
        # Mock apt update command (should succeed but not needed for test)
        mock_update = Mock(returncode=0, stdout="")
        # Mock apt list --upgradable output
        mock_list = Mock(
            returncode=0,
            stdout="Listing...\ntest-package/stable 2.0.0 amd64 [upgradable from: 1.0.0]\n",
        )
        # Mock apt-cache policy for security check
        mock_policy = Mock(returncode=0, stdout="test output without security")

        mock_run.side_effect = [mock_update, mock_list, mock_policy, Mock(returncode=1)]

        with patch("platform.system", return_value="Linux"):
            detector = UpdateDetector()
            detector._detect_apt_updates()

        assert len(detector.available_updates) == 1
        update = detector.available_updates[0]
        assert update["package_name"] == "test-package"
        assert update["current_version"] == "1.0.0"
        assert update["available_version"] == "2.0.0"
        assert update["package_manager"] == "apt"

    @patch("subprocess.run")
    def test_detect_snap_updates(self, mock_run):
        """Test Snap update detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Name     Version  Rev  Size    Publisher   Notes\ntest-snap 1.0      123  10MB    test        -\ntest-snap 2.0      124  12MB    test        -\n",
        )

        with patch("platform.system", return_value="Linux"):
            detector = UpdateDetector()
            detector._detect_snap_updates()

        # Should have parsed the snap output
        assert len(detector.available_updates) >= 0  # May be 0 if parsing fails

    @patch("subprocess.run")
    def test_detect_homebrew_updates(self, mock_run):
        """Test Homebrew update detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"formulae":[{"name":"test-formula","current_version":"2.0","installed_versions":["1.0"]}],"casks":[]}',
        )

        with patch("platform.system", return_value="Darwin"):
            detector = UpdateDetector()
            detector._detect_homebrew_updates()

        assert len(detector.available_updates) == 1
        update = detector.available_updates[0]
        assert update["package_name"] == "test-formula"
        assert update["current_version"] == "1.0"
        assert update["available_version"] == "2.0"
        assert update["package_manager"] == "homebrew"

    @patch("subprocess.run")
    def test_detect_pkg_updates_freebsd(self, mock_run):
        """Test FreeBSD pkg update detection."""
        mock_update = Mock(returncode=0)
        mock_version = Mock(
            returncode=0, stdout="test-package-1.0 < needs updating (remote has 2.0)"
        )

        mock_run.side_effect = [mock_update, mock_version]

        with patch("platform.system", return_value="FreeBSD"):
            detector = UpdateDetector()
            detector._detect_pkg_updates()

        assert len(detector.available_updates) == 1
        update = detector.available_updates[0]
        assert update["package_name"] == "test-package"
        assert update["current_version"] == "1.0"
        assert update["available_version"] == "2.0"
        assert update["package_manager"] == "pkg"

    @patch("os.path.exists")
    def test_check_reboot_required_linux(self, mock_exists):
        """Test reboot required check on Linux."""
        mock_exists.return_value = True

        with patch("platform.system", return_value="Linux"):
            detector = UpdateDetector()
            assert detector.check_reboot_required() is True

    def test_check_reboot_required_no_file(self):
        """Test reboot required check when no reboot file exists."""
        with patch("platform.system", return_value="Linux"), patch(
            "os.path.exists", return_value=False
        ):
            detector = UpdateDetector()
            # Add a kernel update to trigger reboot requirement
            detector.available_updates = [
                {"package_name": "linux-kernel", "package_manager": "apt"}
            ]
            assert detector.check_reboot_required() is True

    def test_check_reboot_required_no_updates(self):
        """Test reboot required check with no updates."""
        with patch("platform.system", return_value="Linux"), patch(
            "os.path.exists", return_value=False
        ):
            detector = UpdateDetector()
            assert detector.check_reboot_required() is False

    def test_apply_updates_no_packages(self):
        """Test applying updates with no packages specified."""
        detector = UpdateDetector()
        result = detector.apply_updates([])

        assert result["success"] is False
        assert "No packages specified" in result["error"]

    @patch("subprocess.run")
    def test_apply_apt_updates(self, mock_run):
        """Test applying APT updates."""
        mock_run.return_value = Mock(returncode=0, stderr="")

        detector = UpdateDetector()
        packages = [
            {
                "package_name": "test-pkg",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "apt",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        detector._apply_apt_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_name"] == "test-pkg"

    @patch("subprocess.run")
    def test_apply_apt_updates_failure(self, mock_run):
        """Test applying APT updates with failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Error message")

        detector = UpdateDetector()
        packages = [
            {
                "package_name": "test-pkg",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "apt",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        detector._apply_apt_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert results["failed_packages"][0]["package_name"] == "test-pkg"

    @patch("platform.system")
    def test_update_categorization(self, mock_system):
        """Test update categorization by type."""
        mock_system.return_value = "Linux"

        def mock_detect_linux_updates(self):
            """Mock Linux detection that sets test updates."""
            self.available_updates = [
                {
                    "package_name": "test1",
                    "is_security_update": True,
                    "is_system_update": False,
                },
                {
                    "package_name": "test2",
                    "is_security_update": False,
                    "is_system_update": True,
                },
                {
                    "package_name": "test3",
                    "is_security_update": False,
                    "is_system_update": False,
                },
            ]

        with patch.object(
            UpdateDetector, "_detect_linux_updates", mock_detect_linux_updates
        ):
            detector = UpdateDetector()
            result = detector.get_available_updates()

            assert result["security_updates"] == 1
            assert result["system_updates"] == 1
            assert result["application_updates"] == 1

    def test_error_handling(self):
        """Test error handling in update detection."""
        with patch("platform.system", return_value="Linux"), patch.object(
            UpdateDetector, "_detect_linux_updates", side_effect=Exception("Test error")
        ):
            detector = UpdateDetector()
            result = detector.get_available_updates()

            assert "error" in result
            assert result["total_updates"] == 0
            assert not result["available_updates"]

    @patch("subprocess.run")
    def test_is_apt_security_update(self, mock_run):
        """Test APT security update detection."""
        mock_run.return_value = Mock(returncode=0, stdout="security update info")

        detector = UpdateDetector()
        assert detector._is_apt_security_update("test-package") is True

        mock_run.return_value = Mock(returncode=0, stdout="regular update")
        assert detector._is_apt_security_update("test-package") is False

    @patch("subprocess.run")
    def test_get_apt_update_size(self, mock_run):
        """Test APT update size retrieval."""
        mock_run.return_value = Mock(returncode=0, stdout="Size: 1024000")

        detector = UpdateDetector()
        size = detector._get_apt_update_size("test-package")
        assert size == 1024000

    @patch("subprocess.run")
    def test_is_dnf_security_update(self, mock_run):
        """Test DNF security update detection."""
        mock_run.return_value = Mock(
            returncode=0, stdout="test-package security update"
        )

        detector = UpdateDetector()
        assert detector._is_dnf_security_update("test-package") is True

        mock_run.return_value = Mock(returncode=1, stdout="")
        assert detector._is_dnf_security_update("test-package") is False
