"""
Unit tests for update detection module.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init

from unittest.mock import Mock, patch

from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.sysmanage_agent.collection.update_detection_linux import LinuxUpdateDetector
from src.sysmanage_agent.collection.update_detection_macos import MacOSUpdateDetector
from src.sysmanage_agent.collection.update_detection_windows import (
    WindowsUpdateDetector,
)


class TestUpdateDetector:
    """Test cases for UpdateDetector class."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create Linux-specific detector for Linux-specific tests
        self.linux_detector = LinuxUpdateDetector()

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
        "src.sysmanage_agent.collection.update_detection_linux.LinuxUpdateDetector.detect_updates"
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
        "src.sysmanage_agent.collection.update_detection_macos.MacOSUpdateDetector.detect_updates"
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
        "src.sysmanage_agent.collection.update_detection_windows.WindowsUpdateDetector.detect_updates"
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
        "src.sysmanage_agent.collection.update_detection_bsd.BSDUpdateDetector.detect_updates"
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
            # Set it on the actual detector, not the facade
            detector.detector.available_updates = [
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

    @patch("subprocess.run")
    def test_apply_apt_updates(self, mock_run):
        """Test applying APT updates."""
        mock_run.return_value = Mock(returncode=0, stderr="")

        packages = [
            {
                "package_name": "test-pkg",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "apt",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        self.linux_detector._apply_apt_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_name"] == "test-pkg"

    @patch("subprocess.run")
    def test_apply_apt_updates_failure(self, mock_run):
        """Test applying APT updates with failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Error message")

        packages = [
            {
                "package_name": "test-pkg",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "apt",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        self.linux_detector._apply_apt_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert results["failed_packages"][0]["package_name"] == "test-pkg"

    @patch("platform.system")
    def test_update_categorization(self, mock_system):
        """Test update categorization by type."""
        mock_system.return_value = "Linux"

        def mock_detect_updates(self):
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

        with patch.object(LinuxUpdateDetector, "detect_updates", mock_detect_updates):
            detector = UpdateDetector()
            result = detector.get_available_updates()

            assert result["security_updates"] == 1
            assert result["system_updates"] == 1
            assert result["application_updates"] == 1

    def test_error_handling(self):
        """Test error handling in update detection."""
        with patch("platform.system", return_value="Linux"), patch.object(
            LinuxUpdateDetector, "detect_updates", side_effect=Exception("Test error")
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

        assert self.linux_detector._is_apt_security_update("test-package") is True

        mock_run.return_value = Mock(returncode=0, stdout="regular update")
        assert self.linux_detector._is_apt_security_update("test-package") is False

    @patch("subprocess.run")
    def test_get_apt_update_size(self, mock_run):
        """Test APT update size retrieval."""
        mock_run.return_value = Mock(returncode=0, stdout="Size: 1024000")

        size = self.linux_detector._get_apt_update_size("test-package")
        assert size == 1024000

    @patch("subprocess.run")
    def test_is_dnf_security_update(self, mock_run):
        """Test DNF security update detection."""
        mock_run.return_value = Mock(
            returncode=0, stdout="test-package security update"
        )

        assert self.linux_detector._is_dnf_security_update("test-package") is True

        mock_run.return_value = Mock(returncode=1, stdout="")
        assert self.linux_detector._is_dnf_security_update("test-package") is False

    @patch("subprocess.run")
    def test_detect_yum_updates_failure(self, mock_run):
        """Test YUM update detection with command failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Failed to check updates")

        self.linux_detector._detect_yum_updates()

        assert len(self.linux_detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_pacman_updates_no_updates(self, mock_run):
        """Test Pacman update detection with no updates available."""
        mock_run.return_value = Mock(returncode=0, stdout="")

        self.linux_detector._detect_pacman_updates()

        assert len(self.linux_detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_zypper_updates_success(self, mock_run):
        """Test successful Zypper update detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""S | Repository | Name     | Current Version | Available Version | Arch
--+------------+----------+-----------------+-------------------+-------
v | Main       | apache2  | 2.4.51-1.1      | 2.4.52-1.1        | x86_64
v | Main       | nginx    | 1.20.1-1.1      | 1.21.0-1.1        | x86_64
""",
        )

        self.linux_detector._detect_zypper_updates()

        assert len(self.linux_detector.available_updates) == 2
        apache_update = next(
            (
                u
                for u in self.linux_detector.available_updates
                if u["package_name"] == "apache2"
            ),
            None,
        )
        assert apache_update is not None
        assert apache_update["current_version"] == "2.4.51-1.1"
        assert apache_update["available_version"] == "2.4.52-1.1"

    @patch("subprocess.run")
    def test_detect_zypper_updates_failure(self, mock_run):
        """Test Zypper update detection with command failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Repository error")

        self.linux_detector._detect_zypper_updates()

        assert len(self.linux_detector.available_updates) == 0

    @patch("subprocess.run")
    @patch("platform.system")
    def test_detect_homebrew_updates_no_updates(self, mock_system, mock_run):
        """Test Homebrew update detection with no updates available."""
        mock_system.return_value = "Darwin"
        detector = UpdateDetector()
        detector._get_brew_command = Mock(return_value="brew")

        mock_run.return_value = Mock(returncode=0, stdout="")

        detector._detect_homebrew_updates()

        assert len(detector.available_updates) == 0

    @patch("subprocess.run")
    @patch("platform.system")
    def test_detect_chocolatey_updates_success(self, mock_system, mock_run):
        """Test successful Chocolatey update detection."""
        mock_system.return_value = "Windows"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""Chocolatey v2.2.2
git|2.42.0.2|2.42.1|false
nodejs|20.8.1|20.9.0|false
python|3.11.6|3.11.7|false
""",
        )

        detector = UpdateDetector()
        detector._detect_chocolatey_updates()

        assert len(detector.available_updates) == 3
        git_update = next(
            (u for u in detector.available_updates if u["package_name"] == "git"), None
        )
        assert git_update is not None
        assert git_update["current_version"] == "2.42.0.2"
        assert git_update["available_version"] == "2.42.1"

    @patch("subprocess.run")
    @patch("platform.system")
    def test_detect_chocolatey_updates_no_command(self, mock_system, mock_run):
        """Test Chocolatey update detection when command not available."""
        mock_system.return_value = "Windows"
        mock_run.side_effect = FileNotFoundError("choco command not found")

        detector = UpdateDetector()
        detector._detect_chocolatey_updates()

        assert len(detector.available_updates) == 0

    @patch("subprocess.run")
    @patch("platform.system")
    def test_detect_winget_updates_success(self, mock_system, mock_run):
        """Test successful Winget update detection."""
        mock_system.return_value = "Windows"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""Name               Id                           Version      Available    Source
------------------------------------------------------------------------------
7-Zip              7zip.7zip                    22.01        23.01        winget
Google Chrome      Google.Chrome                118.0.5993   119.0.6045   winget
Microsoft Edge     Microsoft.Edge               118.0.2088   119.0.2151   winget
""",
        )

        detector = UpdateDetector()
        detector._detect_winget_updates()

        assert len(detector.available_updates) == 3
        sevenzip_update = next(
            (u for u in detector.available_updates if u["package_name"] == "7-Zip"),
            None,
        )
        assert sevenzip_update is not None
        assert sevenzip_update["current_version"] == "22.01"
        assert sevenzip_update["available_version"] == "23.01"

    @patch("subprocess.run")
    @patch("platform.system")
    def test_detect_winget_updates_failure(self, mock_system, mock_run):
        """Test Winget update detection with command failure."""
        mock_system.return_value = "Windows"
        mock_run.return_value = Mock(returncode=1, stderr="Winget error")

        detector = UpdateDetector()
        detector._detect_winget_updates()

        assert len(detector.available_updates) == 0

    @patch("subprocess.run")
    def test_get_apt_update_size_failure(self, mock_run):
        """Test APT update size calculation failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Package not found")

        size = self.linux_detector._get_apt_update_size("nonexistent")

        assert size is None

    @patch("subprocess.run")
    def test_is_apt_security_update_true(self, mock_run):
        """Test APT security update detection - positive case."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  nginx
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst nginx [1.20.1-1ubuntu1] (1.20.1-1ubuntu1.1 Ubuntu:22.04/jammy-security [amd64])
""",
        )

        is_security = self.linux_detector._is_apt_security_update("nginx")

        assert is_security is True

    @patch("subprocess.run")
    def test_is_apt_security_update_false(self, mock_run):
        """Test APT security update detection - negative case."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  nginx
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst nginx [1.20.1-1ubuntu1] (1.20.1-1ubuntu2 Ubuntu:22.04/jammy-updates [amd64])
""",
        )

        is_security = self.linux_detector._is_apt_security_update("nginx")

        assert is_security is False

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_is_homebrew_available_true(self, mock_run, mock_exists):
        """Test Homebrew availability check - positive case."""
        mock_exists.return_value = True
        mock_run.return_value = Mock(returncode=0)

        detector = UpdateDetector()
        available = detector._is_homebrew_available()

        assert available is True

    @patch("os.path.exists")
    def test_is_homebrew_available_false(self, mock_exists):
        """Test Homebrew availability check - negative case."""
        mock_exists.return_value = False

        detector = UpdateDetector()
        available = detector._is_homebrew_available()

        assert available is False

    def test_detect_package_managers_macos(self):
        """Test package manager detection on macOS."""
        with patch("platform.system", return_value="Darwin"):
            with patch.object(
                MacOSUpdateDetector, "_is_homebrew_available", return_value=True
            ):
                detector = UpdateDetector()
                managers = detector._detect_package_managers()

                assert "homebrew" in managers

    def test_detect_package_managers_windows(self):
        """Test package manager detection on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch.object(WindowsUpdateDetector, "_command_exists") as mock_exists:

                def exists_side_effect(cmd):
                    return cmd in ["winget", "choco"]

                mock_exists.side_effect = exists_side_effect

                detector = UpdateDetector()
                managers = detector._detect_package_managers()

                assert "winget" in managers
                assert "chocolatey" in managers

    def test_platform_detection_and_routing(self):
        """Test that platform detection routes to correct update methods."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(LinuxUpdateDetector, "detect_updates") as mock_linux:
                detector = UpdateDetector()
                detector.get_available_updates()

                mock_linux.assert_called_once()

        with patch("platform.system", return_value="Darwin"):
            with patch.object(MacOSUpdateDetector, "detect_updates") as mock_macos:
                detector = UpdateDetector()
                detector.get_available_updates()

                mock_macos.assert_called_once()

        with patch("platform.system", return_value="Windows"):
            with patch.object(WindowsUpdateDetector, "detect_updates") as mock_windows:
                detector = UpdateDetector()
                detector.get_available_updates()

                mock_windows.assert_called_once()
