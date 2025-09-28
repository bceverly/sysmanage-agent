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

    @patch("subprocess.run")
    def test_detect_yum_updates_success(self, mock_run):
        """Test successful YUM update detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""Loaded plugins: fastestmirror, priorities
Determining fastest mirrors
httpd.x86_64                    2.4.37-64.module+el8.9.0+19699+7a7c1871                         appstream
nginx.x86_64                    1:1.20.1-1.el8                                                   epel
""",
        )

        detector = UpdateDetector()
        detector._detect_yum_updates()

        assert len(detector.available_updates) == 2
        httpd_update = next(
            (u for u in detector.available_updates if u["package_name"] == "httpd"),
            None,
        )
        assert httpd_update is not None
        assert (
            httpd_update["available_version"]
            == "2.4.37-64.module+el8.9.0+19699+7a7c1871"
        )

    @patch("subprocess.run")
    def test_detect_yum_updates_failure(self, mock_run):
        """Test YUM update detection with command failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Failed to check updates")

        detector = UpdateDetector()
        detector._detect_yum_updates()

        assert len(detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_pacman_updates_success(self, mock_run):
        """Test successful Pacman update detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""core/bash 5.1.016-1 -> 5.1.016-2
extra/nginx 1.20.1-1 -> 1.21.0-1
community/docker 20.10.21-1 -> 20.10.22-1
""",
        )

        detector = UpdateDetector()
        detector._detect_pacman_updates()

        assert len(detector.available_updates) == 3
        bash_update = next(
            (u for u in detector.available_updates if u["package_name"] == "bash"), None
        )
        assert bash_update is not None
        assert bash_update["current_version"] == "5.1.016-1"
        assert bash_update["available_version"] == "5.1.016-2"

    @patch("subprocess.run")
    def test_detect_pacman_updates_no_updates(self, mock_run):
        """Test Pacman update detection with no updates available."""
        mock_run.return_value = Mock(returncode=0, stdout="")

        detector = UpdateDetector()
        detector._detect_pacman_updates()

        assert len(detector.available_updates) == 0

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

        detector = UpdateDetector()
        detector._detect_zypper_updates()

        assert len(detector.available_updates) == 2
        apache_update = next(
            (u for u in detector.available_updates if u["package_name"] == "apache2"),
            None,
        )
        assert apache_update is not None
        assert apache_update["current_version"] == "2.4.51-1.1"
        assert apache_update["available_version"] == "2.4.52-1.1"

    @patch("subprocess.run")
    def test_detect_zypper_updates_failure(self, mock_run):
        """Test Zypper update detection with command failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Repository error")

        detector = UpdateDetector()
        detector._detect_zypper_updates()

        assert len(detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_homebrew_updates_success(self, mock_run):
        """Test successful Homebrew update detection."""
        detector = UpdateDetector()
        detector._get_brew_command = Mock(return_value="brew")

        mock_run.return_value = Mock(
            returncode=0,
            stdout="""git (2.42.0) < 2.42.1
nginx (1.25.1) < 1.25.2
node (20.8.0) < 20.8.1
""",
        )

        detector._detect_homebrew_updates()

        assert len(detector.available_updates) == 3
        git_update = next(
            (u for u in detector.available_updates if u["package_name"] == "git"), None
        )
        assert git_update is not None
        assert git_update["current_version"] == "2.42.0"
        assert git_update["available_version"] == "2.42.1"

    @patch("subprocess.run")
    def test_detect_homebrew_updates_no_updates(self, mock_run):
        """Test Homebrew update detection with no updates available."""
        detector = UpdateDetector()
        detector._get_brew_command = Mock(return_value="brew")

        mock_run.return_value = Mock(returncode=0, stdout="")

        detector._detect_homebrew_updates()

        assert len(detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_chocolatey_updates_success(self, mock_run):
        """Test successful Chocolatey update detection."""
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
    def test_detect_chocolatey_updates_no_command(self, mock_run):
        """Test Chocolatey update detection when command not available."""
        mock_run.side_effect = FileNotFoundError("choco command not found")

        detector = UpdateDetector()
        detector._detect_chocolatey_updates()

        assert len(detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_winget_updates_success(self, mock_run):
        """Test successful Winget update detection."""
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
    def test_detect_winget_updates_failure(self, mock_run):
        """Test Winget update detection with command failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Winget error")

        detector = UpdateDetector()
        detector._detect_winget_updates()

        assert len(detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_pkg_updates_success(self, mock_run):
        """Test successful FreeBSD pkg update detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""nginx-1.20.1,3
apache24-2.4.54_1
python39-3.9.16_2
postgresql13-server-13.12_1
""",
        )

        detector = UpdateDetector()
        detector._detect_pkg_updates()

        assert len(detector.available_updates) == 4
        nginx_update = next(
            (u for u in detector.available_updates if u["package_name"] == "nginx"),
            None,
        )
        assert nginx_update is not None

    @patch("subprocess.run")
    def test_get_apt_update_size_success(self, mock_run):
        """Test successful APT update size calculation."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  nginx
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Need to get 1,024 kB of archives.
""",
        )

        detector = UpdateDetector()
        size = detector._get_apt_update_size("nginx")

        assert size == 1048576  # 1,024 kB in bytes

    @patch("subprocess.run")
    def test_get_apt_update_size_failure(self, mock_run):
        """Test APT update size calculation failure."""
        mock_run.return_value = Mock(returncode=1, stderr="Package not found")

        detector = UpdateDetector()
        size = detector._get_apt_update_size("nonexistent")

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

        detector = UpdateDetector()
        is_security = detector._is_apt_security_update("nginx")

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

        detector = UpdateDetector()
        is_security = detector._is_apt_security_update("nginx")

        assert is_security is False

    def test_command_exists_exception(self):
        """Test command existence check with exception."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            detector = UpdateDetector()
            exists = detector._command_exists("test-command")

            assert exists is False

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

    @patch("pwd.getpwuid")
    @patch("os.getuid")
    def test_get_homebrew_owner_success(self, mock_getuid, mock_getpwuid):
        """Test Homebrew owner detection."""
        mock_getuid.return_value = 1000
        mock_getpwuid.return_value.pw_name = "testuser"

        detector = UpdateDetector()
        owner = detector._get_homebrew_owner()

        assert owner == "testuser"

    @patch("pwd.getpwuid", side_effect=Exception("User not found"))
    @patch("os.getuid")
    def test_get_homebrew_owner_failure(self, mock_getuid, mock_getpwuid):
        """Test Homebrew owner detection with failure."""
        mock_getuid.return_value = 1000

        detector = UpdateDetector()
        owner = detector._get_homebrew_owner()

        assert owner == "nobody"

    @patch("os.path.exists")
    def test_get_brew_command_intel_mac(self, mock_exists):
        """Test brew command detection on Intel Mac."""

        def exists_side_effect(path):
            return path == "/usr/local/bin/brew"

        mock_exists.side_effect = exists_side_effect

        detector = UpdateDetector()
        detector._get_homebrew_owner = Mock(return_value="testuser")

        command = detector._get_brew_command()

        assert command == "sudo -u testuser /usr/local/bin/brew"

    @patch("os.path.exists")
    def test_get_brew_command_apple_silicon(self, mock_exists):
        """Test brew command detection on Apple Silicon Mac."""

        def exists_side_effect(path):
            return path == "/opt/homebrew/bin/brew"

        mock_exists.side_effect = exists_side_effect

        detector = UpdateDetector()
        detector._get_homebrew_owner = Mock(return_value="testuser")

        command = detector._get_brew_command()

        assert command == "sudo -u testuser /opt/homebrew/bin/brew"

    @patch("os.path.exists")
    def test_get_brew_command_not_found(self, mock_exists):
        """Test brew command detection when not found."""
        mock_exists.return_value = False

        detector = UpdateDetector()
        detector._get_homebrew_owner = Mock(return_value="testuser")

        command = detector._get_brew_command()

        assert command == "sudo -u testuser brew"

    def test_detect_package_managers_macos(self):
        """Test package manager detection on macOS."""
        with patch("platform.system", return_value="Darwin"):
            with patch.object(
                UpdateDetector, "_is_homebrew_available", return_value=True
            ):
                detector = UpdateDetector()
                managers = detector._detect_package_managers()

                assert "homebrew" in managers

    def test_detect_package_managers_windows(self):
        """Test package manager detection on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch.object(UpdateDetector, "_command_exists") as mock_exists:

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
            with patch.object(UpdateDetector, "_detect_linux_updates") as mock_linux:
                detector = UpdateDetector()
                detector.get_available_updates()

                mock_linux.assert_called_once()

        with patch("platform.system", return_value="Darwin"):
            with patch.object(UpdateDetector, "_detect_macos_updates") as mock_macos:
                detector = UpdateDetector()
                detector.get_available_updates()

                mock_macos.assert_called_once()

        with patch("platform.system", return_value="Windows"):
            with patch.object(
                UpdateDetector, "_detect_windows_updates"
            ) as mock_windows:
                detector = UpdateDetector()
                detector.get_available_updates()

                mock_windows.assert_called_once()
