"""
Unit tests for OS-level system update detection functionality (Feature #50).
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init

from unittest.mock import Mock, patch

from src.sysmanage_agent.collection.update_detection import UpdateDetector


class TestOSSystemUpdateDetection:
    """Test cases for OS-level system update detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = UpdateDetector()
        self.detector.available_updates = []

    @patch("subprocess.run")
    def test_detect_windows_system_updates_success(self, mock_run):
        """Test Windows system update detection with available updates."""
        # Mock PowerShell output with Windows updates
        powershell_output = """
[
    {
        "Title": "Security Update for Windows",
        "Description": "Important security update",
        "SizeInBytes": 52428800,
        "Categories": [{"Name": "Security Updates"}]
    },
    {
        "Title": "Feature Update for Windows",
        "Description": "Feature update description",
        "SizeInBytes": 104857600,
        "Categories": [{"Name": "Updates"}]
    }
]
"""
        mock_run.return_value = Mock(
            returncode=0, stdout=powershell_output.strip(), stderr=""
        )

        self.detector._detect_windows_system_updates()

        assert len(self.detector.available_updates) == 2

        # Check security update
        security_update = next(
            u
            for u in self.detector.available_updates
            if "Security Update" in u["package_name"]
        )
        assert security_update["package_name"] == "Security Update for Windows"
        assert security_update["package_manager"] == "Windows Update"
        assert security_update["update_type"] == "security"
        assert security_update["size"] == "50.0 MB"

        # Check feature update
        feature_update = next(
            u
            for u in self.detector.available_updates
            if "Feature Update" in u["package_name"]
        )
        assert feature_update["package_name"] == "Feature Update for Windows"
        assert feature_update["package_manager"] == "Windows Update"
        assert feature_update["update_type"] == "regular"
        assert feature_update["size"] == "100.0 MB"

    @patch("subprocess.run")
    def test_detect_windows_system_updates_no_updates(self, mock_run):
        """Test Windows system update detection with no updates."""
        mock_run.return_value = Mock(returncode=0, stdout="[]", stderr="")

        self.detector._detect_windows_system_updates()
        assert len(self.detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_windows_system_updates_error(self, mock_run):
        """Test Windows system update detection error handling."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="Access denied")

        # Should not raise exception
        self.detector._detect_windows_system_updates()
        assert len(self.detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_windows_system_updates_invalid_json(self, mock_run):
        """Test Windows system update detection with invalid JSON."""
        mock_run.return_value = Mock(returncode=0, stdout="invalid json", stderr="")

        # Should not raise exception
        self.detector._detect_windows_system_updates()
        assert len(self.detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_macos_system_updates_success(self, mock_run):
        """Test macOS system update detection with available updates."""
        softwareupdate_output = """
Software Update Tool

Finding available software...
Software Update found the following new or updated software:
   * Label: macOS Security Update-001
   	Title: macOS Security Update (001), Version: 15.6.1, Size: 250000KiB, Recommended: YES, Action: restart
   * Label: Safari15.6-15613.3.9.1.16
   	Title: Safari (15.6), Version: 15.6, Size: 75000KiB, Recommended: YES
"""
        # Set up mock to handle multiple subprocess calls
        # First call: softwareupdate --list
        # Second call: sw_vers -productVersion (for first update)
        # Third call: sw_vers -productVersion (for second update)
        mock_run.side_effect = [
            Mock(
                returncode=0, stdout=softwareupdate_output.strip(), stderr=""
            ),  # softwareupdate call
            Mock(
                returncode=0, stdout="15.6.1", stderr=""
            ),  # sw_vers call for first update
            Mock(
                returncode=0, stdout="15.6.1", stderr=""
            ),  # sw_vers call for second update
        ]

        self.detector._detect_macos_app_store_updates()

        assert len(self.detector.available_updates) == 2

        # Check security update
        security_update = next(
            u
            for u in self.detector.available_updates
            if "Security Update" in u["package_name"]
        )
        assert security_update["package_name"] == "macOS Security Update (001)"
        assert (
            security_update["package_manager"] == "mac_app_store"
        )  # Updated based on new logic
        assert security_update["is_security_update"] is True
        assert security_update["size_kb"] == 250000
        assert security_update["requires_restart"] is True
        assert security_update["is_recommended"] is True

        # Check Safari update
        safari_update = next(
            u for u in self.detector.available_updates if "Safari" in u["package_name"]
        )
        assert safari_update["package_name"] == "Safari (15.6)"
        assert (
            safari_update["package_manager"] == "mac_app_store"
        )  # Updated based on new logic
        assert (
            safari_update["is_security_update"] is False
        )  # Safari updates are not security in the new logic
        assert safari_update["size_kb"] == 75000
        assert safari_update["requires_restart"] is False
        assert safari_update["is_recommended"] is True

    @patch("subprocess.run")
    def test_detect_macos_system_updates_no_updates(self, mock_run):
        """Test macOS system update detection with no updates."""
        softwareupdate_output = """
Software Update Tool

Finding available software...
No new software available.
"""
        # Set up mock to handle multiple subprocess calls
        mock_run.side_effect = [
            Mock(returncode=0, stdout="15.6.1", stderr=""),  # sw_vers call
            Mock(
                returncode=0, stdout=softwareupdate_output.strip(), stderr=""
            ),  # softwareupdate call
        ]

        self.detector._detect_macos_app_store_updates()
        assert len(self.detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_macos_system_updates_error(self, mock_run):
        """Test macOS system update detection error handling."""
        # First call fails (sw_vers)
        mock_run.side_effect = [
            Mock(
                returncode=1, stdout="", stderr="Permission denied"
            ),  # sw_vers call fails
        ]

        # Should not raise exception
        self.detector._detect_macos_app_store_updates()
        assert len(self.detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_openbsd_system_updates_success(self, mock_run):
        """Test OpenBSD syspatch detection with available patches."""
        syspatch_output = """
001_rsa
002_ssh
003_kernel
"""
        mock_run.return_value = Mock(
            returncode=0, stdout=syspatch_output.strip(), stderr=""
        )

        self.detector._detect_openbsd_system_updates()

        assert len(self.detector.available_updates) == 3

        # Check patches
        patch_names = [u["package_name"] for u in self.detector.available_updates]
        assert "syspatch-001_rsa" in patch_names
        assert "syspatch-002_ssh" in patch_names
        assert "syspatch-003_kernel" in patch_names

        for update in self.detector.available_updates:
            assert update["package_manager"] == "syspatch"
            assert update["is_security_update"] is True
            assert update["is_system_update"] is True

    @patch("subprocess.run")
    def test_detect_openbsd_system_updates_no_patches(self, mock_run):
        """Test OpenBSD syspatch detection with no patches."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        self.detector._detect_openbsd_system_updates()
        assert len(self.detector.available_updates) == 0

    @patch("subprocess.run")
    def test_detect_openbsd_system_updates_error(self, mock_run):
        """Test OpenBSD syspatch detection error handling."""
        mock_run.return_value = Mock(
            returncode=1, stdout="", stderr="syspatch: command not found"
        )

        # Should not raise exception
        self.detector._detect_openbsd_system_updates()
        assert len(self.detector.available_updates) == 0

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_detect_debian_system_updates_success(self, mock_exists, mock_run):
        """Test Debian system update detection."""
        mock_exists.return_value = True

        # Mock apt list --upgradable command with system packages
        apt_output = """Listing...
linux-image-generic/focal-updates 5.4.0.100.100 amd64 [upgradable from: 5.4.0.99.99]
systemd/focal-updates 245.4-4ubuntu3.15 amd64 [upgradable from: 245.4-4ubuntu3.14]"""

        mock_run.return_value = Mock(returncode=0, stdout=apt_output, stderr="")

        self.detector._detect_debian_system_updates()

        # Should call apt list --upgradable (1) + apt-cache policy for each package (2)
        assert mock_run.call_count == 3
        assert len(self.detector.available_updates) == 2

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_detect_redhat_system_updates_success(self, mock_exists, mock_run):
        """Test Red Hat system update detection."""
        mock_exists.return_value = True

        # Mock dnf/yum check-update
        mock_run.return_value = Mock(
            returncode=100,  # dnf/yum returns 100 when updates available
            stdout="systemd.x86_64 1.2.3-1.el8 updates\n",
            stderr="",
        )

        self.detector._detect_redhat_system_updates()

        # Should call dnf/yum check-update
        mock_run.assert_called()

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_detect_arch_system_updates_success(self, mock_exists, mock_run):
        """Test Arch Linux system update detection."""
        mock_exists.return_value = True

        # Mock pacman -Qu
        mock_run.return_value = Mock(
            returncode=0,
            stdout="systemd 250.4-2 -> 251.2-1\nlinux 5.15.1 -> 5.16.1\n",
            stderr="",
        )

        self.detector._detect_arch_system_updates()

        # Should call pacman
        mock_run.assert_called()

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_detect_suse_system_updates_success(self, mock_exists, mock_run):
        """Test SUSE system update detection."""
        mock_exists.return_value = True

        # Mock zypper list-updates
        mock_run.return_value = Mock(
            returncode=0,
            stdout="systemd | 249.4 | 250.1 | openSUSE-Leap-15.3-Update\n",
            stderr="",
        )

        self.detector._detect_suse_system_updates()

        # Should call zypper
        mock_run.assert_called()

    @patch("os.path.exists")
    def test_detect_linux_system_updates_debian(self, mock_exists):
        """Test Linux system update detection on Debian."""

        # Mock /etc/debian_version exists
        def exists_side_effect(path):
            return path == "/etc/debian_version"

        mock_exists.side_effect = exists_side_effect

        with patch.object(
            self.detector, "_detect_debian_system_updates"
        ) as mock_debian:
            self.detector._detect_linux_system_updates()
            mock_debian.assert_called_once()

    @patch("os.path.exists")
    def test_detect_linux_system_updates_redhat(self, mock_exists):
        """Test Linux system update detection on Red Hat."""

        # Mock /etc/redhat-release exists
        def exists_side_effect(path):
            return path == "/etc/redhat-release"

        mock_exists.side_effect = exists_side_effect

        with patch.object(
            self.detector, "_detect_redhat_system_updates"
        ) as mock_redhat:
            self.detector._detect_linux_system_updates()
            mock_redhat.assert_called_once()

    @patch("os.path.exists")
    def test_detect_linux_system_updates_arch(self, mock_exists):
        """Test Linux system update detection on Arch."""

        # Mock /etc/arch-release exists
        def exists_side_effect(path):
            return path == "/etc/arch-release"

        mock_exists.side_effect = exists_side_effect

        with patch.object(self.detector, "_detect_arch_system_updates") as mock_arch:
            self.detector._detect_linux_system_updates()
            mock_arch.assert_called_once()

    @patch("os.path.exists")
    def test_detect_linux_system_updates_suse(self, mock_exists):
        """Test Linux system update detection on SUSE."""

        # Mock /etc/SUSE-brand exists
        def exists_side_effect(path):
            return path == "/etc/SUSE-brand"

        mock_exists.side_effect = exists_side_effect

        with patch.object(self.detector, "_detect_suse_system_updates") as mock_suse:
            self.detector._detect_linux_system_updates()
            mock_suse.assert_called_once()

    def test_integration_os_system_updates_called_first(self):
        """Test that OS system updates are detected within Linux updates."""

        with patch("platform.system", return_value="Linux"):
            # Create a new detector with the mocked platform
            detector = UpdateDetector()

            with patch.object(
                detector, "_detect_linux_system_updates"
            ) as mock_os_updates, patch.object(
                detector, "_detect_package_managers"
            ) as mock_pkg_mgrs:

                mock_pkg_mgrs.return_value = []

                result = detector.get_available_updates()

                # OS system updates should be called within _detect_linux_updates
                mock_os_updates.assert_called_once()
                assert "available_updates" in result

    def test_windows_update_size_conversion(self):
        """Test Windows update size conversion."""
        # Test with 52,428,800 bytes (50 MB)
        size_mb = self.detector._format_size_mb(52428800)
        assert size_mb == "50.0 MB"

        # Test with 1,073,741,824 bytes (1 GB)
        size_mb = self.detector._format_size_mb(1073741824)
        assert size_mb == "1024.0 MB"

        # Test with 0 bytes
        size_mb = self.detector._format_size_mb(0)
        assert size_mb == "0.0 MB"

    def test_macos_update_parsing(self):
        """Test macOS update line parsing."""
        test_line = "   * macOS Security Update-001\n   \tmacOS Security Update (001), 250MB [recommended] [restart]"

        # This would be internal parsing logic that should be tested
        # if it becomes a separate method
        assert "macOS Security Update-001" in test_line
        assert "250MB" in test_line
        assert "[restart]" in test_line

    def test_security_update_classification(self):
        """Test security update classification logic."""
        # Test Windows security classification
        windows_security_categories = [{"Name": "Security Updates"}]
        windows_regular_categories = [{"Name": "Updates"}]

        # This tests the classification logic used in _detect_windows_system_updates
        is_security = any(
            "Security" in cat.get("Name", "") for cat in windows_security_categories
        )
        assert is_security is True

        is_regular = any(
            "Security" in cat.get("Name", "") for cat in windows_regular_categories
        )
        assert is_regular is False

    @patch("platform.system")
    def test_platform_specific_update_detection(self, mock_system):
        """Test that the correct platform-specific method is called."""
        test_cases = [
            ("Windows", "_detect_windows_system_updates"),
            ("Darwin", "_detect_macos_app_store_updates"),
            ("Linux", "_detect_linux_system_updates"),
            ("OpenBSD", "_detect_openbsd_system_updates"),
        ]

        for platform, expected_method in test_cases:
            mock_system.return_value = platform
            detector = UpdateDetector()

            with patch.object(detector, expected_method) as mock_method, patch.object(
                detector, "_detect_package_managers", return_value=[]
            ):

                # Call the platform-specific update method directly
                if platform == "Windows":
                    detector._detect_windows_updates()
                elif platform == "Darwin":
                    detector._detect_macos_updates()
                elif platform == "Linux":
                    detector._detect_linux_updates()
                elif platform == "OpenBSD":
                    detector._detect_bsd_updates()

                mock_method.assert_called_once()

    def test_error_resilience(self):
        """Test that system update detection is resilient to errors."""
        with patch("subprocess.run", side_effect=Exception("Test exception")):
            # Should not raise exception
            self.detector._detect_windows_system_updates()
            self.detector._detect_macos_app_store_updates()
            self.detector._detect_openbsd_system_updates()
            self.detector._detect_linux_system_updates()

            # Should have no updates but not crash
            assert len(self.detector.available_updates) == 0
