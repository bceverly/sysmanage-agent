"""
Unit tests for Linux update detection module.

This module covers:
- APT update detection (Debian/Ubuntu)
- DNF/YUM update detection (Fedora/RHEL/CentOS)
- Pacman update detection (Arch Linux)
- Zypper update detection (openSUSE)
- Snap update detection
- Flatpak update detection
"""

# pylint: disable=protected-access,redefined-outer-name,too-many-public-methods

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_linux import LinuxUpdateDetector


@pytest.fixture
def linux_detector():
    """Create a LinuxUpdateDetector for testing."""
    return LinuxUpdateDetector()


# =============================================================================
# APT Update Detection Tests
# =============================================================================


class TestAptUpdateDetection:
    """Tests for APT package manager update detection."""

    def test_detect_apt_updates_with_multiple_packages(self, linux_detector):
        """Test APT update detection with multiple packages."""
        mock_update = Mock(returncode=0)
        mock_list = Mock(
            returncode=0,
            stdout="""Listing...
nginx/focal-security 1.18.0-0ubuntu1.5 amd64 [upgradable from: 1.18.0-0ubuntu1.4]
vim/focal-updates 2:8.1.2269-1ubuntu5.18 amd64 [upgradable from: 2:8.1.2269-1ubuntu5.17]
curl/focal 7.68.0-1ubuntu2.19 amd64 [upgradable from: 7.68.0-1ubuntu2.18]
""",
        )

        def mock_run(cmd, **_kwargs):
            if "apt-get" in cmd and "update" in cmd:
                return mock_update
            if "apt-cache" in cmd:
                return Mock(returncode=0, stdout="")
            return mock_list

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 3

        # Check nginx (security update)
        nginx_update = next(
            (
                u
                for u in linux_detector.available_updates
                if u["package_name"] == "nginx"
            ),
            None,
        )
        assert nginx_update is not None
        assert nginx_update["current_version"] == "1.18.0-0ubuntu1.4"
        assert nginx_update["available_version"] == "1.18.0-0ubuntu1.5"
        assert nginx_update["package_manager"] == "apt"

    def test_detect_apt_updates_security_package(self, linux_detector):
        """Test APT detection correctly identifies security packages."""
        mock_update = Mock(returncode=0)
        mock_list = Mock(
            returncode=0,
            stdout="""Listing...
openssl/focal-security 1.1.1f-1ubuntu2.21 amd64 [upgradable from: 1.1.1f-1ubuntu2.20]
""",
        )
        mock_policy = Mock(returncode=0, stdout="focal-security")

        def mock_run(cmd, **_kwargs):
            if "apt-get" in cmd:
                return mock_update
            if "apt-cache" in cmd and "policy" in cmd:
                return mock_policy
            if "apt-cache" in cmd and "show" in cmd:
                return Mock(returncode=0, stdout="Size: 1024000")
            return mock_list

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 1
        update = linux_detector.available_updates[0]
        assert update["is_security_update"] is True

    def test_detect_apt_updates_timeout(self, linux_detector):
        """Test APT update detection handles timeout gracefully."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("apt", 60)):
            # Should not raise, just log error
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 0

    def test_detect_apt_updates_command_failure(self, linux_detector):
        """Test APT update detection handles command failure."""
        mock_update = Mock(returncode=0)
        mock_list = Mock(
            returncode=1, stdout="", stderr="Error: Could not open lock file"
        )

        def mock_run(cmd, **_kwargs):
            if "apt-get" in cmd:
                return mock_update
            return mock_list

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 0

    def test_apt_update_size_calculation(self, linux_detector):
        """Test APT update size is correctly retrieved."""
        mock_result = Mock(
            returncode=0,
            stdout="""Package: nginx
Size: 2048576
Version: 1.18.0-0ubuntu1.5
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            size = linux_detector._get_apt_update_size("nginx")

        assert size == 2048576

    def test_apt_update_size_not_found(self, linux_detector):
        """Test APT update size when package not found."""
        mock_result = Mock(returncode=1, stderr="N: Unable to locate package")

        with patch("subprocess.run", return_value=mock_result):
            size = linux_detector._get_apt_update_size("nonexistent")

        assert size is None


# =============================================================================
# DNF/YUM Update Detection Tests
# =============================================================================


class TestDnfUpdateDetection:
    """Tests for DNF/YUM package manager update detection."""

    def test_detect_dnf_updates_success(self, linux_detector):
        """Test successful DNF update detection."""
        mock_result = Mock(
            returncode=100,  # DNF returns 100 when updates available
            stdout="""kernel.x86_64                      5.15.0-150.167              updates
systemd.x86_64                     249-18.el9                  baseos
nginx.x86_64                       1:1.24.0-1.el9              appstream
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._detect_dnf_updates()

        assert len(linux_detector.available_updates) == 3

        kernel_update = next(
            (
                u
                for u in linux_detector.available_updates
                if u["package_name"] == "kernel"
            ),
            None,
        )
        assert kernel_update is not None
        assert kernel_update["package_manager"] == "dnf"

    def test_detect_dnf_security_updates(self, linux_detector):
        """Test DNF security update detection."""
        mock_check = Mock(
            returncode=100,
            stdout="""openssl.x86_64                     3.0.7-24.el9               security
""",
        )
        mock_updateinfo = Mock(
            returncode=0,
            stdout="RHSA-2024:0001 Important/Sec. openssl-3.0.7-24.el9.x86_64",
        )

        def mock_run(cmd, **_kwargs):
            if "updateinfo" in cmd:
                return mock_updateinfo
            return mock_check

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_dnf_updates()

        assert len(linux_detector.available_updates) == 1
        update = linux_detector.available_updates[0]
        assert "security" in update["repository"].lower() or update.get(
            "is_security_update"
        )

    def test_detect_yum_updates_delegates_to_dnf(self, linux_detector):
        """Test YUM update detection uses DNF method."""
        mock_result = Mock(returncode=0, stdout="")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._detect_yum_updates()

        # YUM delegates to DNF, so should work the same way
        assert linux_detector.available_updates == []

    def test_dnf_security_update_check(self, linux_detector):
        """Test _is_dnf_security_update method."""
        mock_result = Mock(
            returncode=0, stdout="CVE-2024-0001 Important security update"
        )

        with patch("subprocess.run", return_value=mock_result):
            is_security = linux_detector._is_dnf_security_update("openssl")

        assert is_security is True

    def test_dnf_security_update_check_not_security(self, linux_detector):
        """Test _is_dnf_security_update returns False for non-security."""
        mock_result = Mock(returncode=0, stdout="Bugfix update for package")

        with patch("subprocess.run", return_value=mock_result):
            is_security = linux_detector._is_dnf_security_update("vim")

        assert is_security is False


# =============================================================================
# Pacman Update Detection Tests
# =============================================================================


class TestPacmanUpdateDetection:
    """Tests for Pacman (Arch Linux) update detection."""

    def test_detect_pacman_updates_success(self, linux_detector):
        """Test successful Pacman update detection."""
        mock_sync = Mock(returncode=0)
        mock_qu = Mock(
            returncode=0,
            stdout="""linux 6.7.0 -> 6.7.1
systemd 254.7-1 -> 254.8-1
vim 9.0.2167-1 -> 9.0.2200-1
""",
        )

        def mock_run(cmd, **_kwargs):
            if "-Sy" in cmd:
                return mock_sync
            return mock_qu

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_pacman_updates()

        assert len(linux_detector.available_updates) == 3

        linux_update = next(
            (
                u
                for u in linux_detector.available_updates
                if u["package_name"] == "linux"
            ),
            None,
        )
        assert linux_update is not None
        assert linux_update["current_version"] == "6.7.0"
        assert linux_update["available_version"] == "6.7.1"
        assert linux_update["package_manager"] == "pacman"

    def test_detect_pacman_updates_no_updates(self, linux_detector):
        """Test Pacman detection when no updates available."""
        mock_sync = Mock(returncode=0)
        mock_qu = Mock(returncode=0, stdout="")

        def mock_run(cmd, **_kwargs):
            if "-Sy" in cmd:
                return mock_sync
            return mock_qu

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_pacman_updates()

        assert len(linux_detector.available_updates) == 0


# =============================================================================
# Zypper Update Detection Tests
# =============================================================================


class TestZypperUpdateDetection:
    """Tests for Zypper (openSUSE) update detection."""

    def test_detect_zypper_updates_success(self, linux_detector):
        """Test successful Zypper update detection."""
        mock_result = Mock(
            returncode=0,
            stdout="""S | Repository | Name              | Current Version | Available Version | Arch
--+------------+-------------------+-----------------+-------------------+-------
v | Main       | apache2           | 2.4.51-1.1      | 2.4.52-1.1        | x86_64
v | Main       | kernel-default    | 5.14.21-150400  | 5.14.21-150500    | x86_64
v | Security   | openssl           | 1.1.1l-1.2      | 1.1.1n-1.1        | x86_64
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._detect_zypper_updates()

        assert len(linux_detector.available_updates) == 3

        openssl_update = next(
            (
                u
                for u in linux_detector.available_updates
                if u["package_name"] == "openssl"
            ),
            None,
        )
        assert openssl_update is not None
        assert openssl_update["package_manager"] == "zypper"

    def test_detect_zypper_updates_failure(self, linux_detector):
        """Test Zypper update detection with command failure."""
        mock_result = Mock(returncode=1, stderr="Repository error")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._detect_zypper_updates()

        assert len(linux_detector.available_updates) == 0


# =============================================================================
# Snap Update Detection Tests
# =============================================================================


class TestSnapUpdateDetection:
    """Tests for Snap package manager update detection."""

    def test_detect_snap_updates_success(self, linux_detector):
        """Test successful Snap update detection."""
        mock_result = Mock(
            returncode=0,
            stdout="""Name       Version         Rev    Publisher     Notes
firefox    120.0           2985   mozilla**     -
chromium   119.0.6045.123  2691   nicpottier    -
vlc        3.0.18          2344   videolan**    -
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._detect_snap_updates()

        assert len(linux_detector.available_updates) == 3

        firefox_update = next(
            (
                u
                for u in linux_detector.available_updates
                if u["package_name"] == "firefox"
            ),
            None,
        )
        assert firefox_update is not None
        assert firefox_update["package_manager"] == "snap"

    def test_detect_snap_updates_no_updates(self, linux_detector):
        """Test Snap detection when no updates available."""
        mock_result = Mock(returncode=0, stdout="")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._detect_snap_updates()

        assert len(linux_detector.available_updates) == 0


# =============================================================================
# Flatpak Update Detection Tests
# =============================================================================


class TestFlatpakUpdateDetection:
    """Tests for Flatpak update detection."""

    def test_detect_flatpak_updates_success(self, linux_detector):
        """Test successful Flatpak update detection."""
        mock_appstream = Mock(returncode=0)
        mock_remote_ls = Mock(
            returncode=0,
            stdout="""org.mozilla.firefox	stable	120.0
org.gnome.Calculator	stable	45.0
org.libreoffice.LibreOffice	stable	7.6.4
""",
        )

        def mock_run(cmd, **_kwargs):
            if "--appstream" in cmd:
                return mock_appstream
            return mock_remote_ls

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_flatpak_updates()

        assert len(linux_detector.available_updates) == 3

    def test_detect_flatpak_updates_no_updates(self, linux_detector):
        """Test Flatpak detection when no updates available."""
        mock_appstream = Mock(returncode=0)
        mock_remote_ls = Mock(returncode=0, stdout="")

        def mock_run(cmd, **_kwargs):
            if "--appstream" in cmd:
                return mock_appstream
            return mock_remote_ls

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_flatpak_updates()

        assert len(linux_detector.available_updates) == 0
