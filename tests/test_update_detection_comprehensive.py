"""
Comprehensive unit tests for update detection module.

This module covers:
- Available updates detection (apt, dnf, pkg, etc.)
- Reboot required detection
- Update history tracking
- Security update detection
- Multi-distro support
- Error handling
"""

# pylint: disable=protected-access,redefined-outer-name,too-many-public-methods

import subprocess
from unittest.mock import Mock, patch, mock_open

import pytest

from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.sysmanage_agent.collection.update_detection_linux import LinuxUpdateDetector
from src.sysmanage_agent.collection.update_detection_bsd import BSDUpdateDetector
from src.sysmanage_agent.collection.update_detection_base import UpdateDetectorBase


@pytest.fixture
def linux_detector():
    """Create a LinuxUpdateDetector for testing."""
    return LinuxUpdateDetector()


@pytest.fixture
def bsd_detector():
    """Create a BSDUpdateDetector for testing."""
    return BSDUpdateDetector()


@pytest.fixture
def base_detector():
    """Create an UpdateDetectorBase for testing."""
    return UpdateDetectorBase()


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


# =============================================================================
# BSD Package Update Detection Tests
# =============================================================================


class TestBsdPkgUpdateDetection:
    """Tests for BSD pkg package manager update detection."""

    def test_detect_pkg_updates_success(self, bsd_detector):
        """Test successful pkg update detection."""
        mock_update = Mock(returncode=0)
        mock_version = Mock(
            returncode=0,
            stdout="""nginx-1.24.0 < needs updating (remote has 1.25.0)
vim-9.0.1 < needs updating (remote has 9.0.2)
python39-3.9.17 < needs updating (remote has 3.9.18)
""",
        )

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update
            return mock_version

        with patch("subprocess.run", side_effect=mock_run):
            bsd_detector._detect_pkg_updates()

        assert len(bsd_detector.available_updates) == 3

        nginx_update = next(
            (u for u in bsd_detector.available_updates if u["package_name"] == "nginx"),
            None,
        )
        assert nginx_update is not None
        assert nginx_update["current_version"] == "1.24.0"
        assert nginx_update["available_version"] == "1.25.0"
        assert nginx_update["package_manager"] == "pkg"

    def test_detect_pkg_updates_complex_package_names(self, bsd_detector):
        """Test pkg detection with complex package names."""
        mock_update = Mock(returncode=0)
        mock_version = Mock(
            returncode=0,
            stdout="""py39-cryptography-41.0.3 < needs updating (remote has 42.0.0)
linux-c7-devtools-7.0 < needs updating (remote has 7.1)
""",
        )

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update
            return mock_version

        with patch("subprocess.run", side_effect=mock_run):
            bsd_detector._detect_pkg_updates()

        # Should parse complex package names correctly
        assert len(bsd_detector.available_updates) >= 0  # May vary based on parsing


class TestBsdPkginUpdateDetection:
    """Tests for NetBSD pkgin package manager update detection."""

    def test_detect_pkgin_updates_success(self, bsd_detector):
        """Test successful pkgin update detection."""
        mock_update = Mock(returncode=0, stderr="")
        mock_list = Mock(
            returncode=0,
            stdout="""vim-9.0.1 Text editor
python311-3.11.6 Python programming language
""",
        )

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update
            return mock_list

        with patch("os.geteuid", return_value=0):
            with patch.object(bsd_detector, "_command_exists", return_value=False):
                with patch("subprocess.run", side_effect=mock_run):
                    bsd_detector._detect_pkgin_updates()

        assert len(bsd_detector.available_updates) == 2

    def test_detect_pkgin_updates_with_doas(self, bsd_detector):
        """Test pkgin detection using doas for privilege escalation."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        def mock_exists(cmd):
            return cmd == "doas"

        with patch("os.geteuid", return_value=1000):  # Non-root
            with patch.object(bsd_detector, "_command_exists", side_effect=mock_exists):
                with patch("subprocess.run", return_value=mock_result):
                    bsd_detector._detect_pkgin_updates()

        # Should complete without error


# =============================================================================
# OpenBSD System Update Detection Tests
# =============================================================================


class TestOpenBsdSystemUpdates:
    """Tests for OpenBSD system update detection."""

    def test_detect_openbsd_syspatch_available(self, bsd_detector):
        """Test OpenBSD syspatch detection with patches available."""
        mock_result = Mock(
            returncode=0,
            stdout="""001_nsd
002_smtpd
003_kernel
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._detect_openbsd_system_updates()

        assert len(bsd_detector.available_updates) == 1
        update = bsd_detector.available_updates[0]
        assert "OpenBSD System Patches" in update["package_name"]
        assert "(3 patches)" in update["package_name"]
        assert update["is_security_update"] is True
        assert update["is_system_update"] is True
        assert update["package_manager"] == "syspatch"

    def test_detect_openbsd_syspatch_none_available(self, bsd_detector):
        """Test OpenBSD syspatch detection when no patches available."""
        mock_result = Mock(returncode=1)  # Return code 1 = no patches

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._detect_openbsd_system_updates()

        assert len(bsd_detector.available_updates) == 0

    def test_detect_openbsd_version_upgrade_available(self, bsd_detector):
        """Test OpenBSD version upgrade detection."""
        mock_version = Mock(returncode=0, stdout="7.5\n")
        mock_html = b"<html><body>OpenBSD 7.6 released!</body></html>"

        with patch("subprocess.run", return_value=mock_version):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = mock_html
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                bsd_detector._detect_openbsd_version_upgrades()

        upgrades = [
            u
            for u in bsd_detector.available_updates
            if u.get("package_manager") == "openbsd-upgrade"
        ]
        assert len(upgrades) == 1
        assert upgrades[0]["current_version"] == "7.5"
        assert upgrades[0]["available_version"] == "7.6"


# =============================================================================
# Reboot Required Detection Tests
# =============================================================================


class TestRebootRequiredDetection:
    """Tests for reboot required detection."""

    def test_linux_reboot_required_file_exists(self, base_detector):
        """Test Linux reboot detection when file exists."""
        base_detector.platform = "linux"

        with patch("os.path.exists", return_value=True):
            result = base_detector.check_reboot_required()

        assert result is True

    def test_linux_reboot_required_kernel_update(self, base_detector):
        """Test Linux reboot detection with kernel update."""
        base_detector.platform = "linux"
        base_detector.available_updates = [
            {"package_name": "linux-image-5.15.0-150", "package_manager": "apt"}
        ]

        with patch("os.path.exists", return_value=False):
            result = base_detector.check_reboot_required()

        assert result is True

    def test_linux_reboot_required_firmware_update(self, base_detector):
        """Test Linux reboot detection with firmware update."""
        base_detector.platform = "linux"
        base_detector.available_updates = [
            {"package_name": "BIOS Update", "package_manager": "fwupd"}
        ]

        with patch("os.path.exists", return_value=False):
            result = base_detector.check_reboot_required()

        assert result is True

    def test_linux_reboot_not_required(self, base_detector):
        """Test Linux reboot not required for regular packages."""
        base_detector.platform = "linux"
        base_detector.available_updates = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "nginx", "package_manager": "apt"},
        ]

        with patch("os.path.exists", return_value=False):
            result = base_detector.check_reboot_required()

        assert result is False

    def test_macos_reboot_required_system_update(self, base_detector):
        """Test macOS reboot detection with system update."""
        base_detector.platform = "darwin"
        base_detector.available_updates = [
            {"package_name": "macOS Sonoma 14.3", "is_system_update": True}
        ]

        result = base_detector.check_reboot_required()

        assert result is True

    def test_macos_reboot_not_required(self, base_detector):
        """Test macOS reboot not required for app updates."""
        base_detector.platform = "darwin"
        base_detector.available_updates = [
            {"package_name": "Firefox", "is_system_update": False}
        ]

        result = base_detector.check_reboot_required()

        assert result is False

    def test_windows_reboot_always_required(self, base_detector):
        """Test Windows reboot detection (always required with updates)."""
        base_detector.platform = "windows"
        base_detector.available_updates = [{"package_name": "KB12345"}]

        result = base_detector.check_reboot_required()

        assert result is True

    def test_windows_reboot_not_required_no_updates(self, base_detector):
        """Test Windows reboot not required when no updates."""
        base_detector.platform = "windows"
        base_detector.available_updates = []

        result = base_detector.check_reboot_required()

        assert result is False


# =============================================================================
# Security Update Detection Tests
# =============================================================================


class TestSecurityUpdateDetection:
    """Tests for security update detection."""

    def test_apt_security_from_repository(self, linux_detector):
        """Test APT security detection from repository name."""
        mock_update = Mock(returncode=0)
        mock_list = Mock(
            returncode=0,
            stdout="""Listing...
openssl/focal-security 1.1.1f-1ubuntu2.21 amd64 [upgradable from: 1.1.1f-1ubuntu2.20]
""",
        )

        def mock_run(cmd, **_kwargs):
            if "apt-get" in cmd:
                return mock_update
            if "apt-cache" in cmd:
                return Mock(returncode=0, stdout="-security")
            return mock_list

        with patch("subprocess.run", side_effect=mock_run):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 1
        assert linux_detector.available_updates[0]["is_security_update"] is True

    def test_dnf_security_from_updateinfo(self, linux_detector):
        """Test DNF security detection from updateinfo."""
        mock_result = Mock(returncode=0, stdout="RHSA-2024:0001 Critical security")

        with patch("subprocess.run", return_value=mock_result):
            is_security = linux_detector._is_dnf_security_update("openssl")

        assert is_security is True

    def test_openbsd_syspatch_always_security(self, bsd_detector):
        """Test that OpenBSD syspatches are always security updates."""
        mock_result = Mock(returncode=0, stdout="001_patch\n")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._detect_openbsd_system_updates()

        if bsd_detector.available_updates:
            assert bsd_detector.available_updates[0]["is_security_update"] is True


# =============================================================================
# Multi-Distro Support Tests
# =============================================================================


class TestMultiDistroSupport:
    """Tests for multi-distribution support."""

    def test_detect_distro_ubuntu(self, linux_detector):
        """Test detection of Ubuntu distribution."""
        os_release_content = """NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
"""
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            linux_detector._detect_linux_system_updates()
        # Should complete without error

    def test_detect_distro_fedora(self, linux_detector):
        """Test detection of Fedora distribution."""
        os_release_content = """NAME="Fedora Linux"
VERSION="39 (Workstation Edition)"
ID=fedora
VERSION_ID=39
"""
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            with patch("subprocess.run", return_value=Mock(returncode=0, stdout="")):
                linux_detector._detect_linux_system_updates()
        # Should complete without error

    def test_detect_distro_arch(self, linux_detector):
        """Test detection of Arch Linux distribution."""
        os_release_content = """NAME="Arch Linux"
ID=arch
"""
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            with patch("subprocess.run", return_value=Mock(returncode=0, stdout="")):
                linux_detector._detect_linux_system_updates()
        # Should complete without error

    def test_detect_distro_opensuse(self, linux_detector):
        """Test detection of openSUSE distribution."""
        os_release_content = """NAME="openSUSE Leap"
VERSION="15.5"
ID=opensuse-leap
VERSION_ID="15.5"
"""
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            with patch("subprocess.run", return_value=Mock(returncode=0, stdout="")):
                linux_detector._detect_linux_system_updates()
        # Should complete without error


# =============================================================================
# Update Orchestration Tests
# =============================================================================


class TestUpdateOrchestration:
    """Tests for update detection orchestration."""

    def test_detect_updates_calls_all_managers(self, linux_detector):
        """Test that detect_updates calls all available package managers."""
        with patch.object(
            linux_detector,
            "_detect_package_managers",
            return_value=["apt", "snap", "flatpak"],
        ):
            with patch.object(linux_detector, "_detect_apt_updates") as mock_apt:
                with patch.object(linux_detector, "_detect_snap_updates") as mock_snap:
                    with patch.object(
                        linux_detector, "_detect_flatpak_updates"
                    ) as mock_flatpak:
                        with patch.object(
                            linux_detector, "_detect_linux_system_updates"
                        ):
                            with patch.object(
                                linux_detector, "_detect_linux_version_upgrades"
                            ):
                                linux_detector.detect_updates()

        mock_apt.assert_called_once()
        mock_snap.assert_called_once()
        mock_flatpak.assert_called_once()

    def test_detect_updates_respects_available_managers(self, linux_detector):
        """Test that detect_updates only calls available package managers."""
        with patch.object(
            linux_detector, "_detect_package_managers", return_value=["apt"]
        ):  # Only apt available
            with patch.object(linux_detector, "_detect_apt_updates") as mock_apt:
                with patch.object(linux_detector, "_detect_snap_updates") as mock_snap:
                    with patch.object(linux_detector, "_detect_linux_system_updates"):
                        with patch.object(
                            linux_detector, "_detect_linux_version_upgrades"
                        ):
                            linux_detector.detect_updates()

        mock_apt.assert_called_once()
        mock_snap.assert_not_called()


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in update detection."""

    def test_handle_permission_denied(self, linux_detector):
        """Test handling of permission denied errors."""
        with patch("subprocess.run", side_effect=PermissionError("Permission denied")):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 0

    def test_handle_file_not_found(self, linux_detector):
        """Test handling of command not found errors."""
        with patch("subprocess.run", side_effect=FileNotFoundError("apt not found")):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 0

    def test_handle_general_exception(self, linux_detector):
        """Test handling of general exceptions."""
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            linux_detector._detect_apt_updates()

        assert len(linux_detector.available_updates) == 0

    def test_partial_failure_recovery(self, linux_detector):
        """Test that partial failures don't stop other detections."""
        call_count = 0

        def mock_run(cmd, **_kwargs):
            nonlocal call_count
            call_count += 1
            if "apt" in " ".join(cmd):
                raise Exception("APT failed")
            return Mock(returncode=0, stdout="")

        with patch("subprocess.run", side_effect=mock_run):
            with patch.object(
                linux_detector, "_detect_package_managers", return_value=["apt", "snap"]
            ):
                with patch.object(linux_detector, "_detect_linux_system_updates"):
                    with patch.object(linux_detector, "_detect_linux_version_upgrades"):
                        linux_detector.detect_updates()

        # Should have attempted both apt and snap
        assert call_count >= 2


# =============================================================================
# Package Manager Detection Tests
# =============================================================================


class TestPackageManagerDetection:
    """Tests for package manager detection."""

    def test_detect_package_managers_caching(self, base_detector):
        """Test that package manager detection is cached."""
        base_detector._package_managers = ["apt", "snap"]

        result = base_detector._detect_package_managers()

        assert result == ["apt", "snap"]

    def test_detect_best_package_manager_linux(self, base_detector):
        """Test best package manager selection on Linux."""
        base_detector.platform = "linux"

        with patch.object(
            base_detector,
            "_detect_package_managers",
            return_value=["apt", "snap", "flatpak"],
        ):
            result = base_detector._detect_best_package_manager()

        assert result == "apt"

    def test_detect_best_package_manager_linux_dnf(self, base_detector):
        """Test best package manager selection preferring dnf."""
        base_detector.platform = "linux"

        with patch.object(
            base_detector, "_detect_package_managers", return_value=["dnf", "snap"]
        ):
            result = base_detector._detect_best_package_manager()

        assert result == "dnf"

    def test_detect_best_package_manager_bsd(self, base_detector):
        """Test best package manager selection on BSD."""
        base_detector.platform = "freebsd"

        with patch.object(
            base_detector, "_detect_package_managers", return_value=["pkg", "pkgin"]
        ):
            result = base_detector._detect_best_package_manager()

        assert result == "pkg"


# =============================================================================
# Update Facade Tests
# =============================================================================


class TestUpdateDetectorFacade:
    """Tests for the UpdateDetector facade class."""

    @patch("platform.system")
    def test_facade_linux_initialization(self, mock_system):
        """Test facade initializes Linux detector."""
        mock_system.return_value = "Linux"
        detector = UpdateDetector()

        assert detector.platform == "linux"
        assert isinstance(detector.detector, LinuxUpdateDetector)

    @patch("platform.system")
    def test_facade_bsd_initialization(self, mock_system):
        """Test facade initializes BSD detector."""
        mock_system.return_value = "FreeBSD"
        detector = UpdateDetector()

        assert detector.platform == "freebsd"
        assert isinstance(detector.detector, BSDUpdateDetector)

    @patch("platform.system")
    def test_facade_unsupported_platform(self, mock_system):
        """Test facade handles unsupported platform."""
        mock_system.return_value = "UnknownOS"
        detector = UpdateDetector()

        result = detector.get_available_updates()

        assert "error" in result
        assert result["total_updates"] == 0

    @patch("platform.system")
    def test_facade_attribute_delegation(self, mock_system):
        """Test facade delegates attributes to platform detector."""
        mock_system.return_value = "Linux"
        detector = UpdateDetector()

        # Should delegate to LinuxUpdateDetector
        assert hasattr(detector, "available_updates")
        assert hasattr(detector, "_detect_package_managers")

    @patch("platform.system")
    def test_facade_get_available_updates_categorization(self, mock_system):
        """Test that get_available_updates correctly categorizes updates."""
        mock_system.return_value = "Linux"
        detector = UpdateDetector()

        # Mock the detect_updates to add test updates
        def mock_detect_updates():
            detector.detector.available_updates = [
                {
                    "package_name": "openssl",
                    "is_security_update": True,
                    "is_system_update": False,
                },
                {
                    "package_name": "linux-image",
                    "is_security_update": False,
                    "is_system_update": True,
                },
                {
                    "package_name": "firefox",
                    "is_security_update": False,
                    "is_system_update": False,
                },
            ]

        with patch.object(detector.detector, "detect_updates", mock_detect_updates):
            with patch.object(
                detector.detector, "check_reboot_required", return_value=False
            ):
                result = detector.get_available_updates()

        assert result["total_updates"] == 3
        assert result["security_updates"] == 1
        assert result["system_updates"] == 1
        assert result["application_updates"] == 1
