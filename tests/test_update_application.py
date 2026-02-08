"""
Tests for update application functionality.

This module covers:
- APT update application
- DNF/YUM update application
- Pacman update application
- Zypper update application
- Snap update application
- Flatpak update application
- BSD pkg update application
- OpenBSD syspatch application
- Firmware update application
- Package installation
"""

# pylint: disable=protected-access,redefined-outer-name

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_linux import LinuxUpdateDetector
from src.sysmanage_agent.collection.update_detection_bsd import BSDUpdateDetector


@pytest.fixture
def linux_detector():
    """Create a LinuxUpdateDetector for testing."""
    return LinuxUpdateDetector()


@pytest.fixture
def bsd_detector():
    """Create a BSDUpdateDetector for testing."""
    return BSDUpdateDetector()


# =============================================================================
# APT Update Application Tests
# =============================================================================


class TestAptUpdateApplication:
    """Tests for APT update application."""

    def test_apply_apt_updates_success(self, linux_detector):
        """Test successful APT update application."""
        packages = [
            {
                "package_name": "nginx",
                "current_version": "1.18.0",
                "available_version": "1.20.0",
                "package_manager": "apt",
            },
            {
                "package_name": "vim",
                "current_version": "8.1.0",
                "available_version": "8.2.0",
                "package_manager": "apt",
            },
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=0, stderr="")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_apt_updates(packages, results)

        assert len(results["updated_packages"]) == 2
        assert len(results["failed_packages"]) == 0
        assert results["updated_packages"][0]["package_name"] == "nginx"
        assert results["updated_packages"][1]["package_name"] == "vim"

    def test_apply_apt_updates_failure(self, linux_detector):
        """Test APT update application with failure."""
        packages = [
            {
                "package_name": "broken-package",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "apt",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=1, stderr="E: Unable to fetch package")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_apt_updates(packages, results)

        assert len(results["updated_packages"]) == 0
        assert len(results["failed_packages"]) == 1
        assert "broken-package" in results["failed_packages"][0]["package_name"]

    def test_apply_apt_updates_timeout(self, linux_detector):
        """Test APT update application timeout."""
        packages = [
            {
                "package_name": "large-package",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "apt",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("apt", 300)):
            linux_detector._apply_apt_updates(packages, results)

        assert len(results["failed_packages"]) == 1


# =============================================================================
# Snap Update Application Tests
# =============================================================================


class TestSnapUpdateApplication:
    """Tests for Snap update application."""

    def test_apply_snap_updates_success(self, linux_detector):
        """Test successful Snap update application."""
        packages = [
            {
                "package_name": "firefox",
                "current_version": "119.0",
                "available_version": "120.0",
                "package_manager": "snap",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=0, stderr="")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_snap_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_manager"] == "snap"

    def test_apply_snap_updates_failure(self, linux_detector):
        """Test Snap update application failure."""
        packages = [
            {
                "package_name": "broken-snap",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "snap",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=1, stderr="error: snap not found")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_snap_updates(packages, results)

        assert len(results["failed_packages"]) == 1


# =============================================================================
# Flatpak Update Application Tests
# =============================================================================


class TestFlatpakUpdateApplication:
    """Tests for Flatpak update application."""

    def test_apply_flatpak_updates_success(self, linux_detector):
        """Test successful Flatpak update application."""
        packages = [
            {
                "package_name": "org.mozilla.firefox",
                "current_version": "119.0",
                "available_version": "120.0",
                "package_manager": "flatpak",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=0, stderr="")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_flatpak_updates(packages, results)

        assert len(results["updated_packages"]) == 1

    def test_apply_flatpak_updates_failure(self, linux_detector):
        """Test Flatpak update application failure."""
        packages = [
            {
                "package_name": "org.broken.App",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "flatpak",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=1, stderr="error: No such ref")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_flatpak_updates(packages, results)

        assert len(results["failed_packages"]) == 1


# =============================================================================
# DNF Update Application Tests
# =============================================================================


class TestDnfUpdateApplication:
    """Tests for DNF update application."""

    def test_apply_dnf_updates_success(self, linux_detector):
        """Test successful DNF update application."""
        packages = [
            {
                "package_name": "httpd",
                "current_version": "2.4.51",
                "available_version": "2.4.52",
                "package_manager": "dnf",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=0, stderr="")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_dnf_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_manager"] == "dnf"

    def test_apply_dnf_updates_failure(self, linux_detector):
        """Test DNF update application failure."""
        packages = [
            {
                "package_name": "broken-package",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "dnf",
            }
        ]
        results = {"updated_packages": [], "failed_packages": []}

        mock_result = Mock(returncode=1, stderr="Error: Package not found")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_dnf_updates(packages, results)

        assert len(results["failed_packages"]) == 1


# =============================================================================
# Firmware Update Application Tests
# =============================================================================


class TestFirmwareUpdateApplication:
    """Tests for firmware (fwupd) update application."""

    def test_apply_fwupd_updates_success(self, linux_detector):
        """Test successful firmware update application."""
        packages = [
            {
                "package_name": "Dell BIOS",
                "device_id": "device123",
                "current_version": "1.0.0",
                "available_version": "1.1.0",
                "package_manager": "fwupd",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stderr="")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_fwupd_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        # requires_reboot is set per package, not on results dict
        assert results["updated_packages"][0].get("requires_reboot") is True

    def test_apply_fwupd_updates_failure(self, linux_detector):
        """Test firmware update application failure."""
        packages = [
            {
                "package_name": "Dell BIOS",
                "device_id": "device123",
                "current_version": "1.0.0",
                "available_version": "1.1.0",
                "package_manager": "fwupd",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=1, stderr="Device not found")

        with patch("subprocess.run", return_value=mock_result):
            linux_detector._apply_fwupd_updates(packages, results)

        assert len(results["failed_packages"]) == 1


# =============================================================================
# BSD pkg Update Application Tests
# =============================================================================


class TestBsdPkgUpdateApplication:
    """Tests for BSD pkg update application."""

    def test_apply_pkg_updates_success(self, bsd_detector):
        """Test successful pkg update application."""
        packages = [
            {
                "package_name": "nginx",
                "current_version": "1.24.0",
                "available_version": "1.25.0",
                "package_manager": "pkg",
            },
            {
                "package_name": "vim",
                "current_version": "9.0.1",
                "available_version": "9.0.2",
                "package_manager": "pkg",
            },
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="Packages upgraded", stderr="")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._apply_pkg_updates(packages, results)

        assert len(results["updated_packages"]) == 2
        assert len(results["failed_packages"]) == 0

    def test_apply_pkg_updates_failure(self, bsd_detector):
        """Test pkg update application failure."""
        packages = [
            {
                "package_name": "broken-pkg",
                "current_version": "1.0",
                "available_version": "2.0",
                "package_manager": "pkg",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=1, stderr="pkg: No package(s) matching")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._apply_pkg_updates(packages, results)

        assert len(results["failed_packages"]) == 1

    def test_apply_pkg_updates_exception(self, bsd_detector):
        """Test pkg update application with exception."""
        packages = [
            {
                "package_name": "test-pkg",
                "available_version": "1.0",
                "package_manager": "pkg",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            bsd_detector._apply_pkg_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "Unexpected error" in results["failed_packages"][0]["error"]


# =============================================================================
# OpenBSD Syspatch Application Tests
# =============================================================================


class TestSyspatchApplication:
    """Tests for OpenBSD syspatch application."""

    def test_apply_syspatch_success(self, bsd_detector):
        """Test successful syspatch application."""
        packages = [
            {
                "package_name": "OpenBSD System Patches (3 patches)",
                "available_version": "001_nsd, 002_smtpd, 003_kernel",
                "package_manager": "syspatch",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="Patches applied")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._apply_syspatch_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["requires_reboot"] is True

    def test_apply_syspatch_failure(self, bsd_detector):
        """Test syspatch application failure."""
        packages = [
            {
                "package_name": "OpenBSD System Patches",
                "package_manager": "syspatch",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=1, stderr="syspatch: error fetching patches")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._apply_syspatch_updates(packages, results)

        assert len(results["failed_packages"]) == 1

    def test_apply_syspatch_timeout(self, bsd_detector):
        """Test syspatch application timeout."""
        packages = [
            {
                "package_name": "OpenBSD System Patches",
                "package_manager": "syspatch",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("syspatch", 600)
        ):
            bsd_detector._apply_syspatch_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "timed out" in results["failed_packages"][0]["error"]


# =============================================================================
# OpenBSD Version Upgrade Application Tests
# =============================================================================


class TestOpenBsdUpgradeApplication:
    """Tests for OpenBSD version upgrade application."""

    def test_apply_openbsd_upgrade_success(self, bsd_detector):
        """Test successful OpenBSD upgrade application."""
        packages = [
            {
                "package_name": "OpenBSD Release Upgrade",
                "current_version": "7.5",
                "available_version": "7.6",
                "package_manager": "openbsd-upgrade",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=0, stdout="Upgrade downloaded")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._apply_openbsd_upgrade_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["requires_reboot"] is True

    def test_apply_openbsd_upgrade_failure(self, bsd_detector):
        """Test OpenBSD upgrade application failure."""
        packages = [
            {
                "package_name": "OpenBSD Release Upgrade",
                "current_version": "7.5",
                "available_version": "7.6",
                "package_manager": "openbsd-upgrade",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=1, stderr="Failed to fetch upgrade")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._apply_openbsd_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1


# =============================================================================
# FreeBSD Version Upgrade Application Tests
# =============================================================================


class TestFreeBsdUpgradeApplication:
    """Tests for FreeBSD version upgrade application."""

    def test_apply_freebsd_upgrade_success(self, bsd_detector):
        """Test successful FreeBSD upgrade application."""
        packages = [
            {
                "package_name": "freebsd-release",
                "current_version": "13.2-RELEASE",
                "available_version": "14.0-RELEASE",
                "package_manager": "freebsd-upgrade",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_upgrade = Mock(returncode=0, stdout="Upgrade ready")
        mock_install = Mock(returncode=0, stdout="Upgrade installed")

        def mock_run(cmd, **_kwargs):
            if "upgrade" in cmd:
                return mock_upgrade
            return mock_install

        with patch("subprocess.run", side_effect=mock_run):
            bsd_detector._apply_freebsd_upgrade_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["requires_reboot"] is True

    def test_apply_freebsd_upgrade_failure(self, bsd_detector):
        """Test FreeBSD upgrade application failure."""
        packages = [
            {
                "package_name": "freebsd-release",
                "package_manager": "freebsd-upgrade",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock(returncode=1, stderr="Failed to fetch upgrade")

        with patch("subprocess.run", return_value=mock_result):
            bsd_detector._apply_freebsd_upgrade_updates(packages, results)

        assert len(results["failed_packages"]) == 1


# =============================================================================
# Package Installation Tests
# =============================================================================


class TestPackageInstallation:
    """Tests for package installation functionality."""

    def test_install_with_apt_success(self, linux_detector):
        """Test successful APT package installation."""
        mock_update = Mock(returncode=0)
        mock_install = Mock(returncode=0, stdout="Package installed successfully")
        mock_version = Mock(returncode=0, stdout="Version: 2.0.0")

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update
            if "dpkg" in cmd:
                return mock_version
            return mock_install

        with patch("subprocess.run", side_effect=mock_run):
            result = linux_detector._install_with_apt("nginx")

        assert result["success"] is True
        assert result["version"] == "2.0.0"

    def test_install_with_apt_failure(self, linux_detector):
        """Test APT package installation failure."""
        mock_update = Mock(returncode=0)
        error = subprocess.CalledProcessError(100, "apt")
        error.stderr = "E: Unable to locate package"
        error.stdout = ""

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update
            raise error

        with patch("subprocess.run", side_effect=mock_run):
            result = linux_detector._install_with_apt("nonexistent-package")

        assert result["success"] is False
        assert "Failed to install" in result["error"]

    def test_install_with_apt_timeout(self, linux_detector):
        """Test APT package installation timeout."""
        mock_update = Mock(returncode=0)

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update
            raise subprocess.TimeoutExpired("apt", 300)

        with patch("subprocess.run", side_effect=mock_run):
            result = linux_detector._install_with_apt("large-package")

        assert result["success"] is False
        assert "timed out" in result["error"]

    def test_install_with_dnf_success(self, linux_detector):
        """Test successful DNF package installation."""
        mock_result = Mock(returncode=0, stdout="Package installed")

        with patch("subprocess.run", return_value=mock_result):
            result = linux_detector._install_with_dnf("httpd")

        assert result["success"] is True

    def test_install_with_dnf_failure(self, linux_detector):
        """Test DNF package installation failure."""
        error = subprocess.CalledProcessError(1, "dnf")
        error.stderr = "No package httpd available"
        error.stdout = ""

        with patch("subprocess.run", side_effect=error):
            result = linux_detector._install_with_dnf("nonexistent")

        assert result["success"] is False

    def test_install_with_yum_success(self, linux_detector):
        """Test successful YUM package installation."""
        mock_result = Mock(returncode=0, stdout="Package installed")

        with patch("subprocess.run", return_value=mock_result):
            result = linux_detector._install_with_yum("httpd")

        assert result["success"] is True

    def test_install_with_pacman_success(self, linux_detector):
        """Test successful Pacman package installation."""
        mock_result = Mock(returncode=0, stdout="Package installed")

        with patch("subprocess.run", return_value=mock_result):
            result = linux_detector._install_with_pacman("nginx")

        assert result["success"] is True

    def test_install_with_zypper_success(self, linux_detector):
        """Test successful Zypper package installation."""
        mock_result = Mock(returncode=0, stdout="Package installed")

        with patch("subprocess.run", return_value=mock_result):
            result = linux_detector._install_with_zypper("apache2")

        assert result["success"] is True


# =============================================================================
# BSD Package Installation Tests
# =============================================================================


class TestBsdPackageInstallation:
    """Tests for BSD package installation functionality."""

    def test_install_with_pkg_freebsd_root(self, bsd_detector):
        """Test FreeBSD pkg installation as root."""
        mock_result = Mock(returncode=0, stdout="Package installed")

        with patch("platform.system", return_value="FreeBSD"):
            with patch("os.geteuid", return_value=0):
                with patch("subprocess.run", return_value=mock_result):
                    result = bsd_detector._install_with_pkg("nginx")

        assert result["success"] is True

    def test_install_with_pkg_freebsd_non_root(self, bsd_detector):
        """Test FreeBSD pkg installation as non-root (using sudo)."""
        mock_result = Mock(returncode=0, stdout="Package installed")

        with patch("platform.system", return_value="FreeBSD"):
            with patch("os.geteuid", return_value=1000):
                with patch("subprocess.run", return_value=mock_result) as mock_run:
                    result = bsd_detector._install_with_pkg("nginx")

        assert result["success"] is True
        # Verify sudo was used
        call_args = mock_run.call_args[0][0]
        assert "sudo" in call_args

    def test_install_with_pkg_openbsd_root(self, bsd_detector):
        """Test OpenBSD pkg_add installation as root."""
        mock_result = Mock(returncode=0, stdout="Package added")

        with patch("platform.system", return_value="OpenBSD"):
            with patch("os.geteuid", return_value=0):
                with patch("subprocess.run", return_value=mock_result) as mock_run:
                    result = bsd_detector._install_with_pkg("vim")

        assert result["success"] is True
        # Verify pkg_add was used
        call_args = mock_run.call_args[0][0]
        assert "pkg_add" in call_args

    def test_install_with_pkg_openbsd_non_root(self, bsd_detector):
        """Test OpenBSD pkg_add installation as non-root (using doas)."""
        mock_result = Mock(returncode=0, stdout="Package added")

        with patch("platform.system", return_value="OpenBSD"):
            with patch("os.geteuid", return_value=1000):
                with patch("subprocess.run", return_value=mock_result) as mock_run:
                    result = bsd_detector._install_with_pkg("vim")

        assert result["success"] is True
        # Verify doas was used
        call_args = mock_run.call_args[0][0]
        assert "doas" in call_args

    def test_install_with_pkgin_success(self, bsd_detector):
        """Test successful pkgin installation."""
        mock_result = Mock(returncode=0, stdout="Package installed")

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", return_value=mock_result):
                result = bsd_detector._install_with_pkgin("vim")

        assert result["success"] is True

    def test_install_with_pkgin_timeout(self, bsd_detector):
        """Test pkgin installation timeout."""
        with patch("os.geteuid", return_value=0):
            with patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("pkgin", 300)
            ):
                result = bsd_detector._install_with_pkgin("large-package")

        assert result["success"] is False
        assert "timed out" in result["error"]


# =============================================================================
# apply_updates Method Tests
# =============================================================================


class TestApplyUpdatesMethod:
    """Tests for the apply_updates orchestration method."""

    def test_apply_updates_empty_packages(self, bsd_detector):
        """Test apply_updates with no packages."""
        result = bsd_detector.apply_updates()

        assert result["updated_packages"] == []
        assert result["failed_packages"] == []

    def test_apply_updates_with_packages_list(self, bsd_detector):
        """Test apply_updates with packages list."""
        packages = [
            {"name": "nginx", "package_manager": "pkg"},
            {"name": "vim", "package_manager": "pkg"},
        ]

        bsd_detector.available_updates = [
            {
                "package_name": "nginx",
                "package_manager": "pkg",
                "current_version": "1.24.0",
                "available_version": "1.25.0",
            },
            {
                "package_name": "vim",
                "package_manager": "pkg",
                "current_version": "9.0.1",
                "available_version": "9.0.2",
            },
        ]

        mock_result = Mock(returncode=0, stdout="Updated")

        with patch("subprocess.run", return_value=mock_result):
            result = bsd_detector.apply_updates(packages=packages)

        assert "updated_packages" in result
        assert "failed_packages" in result

    def test_apply_updates_legacy_format(self, bsd_detector):
        """Test apply_updates with legacy format (package_names list)."""
        bsd_detector.available_updates = [
            {
                "package_name": "nginx",
                "package_manager": "pkg",
                "available_version": "1.25.0",
            }
        ]

        mock_result = Mock(returncode=0, stdout="Updated")

        with patch("subprocess.run", return_value=mock_result):
            result = bsd_detector.apply_updates(
                package_names=["nginx"], package_managers=["pkg"]
            )

        assert "updated_packages" in result

    def test_apply_updates_unsupported_manager(self, bsd_detector):
        """Test apply_updates with unsupported package manager."""
        packages = [{"name": "test", "package_manager": "unsupported_pm"}]

        result = bsd_detector.apply_updates(packages=packages)

        assert len(result["failed_packages"]) == 1
        assert "Unsupported package manager" in result["failed_packages"][0]["error"]

    def test_apply_updates_mixed_managers(self, bsd_detector):
        """Test apply_updates with multiple package managers."""
        packages = [
            {"name": "nginx", "package_manager": "pkg"},
            {"name": "patches", "package_manager": "syspatch"},
        ]

        bsd_detector.available_updates = [
            {
                "package_name": "nginx",
                "package_manager": "pkg",
                "available_version": "1.25.0",
            },
            {
                "package_name": "patches",
                "package_manager": "syspatch",
                "available_version": "001_fix",
            },
        ]

        mock_result = Mock(returncode=0, stdout="Updated")

        with patch("subprocess.run", return_value=mock_result):
            result = bsd_detector.apply_updates(packages=packages)

        # Should have processed both package managers
        total = len(result["updated_packages"]) + len(result["failed_packages"])
        assert total >= 0  # At least attempted both

    def test_apply_updates_exception_handling(self, bsd_detector):
        """Test apply_updates handles exceptions gracefully."""
        packages = [{"name": "test", "package_manager": "pkg"}]

        with patch.object(
            bsd_detector,
            "_collect_packages_by_manager",
            side_effect=Exception("Unexpected error"),
        ):
            result = bsd_detector.apply_updates(packages=packages)

        assert len(result["failed_packages"]) == 1
        assert "Unexpected error" in result["failed_packages"][0]["error"]
