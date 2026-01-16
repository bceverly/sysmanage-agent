"""
Tests for package manager detection utilities.
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.role_detection_package_managers import (
    is_valid_unix_username,
    PackageManagerDetector,
)


class TestIsValidUnixUsername:
    """Tests for is_valid_unix_username function."""

    def test_valid_username_lowercase(self):
        """Test valid lowercase username."""
        assert is_valid_unix_username("john") is True

    def test_valid_username_with_underscore_start(self):
        """Test valid username starting with underscore."""
        assert is_valid_unix_username("_service") is True

    def test_valid_username_with_digits(self):
        """Test valid username with digits."""
        assert is_valid_unix_username("user123") is True

    def test_valid_username_with_hyphen(self):
        """Test valid username with hyphen."""
        assert is_valid_unix_username("test-user") is True

    def test_valid_username_with_underscore(self):
        """Test valid username with underscore."""
        assert is_valid_unix_username("test_user") is True

    def test_invalid_username_empty(self):
        """Test empty username is invalid."""
        assert is_valid_unix_username("") is False

    def test_invalid_username_none(self):
        """Test None username is invalid."""
        assert is_valid_unix_username(None) is False

    def test_invalid_username_starts_with_digit(self):
        """Test username starting with digit is invalid."""
        assert is_valid_unix_username("123user") is False

    def test_invalid_username_uppercase(self):
        """Test uppercase username is invalid."""
        assert is_valid_unix_username("John") is False

    def test_invalid_username_too_long(self):
        """Test username over 32 chars is invalid."""
        assert is_valid_unix_username("a" * 33) is False

    def test_invalid_username_special_chars(self):
        """Test username with special chars is invalid."""
        assert is_valid_unix_username("user@host") is False
        assert is_valid_unix_username("user!name") is False


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def detector(logger):
    """Create a PackageManagerDetector for testing."""
    return PackageManagerDetector("linux", logger)


class TestPackageManagerDetectorInit:
    """Tests for PackageManagerDetector initialization."""

    def test_init_sets_system(self, logger):
        """Test that __init__ sets system."""
        detector = PackageManagerDetector("linux", logger)
        assert detector.system == "linux"

    def test_init_sets_logger(self, logger):
        """Test that __init__ sets logger."""
        detector = PackageManagerDetector("linux", logger)
        assert detector.logger == logger


class TestGetInstalledPackages:
    """Tests for get_installed_packages method."""

    def test_get_packages_linux_dpkg(self, logger):
        """Test getting packages on Linux with dpkg."""
        detector = PackageManagerDetector("linux", logger)

        with patch.object(detector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "dpkg"
            with patch.object(
                detector, "_get_dpkg_packages", return_value={"pkg1": "1.0"}
            ):
                result = detector.get_installed_packages()

        assert "pkg1" in result

    def test_get_packages_linux_rpm(self, logger):
        """Test getting packages on Linux with rpm."""
        detector = PackageManagerDetector("linux", logger)

        with patch.object(detector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "rpm"
            with patch.object(
                detector, "_get_rpm_packages", return_value={"pkg2": "2.0"}
            ):
                result = detector.get_installed_packages()

        assert "pkg2" in result

    def test_get_packages_macos(self, logger):
        """Test getting packages on macOS."""
        detector = PackageManagerDetector("darwin", logger)

        with patch.object(detector, "_command_exists", return_value=True):
            with patch.object(
                detector, "_get_homebrew_packages", return_value={"brew-pkg": "1.0"}
            ):
                result = detector.get_installed_packages()

        assert "brew-pkg" in result

    def test_get_packages_freebsd(self, logger):
        """Test getting packages on FreeBSD."""
        detector = PackageManagerDetector("freebsd", logger)

        with patch.object(detector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "pkg"
            with patch.object(
                detector, "_get_pkg_packages", return_value={"fbsd-pkg": "1.0"}
            ):
                result = detector.get_installed_packages()

        assert "fbsd-pkg" in result

    def test_get_packages_exception(self, logger):
        """Test getting packages with exception."""
        detector = PackageManagerDetector("linux", logger)

        with patch.object(detector, "_command_exists", side_effect=Exception("test")):
            result = detector.get_installed_packages()

        assert not result


class TestGetDpkgPackages:
    """Tests for _get_dpkg_packages method."""

    def test_get_dpkg_packages_success(self, detector):
        """Test successful dpkg package retrieval."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "package1\t1.0.0\npackage2\t2.0.0\n"

        with patch.object(
            detector, "_get_command_path", return_value="/usr/bin/dpkg-query"
        ):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._get_dpkg_packages()

        assert result == {"package1": "1.0.0", "package2": "2.0.0"}

    def test_get_dpkg_packages_no_command(self, detector):
        """Test dpkg packages when command not found."""
        with patch.object(detector, "_get_command_path", return_value=None):
            result = detector._get_dpkg_packages()

        assert result == {}


class TestGetRpmPackages:
    """Tests for _get_rpm_packages method."""

    def test_get_rpm_packages_success(self, detector):
        """Test successful rpm package retrieval."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "rpm-pkg1\t1.0\nrpm-pkg2\t2.0\n"

        with patch.object(detector, "_get_command_path", return_value="/usr/bin/rpm"):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._get_rpm_packages()

        assert result == {"rpm-pkg1": "1.0", "rpm-pkg2": "2.0"}


class TestGetPacmanPackages:
    """Tests for _get_pacman_packages method."""

    def test_get_pacman_packages_success(self, detector):
        """Test successful pacman package retrieval."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "pacman-pkg1 1.0.0\npacman-pkg2 2.0.0\n"

        with patch.object(
            detector, "_get_command_path", return_value="/usr/bin/pacman"
        ):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._get_pacman_packages()

        assert result == {"pacman-pkg1": "1.0.0", "pacman-pkg2": "2.0.0"}


class TestGetSnapPackages:
    """Tests for _get_snap_packages method."""

    def test_get_snap_packages_success(self, detector):
        """Test successful snap package retrieval."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Name       Version  Rev  Tracking  Publisher  Notes
snap-pkg1  1.0      123  stable    canonical  -
snap-pkg2  2.0      456  stable    canonical  -
"""

        with patch.object(detector, "_get_command_path", return_value="/usr/bin/snap"):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._get_snap_packages()

        assert result == {"snap-pkg1": "1.0", "snap-pkg2": "2.0"}


class TestGetHomebrewPackages:
    """Tests for _get_homebrew_packages method."""

    def test_get_homebrew_packages_success(self, logger):
        """Test successful Homebrew package retrieval."""
        detector = PackageManagerDetector("darwin", logger)

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "brew-pkg1 1.0.0\nbrew-pkg2 2.0.0 2.1.0\n"

        with patch.object(
            detector, "_get_command_path", return_value="/opt/homebrew/bin/brew"
        ):
            with patch("os.getuid", return_value=1000):  # Non-root
                with patch("subprocess.run", return_value=mock_result):
                    result = detector._get_homebrew_packages()

        assert result == {"brew-pkg1": "1.0.0", "brew-pkg2": "2.0.0"}


class TestGetPkginPackages:
    """Tests for _get_pkgin_packages method."""

    def test_get_pkgin_packages_success(self, logger):
        """Test successful pkgin package retrieval."""
        detector = PackageManagerDetector("netbsd", logger)

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "pkg1-1.0 Some package\npkg2-2.0 Another package\n"

        with patch.object(
            detector, "_get_command_path", return_value="/usr/pkg/bin/pkgin"
        ):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._get_pkgin_packages()

        assert result == {"pkg1": "1.0", "pkg2": "2.0"}


class TestGetPkgPackages:
    """Tests for _get_pkg_packages method."""

    def test_get_pkg_packages_success(self, logger):
        """Test successful pkg package retrieval."""
        detector = PackageManagerDetector("freebsd", logger)

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "pkg1-1.0 Description\npkg2-2.0 Another\n"

        with patch.object(detector, "_get_command_path", return_value="/usr/sbin/pkg"):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._get_pkg_packages()

        assert result == {"pkg1": "1.0", "pkg2": "2.0"}


class TestFindPackageVersion:
    """Tests for find_package_version method."""

    def test_find_exact_match(self, detector):
        """Test finding package with exact match."""
        packages = {"postgresql": "14.0", "mysql": "8.0"}
        result = detector.find_package_version("postgresql", packages)
        assert result == "14.0"

    def test_find_partial_match(self, detector):
        """Test finding package with partial match."""
        packages = {"postgresql-14": "14.0", "mysql-server": "8.0"}
        result = detector.find_package_version("postgresql", packages)
        assert result == "14.0"

    def test_find_no_match(self, detector):
        """Test finding package with no match."""
        packages = {"mysql": "8.0"}
        result = detector.find_package_version("postgresql", packages)
        assert result is None


class TestCommandHelpers:
    """Tests for command helper methods."""

    def test_command_exists_true(self, detector):
        """Test command exists returns True."""
        with patch("shutil.which", return_value="/usr/bin/test"):
            result = detector._command_exists("test")
        assert result is True

    def test_command_exists_false(self, detector):
        """Test command exists returns False."""
        with patch("shutil.which", return_value=None):
            result = detector._command_exists("nonexistent")
        assert result is False

    def test_get_command_path(self, detector):
        """Test getting command path."""
        with patch("shutil.which", return_value="/usr/bin/test"):
            result = detector._get_command_path("test")
        assert result == "/usr/bin/test"
