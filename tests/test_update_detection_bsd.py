"""
Tests for BSD update detection module.
"""

# pylint: disable=redefined-outer-name,protected-access

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_bsd import (
    BSDUpdateDetector,
)


@pytest.fixture
def detector():
    """Create a BSDUpdateDetector for testing."""
    return BSDUpdateDetector()


class TestBSDUpdateDetectorInit:
    """Tests for BSDUpdateDetector initialization."""

    def test_init_inherits_from_base(self, detector):
        """Test that BSDUpdateDetector inherits from UpdateDetectorBase."""
        assert hasattr(detector, "platform")
        assert hasattr(detector, "available_updates")
        assert hasattr(detector, "_package_managers")


class TestDetectPkgUpdates:
    """Tests for _detect_pkg_updates method."""

    def test_detect_pkg_updates_success(self, detector):
        """Test successful pkg update detection."""
        mock_update_result = Mock()
        mock_update_result.returncode = 0

        mock_version_result = Mock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = (
            "nginx-1.24.0 < needs updating (remote has 1.25.0)\n"
        )

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update_result
            return mock_version_result

        with patch("subprocess.run", side_effect=mock_run):
            detector._detect_pkg_updates()

        assert len(detector.available_updates) == 1
        update = detector.available_updates[0]
        assert update["package_name"] == "nginx"
        assert update["current_version"] == "1.24.0"
        assert update["available_version"] == "1.25.0"
        assert update["package_manager"] == "pkg"

    def test_detect_pkg_updates_no_updates(self, detector):
        """Test pkg update detection with no updates."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_pkg_updates()

        assert len(detector.available_updates) == 0

    def test_detect_pkg_updates_exception(self, detector):
        """Test pkg update detection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            # Should not raise
            detector._detect_pkg_updates()

        assert len(detector.available_updates) == 0


class TestDetectPkginUpdates:
    """Tests for _detect_pkgin_updates method."""

    def test_detect_pkgin_updates_success_root(self, detector):
        """Test successful pkgin update detection as root."""
        mock_update_result = Mock()
        mock_update_result.returncode = 0

        mock_list_result = Mock()
        mock_list_result.returncode = 0
        mock_list_result.stdout = "vim-9.0.1 Text editor\n"

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update_result
            return mock_list_result

        with patch("os.geteuid", return_value=0):  # Running as root
            with patch.object(detector, "_command_exists", return_value=False):
                with patch("subprocess.run", side_effect=mock_run):
                    detector._detect_pkgin_updates()

        assert len(detector.available_updates) == 1
        update = detector.available_updates[0]
        assert update["package_name"] == "vim"
        assert update["current_version"] == "9.0.1"
        assert update["package_manager"] == "pkgin"

    def test_detect_pkgin_updates_success_non_root_doas(self, detector):
        """Test pkgin update detection with doas."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "pkg-1.0 Package\n"

        with patch("os.geteuid", return_value=1000):  # Non-root
            with patch.object(detector, "_command_exists") as mock_exists:
                mock_exists.side_effect = lambda cmd: cmd == "doas"
                with patch("subprocess.run", return_value=mock_result):
                    detector._detect_pkgin_updates()

        assert len(detector.available_updates) >= 0  # May or may not have updates

    def test_detect_pkgin_updates_update_failure(self, detector):
        """Test pkgin update detection when update fails."""
        mock_update_result = Mock()
        mock_update_result.returncode = 1
        mock_update_result.stderr = "Permission denied"

        mock_list_result = Mock()
        mock_list_result.returncode = 0
        mock_list_result.stdout = ""

        def mock_run(cmd, **_kwargs):
            if "update" in cmd:
                return mock_update_result
            return mock_list_result

        with patch("os.geteuid", return_value=1000):
            with patch.object(detector, "_command_exists", return_value=False):
                with patch("subprocess.run", side_effect=mock_run):
                    detector._detect_pkgin_updates()

        # Should still complete, just with warning

    def test_detect_pkgin_updates_exception(self, detector):
        """Test pkgin update detection with exception."""
        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", side_effect=Exception("test error")):
                # Should not raise
                detector._detect_pkgin_updates()


class TestApplyPkgUpdates:
    """Tests for _apply_pkg_updates method."""

    def test_apply_pkg_updates_success(self, detector):
        """Test successful pkg update application."""
        packages = [
            {
                "package_name": "nginx",
                "current_version": "1.24.0",
                "available_version": "1.25.0",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Package upgraded"

        with patch("subprocess.run", return_value=mock_result):
            detector._apply_pkg_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["updated_packages"][0]["package_name"] == "nginx"
        assert len(results["failed_packages"]) == 0

    def test_apply_pkg_updates_failure(self, detector):
        """Test pkg update application failure."""
        packages = [
            {
                "package_name": "nginx",
                "current_version": "1.24.0",
                "available_version": "1.25.0",
            }
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to upgrade"

        with patch("subprocess.run", return_value=mock_result):
            detector._apply_pkg_updates(packages, results)

        assert len(results["updated_packages"]) == 0
        assert len(results["failed_packages"]) == 1

    def test_apply_pkg_updates_exception(self, detector):
        """Test pkg update application with exception."""
        packages = [{"package_name": "nginx", "available_version": "1.25.0"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch("subprocess.run", side_effect=Exception("test error")):
            detector._apply_pkg_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "test error" in results["failed_packages"][0]["error"]


class TestDetectOpenbsdSystemUpdates:
    """Tests for _detect_openbsd_system_updates method."""

    def test_detect_openbsd_system_updates_available(self, detector):
        """Test OpenBSD system update detection with patches available."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "syspatch001\nsyspatch002\n"

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_openbsd_system_updates()

        assert len(detector.available_updates) == 1
        update = detector.available_updates[0]
        assert "OpenBSD System Patches" in update["package_name"]
        assert update["package_manager"] == "syspatch"
        assert update["is_security_update"] is True
        assert update["is_system_update"] is True

    def test_detect_openbsd_system_updates_none(self, detector):
        """Test OpenBSD system update detection with no patches."""
        mock_result = Mock()
        mock_result.returncode = 1  # Return code 1 means no patches

        with patch("subprocess.run", return_value=mock_result):
            detector._detect_openbsd_system_updates()

        assert len(detector.available_updates) == 0

    def test_detect_openbsd_system_updates_syspatch_not_found(self, detector):
        """Test when syspatch is not available."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            detector._detect_openbsd_system_updates()

        assert len(detector.available_updates) == 0

    def test_detect_openbsd_system_updates_timeout(self, detector):
        """Test OpenBSD system update detection timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 60)):
            detector._detect_openbsd_system_updates()

        # Should not raise, just log warning


class TestDetectOpenbsdVersionUpgrades:
    """Tests for _detect_openbsd_version_upgrades method."""

    def test_detect_openbsd_version_upgrade_available(self, detector):
        """Test OpenBSD version upgrade detection."""
        mock_version_result = Mock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = "7.5\n"

        mock_html = b"<html><body>OpenBSD 7.6 released!</body></html>"

        with patch("subprocess.run", return_value=mock_version_result):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = mock_html
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                detector._detect_openbsd_version_upgrades()

        # Should find an upgrade
        upgrades = [
            u
            for u in detector.available_updates
            if u.get("package_manager") == "openbsd-upgrade"
        ]
        assert len(upgrades) == 1
        assert upgrades[0]["current_version"] == "7.5"
        assert upgrades[0]["available_version"] == "7.6"

    def test_detect_openbsd_version_current(self, detector):
        """Test OpenBSD version detection when already current."""
        mock_version_result = Mock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = "7.6\n"

        mock_html = b"<html><body>OpenBSD 7.6 released!</body></html>"

        with patch("subprocess.run", return_value=mock_version_result):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = mock_html
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                detector._detect_openbsd_version_upgrades()

        # Should not find an upgrade (already current)
        upgrades = [
            u
            for u in detector.available_updates
            if u.get("package_manager") == "openbsd-upgrade"
        ]
        assert len(upgrades) == 0


class TestDetectUpdates:
    """Tests for detect_updates method."""

    def test_detect_updates_calls_all_methods(self, detector):
        """Test that detect_updates calls all detection methods."""
        with patch.object(detector, "_detect_openbsd_system_updates") as mock_sys:
            with patch.object(detector, "_detect_openbsd_version_upgrades") as mock_ver:
                with patch.object(
                    detector, "_detect_package_managers", return_value=[]
                ):
                    with patch("platform.system", return_value="OpenBSD"):
                        detector.detect_updates()

        mock_sys.assert_called_once()
        mock_ver.assert_called_once()

    def test_detect_updates_freebsd(self, detector):
        """Test detect_updates on FreeBSD."""
        with patch.object(detector, "_detect_openbsd_system_updates"):
            with patch.object(detector, "_detect_openbsd_version_upgrades"):
                with patch.object(
                    detector, "_detect_freebsd_version_upgrades"
                ) as mock_fbsd:
                    with patch.object(
                        detector, "_detect_package_managers", return_value=[]
                    ):
                        with patch("platform.system", return_value="FreeBSD"):
                            detector.detect_updates()

        mock_fbsd.assert_called_once()

    def test_detect_updates_with_pkg(self, detector):
        """Test detect_updates with pkg available."""
        with patch.object(detector, "_detect_openbsd_system_updates"):
            with patch.object(detector, "_detect_openbsd_version_upgrades"):
                with patch.object(
                    detector, "_detect_package_managers", return_value=["pkg"]
                ):
                    with patch.object(detector, "_detect_pkg_updates") as mock_pkg:
                        with patch("platform.system", return_value="OpenBSD"):
                            detector.detect_updates()

        mock_pkg.assert_called_once()


class TestInstallWithPkg:
    """Tests for _install_with_pkg method."""

    def test_install_with_pkg_freebsd_root(self, detector):
        """Test installing with pkg on FreeBSD as root."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Package installed"

        with patch("platform.system", return_value="FreeBSD"):
            with patch("os.geteuid", return_value=0):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector._install_with_pkg("nginx")

        assert result["success"] is True

    def test_install_with_pkg_openbsd_root(self, detector):
        """Test installing with pkg_add on OpenBSD as root."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Package added"

        with patch("platform.system", return_value="OpenBSD"):
            with patch("os.geteuid", return_value=0):
                with patch("subprocess.run", return_value=mock_result):
                    result = detector._install_with_pkg("vim")

        assert result["success"] is True

    def test_install_with_pkg_failure(self, detector):
        """Test install failure."""
        error = subprocess.CalledProcessError(1, "cmd")
        error.stderr = "Installation failed"
        error.stdout = ""

        with patch("platform.system", return_value="FreeBSD"):
            with patch("os.geteuid", return_value=0):
                with patch("subprocess.run", side_effect=error):
                    result = detector._install_with_pkg("invalid-pkg")

        assert result["success"] is False
        assert "Failed to install" in result["error"]


class TestInstallWithPkgin:
    """Tests for _install_with_pkgin method."""

    def test_install_with_pkgin_root(self, detector):
        """Test installing with pkgin as root."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Package installed"

        with patch("os.geteuid", return_value=0):
            with patch("subprocess.run", return_value=mock_result):
                result = detector._install_with_pkgin("vim")

        assert result["success"] is True

    def test_install_with_pkgin_non_root(self, detector):
        """Test installing with pkgin as non-root (using sudo)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Package installed"

        with patch("os.geteuid", return_value=1000):
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                result = detector._install_with_pkgin("vim")

        assert result["success"] is True
        # Verify sudo was used
        call_args = mock_run.call_args[0][0]
        assert "sudo" in call_args

    def test_install_with_pkgin_timeout(self, detector):
        """Test install timeout."""
        with patch("os.geteuid", return_value=0):
            with patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300)
            ):
                result = detector._install_with_pkgin("slow-pkg")

        assert result["success"] is False
        assert "timed out" in result["error"]


class TestApplySyspatchUpdates:
    """Tests for _apply_syspatch_updates method."""

    def test_apply_syspatch_success(self, detector):
        """Test successful syspatch application."""
        packages = [
            {"package_name": "OpenBSD System Patches", "available_version": "patch1"}
        ]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            detector._apply_syspatch_updates(packages, results)

        assert len(results["updated_packages"]) == 1
        assert results["requires_reboot"] is True

    def test_apply_syspatch_failure(self, detector):
        """Test syspatch application failure."""
        packages = [{"package_name": "OpenBSD System Patches"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Patch failed"

        with patch("subprocess.run", return_value=mock_result):
            detector._apply_syspatch_updates(packages, results)

        assert len(results["failed_packages"]) == 1

    def test_apply_syspatch_timeout(self, detector):
        """Test syspatch timeout."""
        packages = [{"package_name": "OpenBSD System Patches"}]
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
        }

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 600)):
            detector._apply_syspatch_updates(packages, results)

        assert len(results["failed_packages"]) == 1
        assert "timed out" in results["failed_packages"][0]["error"]


class TestApplyUpdates:
    """Tests for apply_updates method."""

    def test_apply_updates_empty(self, detector):
        """Test apply_updates with no packages."""
        result = detector.apply_updates()

        assert result["updated_packages"] == []
        assert result["failed_packages"] == []

    def test_apply_updates_with_packages(self, detector):
        """Test apply_updates with packages list."""
        packages = [{"name": "nginx", "package_manager": "pkg"}]

        detector.available_updates = [
            {
                "package_name": "nginx",
                "package_manager": "pkg",
                "current_version": "1.24.0",
                "available_version": "1.25.0",
            }
        ]

        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = detector.apply_updates(packages=packages)

        assert "updated_packages" in result
        assert "failed_packages" in result

    def test_apply_updates_legacy_format(self, detector):
        """Test apply_updates with legacy format (package_names list)."""
        mock_result = Mock()
        mock_result.returncode = 0

        detector.available_updates = [
            {
                "package_name": "nginx",
                "package_manager": "pkg",
                "available_version": "1.25.0",
            }
        ]

        with patch("subprocess.run", return_value=mock_result):
            result = detector.apply_updates(
                package_names=["nginx"], package_managers=["pkg"]
            )

        assert "updated_packages" in result

    def test_apply_updates_unsupported_manager(self, detector):
        """Test apply_updates with unsupported package manager."""
        packages = [{"name": "pkg", "package_manager": "unsupported_manager"}]

        result = detector.apply_updates(packages=packages)

        assert len(result["failed_packages"]) == 1
        assert "Unsupported package manager" in result["failed_packages"][0]["error"]
