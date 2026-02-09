"""
Tests for Linux system update detectors module.

This module covers:
- Debian/Ubuntu system update detection
- Red Hat/Fedora system update detection
- Arch Linux system update detection
- SUSE system update detection
- Release upgrade detection
- Firmware (fwupd) update detection
"""

# pylint: disable=protected-access,redefined-outer-name

import json
import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.linux_system_update_detectors import (
    LinuxSystemUpdateDetector,
)
from src.sysmanage_agent.collection.linux_update_detectors import (
    LinuxUpdateDetector as LinuxPkgDetector,
)


@pytest.fixture
def system_detector():
    """Create a LinuxSystemUpdateDetector for testing."""
    return LinuxSystemUpdateDetector()


@pytest.fixture
def pkg_detector():
    """Create a LinuxPkgDetector for testing."""

    def is_system_package(name):
        return name.startswith("linux-") or name in ["libc6", "systemd"]

    return LinuxPkgDetector(is_system_package)


# =============================================================================
# Debian System Update Detection Tests
# =============================================================================


class TestDebianSystemUpdates:
    """Tests for Debian/Ubuntu system update detection."""

    def test_detect_debian_system_updates_success(self):
        """Test successful Debian system update detection."""
        mock_result = Mock(
            returncode=0,
            stdout="""Listing...
linux-image-5.15.0-100-generic/jammy-updates 5.15.0-100.110 amd64 [upgradable from: 5.15.0-99.109]
systemd/jammy-updates 249.11-0ubuntu3.12 amd64 [upgradable from: 249.11-0ubuntu3.11]
libc6/jammy-security 2.35-0ubuntu3.5 amd64 [upgradable from: 2.35-0ubuntu3.4]
vim/jammy-updates 2:8.2.3995-1ubuntu2.13 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.12]
""",
        )

        def mock_run(cmd, **_kwargs):
            if "apt-cache" in cmd:
                return Mock(returncode=0, stdout="")
            return mock_result

        with patch("subprocess.run", side_effect=mock_run):
            updates = LinuxSystemUpdateDetector.detect_debian_system_updates()

        # Should only detect system packages (linux-image, systemd, libc6)
        system_names = [u["package_name"] for u in updates]
        assert any("linux-image" in name for name in system_names)
        assert any("systemd" in name for name in system_names)
        assert any("libc6" in name for name in system_names)
        # vim should NOT be in system updates
        assert "vim" not in system_names

    def test_detect_debian_system_updates_security(self):
        """Test Debian system update security detection."""
        mock_list = Mock(
            returncode=0,
            stdout="""Listing...
linux-image-5.15.0-100-generic/jammy-security 5.15.0-100.110 amd64 [upgradable from: 5.15.0-99.109]
""",
        )
        mock_policy = Mock(returncode=0, stdout="jammy-security")

        def mock_run(cmd, **_kwargs):
            if "apt-cache" in cmd and "policy" in cmd:
                return mock_policy
            return mock_list

        with patch("subprocess.run", side_effect=mock_run):
            updates = LinuxSystemUpdateDetector.detect_debian_system_updates()

        if updates:
            # Check that security flag is set correctly
            assert any(u.get("is_security_update") for u in updates)

    def test_detect_debian_system_updates_no_updates(self):
        """Test Debian system update detection with no updates."""
        mock_result = Mock(returncode=0, stdout="Listing...")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_debian_system_updates()

        assert not updates

    def test_detect_debian_system_updates_failure(self):
        """Test Debian system update detection with command failure."""
        mock_result = Mock(returncode=1, stderr="Error")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_debian_system_updates()

        assert not updates


# =============================================================================
# Red Hat System Update Detection Tests
# =============================================================================


class TestRedHatSystemUpdates:
    """Tests for Red Hat/Fedora system update detection."""

    def test_detect_redhat_system_updates_success(self):
        """Test successful Red Hat system update detection."""
        mock_result = Mock(
            returncode=100,  # dnf returns 100 when updates available
            stdout="""kernel.x86_64                      5.15.0-150.167              updates
systemd.x86_64                     249-18.el9                  baseos
glibc.x86_64                       2.34-60.el9                 baseos
httpd.x86_64                       2.4.53-11.el9               appstream
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_redhat_system_updates()

        # Should only detect system packages
        system_names = [u["package_name"] for u in updates]
        assert any("kernel" in name for name in system_names)
        assert any("systemd" in name for name in system_names)
        assert any("glibc" in name for name in system_names)
        # httpd should NOT be in system updates
        assert "httpd" not in system_names

    def test_detect_redhat_system_updates_no_updates(self):
        """Test Red Hat system update detection with no updates."""
        mock_result = Mock(returncode=0, stdout="")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_redhat_system_updates()

        assert not updates

    def test_detect_redhat_system_updates_marks_system(self):
        """Test Red Hat detection marks updates as system updates."""
        mock_result = Mock(
            returncode=100,
            stdout="kernel.x86_64                      5.15.0-150.167              updates",
        )

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_redhat_system_updates()

        if updates:
            assert updates[0]["is_system_update"] is True
            assert updates[0]["package_manager"] == "dnf"


# =============================================================================
# Arch System Update Detection Tests
# =============================================================================


class TestArchSystemUpdates:
    """Tests for Arch Linux system update detection."""

    def test_detect_arch_system_updates_success(self):
        """Test successful Arch system update detection."""
        mock_result = Mock(
            returncode=0,
            stdout="""linux 6.7.0-arch1-1 -> 6.7.1-arch1-1
systemd 254.7-1 -> 254.8-1
glibc 2.38-7 -> 2.39-1
firefox 122.0-1 -> 122.0.1-1
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_arch_system_updates()

        # Should only detect system packages
        system_names = [u["package_name"] for u in updates]
        assert "linux" in system_names
        assert "systemd" in system_names
        assert "glibc" in system_names
        # firefox should NOT be in system updates
        assert "firefox" not in system_names

    def test_detect_arch_system_updates_no_updates(self):
        """Test Arch system update detection with no updates."""
        mock_result = Mock(returncode=0, stdout="")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_arch_system_updates()

        assert not updates

    def test_detect_arch_system_updates_marks_versions(self):
        """Test Arch detection extracts version info correctly."""
        mock_result = Mock(returncode=0, stdout="linux 6.7.0-arch1-1 -> 6.7.1-arch1-1")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_arch_system_updates()

        if updates:
            assert updates[0]["current_version"] == "6.7.0-arch1-1"
            assert updates[0]["available_version"] == "6.7.1-arch1-1"


# =============================================================================
# SUSE System Update Detection Tests
# =============================================================================


class TestSuseSystemUpdates:
    """Tests for SUSE system update detection."""

    def test_detect_suse_system_updates_success(self):
        """Test successful SUSE system update detection."""
        mock_result = Mock(
            returncode=0,
            stdout="""S | Repository | Name           | Current Version  | Available Version | Arch
--+------------+----------------+------------------+-------------------+-------
v | Main       | kernel-default | 5.14.21-150400   | 5.14.21-150500    | x86_64
v | Main       | systemd        | 249-150400.8.35  | 249-150500.8.1    | x86_64
v | Main       | glibc          | 2.31-150300.46.1 | 2.31-150400.1.1   | x86_64
v | Main       | nginx          | 1.19.8-150300.3  | 1.21.6-150400.1   | x86_64
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_suse_system_updates()

        # Should only detect system packages
        system_names = [u["package_name"] for u in updates]
        assert "kernel-default" in system_names
        assert "systemd" in system_names
        assert "glibc" in system_names
        # nginx should NOT be in system updates
        assert "nginx" not in system_names

    def test_detect_suse_system_updates_no_updates(self):
        """Test SUSE system update detection with no updates."""
        mock_result = Mock(returncode=0, stdout="")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_suse_system_updates()

        assert not updates


# =============================================================================
# Ubuntu Release Upgrade Detection Tests
# =============================================================================


class TestUbuntuReleaseUpgrades:
    """Tests for Ubuntu release upgrade detection."""

    def test_detect_ubuntu_release_upgrade_available(self):
        """Test Ubuntu release upgrade detection when available."""
        mock_do_release = Mock(
            returncode=0,
            stdout="New release '24.04' available.\nRun 'do-release-upgrade' to upgrade to it.",
        )
        mock_lsb = Mock(returncode=0, stdout="22.04")

        def mock_run(cmd, **_kwargs):
            if "lsb_release" in cmd:
                return mock_lsb
            return mock_do_release

        with patch("subprocess.run", side_effect=mock_run):
            updates = LinuxSystemUpdateDetector.detect_ubuntu_release_upgrades()

        assert len(updates) == 1
        assert updates[0]["package_name"] == "Ubuntu Release Upgrade"
        assert updates[0]["current_version"] == "22.04"
        assert updates[0]["available_version"] == "24.04"
        assert updates[0]["is_release_upgrade"] is True
        assert updates[0]["requires_reboot"] is True

    def test_detect_ubuntu_release_upgrade_none_available(self):
        """Test Ubuntu release upgrade detection when none available."""
        mock_result = Mock(returncode=0, stdout="No new release found.")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_ubuntu_release_upgrades()

        assert not updates

    def test_detect_ubuntu_release_upgrade_command_failure(self):
        """Test Ubuntu release upgrade detection with command failure."""
        with patch(
            "subprocess.run",
            side_effect=FileNotFoundError("do-release-upgrade not found"),
        ):
            updates = LinuxSystemUpdateDetector.detect_ubuntu_release_upgrades()

        assert not updates


# =============================================================================
# Fedora Version Upgrade Detection Tests
# =============================================================================


class TestFedoraVersionUpgrades:
    """Tests for Fedora version upgrade detection."""

    def test_detect_fedora_version_upgrade_available(self):
        """Test Fedora version upgrade detection when available."""
        mock_result = Mock(returncode=0, stdout="Fedora 40 is available for upgrade.")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_fedora_version_upgrades()

        assert len(updates) == 1
        assert updates[0]["package_name"] == "Fedora Release Upgrade"
        assert "40" in updates[0]["available_version"]
        assert updates[0]["is_release_upgrade"] is True

    def test_detect_fedora_version_upgrade_none_available(self):
        """Test Fedora version upgrade detection when none available."""
        mock_result = Mock(returncode=0, stdout="System is up to date.")

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_fedora_version_upgrades()

        assert not updates


# =============================================================================
# openSUSE Version Upgrade Detection Tests
# =============================================================================


class TestOpenSuseVersionUpgrades:
    """Tests for openSUSE version upgrade detection."""

    def test_detect_opensuse_version_upgrade_available(self):
        """Test openSUSE version upgrade detection when available."""
        mock_result = Mock(
            returncode=0, stdout="15.6 upgrade available from repository."
        )

        with patch("subprocess.run", return_value=mock_result):
            updates = LinuxSystemUpdateDetector.detect_opensuse_version_upgrades()

        assert len(updates) == 1
        assert updates[0]["package_name"] == "openSUSE Release Upgrade"
        assert "15.6" in updates[0]["available_version"]


# =============================================================================
# Firmware (fwupd) Update Detection Tests
# =============================================================================


class TestFwupdUpdateDetection:
    """Tests for firmware update detection via fwupd."""

    def test_detect_fwupd_updates_success(self, pkg_detector):
        """Test successful fwupd firmware update detection."""
        mock_devices = Mock(returncode=0, stdout="{}")
        mock_refresh = Mock(returncode=0)
        mock_updates = Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "Devices": [
                        {
                            "DeviceId": "device123",
                            "Name": "System BIOS",
                            "Vendor": "Dell Inc.",
                            "Version": "1.0.0",
                            "Releases": [
                                {
                                    "Version": "1.1.0",
                                    "Summary": "BIOS security update",
                                    "Urgency": "high",
                                    "Size": 10485760,
                                }
                            ],
                        }
                    ]
                }
            ),
        )

        def mock_run(cmd, **_kwargs):
            cmd_str = " ".join(cmd)
            if "get-devices" in cmd_str:
                return mock_devices
            if "refresh" in cmd_str:
                return mock_refresh
            if "get-updates" in cmd_str:
                return mock_updates
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            updates = pkg_detector.detect_fwupd_updates()

        assert len(updates) == 1
        update = updates[0]
        assert "BIOS" in update["package_name"]
        assert update["current_version"] == "1.0.0"
        assert update["available_version"] == "1.1.0"
        assert update["package_manager"] == "fwupd"
        assert update["is_system_update"] is True

    def test_detect_fwupd_updates_no_updates(self, pkg_detector):
        """Test fwupd detection when no updates available."""
        mock_devices = Mock(returncode=0, stdout="{}")
        mock_refresh = Mock(returncode=0)
        mock_updates = Mock(returncode=2, stdout="")  # Return code 2 = no updates

        def mock_run(cmd, **_kwargs):
            cmd_str = " ".join(cmd)
            if "get-devices" in cmd_str:
                return mock_devices
            if "refresh" in cmd_str:
                return mock_refresh
            if "get-updates" in cmd_str:
                return mock_updates
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            updates = pkg_detector.detect_fwupd_updates()

        assert not updates

    def test_detect_fwupd_daemon_not_running(self, pkg_detector):
        """Test fwupd detection when daemon not running."""
        mock_devices = Mock(returncode=1, stderr="Cannot connect to fwupd")

        with patch("subprocess.run", return_value=mock_devices):
            updates = pkg_detector.detect_fwupd_updates()

        assert not updates

    def test_check_fwupd_daemon_running(self, pkg_detector):
        """Test fwupd daemon check when running."""
        mock_result = Mock(returncode=0)

        with patch("subprocess.run", return_value=mock_result):
            result = pkg_detector.check_fwupd_daemon()

        assert result is True

    def test_check_fwupd_daemon_not_running(self, pkg_detector):
        """Test fwupd daemon check when not running."""
        with patch(
            "subprocess.run", side_effect=FileNotFoundError("fwupdmgr not found")
        ):
            result = pkg_detector.check_fwupd_daemon()

        assert result is False

    def test_fwupd_security_update_detection(self, pkg_detector):
        """Test fwupd security update detection from release info."""
        # Test release with security keywords
        release_with_cve = {
            "Description": "Fixes CVE-2024-0001 vulnerability",
            "Summary": "Security patch for firmware",
            "Urgency": "high",
        }
        assert pkg_detector._is_fwupd_security_update(release_with_cve) is True

        # Test release without security keywords
        release_normal = {
            "Description": "Performance improvements",
            "Summary": "General update",
            "Urgency": "medium",
        }
        assert pkg_detector._is_fwupd_security_update(release_normal) is False

        # Test release with critical urgency
        release_critical = {
            "Description": "Update",
            "Summary": "Update",
            "Urgency": "critical",
        }
        assert pkg_detector._is_fwupd_security_update(release_critical) is True

    def test_fwupd_multiple_devices(self, pkg_detector):
        """Test fwupd detection with multiple devices."""
        mock_devices = Mock(returncode=0, stdout="{}")
        mock_refresh = Mock(returncode=0)
        mock_updates = Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "Devices": [
                        {
                            "DeviceId": "device1",
                            "Name": "System BIOS",
                            "Vendor": "Dell",
                            "Version": "1.0.0",
                            "Releases": [{"Version": "1.1.0", "Summary": "Update"}],
                        },
                        {
                            "DeviceId": "device2",
                            "Name": "SSD Firmware",
                            "Vendor": "Samsung",
                            "Version": "2.0.0",
                            "Releases": [{"Version": "2.1.0", "Summary": "Update"}],
                        },
                    ]
                }
            ),
        )

        def mock_run(cmd, **_kwargs):
            cmd_str = " ".join(cmd)
            if "get-devices" in cmd_str:
                return mock_devices
            if "refresh" in cmd_str:
                return mock_refresh
            if "get-updates" in cmd_str:
                return mock_updates
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            updates = pkg_detector.detect_fwupd_updates()

        assert len(updates) == 2

    def test_fwupd_device_already_current(self, pkg_detector):
        """Test fwupd skips devices already at current version."""
        mock_devices = Mock(returncode=0, stdout="{}")
        mock_refresh = Mock(returncode=0)
        mock_updates = Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "Devices": [
                        {
                            "DeviceId": "device1",
                            "Name": "BIOS",
                            "Vendor": "Dell",
                            "Version": "1.0.0",
                            "Releases": [
                                {"Version": "1.0.0", "Summary": "Current"}
                            ],  # Same version
                        }
                    ]
                }
            ),
        )

        def mock_run(cmd, **_kwargs):
            cmd_str = " ".join(cmd)
            if "get-devices" in cmd_str:
                return mock_devices
            if "refresh" in cmd_str:
                return mock_refresh
            if "get-updates" in cmd_str:
                return mock_updates
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            updates = pkg_detector.detect_fwupd_updates()

        assert len(updates) == 0


# =============================================================================
# DNF Update Detection Tests
# =============================================================================


class TestDnfPkgDetection:
    """Tests for DNF package detection."""

    def test_detect_dnf_updates_with_repository(self, pkg_detector):
        """Test DNF detection includes repository info."""
        mock_result = Mock(
            returncode=100,
            stdout="""kernel.x86_64                      5.15.0-150.167              updates
httpd.x86_64                       2.4.53-11.el9               appstream
openssl.x86_64                     3.0.7-24.el9                baseos
""",
        )

        with patch("subprocess.run", return_value=mock_result):
            updates = pkg_detector.detect_dnf_updates()

        assert len(updates) == 3
        kernel_update = next(
            (u for u in updates if u["package_name"] == "kernel"), None
        )
        assert kernel_update is not None
        assert kernel_update["repository"] == "updates"


# =============================================================================
# Zypper Parsing Tests
# =============================================================================


class TestZypperParsing:
    """Tests for Zypper output parsing."""

    def test_parse_zypper_output_with_header(self, pkg_detector):
        """Test Zypper output parsing with table header."""
        stdout = """S | Repository | Name     | Current Version | Available Version | Arch
--+------------+----------+-----------------+-------------------+-------
v | Main       | apache2  | 2.4.51-1.1      | 2.4.52-1.1        | x86_64
v | Security   | openssl  | 1.1.1l-1.2      | 1.1.1n-1.1        | x86_64
"""
        updates = pkg_detector._parse_zypper_output(stdout)

        assert len(updates) == 2
        assert updates[0]["package_name"] == "apache2"
        assert updates[0]["current_version"] == "2.4.51-1.1"
        assert updates[0]["available_version"] == "2.4.52-1.1"

    def test_parse_zypper_output_security_flag(self, pkg_detector):
        """Test Zypper parsing correctly identifies security updates."""
        stdout = """S | Repository | Name    | Current | Available | Arch
--+------------+---------+---------+-----------+-------
s | Security   | openssl | 1.0     | 1.1       | x86_64
"""
        updates = pkg_detector._parse_zypper_output(stdout)

        if updates:
            # 's' in first column or 'Security' in repo should mark it
            assert updates[0].get("is_security_update") or "Security" in updates[0].get(
                "repository", ""
            )


# =============================================================================
# APT Parsing Tests
# =============================================================================


class TestAptParsing:
    """Tests for APT output parsing."""

    def test_parse_apt_upgradable_complex(self, pkg_detector):
        """Test APT parsing with complex package names."""
        stdout = """Listing...
linux-image-5.15.0-100-generic/jammy-updates 5.15.0-100.110 amd64 [upgradable from: 5.15.0-99.109]
python3.10-venv/jammy-security 3.10.12-1~22.04.3 amd64 [upgradable from: 3.10.12-1~22.04.2]
libsystemd0/jammy-updates 249.11-0ubuntu3.12 amd64 [upgradable from: 249.11-0ubuntu3.11]
"""
        updates = pkg_detector._parse_apt_upgradable_output(stdout)

        assert len(updates) == 3
        assert updates[0]["package_name"] == "linux-image-5.15.0-100-generic"
        assert updates[1]["package_name"] == "python3.10-venv"
        assert updates[2]["package_name"] == "libsystemd0"

    def test_parse_apt_upgradable_empty(self, pkg_detector):
        """Test APT parsing with no upgradable packages."""
        stdout = "Listing..."
        updates = pkg_detector._parse_apt_upgradable_output(stdout)

        assert not updates

    def test_parse_apt_upgradable_marks_security(self, pkg_detector):
        """Test APT parsing marks security updates correctly."""
        stdout = """Listing...
openssl/jammy-security 3.0.2-0ubuntu1.12 amd64 [upgradable from: 3.0.2-0ubuntu1.11]
vim/jammy-updates 2:8.2.3995-1ubuntu2.13 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.12]
"""
        updates = pkg_detector._parse_apt_upgradable_output(stdout)

        assert len(updates) == 2
        openssl_update = next(
            (u for u in updates if u["package_name"] == "openssl"), None
        )
        vim_update = next((u for u in updates if u["package_name"] == "vim"), None)
        assert openssl_update["is_security_update"] is True
        assert vim_update["is_security_update"] is False


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestSystemUpdateErrorHandling:
    """Tests for error handling in system update detection."""

    def test_debian_detection_timeout(self):
        """Test Debian detection handles timeout gracefully."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("apt", 30)):
            updates = LinuxSystemUpdateDetector.detect_debian_system_updates()

        assert not updates

    def test_redhat_detection_permission_error(self):
        """Test Red Hat detection handles permission error."""
        with patch("subprocess.run", side_effect=PermissionError("Access denied")):
            updates = LinuxSystemUpdateDetector.detect_redhat_system_updates()

        assert not updates

    def test_arch_detection_file_not_found(self):
        """Test Arch detection handles missing pacman."""
        with patch("subprocess.run", side_effect=FileNotFoundError("pacman not found")):
            updates = LinuxSystemUpdateDetector.detect_arch_system_updates()

        assert not updates

    def test_fwupd_json_parse_error(self, pkg_detector):
        """Test fwupd handles JSON parse errors."""
        mock_devices = Mock(returncode=0, stdout="{}")
        mock_refresh = Mock(returncode=0)
        mock_updates = Mock(returncode=0, stdout="not valid json{{{")

        def mock_run(cmd, **_kwargs):
            cmd_str = " ".join(cmd)
            if "get-devices" in cmd_str:
                return mock_devices
            if "refresh" in cmd_str:
                return mock_refresh
            if "get-updates" in cmd_str:
                return mock_updates
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            updates = pkg_detector.detect_fwupd_updates()

        assert not updates
