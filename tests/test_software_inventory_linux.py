#!/usr/bin/env python3
"""
Comprehensive tests for Linux software inventory collection module.

Tests all Linux package managers: apt/dpkg, snap, flatpak, dnf, yum, pacman, zypper, apk.
Covers installed package listing, version parsing, error handling, and edge cases.
"""

# pylint: disable=redefined-outer-name,protected-access

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.software_inventory_linux import (
    LinuxSoftwareInventoryCollector,
)


@pytest.fixture
def collector():
    """Create a LinuxSoftwareInventoryCollector for testing."""
    return LinuxSoftwareInventoryCollector()


class TestLinuxSoftwareInventoryCollectorInit:
    """Tests for LinuxSoftwareInventoryCollector initialization."""

    def test_init_sets_empty_collected_packages(self, collector):
        """Test that __init__ sets empty collected_packages list."""
        assert collector.collected_packages == []

    def test_init_sets_package_managers_to_none(self, collector):
        """Test that __init__ sets _package_managers to None."""
        assert collector._package_managers is None


class TestDetectPackageManagers:
    """Tests for detect_package_managers method."""

    def test_detect_apt_available(self, collector):
        """Test detection when apt is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd in ["apt", "apt-get", "dpkg"]
            result = collector.detect_package_managers()

        assert "apt" in result

    def test_detect_snap_available(self, collector):
        """Test detection when snap is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "snap"
            result = collector.detect_package_managers()

        assert "snap" in result

    def test_detect_flatpak_available(self, collector):
        """Test detection when flatpak is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "flatpak"
            result = collector.detect_package_managers()

        assert "flatpak" in result

    def test_detect_dnf_available(self, collector):
        """Test detection when dnf is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "dnf"
            result = collector.detect_package_managers()

        assert "dnf" in result

    def test_detect_yum_available(self, collector):
        """Test detection when yum is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "yum"
            result = collector.detect_package_managers()

        assert "yum" in result

    def test_detect_pacman_available(self, collector):
        """Test detection when pacman is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "pacman"
            result = collector.detect_package_managers()

        assert "pacman" in result

    def test_detect_zypper_available(self, collector):
        """Test detection when zypper is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "zypper"
            result = collector.detect_package_managers()

        assert "zypper" in result

    def test_detect_apk_available(self, collector):
        """Test detection when apk is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "apk"
            result = collector.detect_package_managers()

        assert "apk" in result

    def test_detect_portage_available(self, collector):
        """Test detection when emerge (portage) is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "emerge"
            result = collector.detect_package_managers()

        assert "portage" in result

    def test_detect_multiple_managers(self, collector):
        """Test detection when multiple managers available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd in [
                "apt",
                "snap",
                "flatpak",
                "dnf",
            ]
            result = collector.detect_package_managers()

        assert "apt" in result
        assert "snap" in result
        assert "flatpak" in result
        assert "dnf" in result

    def test_detect_no_managers(self, collector):
        """Test detection when no managers available."""
        with patch.object(collector, "_command_exists", return_value=False):
            result = collector.detect_package_managers()

        assert result == []

    def test_detect_managers_cached(self, collector):
        """Test that package managers are cached after first detection."""
        collector._package_managers = ["apt", "snap"]
        result = collector.detect_package_managers()

        assert result == ["apt", "snap"]


class TestCollectPackages:
    """Tests for collect_packages method."""

    def test_collect_packages_with_apt(self, collector):
        """Test collecting packages when apt is available."""
        with patch.object(collector, "detect_package_managers", return_value=["apt"]):
            with patch.object(collector, "_collect_apt_packages") as mock_collect:
                collector.collect_packages()

        mock_collect.assert_called_once()

    def test_collect_packages_with_multiple_managers(self, collector):
        """Test collecting packages when multiple managers are available."""
        with patch.object(
            collector, "detect_package_managers", return_value=["apt", "snap", "dnf"]
        ):
            with patch.object(collector, "_collect_apt_packages") as mock_apt:
                with patch.object(collector, "_collect_snap_packages") as mock_snap:
                    with patch.object(collector, "_collect_dnf_packages") as mock_dnf:
                        collector.collect_packages()

        mock_apt.assert_called_once()
        mock_snap.assert_called_once()
        mock_dnf.assert_called_once()


class TestCollectAptPackages:
    """Tests for _collect_apt_packages method."""

    def test_collect_apt_packages_success(self, collector):
        """Test successful apt package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "firefox\t91.0\tamd64\tMozilla Firefox\t200000\n"
            "vim\t8.2.2434\tamd64\tVi IMproved\t3000\n"
            "curl\t7.74.0\tamd64\tCommand line tool\t500\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_apt_packages()

        assert len(collector.collected_packages) == 3
        firefox = collector.collected_packages[0]
        assert firefox["package_name"] == "firefox"
        assert firefox["version"] == "91.0"
        assert firefox["architecture"] == "amd64"
        assert firefox["package_manager"] == "apt"
        assert firefox["source"] == "debian_repository"
        # Size is in KB, converted to bytes
        assert firefox["size_bytes"] == 200000 * 1024

    def test_collect_apt_packages_empty_output(self, collector):
        """Test apt package collection with empty output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_apt_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_apt_packages_failure(self, collector):
        """Test apt package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_apt_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_apt_packages_exception(self, collector):
        """Test apt package collection with exception."""
        with patch("subprocess.run", side_effect=Exception("dpkg error")):
            # Should not raise, just log error
            collector._collect_apt_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_apt_packages_timeout(self, collector):
        """Test apt package collection with timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            collector._collect_apt_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_apt_packages_without_size(self, collector):
        """Test apt package collection without size field."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "firefox\t91.0\tamd64\tMozilla Firefox\n"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_apt_packages()

        assert len(collector.collected_packages) == 1
        assert "size_bytes" not in collector.collected_packages[0]

    def test_collect_apt_packages_partial_line(self, collector):
        """Test apt package collection with incomplete lines."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "firefox\t91.0\tamd64\tMozilla Firefox\t200000\n"
            "incomplete\t1.0\n"  # Missing fields
            "vim\t8.2\tamd64\tVi\t3000\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_apt_packages()

        # Only valid lines should be parsed
        assert len(collector.collected_packages) == 2


class TestParseAptPackageLine:
    """Tests for _parse_apt_package_line method."""

    def test_parse_complete_line(self, collector):
        """Test parsing a complete apt package line."""
        parts = ["nginx", "1.18.0", "amd64", "High performance web server", "2048"]
        result = collector._parse_apt_package_line(parts)

        assert result is not None
        assert result["package_name"] == "nginx"
        assert result["version"] == "1.18.0"
        assert result["architecture"] == "amd64"
        assert result["description"] == "High performance web server"
        assert result["size_bytes"] == 2048 * 1024

    def test_parse_line_without_size(self, collector):
        """Test parsing apt package line without size."""
        parts = ["nginx", "1.18.0", "amd64", "High performance web server"]
        result = collector._parse_apt_package_line(parts)

        assert result is not None
        assert "size_bytes" not in result

    def test_parse_line_too_short(self, collector):
        """Test parsing apt package line that's too short."""
        parts = ["nginx", "1.18.0", "amd64"]
        result = collector._parse_apt_package_line(parts)

        assert result is None

    def test_parse_line_with_non_numeric_size(self, collector):
        """Test parsing apt package line with non-numeric size."""
        parts = ["nginx", "1.18.0", "amd64", "Web server", "unknown"]
        result = collector._parse_apt_package_line(parts)

        assert result is not None
        assert "size_bytes" not in result


class TestCollectSnapPackages:
    """Tests for _collect_snap_packages method."""

    def test_collect_snap_packages_success(self, collector):
        """Test successful snap package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Name      Version    Rev   Tracking       Publisher   Notes\n"
            "code      1.52.1     54    latest/stable  vscode*     classic\n"
            "firefox   91.0       100   latest/stable  mozilla     -\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_snap_packages()

        assert len(collector.collected_packages) == 2
        code = collector.collected_packages[0]
        assert code["package_name"] == "code"
        assert code["version"] == "1.52.1"
        assert code["package_manager"] == "snap"
        assert "snap_store" in code["source"]

    def test_collect_snap_packages_empty(self, collector):
        """Test snap package collection with no packages."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Name      Version    Rev   Tracking       Publisher   Notes\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_snap_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_snap_packages_failure(self, collector):
        """Test snap package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_snap_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_snap_packages_exception(self, collector):
        """Test snap package collection with exception."""
        with patch("subprocess.run", side_effect=Exception("snap error")):
            collector._collect_snap_packages()

        assert len(collector.collected_packages) == 0


class TestParseSnapPackageLine:
    """Tests for _parse_snap_package_line method."""

    def test_parse_complete_line(self, collector):
        """Test parsing complete snap package line."""
        parts = ["code", "1.52.1", "54", "latest/stable", "vscode*", "classic"]
        result = collector._parse_snap_package_line(parts)

        assert result is not None
        assert result["package_name"] == "code"
        assert result["version"] == "1.52.1"
        assert result["source"] == "snap_store/latest/stable"

    def test_parse_line_without_channel(self, collector):
        """Test parsing snap package line without channel info."""
        parts = ["code", "1.52.1", "54"]
        result = collector._parse_snap_package_line(parts)

        assert result is not None
        assert result["source"] == "snap_store"

    def test_parse_line_too_short(self, collector):
        """Test parsing snap package line that's too short."""
        parts = ["code", "1.52.1"]
        result = collector._parse_snap_package_line(parts)

        assert result is None


class TestCollectFlatpakPackages:
    """Tests for _collect_flatpak_packages method."""

    def test_collect_flatpak_packages_success(self, collector):
        """Test successful flatpak package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Name\tApplication ID\tVersion\tInstalled size\tOrigin\n"
            "VSCode\tcom.visualstudio.code\t1.52.1\t200 MB\tflathub\n"
            "Firefox\torg.mozilla.firefox\t91.0\t150 MB\tflathub\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_flatpak_packages()

        assert len(collector.collected_packages) == 2
        vscode = collector.collected_packages[0]
        assert vscode["package_name"] == "VSCode"
        assert vscode["bundle_id"] == "com.visualstudio.code"
        assert vscode["version"] == "1.52.1"
        assert vscode["package_manager"] == "flatpak"
        assert vscode["source"] == "flathub"
        assert vscode["size_bytes"] == 200 * 1024 * 1024

    def test_collect_flatpak_packages_empty(self, collector):
        """Test flatpak package collection with no packages."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Name\tApplication ID\tVersion\tInstalled size\tOrigin\n"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_flatpak_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_flatpak_packages_failure(self, collector):
        """Test flatpak package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_flatpak_packages()

        assert len(collector.collected_packages) == 0


class TestParseFlatpakPackageLine:
    """Tests for _parse_flatpak_package_line method."""

    def test_parse_complete_line(self, collector):
        """Test parsing complete flatpak package line."""
        parts = ["VSCode", "com.visualstudio.code", "1.52.1", "200 MB", "flathub"]
        result = collector._parse_flatpak_package_line(parts)

        assert result is not None
        assert result["package_name"] == "VSCode"
        assert result["bundle_id"] == "com.visualstudio.code"
        assert result["version"] == "1.52.1"
        assert result["source"] == "flathub"

    def test_parse_line_without_name(self, collector):
        """Test parsing flatpak line with empty name (uses app ID)."""
        parts = ["", "com.visualstudio.code", "1.52.1", "200 MB", "flathub"]
        result = collector._parse_flatpak_package_line(parts)

        assert result is not None
        assert result["package_name"] == "com.visualstudio.code"

    def test_parse_line_too_short(self, collector):
        """Test parsing flatpak package line that's too short."""
        parts = ["VSCode"]
        result = collector._parse_flatpak_package_line(parts)

        assert result is None


class TestCollectDnfPackages:
    """Tests for _collect_dnf_packages method."""

    def test_collect_dnf_packages_success(self, collector):
        """Test successful DNF package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Installed Packages\n"
            "firefox.x86_64              91.0-1.fc34              @updates\n"
            "vim-enhanced.x86_64         8.2.3568-1.fc34          @fedora\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_dnf_packages()

        assert len(collector.collected_packages) == 2
        firefox = collector.collected_packages[0]
        assert firefox["package_name"] == "firefox"
        assert firefox["version"] == "91.0-1.fc34"
        assert firefox["package_manager"] == "dnf"
        assert firefox["source"] == "@updates"

    def test_collect_dnf_packages_no_installed_section(self, collector):
        """Test DNF package collection without 'Installed Packages' section."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Some other output\nNo packages here"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_dnf_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_dnf_packages_failure(self, collector):
        """Test DNF package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_dnf_packages()

        assert len(collector.collected_packages) == 0


class TestParseDnfPackageLine:
    """Tests for _parse_dnf_package_line method."""

    def test_parse_complete_line(self, collector):
        """Test parsing complete DNF package line."""
        parts = ["firefox.x86_64", "91.0-1.fc34", "@updates"]
        result = collector._parse_dnf_package_line(parts)

        assert result is not None
        assert result["package_name"] == "firefox"
        assert result["version"] == "91.0-1.fc34"
        assert result["source"] == "@updates"

    def test_parse_line_too_short(self, collector):
        """Test parsing DNF package line that's too short."""
        parts = ["firefox.x86_64", "91.0"]
        result = collector._parse_dnf_package_line(parts)

        assert result is None


class TestCollectPacmanPackages:
    """Tests for _collect_pacman_packages method."""

    def test_collect_pacman_packages_success(self, collector):
        """Test successful pacman package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "firefox 91.0-1\nvim 8.2.3568-1\ncurl 7.79.1-1\n"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_pacman_packages()

        assert len(collector.collected_packages) == 3
        firefox = collector.collected_packages[0]
        assert firefox["package_name"] == "firefox"
        assert firefox["version"] == "91.0-1"
        assert firefox["package_manager"] == "pacman"
        assert firefox["source"] == "arch_repository"

    def test_collect_pacman_packages_empty(self, collector):
        """Test pacman package collection with no packages."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_pacman_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_pacman_packages_failure(self, collector):
        """Test pacman package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_pacman_packages()

        assert len(collector.collected_packages) == 0


class TestParsePacmanPackageLine:
    """Tests for _parse_pacman_package_line method."""

    def test_parse_complete_line(self, collector):
        """Test parsing complete pacman package line."""
        parts = ["firefox", "91.0-1"]
        result = collector._parse_pacman_package_line(parts)

        assert result is not None
        assert result["package_name"] == "firefox"
        assert result["version"] == "91.0-1"

    def test_parse_line_too_short(self, collector):
        """Test parsing pacman package line that's too short."""
        parts = ["firefox"]
        result = collector._parse_pacman_package_line(parts)

        assert result is None


class TestCollectZypperPackages:
    """Tests for _collect_zypper_packages method."""

    def test_collect_zypper_packages_success(self, collector):
        """Test successful zypper package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "firefox\t91.0-1.1\tx86_64\tMozilla Firefox Web Browser\t209715200\n"
            "vim\t8.2.3568\tx86_64\tVi IMproved\t30000000\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_zypper_packages()

        assert len(collector.collected_packages) == 2
        firefox = collector.collected_packages[0]
        assert firefox["package_name"] == "firefox"
        assert firefox["version"] == "91.0-1.1"
        assert firefox["architecture"] == "x86_64"
        assert firefox["package_manager"] == "zypper"
        assert firefox["source"] == "opensuse_repository"
        assert firefox["size_bytes"] == 209715200

    def test_collect_zypper_packages_empty(self, collector):
        """Test zypper package collection with no packages."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_zypper_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_zypper_packages_failure(self, collector):
        """Test zypper package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_zypper_packages()

        assert len(collector.collected_packages) == 0


class TestParseZypperPackageLine:
    """Tests for _parse_zypper_package_line method."""

    def test_parse_complete_line(self, collector):
        """Test parsing complete zypper package line."""
        parts = ["firefox", "91.0-1.1", "x86_64", "Mozilla Firefox", "209715200"]
        result = collector._parse_zypper_package_line(parts)

        assert result is not None
        assert result["package_name"] == "firefox"
        assert result["version"] == "91.0-1.1"
        assert result["architecture"] == "x86_64"
        assert result["size_bytes"] == 209715200

    def test_parse_line_without_size(self, collector):
        """Test parsing zypper line without size."""
        parts = ["firefox", "91.0-1.1", "x86_64", "Mozilla Firefox"]
        result = collector._parse_zypper_package_line(parts)

        assert result is not None
        assert "size_bytes" not in result

    def test_parse_line_too_short(self, collector):
        """Test parsing zypper package line that's too short."""
        parts = ["firefox", "91.0", "x86_64"]
        result = collector._parse_zypper_package_line(parts)

        assert result is None


class TestCollectApkPackages:
    """Tests for _collect_apk_packages method."""

    def test_collect_apk_packages_success(self, collector):
        """Test successful APK package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "busybox-1.36.1-r0\npy3-pip-23.1.2-r0\ncurl-8.2.1-r0\n"

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_apk_packages()

        assert len(collector.collected_packages) == 3
        busybox = collector.collected_packages[0]
        assert busybox["package_name"] == "busybox"
        assert busybox["version"] == "1.36.1-r0"
        assert busybox["package_manager"] == "apk"
        assert busybox["source"] == "alpine_repository"

    def test_collect_apk_packages_empty(self, collector):
        """Test APK package collection with no packages."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_apk_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_apk_packages_failure(self, collector):
        """Test APK package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_apk_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_apk_packages_exception(self, collector):
        """Test APK package collection with exception."""
        with patch("subprocess.run", side_effect=Exception("apk error")):
            collector._collect_apk_packages()

        assert len(collector.collected_packages) == 0


class TestParseApkNameVersion:
    """Tests for _parse_apk_name_version method."""

    def test_parse_simple_package(self, collector):
        """Test parsing simple APK package."""
        name, version = collector._parse_apk_name_version("busybox-1.36.1-r0")
        assert name == "busybox"
        assert version == "1.36.1-r0"

    def test_parse_package_with_hyphen_prefix(self, collector):
        """Test parsing APK package with hyphen in name."""
        name, version = collector._parse_apk_name_version("py3-pip-23.1.2-r0")
        assert name == "py3-pip"
        assert version == "23.1.2-r0"

    def test_parse_package_no_revision(self, collector):
        """Test parsing APK package without revision."""
        name, version = collector._parse_apk_name_version("curl-8.2.1")
        assert name == "curl"
        assert version == "8.2.1"

    def test_parse_unparseable_package(self, collector):
        """Test parsing unparseable APK package."""
        name, version = collector._parse_apk_name_version("invalid")
        assert name == "invalid"
        assert version is None


class TestCollectYumPackages:
    """Tests for _collect_yum_packages method."""

    def test_collect_yum_packages_not_implemented(self, collector):
        """Test that yum collection logs but doesn't fail."""
        # Should not raise any exception
        collector._collect_yum_packages()

        # Should not add any packages (not implemented)
        assert len(collector.collected_packages) == 0


class TestCollectPortagePackages:
    """Tests for _collect_portage_packages method."""

    def test_collect_portage_packages_not_implemented(self, collector):
        """Test that portage collection logs but doesn't fail."""
        # Should not raise any exception
        collector._collect_portage_packages()

        # Should not add any packages (not implemented)
        assert len(collector.collected_packages) == 0


class TestIsSystemPackageLinux:
    """Tests for _is_system_package_linux method."""

    def test_lib_package_is_system(self, collector):
        """Test that lib* packages are system packages."""
        assert collector._is_system_package_linux("libc6") is True
        assert collector._is_system_package_linux("libssl1.1") is True

    def test_python_package_is_system(self, collector):
        """Test that python3-* packages are system packages."""
        assert collector._is_system_package_linux("python3-pip") is True
        assert collector._is_system_package_linux("python3-dev") is True

    def test_linux_package_is_system(self, collector):
        """Test that linux-* packages are system packages."""
        assert collector._is_system_package_linux("linux-headers") is True
        assert collector._is_system_package_linux("linux-image") is True

    def test_systemd_package_is_system(self, collector):
        """Test that systemd packages are system packages."""
        assert collector._is_system_package_linux("systemd") is True
        assert collector._is_system_package_linux("systemd-libs") is True

    def test_base_package_is_system(self, collector):
        """Test that base-* packages are system packages."""
        assert collector._is_system_package_linux("base-files") is True

    def test_kernel_package_is_system(self, collector):
        """Test that kernel packages are system packages."""
        assert collector._is_system_package_linux("kernel-headers") is True

    def test_firmware_package_is_system(self, collector):
        """Test that firmware packages are system packages."""
        assert collector._is_system_package_linux("firmware-linux") is True

    def test_user_package_not_system(self, collector):
        """Test that user packages are not system packages."""
        assert collector._is_system_package_linux("firefox") is False
        assert collector._is_system_package_linux("vim") is False
        assert collector._is_system_package_linux("nginx") is False

    def test_empty_string_not_system(self, collector):
        """Test that empty string is not a system package."""
        assert collector._is_system_package_linux("") is False


class TestManagerCollectorMapping:
    """Tests for _MANAGER_COLLECTORS mapping."""

    def test_all_managers_have_collectors(self, collector):
        """Test that all expected managers are mapped to collectors."""
        expected_managers = [
            "apt",
            "snap",
            "flatpak",
            "yum",
            "dnf",
            "pacman",
            "zypper",
            "portage",
            "apk",
        ]
        for manager in expected_managers:
            assert manager in collector._MANAGER_COLLECTORS
            method_name = collector._MANAGER_COLLECTORS[manager]
            assert hasattr(collector, method_name)


class TestErrorRecovery:
    """Tests for error recovery and graceful degradation."""

    def test_subprocess_called_process_error(self, collector):
        """Test handling of CalledProcessError."""
        with patch(
            "subprocess.run", side_effect=subprocess.CalledProcessError(1, "cmd")
        ):
            collector._collect_apt_packages()
            collector._collect_snap_packages()
            collector._collect_dnf_packages()

        # Should not crash and no packages collected
        assert len(collector.collected_packages) == 0

    def test_permission_denied_error(self, collector):
        """Test handling of permission denied errors."""
        with patch("subprocess.run", side_effect=PermissionError("Permission denied")):
            collector._collect_apt_packages()

        # Should not crash
        assert len(collector.collected_packages) == 0

    def test_multiple_collector_failures(self, collector):
        """Test that failures in one collector don't affect others."""
        call_count = 0

        def side_effect(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("First call fails")
            return Mock(returncode=0, stdout="package 1.0")

        with patch.object(
            collector, "detect_package_managers", return_value=["apt", "pacman"]
        ):
            with patch("subprocess.run", side_effect=side_effect):
                collector.collect_packages()

        # One should fail, one should succeed
        assert len(collector.collected_packages) == 1
