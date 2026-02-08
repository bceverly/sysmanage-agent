#!/usr/bin/env python3
"""
Comprehensive tests for software inventory collection covering:
- Multi-distro support scenarios
- Version parsing edge cases
- Package manager detection across platforms
- Error handling and recovery
- Integration scenarios

This test file covers cross-platform scenarios and edge cases not covered
in the platform-specific test files.
"""

# pylint: disable=redefined-outer-name,protected-access

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.software_inventory_collection import (
    SoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_base import (
    SoftwareInventoryCollectorBase,
)
from src.sysmanage_agent.collection.software_inventory_linux import (
    LinuxSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_windows import (
    WindowsSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_macos import (
    MacOSSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_bsd import (
    BSDSoftwareInventoryCollector,
)


class TestMultiDistroSupport:
    """Tests for multi-distribution Linux support."""

    @pytest.fixture
    def linux_collector(self):
        """Create a LinuxSoftwareInventoryCollector for testing."""
        return LinuxSoftwareInventoryCollector()

    def test_debian_ubuntu_apt_collection(self, linux_collector):
        """Test package collection on Debian/Ubuntu with apt."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "apt\t2.2.4\tamd64\tPackage manager\t4096\n"
            "dpkg\t1.20.9\tamd64\tDebian package manager\t2048\n"
            "ubuntu-minimal\t1.481\tall\tMinimal core of Ubuntu\t100\n"
        )

        with patch.object(
            linux_collector, "detect_package_managers", return_value=["apt"]
        ):
            with patch("subprocess.run", return_value=mock_result):
                linux_collector.collect_packages()

        assert len(linux_collector.collected_packages) == 3
        for pkg in linux_collector.collected_packages:
            assert pkg["package_manager"] == "apt"
            assert pkg["source"] == "debian_repository"

    def test_fedora_dnf_collection(self, linux_collector):
        """Test package collection on Fedora with DNF."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Installed Packages\n"
            "fedora-release.noarch              35-1               @anaconda\n"
            "dnf.noarch                         4.10.0-1.fc35      @updates\n"
            "kernel.x86_64                      5.14.0-60.fc35     @updates\n"
        )

        with patch.object(
            linux_collector, "detect_package_managers", return_value=["dnf"]
        ):
            with patch("subprocess.run", return_value=mock_result):
                linux_collector.collect_packages()

        assert len(linux_collector.collected_packages) == 3
        for pkg in linux_collector.collected_packages:
            assert pkg["package_manager"] == "dnf"

    def test_arch_pacman_collection(self, linux_collector):
        """Test package collection on Arch Linux with pacman."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "pacman 6.0.1-2\n" "linux 5.14.8.arch1-1\n" "base 2-2\n" "systemd 249.4-1\n"
        )

        with patch.object(
            linux_collector, "detect_package_managers", return_value=["pacman"]
        ):
            with patch("subprocess.run", return_value=mock_result):
                linux_collector.collect_packages()

        assert len(linux_collector.collected_packages) == 4
        for pkg in linux_collector.collected_packages:
            assert pkg["package_manager"] == "pacman"
            assert pkg["source"] == "arch_repository"

    def test_opensuse_zypper_collection(self, linux_collector):
        """Test package collection on openSUSE with zypper."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "zypper\t1.14.50-3.1\tx86_64\tCommand line software manager\t2500000\n"
            "opensuse-release\t15.3-10.1\tx86_64\topenSUSE release file\t100000\n"
        )

        with patch.object(
            linux_collector, "detect_package_managers", return_value=["zypper"]
        ):
            with patch("subprocess.run", return_value=mock_result):
                linux_collector.collect_packages()

        assert len(linux_collector.collected_packages) == 2
        for pkg in linux_collector.collected_packages:
            assert pkg["package_manager"] == "zypper"
            assert pkg["source"] == "opensuse_repository"

    def test_alpine_apk_collection(self, linux_collector):
        """Test package collection on Alpine Linux with apk."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "apk-tools-2.12.7-r0\n"
            "alpine-base-3.14.2-r0\n"
            "busybox-1.33.1-r3\n"
            "musl-1.2.2-r3\n"
        )

        with patch.object(
            linux_collector, "detect_package_managers", return_value=["apk"]
        ):
            with patch("subprocess.run", return_value=mock_result):
                linux_collector.collect_packages()

        assert len(linux_collector.collected_packages) == 4
        for pkg in linux_collector.collected_packages:
            assert pkg["package_manager"] == "apk"
            assert pkg["source"] == "alpine_repository"

    def test_multiple_package_managers(self, linux_collector):
        """Test system with multiple package managers (e.g., apt + snap + flatpak)."""
        apt_result = Mock(
            returncode=0, stdout="firefox\t91.0\tamd64\tMozilla Firefox\t200000\n"
        )
        snap_result = Mock(
            returncode=0,
            stdout="Name    Version  Rev\ncode    1.60.0   100 latest/stable\n",
        )
        flatpak_result = Mock(
            returncode=0,
            stdout="Name\tApp ID\tVersion\nSlack\tcom.slack.Slack\t4.20.0\n",
        )

        with patch.object(
            linux_collector,
            "detect_package_managers",
            return_value=["apt", "snap", "flatpak"],
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [apt_result, snap_result, flatpak_result]
                linux_collector.collect_packages()

        assert len(linux_collector.collected_packages) == 3

        managers = {
            pkg["package_manager"] for pkg in linux_collector.collected_packages
        }
        assert managers == {"apt", "snap", "flatpak"}


class TestVersionParsing:
    """Tests for version parsing across different formats."""

    @pytest.fixture
    def base_collector(self):
        """Create a SoftwareInventoryCollectorBase for testing."""
        return SoftwareInventoryCollectorBase()

    @pytest.fixture
    def linux_collector(self):
        """Create a LinuxSoftwareInventoryCollector for testing."""
        return LinuxSoftwareInventoryCollector()

    def test_parse_semantic_version(self, linux_collector):
        """Test parsing semantic version (major.minor.patch)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "package 1.2.3\n"

        with patch("subprocess.run", return_value=mock_result):
            linux_collector._collect_pacman_packages()

        assert linux_collector.collected_packages[0]["version"] == "1.2.3"

    def test_parse_version_with_release(self, linux_collector):
        """Test parsing version with release number."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Installed Packages\n"
            "package.x86_64              1.2.3-4.fc35     @updates\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            linux_collector._collect_dnf_packages()

        assert linux_collector.collected_packages[0]["version"] == "1.2.3-4.fc35"

    def test_parse_version_with_epoch(self, linux_collector):
        """Test parsing version with epoch prefix."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "package\t1:1.2.3-4\tamd64\tDescription\t1000\n"

        with patch("subprocess.run", return_value=mock_result):
            linux_collector._collect_apt_packages()

        assert linux_collector.collected_packages[0]["version"] == "1:1.2.3-4"

    def test_parse_alpine_version_with_revision(self, linux_collector):
        """Test parsing Alpine version with revision."""
        name, version = linux_collector._parse_apk_name_version("busybox-1.33.1-r3")

        assert name == "busybox"
        assert version == "1.33.1-r3"

    def test_parse_alpine_complex_package_name(self, linux_collector):
        """Test parsing Alpine package with hyphenated name."""
        name, version = linux_collector._parse_apk_name_version(
            "py3-setuptools-57.4.0-r0"
        )

        assert name == "py3-setuptools"
        assert version == "57.4.0-r0"

    def test_parse_version_date_based(self, linux_collector):
        """Test parsing date-based version."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "package 20210915\n"

        with patch("subprocess.run", return_value=mock_result):
            linux_collector._collect_pacman_packages()

        assert linux_collector.collected_packages[0]["version"] == "20210915"

    def test_parse_version_with_git_hash(self, linux_collector):
        """Test parsing version with git hash."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "package 1.0.0.r123.abc123f\n"

        with patch("subprocess.run", return_value=mock_result):
            linux_collector._collect_pacman_packages()

        assert linux_collector.collected_packages[0]["version"] == "1.0.0.r123.abc123f"


class TestPackageManagerDetection:
    """Tests for package manager detection across platforms."""

    def test_linux_manager_detection_order(self):
        """Test that Linux managers are detected in correct order."""
        collector = LinuxSoftwareInventoryCollector()

        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd in ["apt", "snap"]
            managers = collector.detect_package_managers()

        # apt should be detected first due to order in manager_executables
        assert managers[0] == "apt"

    def test_windows_manager_detection(self):
        """Test Windows package manager detection."""
        collector = WindowsSoftwareInventoryCollector()

        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd in ["winget", "choco"]
            managers = collector.detect_package_managers()

        assert "winget" in managers
        assert "chocolatey" in managers

    def test_macos_manager_detection(self):
        """Test macOS package manager detection."""
        collector = MacOSSoftwareInventoryCollector()

        with patch.object(collector, "_is_homebrew_available", return_value=True):
            with patch.object(collector, "_command_exists") as mock_exists:
                mock_exists.side_effect = lambda cmd: cmd == "port"
                managers = collector.detect_package_managers()

        assert "homebrew" in managers
        assert "macports" in managers

    def test_bsd_manager_detection(self):
        """Test BSD package manager detection."""
        collector = BSDSoftwareInventoryCollector()

        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd in ["pkg", "pkg_info"]
            managers = collector.detect_package_managers()

        assert "pkg" in managers
        assert "pkg_info" in managers


class TestPlatformSelection:
    """Tests for platform-specific collector selection."""

    def test_linux_collector_selected(self):
        """Test that Linux collector is selected on Linux."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        assert isinstance(collector.collector, LinuxSoftwareInventoryCollector)

    def test_darwin_collector_selected(self):
        """Test that macOS collector is selected on Darwin."""
        with patch("platform.system", return_value="Darwin"):
            collector = SoftwareInventoryCollector()

        assert isinstance(collector.collector, MacOSSoftwareInventoryCollector)

    def test_windows_collector_selected(self):
        """Test that Windows collector is selected on Windows."""
        with patch("platform.system", return_value="Windows"):
            collector = SoftwareInventoryCollector()

        assert isinstance(collector.collector, WindowsSoftwareInventoryCollector)

    def test_freebsd_collector_selected(self):
        """Test that BSD collector is selected on FreeBSD."""
        with patch("platform.system", return_value="FreeBSD"):
            collector = SoftwareInventoryCollector()

        assert isinstance(collector.collector, BSDSoftwareInventoryCollector)

    def test_openbsd_collector_selected(self):
        """Test that BSD collector is selected on OpenBSD."""
        with patch("platform.system", return_value="OpenBSD"):
            collector = SoftwareInventoryCollector()

        assert isinstance(collector.collector, BSDSoftwareInventoryCollector)

    def test_netbsd_collector_selected(self):
        """Test that BSD collector is selected on NetBSD."""
        with patch("platform.system", return_value="NetBSD"):
            collector = SoftwareInventoryCollector()

        assert isinstance(collector.collector, BSDSoftwareInventoryCollector)

    def test_unsupported_platform(self):
        """Test handling of unsupported platform."""
        with patch("platform.system", return_value="UnknownOS"):
            collector = SoftwareInventoryCollector()

        assert collector.collector is None
        result = collector.get_software_inventory()
        assert result["error"] == "Unsupported platform"


class TestSizeParsing:
    """Tests for size string parsing."""

    @pytest.fixture
    def base_collector(self):
        """Create a SoftwareInventoryCollectorBase for testing."""
        return SoftwareInventoryCollectorBase()

    def test_parse_bytes(self, base_collector):
        """Test parsing bytes."""
        assert base_collector._parse_size_string("1024B") == 1024
        assert base_collector._parse_size_string("512 B") == 512

    def test_parse_kilobytes(self, base_collector):
        """Test parsing kilobytes."""
        assert base_collector._parse_size_string("1KB") == 1024
        assert base_collector._parse_size_string("2 KB") == 2048

    def test_parse_megabytes(self, base_collector):
        """Test parsing megabytes."""
        assert base_collector._parse_size_string("1MB") == 1048576
        assert base_collector._parse_size_string("1.5 MB") == int(1.5 * 1024 * 1024)

    def test_parse_gigabytes(self, base_collector):
        """Test parsing gigabytes."""
        assert base_collector._parse_size_string("1GB") == 1073741824
        assert base_collector._parse_size_string("2.5 GB") == int(2.5 * 1024**3)

    def test_parse_terabytes(self, base_collector):
        """Test parsing terabytes."""
        assert base_collector._parse_size_string("1TB") == 1099511627776

    def test_parse_lowercase(self, base_collector):
        """Test parsing lowercase units."""
        assert base_collector._parse_size_string("100mb") == 100 * 1024 * 1024

    def test_parse_no_unit(self, base_collector):
        """Test parsing number without unit."""
        assert base_collector._parse_size_string("1024") == 1024

    def test_parse_invalid(self, base_collector):
        """Test parsing invalid size strings."""
        assert base_collector._parse_size_string("") is None
        assert base_collector._parse_size_string("   ") is None
        assert base_collector._parse_size_string("invalid") is None
        assert base_collector._parse_size_string(None) is None


class TestErrorHandling:
    """Tests for error handling and recovery."""

    def test_subprocess_timeout_recovery(self):
        """Test recovery from subprocess timeout."""
        collector = LinuxSoftwareInventoryCollector()

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            # Should not raise
            collector._collect_apt_packages()
            collector._collect_snap_packages()
            collector._collect_dnf_packages()

        assert len(collector.collected_packages) == 0

    def test_permission_error_recovery(self):
        """Test recovery from permission errors."""
        collector = LinuxSoftwareInventoryCollector()

        with patch("subprocess.run", side_effect=PermissionError("Access denied")):
            collector._collect_apt_packages()

        assert len(collector.collected_packages) == 0

    def test_file_not_found_recovery(self):
        """Test recovery from file not found errors."""
        collector = LinuxSoftwareInventoryCollector()

        with patch("subprocess.run", side_effect=FileNotFoundError("dpkg not found")):
            collector._collect_apt_packages()

        assert len(collector.collected_packages) == 0

    def test_partial_collection_success(self):
        """Test that partial collection succeeds when some managers fail."""
        collector = LinuxSoftwareInventoryCollector()

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("apt failed")
            return Mock(returncode=0, stdout="package 1.0\n")

        with patch.object(
            collector, "detect_package_managers", return_value=["apt", "pacman"]
        ):
            with patch("subprocess.run", side_effect=side_effect):
                collector.collect_packages()

        # Should have collected from pacman despite apt failure
        assert len(collector.collected_packages) == 1

    def test_get_software_inventory_exception_handling(self):
        """Test get_software_inventory handles exceptions."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        with patch.object(
            collector.collector, "collect_packages", side_effect=Exception("Test error")
        ):
            result = collector.get_software_inventory()

        assert result["error"] == "Test error"
        assert result["total_packages"] == 0


class TestAttributeDelegation:
    """Tests for attribute delegation in SoftwareInventoryCollector."""

    def test_getattr_delegation(self):
        """Test that attribute access is delegated to platform collector."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        # Access attribute that exists on Linux collector
        assert hasattr(collector.collector, "collected_packages")
        assert collector.collected_packages == []

    def test_getattr_no_collector(self):
        """Test AttributeError when no collector."""
        with patch("platform.system", return_value="UnknownOS"):
            collector = SoftwareInventoryCollector()

        with pytest.raises(AttributeError):
            _ = collector.nonexistent_attribute

    def test_explicit_delegation_methods(self):
        """Test explicit delegation methods."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        # These should not raise
        result = collector._detect_package_managers()
        assert isinstance(result, list)


class TestCollectionTimestamp:
    """Tests for collection timestamp handling."""

    def test_timestamp_in_result(self):
        """Test that timestamp is included in result."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        with patch.object(collector.collector, "collect_packages"):
            result = collector.get_software_inventory()

        assert "collection_timestamp" in result
        # Should be ISO format
        assert "T" in result["collection_timestamp"]

    def test_timestamp_is_utc(self):
        """Test that timestamp is in UTC."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        with patch.object(collector.collector, "collect_packages"):
            result = collector.get_software_inventory()

        # UTC timestamps end with +00:00 or Z
        timestamp = result["collection_timestamp"]
        assert "+00:00" in timestamp or "Z" in timestamp or timestamp.endswith("00")


class TestSystemPackageDetection:
    """Tests for system package detection."""

    @pytest.fixture
    def linux_collector(self):
        """Create a LinuxSoftwareInventoryCollector for testing."""
        return LinuxSoftwareInventoryCollector()

    @pytest.fixture
    def bsd_collector(self):
        """Create a BSDSoftwareInventoryCollector for testing."""
        return BSDSoftwareInventoryCollector()

    def test_linux_system_packages(self, linux_collector):
        """Test Linux system package detection."""
        system_packages = [
            "libc6",
            "libssl1.1",
            "python3-minimal",
            "linux-image-5.4",
            "systemd",
            "base-files",
            "kernel-headers",
            "firmware-linux",
        ]

        for pkg in system_packages:
            assert linux_collector._is_system_package_linux(pkg) is True

    def test_linux_user_packages(self, linux_collector):
        """Test Linux user package detection."""
        user_packages = [
            "firefox",
            "vim",
            "nginx",
            "docker",
            "git",
            "nodejs",
        ]

        for pkg in user_packages:
            assert linux_collector._is_system_package_linux(pkg) is False

    def test_bsd_system_packages(self, bsd_collector):
        """Test BSD system package detection."""
        system_packages = [
            "base-system",
            "libiconv",
            "perl-5.32",
            "python38",
            "openssl",
        ]

        for pkg in system_packages:
            assert bsd_collector._is_bsd_system_package(pkg) is True

    def test_bsd_user_packages(self, bsd_collector):
        """Test BSD user package detection."""
        user_packages = [
            "firefox",
            "nginx",
            "vim",
            "git",
        ]

        for pkg in user_packages:
            assert bsd_collector._is_bsd_system_package(pkg) is False


class TestIntegrationScenarios:
    """Integration tests for realistic scenarios."""

    def test_full_linux_inventory_flow(self):
        """Test complete Linux inventory collection flow."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        apt_output = "firefox\t91.0\tamd64\tMozilla Firefox\t200000\n"

        with patch.object(
            collector.collector, "detect_package_managers", return_value=["apt"]
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout=apt_output)
                result = collector.get_software_inventory()

        assert result["platform"] == "linux"
        assert result["total_packages"] == 1
        assert len(result["software_packages"]) == 1
        assert "error" not in result

    def test_empty_system(self):
        """Test inventory collection on system with no packages."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        with patch.object(
            collector.collector, "detect_package_managers", return_value=[]
        ):
            result = collector.get_software_inventory()

        assert result["total_packages"] == 0
        assert result["software_packages"] == []

    def test_large_package_list(self):
        """Test handling of large package list."""
        with patch("platform.system", return_value="Linux"):
            collector = SoftwareInventoryCollector()

        # Generate 1000 packages
        packages = "\n".join(
            f"package{i}\t{i}.0.0\tamd64\tPackage {i}\t1000" for i in range(1000)
        )

        with patch.object(
            collector.collector, "detect_package_managers", return_value=["apt"]
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout=packages)
                result = collector.get_software_inventory()

        assert result["total_packages"] == 1000
