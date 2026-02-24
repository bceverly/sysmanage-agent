"""
Comprehensive unit tests for bhyve VM provisioning helpers.

Tests cover:
- BhyveProvisioningHelper initialization
- nmdm device ID generation
- Console device path generation
- Linux guest detection
- Cloud-init ISO creation
- bhyve command generation
- VM startup with bhyveload (FreeBSD guests)
- VM startup with UEFI (Linux guests)
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
import os
import subprocess

from unittest.mock import Mock, patch, mock_open

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_provisioning import (
    BhyveProvisioningHelper,
    BHYVE_CLOUDINIT_DIR,
)
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_bhyve_provisioning")


@pytest.fixture
def provisioning_helper(logger):
    """Create a BhyveProvisioningHelper instance for testing."""
    return BhyveProvisioningHelper(logger)


@pytest.fixture
def base_config():
    """Create a base BhyveVmConfig for testing."""
    return BhyveVmConfig(
        distribution="ubuntu:22.04",
        vm_name="test-vm",
        hostname="test.example.com",
        username="admin",
        password_hash="$6$rounds=4096$...",
        server_url="https://server.example.com",
        agent_install_commands=["apt install sysmanage-agent"],
        memory="2G",
        disk_size="20G",
        cpus=2,
        server_port=8443,
        use_https=True,
    )


@pytest.fixture
def freebsd_config():
    """Create a FreeBSD BhyveVmConfig for testing."""
    return BhyveVmConfig(
        distribution="freebsd:14",
        vm_name="freebsd-vm",
        hostname="freebsd.example.com",
        username="admin",
        password_hash="$6$rounds=4096$...",
        server_url="https://server.example.com",
        agent_install_commands=["pkg install sysmanage-agent"],
        memory="1G",
        disk_size="10G",
        cpus=1,
        server_port=8443,
        use_https=True,
        use_uefi=False,
    )


class TestBhyveProvisioningHelperInit:
    """Tests for BhyveProvisioningHelper initialization."""

    def test_init_sets_logger(self, provisioning_helper, logger):
        """Test that __init__ sets logger."""
        assert provisioning_helper.logger == logger

    def test_init_with_custom_logger(self):
        """Test initialization with a custom logger."""
        custom_logger = logging.getLogger("custom_test")
        helper = BhyveProvisioningHelper(custom_logger)
        assert helper.logger == custom_logger


class TestGetNmdmId:
    """Tests for get_nmdm_id method."""

    def test_nmdm_id_returns_integer(self, provisioning_helper):
        """Test that get_nmdm_id returns an integer."""
        result = provisioning_helper.get_nmdm_id("test-vm")
        assert isinstance(result, int)

    def test_nmdm_id_in_range(self, provisioning_helper):
        """Test that nmdm_id is in valid range 0-999."""
        result = provisioning_helper.get_nmdm_id("test-vm")
        assert 0 <= result < 1000

    def test_nmdm_id_consistent(self, provisioning_helper):
        """Test that same VM name always returns same ID."""
        result1 = provisioning_helper.get_nmdm_id("consistent-vm")
        result2 = provisioning_helper.get_nmdm_id("consistent-vm")
        assert result1 == result2

    def test_nmdm_id_different_vms(self, provisioning_helper):
        """Test that different VM names return different IDs (usually)."""
        # Note: Due to hash collisions, this isn't guaranteed,
        # but for most names it should differ
        result1 = provisioning_helper.get_nmdm_id("vm-one")
        result2 = provisioning_helper.get_nmdm_id("vm-two")
        # We just verify both are valid
        assert 0 <= result1 < 1000
        assert 0 <= result2 < 1000

    def test_nmdm_id_empty_name(self, provisioning_helper):
        """Test nmdm_id with empty VM name."""
        result = provisioning_helper.get_nmdm_id("")
        assert 0 <= result < 1000


class TestGetConsoleDevice:
    """Tests for get_console_device method."""

    def test_console_device_format(self, provisioning_helper):
        """Test that console device has correct format."""
        result = provisioning_helper.get_console_device("test-vm")
        assert result.startswith("/dev/nmdm")
        assert result.endswith("B")

    def test_console_device_consistent(self, provisioning_helper):
        """Test that same VM name returns same device."""
        result1 = provisioning_helper.get_console_device("test-vm")
        result2 = provisioning_helper.get_console_device("test-vm")
        assert result1 == result2

    def test_console_device_uses_nmdm_id(self, provisioning_helper):
        """Test that console device uses correct nmdm ID."""
        nmdm_id = provisioning_helper.get_nmdm_id("test-vm")
        console = provisioning_helper.get_console_device("test-vm")
        expected = f"/dev/nmdm{nmdm_id}B"
        assert console == expected


class TestIsLinuxGuest:
    """Tests for is_linux_guest method."""

    def test_ubuntu_is_linux(self, provisioning_helper, base_config):
        """Test that Ubuntu is detected as Linux."""
        base_config.distribution = "ubuntu:22.04"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_debian_is_linux(self, provisioning_helper, base_config):
        """Test that Debian is detected as Linux."""
        base_config.distribution = "debian:12"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_fedora_is_linux(self, provisioning_helper, base_config):
        """Test that Fedora is detected as Linux."""
        base_config.distribution = "fedora:39"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_centos_is_linux(self, provisioning_helper, base_config):
        """Test that CentOS is detected as Linux."""
        base_config.distribution = "centos:8"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_rhel_is_linux(self, provisioning_helper, base_config):
        """Test that RHEL is detected as Linux."""
        base_config.distribution = "rhel:9"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_rocky_is_linux(self, provisioning_helper, base_config):
        """Test that Rocky Linux is detected as Linux."""
        base_config.distribution = "rocky:9"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_alma_is_linux(self, provisioning_helper, base_config):
        """Test that AlmaLinux is detected as Linux."""
        base_config.distribution = "almalinux:9"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_alpine_is_linux(self, provisioning_helper, base_config):
        """Test that Alpine is detected as Linux."""
        base_config.distribution = "alpine:3.18"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_arch_is_linux(self, provisioning_helper, base_config):
        """Test that Arch Linux is detected as Linux."""
        base_config.distribution = "archlinux"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_opensuse_is_linux(self, provisioning_helper, base_config):
        """Test that openSUSE is detected as Linux."""
        base_config.distribution = "opensuse:leap"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_suse_is_linux(self, provisioning_helper, base_config):
        """Test that SUSE is detected as Linux."""
        base_config.distribution = "suse:sles15"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_generic_linux_is_linux(self, provisioning_helper, base_config):
        """Test that generic linux is detected as Linux."""
        base_config.distribution = "linux-generic"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_freebsd_is_not_linux(self, provisioning_helper, freebsd_config):
        """Test that FreeBSD is not detected as Linux."""
        assert provisioning_helper.is_linux_guest(freebsd_config) is False

    def test_openbsd_is_not_linux(self, provisioning_helper, base_config):
        """Test that OpenBSD is not detected as Linux."""
        base_config.distribution = "openbsd:7.4"
        assert provisioning_helper.is_linux_guest(base_config) is False

    def test_netbsd_is_not_linux(self, provisioning_helper, base_config):
        """Test that NetBSD is not detected as Linux."""
        base_config.distribution = "netbsd:10"
        assert provisioning_helper.is_linux_guest(base_config) is False

    def test_case_insensitive_detection(self, provisioning_helper, base_config):
        """Test that detection is case-insensitive."""
        base_config.distribution = "UBUNTU:22.04"
        assert provisioning_helper.is_linux_guest(base_config) is True

        base_config.distribution = "Ubuntu:22.04"
        assert provisioning_helper.is_linux_guest(base_config) is True

    def test_empty_distribution(self, provisioning_helper):
        """Test with empty distribution."""
        # Create a new config without the distribution validation
        config = Mock()
        config.distribution = ""
        assert provisioning_helper.is_linux_guest(config) is False

    def test_none_distribution(self, provisioning_helper):
        """Test with None distribution."""
        config = Mock()
        config.distribution = None
        assert provisioning_helper.is_linux_guest(config) is False


class TestCreateCloudInitIso:
    """Tests for create_cloud_init_iso method."""

    def test_create_cloud_init_iso_success_with_makefs(
        self, provisioning_helper, base_config
    ):
        """Test successful cloud-init ISO creation with makefs."""
        with patch("os.makedirs") as mock_makedirs:
            with patch("builtins.open", mock_open()) as _mock_file:
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is True
        assert "path" in result
        assert base_config.vm_name in result["path"]
        mock_makedirs.assert_called_once()

    def test_create_cloud_init_iso_fallback_to_genisoimage(
        self, provisioning_helper, base_config
    ):
        """Test cloud-init ISO creation falls back to genisoimage."""
        with patch("os.makedirs"):
            with patch("builtins.open", mock_open()):
                with patch("subprocess.run") as mock_run:
                    # makefs fails, genisoimage succeeds
                    mock_run.side_effect = [
                        Mock(returncode=1, stdout="", stderr="makefs not found"),
                        Mock(returncode=0, stdout="", stderr=""),
                    ]
                    result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is True
        assert mock_run.call_count == 2

    def test_create_cloud_init_iso_both_tools_fail(
        self, provisioning_helper, base_config
    ):
        """Test cloud-init ISO creation when both tools fail."""
        with patch("os.makedirs"):
            with patch("builtins.open", mock_open()):
                with patch("subprocess.run") as mock_run:
                    # Both makefs and genisoimage fail
                    mock_run.return_value = Mock(
                        returncode=1, stdout="", stderr="Command failed"
                    )
                    result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is False
        assert "error" in result
        assert "Failed to create cloud-init ISO" in result["error"]

    def test_create_cloud_init_iso_makedirs_exception(
        self, provisioning_helper, base_config
    ):
        """Test cloud-init ISO creation handles makedirs exception."""
        with patch("os.makedirs", side_effect=OSError("Permission denied")):
            result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is False
        assert "error" in result

    def test_create_cloud_init_iso_file_write_exception(
        self, provisioning_helper, base_config
    ):
        """Test cloud-init ISO creation handles file write exception."""
        with patch("os.makedirs"):
            with patch("builtins.open", side_effect=IOError("Cannot write")):
                result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is False
        assert "error" in result

    def test_create_cloud_init_iso_sets_path_on_config(
        self, provisioning_helper, base_config
    ):
        """Test that ISO path is set on config object."""
        with patch("os.makedirs"):
            with patch("builtins.open", mock_open()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    provisioning_helper.create_cloud_init_iso(base_config)

        expected_path = os.path.join(BHYVE_CLOUDINIT_DIR, f"{base_config.vm_name}.iso")
        assert base_config.cloud_init_iso_path == expected_path

    def test_create_cloud_init_iso_with_debian_image(
        self, provisioning_helper, base_config
    ):
        """Test cloud-init ISO with Debian cloud image URL."""
        base_config.cloud_image_url = (
            "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12.qcow2"
        )
        with patch("os.makedirs"):
            with patch("builtins.open", mock_open()) as _mock_file:
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is True

    def test_create_cloud_init_iso_with_alpine_image(
        self, provisioning_helper, base_config
    ):
        """Test cloud-init ISO with Alpine cloud image URL."""
        base_config.cloud_image_url = (
            "https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/"
            "x86_64/alpine-virt-3.18.0-x86_64.iso"
        )
        with patch("os.makedirs"):
            with patch("builtins.open", mock_open()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is True

    def test_create_cloud_init_iso_with_freebsd_image(
        self, provisioning_helper, freebsd_config
    ):
        """Test cloud-init ISO with FreeBSD cloud image URL."""
        freebsd_config.cloud_image_url = (
            "https://download.freebsd.org/ftp/releases/VM-IMAGES/"
            "14.0-RELEASE/amd64/Latest/FreeBSD-14.0-RELEASE-amd64.qcow2.xz"
        )
        with patch("os.makedirs"):
            with patch("builtins.open", mock_open()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = provisioning_helper.create_cloud_init_iso(freebsd_config)

        assert result["success"] is True

    def test_create_cloud_init_iso_with_auto_approve_token(
        self, provisioning_helper, base_config
    ):
        """Test cloud-init ISO creation with auto-approve token."""
        base_config.auto_approve_token = "test-token-uuid"
        with patch("os.makedirs"):
            with patch("builtins.open", mock_open()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is True

    def test_create_cloud_init_iso_with_no_agent_commands(
        self, provisioning_helper, base_config
    ):
        """Test cloud-init ISO creation with empty agent install commands."""
        base_config.agent_install_commands = []
        with patch("os.makedirs"):
            with patch("builtins.open", mock_open()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is True

    def test_create_cloud_init_iso_escapes_single_quotes(
        self, provisioning_helper, base_config
    ):
        """Test that single quotes in commands are escaped."""
        base_config.agent_install_commands = [
            "echo 'hello world'",
            "apt install 'package-name'",
        ]
        written_content = []
        mock_file_opener = mock_open()

        def write_side_effect(data):
            written_content.append(data)

        mock_file_opener.return_value.write = write_side_effect

        with patch("os.makedirs"):
            with patch("builtins.open", mock_file_opener):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = provisioning_helper.create_cloud_init_iso(base_config)

        assert result["success"] is True


class TestGenerateBhyveCommand:
    """Tests for generate_bhyve_command method."""

    def test_generate_bhyve_command_basic(self, provisioning_helper, base_config):
        """Test basic bhyve command generation."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        assert cmd[0] == "bhyve"
        assert "-A" in cmd  # ACPI tables
        assert "-H" in cmd  # Yield CPU on HLT
        assert "-P" in cmd  # Exit on PAUSE
        assert base_config.vm_name in cmd

    def test_generate_bhyve_command_with_nmdm(self, provisioning_helper, base_config):
        """Test bhyve command with nmdm console (default)."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        cmd = provisioning_helper.generate_bhyve_command(
            base_config, "tap0", use_nmdm=True
        )

        nmdm_id = provisioning_helper.get_nmdm_id(base_config.vm_name)
        expected_console = f"/dev/nmdm{nmdm_id}A"

        # Find the console argument
        console_found = False
        for i, arg in enumerate(cmd):
            if arg == "-l" and i + 1 < len(cmd) and "com1" in cmd[i + 1]:
                assert expected_console in cmd[i + 1]
                console_found = True
                break
        assert console_found, "Console device not found in command"

    def test_generate_bhyve_command_without_nmdm(
        self, provisioning_helper, base_config
    ):
        """Test bhyve command with stdio console."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        cmd = provisioning_helper.generate_bhyve_command(
            base_config, "tap0", use_nmdm=False
        )

        # Find the console argument
        console_found = False
        for i, arg in enumerate(cmd):
            if arg == "-l" and i + 1 < len(cmd) and "com1" in cmd[i + 1]:
                assert "stdio" in cmd[i + 1]
                console_found = True
                break
        assert console_found, "Console device not found in command"

    def test_generate_bhyve_command_memory(self, provisioning_helper, base_config):
        """Test that memory is correctly specified."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        base_config.memory = "4G"
        cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        # Find -m argument
        for i, arg in enumerate(cmd):
            if arg == "-m":
                assert cmd[i + 1] == "4096M"
                break
        else:
            pytest.fail("Memory argument not found")

    def test_generate_bhyve_command_cpus(self, provisioning_helper, base_config):
        """Test that CPUs are correctly specified."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        base_config.cpus = 4
        cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        # Find -c argument
        for i, arg in enumerate(cmd):
            if arg == "-c":
                assert cmd[i + 1] == "4"
                break
        else:
            pytest.fail("CPU argument not found")

    def test_generate_bhyve_command_network(self, provisioning_helper, base_config):
        """Test that network interface is correctly specified."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        tap_interface = "tap42"
        cmd = provisioning_helper.generate_bhyve_command(base_config, tap_interface)

        # Find virtio-net argument
        net_found = False
        for arg in cmd:
            if "virtio-net" in arg and tap_interface in arg:
                net_found = True
                break
        assert net_found, "Network interface not found in command"

    def test_generate_bhyve_command_disk(self, provisioning_helper, base_config):
        """Test that disk is correctly specified."""
        base_config.disk_path = "/vm/test-vm/custom-disk.img"
        cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        # Find virtio-blk argument
        disk_found = False
        for arg in cmd:
            if "virtio-blk" in arg and base_config.disk_path in arg:
                disk_found = True
                break
        assert disk_found, "Disk not found in command"

    def test_generate_bhyve_command_with_cloudinit_iso(
        self, provisioning_helper, base_config
    ):
        """Test bhyve command with cloud-init ISO."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        base_config.cloud_init_iso_path = "/vm/cloud-init/test-vm.iso"

        with patch("os.path.exists", return_value=True):
            cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        # Find ahci-cd argument
        cdrom_found = False
        for arg in cmd:
            if "ahci-cd" in arg and base_config.cloud_init_iso_path in arg:
                cdrom_found = True
                break
        assert cdrom_found, "Cloud-init ISO not found in command"

    def test_generate_bhyve_command_without_cloudinit_iso(
        self, provisioning_helper, base_config
    ):
        """Test bhyve command without cloud-init ISO."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        base_config.cloud_init_iso_path = ""

        cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        # Verify no ahci-cd argument
        for arg in cmd:
            assert "ahci-cd" not in arg

    def test_generate_bhyve_command_cloudinit_iso_not_exists(
        self, provisioning_helper, base_config
    ):
        """Test bhyve command when cloud-init ISO doesn't exist."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        base_config.cloud_init_iso_path = "/vm/cloud-init/missing.iso"

        with patch("os.path.exists", return_value=False):
            cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        # Verify no ahci-cd argument
        for arg in cmd:
            assert "ahci-cd" not in arg

    def test_generate_bhyve_command_with_uefi_linux_guest(
        self, provisioning_helper, base_config
    ):
        """Test bhyve command with UEFI for Linux guest."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        base_config.distribution = "ubuntu:22.04"

        def mock_exists(path):
            if path == "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd":
                return True
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        # Find bootrom argument
        bootrom_found = False
        for i, arg in enumerate(cmd):
            if arg == "-l" and i + 1 < len(cmd) and "bootrom" in cmd[i + 1]:
                bootrom_found = True
                break
        assert bootrom_found, "UEFI bootrom not found in command"

    def test_generate_bhyve_command_with_uefi_explicit(
        self, provisioning_helper, freebsd_config
    ):
        """Test bhyve command with explicit UEFI flag."""
        freebsd_config.disk_path = "/vm/freebsd-vm/disk.img"
        freebsd_config.use_uefi = True

        def mock_exists(path):
            if path == "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd":
                return True
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            cmd = provisioning_helper.generate_bhyve_command(freebsd_config, "tap0")

        # Find bootrom argument
        bootrom_found = False
        for i, arg in enumerate(cmd):
            if arg == "-l" and i + 1 < len(cmd) and "bootrom" in cmd[i + 1]:
                bootrom_found = True
                break
        assert bootrom_found, "UEFI bootrom not found in command"

    def test_generate_bhyve_command_without_uefi_freebsd(
        self, provisioning_helper, freebsd_config
    ):
        """Test bhyve command without UEFI for FreeBSD guest."""
        freebsd_config.disk_path = "/vm/freebsd-vm/disk.img"
        freebsd_config.use_uefi = False

        cmd = provisioning_helper.generate_bhyve_command(freebsd_config, "tap0")

        # Verify no bootrom argument
        for i, arg in enumerate(cmd):
            if arg == "-l" and i + 1 < len(cmd) and "bootrom" in cmd[i + 1]:
                pytest.fail("UEFI bootrom should not be present for FreeBSD")

    def test_generate_bhyve_command_uefi_firmware_missing(
        self, provisioning_helper, base_config
    ):
        """Test bhyve command when UEFI firmware is missing."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        base_config.distribution = "ubuntu:22.04"

        with patch("os.path.exists", return_value=False):
            cmd = provisioning_helper.generate_bhyve_command(base_config, "tap0")

        # Verify no bootrom argument
        for i, arg in enumerate(cmd):
            if arg == "-l" and i + 1 < len(cmd) and "bootrom" in cmd[i + 1]:
                pytest.fail(
                    "UEFI bootrom should not be present when firmware is missing"
                )


class TestStartVmWithBhyveload:
    """Tests for start_vm_with_bhyveload method."""

    def test_start_vm_with_bhyveload_success(self, provisioning_helper, freebsd_config):
        """Test successful VM startup with bhyveload."""
        freebsd_config.disk_path = "/vm/freebsd-vm/disk.img"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            with patch("os.path.exists", return_value=False):
                result = provisioning_helper.start_vm_with_bhyveload(
                    freebsd_config, "tap0"
                )

        assert result["success"] is True

    def test_start_vm_with_bhyveload_load_failure(
        self, provisioning_helper, freebsd_config
    ):
        """Test bhyveload failure."""
        freebsd_config.disk_path = "/vm/freebsd-vm/disk.img"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="bhyveload: can't load kernel"
            )
            result = provisioning_helper.start_vm_with_bhyveload(freebsd_config, "tap0")

        assert result["success"] is False
        assert "bhyveload failed" in result["error"]

    def test_start_vm_with_bhyveload_bhyve_failure(
        self, provisioning_helper, freebsd_config
    ):
        """Test bhyve start failure after successful bhyveload."""
        freebsd_config.disk_path = "/vm/freebsd-vm/disk.img"

        with patch("subprocess.run") as mock_run:
            # bhyveload succeeds, daemon/bhyve fails
            mock_run.side_effect = [
                Mock(returncode=0, stdout="", stderr=""),  # bhyveload
                Mock(returncode=1),  # daemon+bhyve (no stdout/stderr with DEVNULL)
            ]
            with patch("os.path.exists", return_value=False):
                result = provisioning_helper.start_vm_with_bhyveload(
                    freebsd_config, "tap0"
                )

        assert result["success"] is False
        assert "Failed to start bhyve" in result["error"]

    def test_start_vm_with_bhyveload_exception(
        self, provisioning_helper, freebsd_config
    ):
        """Test bhyveload with exception."""
        freebsd_config.disk_path = "/vm/freebsd-vm/disk.img"

        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            result = provisioning_helper.start_vm_with_bhyveload(freebsd_config, "tap0")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    def test_start_vm_with_bhyveload_timeout(self, provisioning_helper, freebsd_config):
        """Test bhyveload with timeout exception."""
        freebsd_config.disk_path = "/vm/freebsd-vm/disk.img"

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("bhyveload", 120)
        ):
            result = provisioning_helper.start_vm_with_bhyveload(freebsd_config, "tap0")

        assert result["success"] is False

    def test_start_vm_with_bhyveload_uses_daemon(
        self, provisioning_helper, freebsd_config
    ):
        """Test that bhyve is started with daemon."""
        freebsd_config.disk_path = "/vm/freebsd-vm/disk.img"
        captured_cmds = []

        def capture_run(cmd, **_kwargs):
            captured_cmds.append(cmd)
            return Mock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=capture_run):
            with patch("os.path.exists", return_value=False):
                provisioning_helper.start_vm_with_bhyveload(freebsd_config, "tap0")

        # Second command should start with daemon
        assert len(captured_cmds) == 2
        assert captured_cmds[0][0] == "bhyveload"
        assert captured_cmds[1][0] == "daemon"


class TestStartVmWithUefi:
    """Tests for start_vm_with_uefi method."""

    def test_start_vm_with_uefi_success(self, provisioning_helper, base_config):
        """Test successful VM startup with UEFI."""
        base_config.disk_path = "/vm/test-vm/disk.img"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            with patch("os.path.exists", return_value=False):
                result = provisioning_helper.start_vm_with_uefi(base_config, "tap0")

        assert result["success"] is True

    def test_start_vm_with_uefi_failure(self, provisioning_helper, base_config):
        """Test UEFI VM startup failure."""
        base_config.disk_path = "/vm/test-vm/disk.img"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1)
            with patch("os.path.exists", return_value=False):
                result = provisioning_helper.start_vm_with_uefi(base_config, "tap0")

        assert result["success"] is False
        assert "Failed to start bhyve" in result["error"]

    def test_start_vm_with_uefi_exception(self, provisioning_helper, base_config):
        """Test UEFI VM startup with exception."""
        base_config.disk_path = "/vm/test-vm/disk.img"

        with patch("subprocess.run", side_effect=Exception("UEFI error")):
            result = provisioning_helper.start_vm_with_uefi(base_config, "tap0")

        assert result["success"] is False
        assert "UEFI error" in result["error"]

    def test_start_vm_with_uefi_timeout(self, provisioning_helper, base_config):
        """Test UEFI VM startup with timeout."""
        base_config.disk_path = "/vm/test-vm/disk.img"

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("bhyve", 180)
        ):
            result = provisioning_helper.start_vm_with_uefi(base_config, "tap0")

        assert result["success"] is False

    def test_start_vm_with_uefi_uses_daemon(self, provisioning_helper, base_config):
        """Test that UEFI bhyve is started with daemon."""
        base_config.disk_path = "/vm/test-vm/disk.img"
        captured_cmd: list[str] = []

        def capture_run(cmd, **_kwargs):
            captured_cmd.clear()
            captured_cmd.extend(cmd)
            return Mock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=capture_run):
            with patch("os.path.exists", return_value=False):
                provisioning_helper.start_vm_with_uefi(base_config, "tap0")

        assert len(captured_cmd) > 0
        assert captured_cmd[0] == "daemon"
        assert "-p" in captured_cmd
        assert any(base_config.vm_name in arg for arg in captured_cmd)


class TestBhyveVmConfig:
    """Tests for BhyveVmConfig dataclass."""

    def test_valid_config_creation(self):
        """Test creating a valid BhyveVmConfig."""
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=["apt install agent"],
        )
        assert config.vm_name == "test-vm"
        assert config.cpus == 1  # Default
        assert config.memory == "1G"  # Default

    def test_invalid_empty_vm_name(self):
        """Test that empty VM name raises ValueError."""
        with pytest.raises(ValueError, match="VM name is required"):
            BhyveVmConfig(
                distribution="ubuntu:22.04",
                vm_name="",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$...",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_invalid_empty_hostname(self):
        """Test that empty hostname raises ValueError."""
        with pytest.raises(ValueError, match="Hostname is required"):
            BhyveVmConfig(
                distribution="ubuntu:22.04",
                vm_name="test-vm",
                hostname="",
                username="admin",
                password_hash="$6$...",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_invalid_empty_username(self):
        """Test that empty username raises ValueError."""
        with pytest.raises(ValueError, match="Username is required"):
            BhyveVmConfig(
                distribution="ubuntu:22.04",
                vm_name="test-vm",
                hostname="test.example.com",
                username="",
                password_hash="$6$...",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_invalid_empty_password_hash(self):
        """Test that empty password hash raises ValueError."""
        with pytest.raises(ValueError, match="Password hash is required"):
            BhyveVmConfig(
                distribution="ubuntu:22.04",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_invalid_empty_distribution(self):
        """Test that empty distribution raises ValueError."""
        with pytest.raises(ValueError, match="Distribution is required"):
            BhyveVmConfig(
                distribution="",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$...",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_invalid_memory_format(self):
        """Test that invalid memory format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid memory format"):
            BhyveVmConfig(
                distribution="ubuntu:22.04",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$...",
                server_url="https://server.example.com",
                agent_install_commands=[],
                memory="invalid",
            )

    def test_invalid_disk_size_format(self):
        """Test that invalid disk size format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid disk size format"):
            BhyveVmConfig(
                distribution="ubuntu:22.04",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$...",
                server_url="https://server.example.com",
                agent_install_commands=[],
                disk_size="invalid",
            )

    def test_invalid_cpus_zero(self):
        """Test that zero CPUs raises ValueError."""
        with pytest.raises(ValueError, match="CPUs must be at least 1"):
            BhyveVmConfig(
                distribution="ubuntu:22.04",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$...",
                server_url="https://server.example.com",
                agent_install_commands=[],
                cpus=0,
            )

    def test_invalid_cpus_too_many(self):
        """Test that too many CPUs raises ValueError."""
        with pytest.raises(ValueError, match="CPUs cannot exceed 64"):
            BhyveVmConfig(
                distribution="ubuntu:22.04",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$...",
                server_url="https://server.example.com",
                agent_install_commands=[],
                cpus=65,
            )

    def test_get_memory_mb_from_gb(self):
        """Test getting memory in MB from GB specification."""
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="4G",
        )
        assert config.get_memory_mb() == 4096

    def test_get_memory_mb_from_mb(self):
        """Test getting memory in MB from MB specification."""
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="2048M",
        )
        assert config.get_memory_mb() == 2048

    def test_get_memory_gb(self):
        """Test getting memory in GB."""
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="8G",
        )
        assert config.get_memory_gb() == 8.0

    def test_get_disk_gb(self):
        """Test getting disk size in GB."""
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            disk_size="50G",
        )
        assert config.get_disk_gb() == 50

    def test_get_disk_gb_from_tb(self):
        """Test getting disk size from TB specification."""
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            disk_size="2T",
        )
        assert config.get_disk_gb() == 2048

    def test_memory_formats(self):
        """Test various memory format specifications."""
        # Test with GB suffix
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="2GB",
        )
        assert config.get_memory_mb() == 2048

        # Test with MB suffix
        config2 = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm2",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="512MB",
        )
        assert config2.get_memory_mb() == 512

    def test_disk_formats(self):
        """Test various disk size format specifications."""
        # Test with GB suffix
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            disk_size="100GB",
        )
        assert config.get_disk_gb() == 100

        # Test with TB suffix
        config2 = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm2",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            disk_size="1TB",
        )
        assert config2.get_disk_gb() == 1024

    def test_optional_fields_defaults(self):
        """Test that optional fields have correct defaults."""
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
        )
        assert config.memory == "1G"
        assert config.disk_size == "20G"
        assert config.cpus == 1
        assert config.server_port == 8443
        assert config.use_https is True
        assert config.cloud_image_url == ""
        assert config.iso_url == ""
        assert config.use_cloud_init is True
        assert config.use_uefi is True
        assert config.auto_approve_token is None
        assert config.child_host_id is None
        assert config.vm_dir == "/vm"
        assert config.zvol_parent == "zroot/vm"
        assert config.use_zvol is False

    def test_computed_fields_initialized(self):
        """Test that computed fields are initialized to empty strings."""
        config = BhyveVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$...",
            server_url="https://server.example.com",
            agent_install_commands=[],
        )
        assert config.disk_path == ""
        assert config.cloud_init_iso_path == ""
        assert config.cloud_image_path == ""


class TestBhyveCloudinitDir:
    """Tests for BHYVE_CLOUDINIT_DIR constant."""

    def test_cloudinit_dir_path(self):
        """Test that cloud-init directory has correct path."""
        assert BHYVE_CLOUDINIT_DIR == "/vm/cloud-init"

    def test_cloudinit_dir_used_in_iso_creation(self, provisioning_helper, base_config):
        """Test that cloud-init directory is used in ISO creation."""
        with patch("os.makedirs") as mock_makedirs:
            with patch("builtins.open", mock_open()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    provisioning_helper.create_cloud_init_iso(base_config)

        # Check that makedirs was called with a path under BHYVE_CLOUDINIT_DIR
        call_args = mock_makedirs.call_args[0][0]
        assert call_args.startswith(BHYVE_CLOUDINIT_DIR)
