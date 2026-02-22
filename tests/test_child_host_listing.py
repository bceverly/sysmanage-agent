"""
Comprehensive unit tests for child_host_listing module.

Tests cover:
- is_safe_vbox_path function for VirtualBox path validation
- ChildHostListing class initialization
- Hyper-V VM listing
- LXD container listing and helper methods
- KVM VM listing and parsing
- VirtualBox VM listing
- VMM (OpenBSD) VM listing
- bhyve (FreeBSD) VM listing
- Error handling for all hypervisors
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import json
import logging
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_listing import (
    ChildHostListing,
    is_safe_vbox_path,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def listing(logger):
    """Create a ChildHostListing instance for testing."""
    return ChildHostListing(logger)


class TestIsSafeVboxPath:
    """Tests for is_safe_vbox_path function."""

    def test_empty_path_not_safe(self):
        """Test that empty path is not safe."""
        assert is_safe_vbox_path("") is False
        assert is_safe_vbox_path(None) is False

    def test_usr_bin_path_safe(self):
        """Test that /usr/bin path is safe."""
        assert is_safe_vbox_path("/usr/bin/VBoxManage") is True

    def test_usr_local_bin_path_safe(self):
        """Test that /usr/local/bin path is safe."""
        assert is_safe_vbox_path("/usr/local/bin/VBoxManage") is True

    def test_opt_virtualbox_path_safe(self):
        """Test that /opt/VirtualBox path is safe."""
        assert is_safe_vbox_path("/opt/VirtualBox/VBoxManage") is True

    def test_macos_applications_path_safe(self):
        """Test that macOS Applications path is safe."""
        path = "/Applications/VirtualBox.app/Contents/MacOS/VBoxManage"
        assert is_safe_vbox_path(path) is True

    def test_unsafe_path_rejected(self):
        """Test that unsafe paths are rejected."""
        assert is_safe_vbox_path("/tmp/VBoxManage") is False
        assert is_safe_vbox_path("/home/user/VBoxManage") is False
        assert is_safe_vbox_path("/var/tmp/VBoxManage") is False

    def test_relative_path_rejected(self):
        """Test that relative paths are rejected."""
        with patch("os.path.abspath", return_value="/tmp/evil/VBoxManage"):
            assert is_safe_vbox_path("./VBoxManage") is False

    def test_windows_program_files_path_safe(self):
        """Test Windows Program Files path is safe on Windows."""
        with patch("platform.system", return_value="Windows"):
            # This normalized path would contain Oracle\VirtualBox under Program Files
            with patch(
                "os.path.normpath",
                return_value="C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe",
            ):
                with patch(
                    "os.path.abspath",
                    return_value="C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe",
                ):
                    assert (
                        is_safe_vbox_path(
                            "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"
                        )
                        is True
                    )

    def test_windows_program_files_x86_path_safe(self):
        """Test Windows Program Files (x86) path is safe on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch(
                "os.path.normpath",
                return_value="C:\\Program Files (x86)\\Oracle\\VirtualBox\\VBoxManage.exe",
            ):
                with patch(
                    "os.path.abspath",
                    return_value="C:\\Program Files (x86)\\Oracle\\VirtualBox\\VBoxManage.exe",
                ):
                    assert (
                        is_safe_vbox_path(
                            "C:\\Program Files (x86)\\Oracle\\VirtualBox\\VBoxManage.exe"
                        )
                        is True
                    )

    def test_windows_unsafe_path_rejected(self):
        """Test Windows unsafe path is rejected."""
        with patch("platform.system", return_value="Windows"):
            with patch(
                "os.path.normpath", return_value="C:\\Users\\evil\\VBoxManage.exe"
            ):
                with patch(
                    "os.path.abspath", return_value="C:\\Users\\evil\\VBoxManage.exe"
                ):
                    assert is_safe_vbox_path("C:\\Users\\evil\\VBoxManage.exe") is False


class TestChildHostListingInit:
    """Tests for ChildHostListing initialization."""

    def test_init_sets_logger(self, listing, logger):
        """Test that __init__ sets logger."""
        assert listing.logger == logger

    def test_init_creates_wsl_listing(self, listing):
        """Test that __init__ creates WSL listing delegate."""
        assert listing._wsl_listing is not None


class TestListWslInstances:
    """Tests for list_wsl_instances method."""

    def test_list_wsl_delegates_to_wsl_listing(self, listing):
        """Test that list_wsl_instances delegates to _wsl_listing."""
        with patch.object(
            listing._wsl_listing,
            "list_wsl_instances",
            return_value=[{"child_type": "wsl"}],
        ):
            result = listing.list_wsl_instances()

        assert result == [{"child_type": "wsl"}]


class TestListHypervVms:
    """Tests for list_hyperv_vms method."""

    def test_list_hyperv_vms_success(self, listing):
        """Test listing Hyper-V VMs successfully."""
        vm_data = [
            {"Name": "test-vm-1", "State": "2", "VMId": "guid-1"},
            {"Name": "test-vm-2", "State": "3", "VMId": "guid-2"},
        ]
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(vm_data)

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_hyperv_vms()

        assert len(result) == 2
        assert result[0]["child_type"] == "hyperv"
        assert result[0]["child_name"] == "test-vm-1"
        assert result[0]["status"] == "running"
        assert result[1]["status"] == "stopped"

    def test_list_hyperv_vms_single_vm(self, listing):
        """Test listing Hyper-V with single VM (dict instead of array)."""
        vm_data = {"Name": "single-vm", "State": "running", "VMId": "guid-1"}
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(vm_data)

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_hyperv_vms()

        assert len(result) == 1
        assert result[0]["child_name"] == "single-vm"

    def test_list_hyperv_vms_state_mapping_running(self, listing):
        """Test Hyper-V running state mapping."""
        vm_data = [{"Name": "vm", "State": "running", "VMId": "guid"}]
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(vm_data)

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_hyperv_vms()

        assert result[0]["status"] == "running"

    def test_list_hyperv_vms_state_mapping_off(self, listing):
        """Test Hyper-V off state mapping."""
        vm_data = [{"Name": "vm", "State": "off", "VMId": "guid"}]
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(vm_data)

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_hyperv_vms()

        assert result[0]["status"] == "stopped"

    def test_list_hyperv_vms_state_mapping_unknown(self, listing):
        """Test Hyper-V unknown state is passed through."""
        vm_data = [{"Name": "vm", "State": "paused", "VMId": "guid"}]
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(vm_data)

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_hyperv_vms()

        assert result[0]["status"] == "paused"

    def test_list_hyperv_vms_command_failure(self, listing):
        """Test Hyper-V listing when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_hyperv_vms()

        assert result == []

    def test_list_hyperv_vms_empty_output(self, listing):
        """Test Hyper-V listing with empty output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_hyperv_vms()

        assert result == []

    def test_list_hyperv_vms_json_decode_error(self, listing):
        """Test Hyper-V listing with invalid JSON."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "not valid json"

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_hyperv_vms()

        assert result == []

    def test_list_hyperv_vms_exception(self, listing):
        """Test Hyper-V listing with exception."""
        with patch("subprocess.run", side_effect=Exception("PowerShell error")):
            result = listing.list_hyperv_vms()

        assert result == []


class TestListLxdContainers:
    """Tests for list_lxd_containers method."""

    def test_list_lxd_containers_success(self, listing):
        """Test listing LXD containers successfully."""
        container_data = [
            {
                "name": "container-1",
                "status": "Running",
                "type": "container",
                "architecture": "x86_64",
                "created_at": "2024-01-01T00:00:00Z",
                "config": {
                    "image.os": "ubuntu",
                    "image.release": "jammy",
                },
                "state": {
                    "network": {
                        "eth0": {
                            "addresses": [
                                {"family": "inet", "address": "10.0.0.5"},
                                {"family": "inet6", "address": "2001:db8::1"},
                            ]
                        }
                    }
                },
            }
        ]
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(container_data)

        mock_hostname_result = Mock()
        mock_hostname_result.returncode = 0
        mock_hostname_result.stdout = "container-1.example.com"

        with patch("subprocess.run", side_effect=[mock_result, mock_hostname_result]):
            result = listing.list_lxd_containers()

        assert len(result) == 1
        assert result[0]["child_type"] == "lxd"
        assert result[0]["child_name"] == "container-1"
        assert result[0]["status"] == "running"
        assert result[0]["type"] == "container"
        assert result[0]["architecture"] == "x86_64"
        assert result[0]["ipv4_address"] == "10.0.0.5"
        assert result[0]["ipv6_address"] == "2001:db8::1"

    def test_list_lxd_containers_stopped(self, listing):
        """Test listing stopped LXD container."""
        container_data = [
            {
                "name": "stopped-container",
                "status": "Stopped",
                "type": "container",
                "architecture": "x86_64",
                "created_at": "2024-01-01T00:00:00Z",
                "config": {},
            }
        ]
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(container_data)

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_lxd_containers()

        assert result[0]["status"] == "stopped"
        assert result[0]["ipv4_address"] is None
        assert result[0]["ipv6_address"] is None
        assert result[0]["hostname"] is None

    def test_list_lxd_containers_unknown_status(self, listing):
        """Test LXD container with unknown status."""
        container_data = [
            {
                "name": "container",
                "status": "Freezing",
                "type": "container",
                "architecture": "x86_64",
                "created_at": "2024-01-01T00:00:00Z",
                "config": {},
            }
        ]
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(container_data)

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_lxd_containers()

        assert result[0]["status"] == "freezing"

    def test_list_lxd_containers_command_failure(self, listing):
        """Test LXD listing when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_lxd_containers()

        assert result == []

    def test_list_lxd_containers_json_decode_error(self, listing):
        """Test LXD listing with invalid JSON."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "not valid json"

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_lxd_containers()

        assert result == []

    def test_list_lxd_containers_file_not_found(self, listing):
        """Test LXD listing when lxc command not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = listing.list_lxd_containers()

        assert result == []

    def test_list_lxd_containers_exception(self, listing):
        """Test LXD listing with generic exception."""
        with patch("subprocess.run", side_effect=Exception("Unknown error")):
            result = listing.list_lxd_containers()

        assert result == []


class TestExtractContainerIps:
    """Tests for _extract_container_ips method."""

    def test_extract_ips_not_running(self, listing):
        """Test IP extraction when container not running."""
        ipv4, ipv6 = listing._extract_container_ips({}, "stopped")
        assert ipv4 is None
        assert ipv6 is None

    def test_extract_ips_no_state(self, listing):
        """Test IP extraction when no state information."""
        ipv4, ipv6 = listing._extract_container_ips({}, "running")
        assert ipv4 is None
        assert ipv6 is None

    def test_extract_ips_with_addresses(self, listing):
        """Test IP extraction with valid addresses."""
        container = {
            "state": {
                "network": {
                    "eth0": {
                        "addresses": [
                            {"family": "inet", "address": "10.0.0.100"},
                            {"family": "inet6", "address": "2001:db8::100"},
                        ]
                    }
                }
            }
        }
        ipv4, ipv6 = listing._extract_container_ips(container, "running")
        assert ipv4 == "10.0.0.100"
        assert ipv6 == "2001:db8::100"

    def test_extract_ips_skips_loopback(self, listing):
        """Test IP extraction skips loopback interface."""
        container = {
            "state": {
                "network": {
                    "lo": {
                        "addresses": [
                            {"family": "inet", "address": "127.0.0.1"},
                        ]
                    },
                    "eth0": {
                        "addresses": [
                            {"family": "inet", "address": "10.0.0.100"},
                        ]
                    },
                }
            }
        }
        ipv4, _ipv6 = listing._extract_container_ips(container, "running")
        assert ipv4 == "10.0.0.100"

    def test_extract_ips_skips_link_local_ipv6(self, listing):
        """Test IP extraction skips link-local IPv6 addresses."""
        container = {
            "state": {
                "network": {
                    "eth0": {
                        "addresses": [
                            {"family": "inet6", "address": "fe80::1"},
                            {"family": "inet6", "address": "2001:db8::1"},
                        ]
                    }
                }
            }
        }
        _ipv4, ipv6 = listing._extract_container_ips(container, "running")
        assert ipv6 == "2001:db8::1"


class TestExtractIpsFromInterface:
    """Tests for _extract_ips_from_interface method."""

    def test_extract_ipv4_and_ipv6(self, listing):
        """Test extracting both IPv4 and IPv6 from interface."""
        iface_data = {
            "addresses": [
                {"family": "inet", "address": "192.168.1.100"},
                {"family": "inet6", "address": "2001:db8::100"},
            ]
        }
        ipv4, ipv6 = listing._extract_ips_from_interface(iface_data, None, None)
        assert ipv4 == "192.168.1.100"
        assert ipv6 == "2001:db8::100"

    def test_extract_preserves_existing_ipv4(self, listing):
        """Test that existing IPv4 is preserved."""
        iface_data = {
            "addresses": [
                {"family": "inet", "address": "192.168.1.200"},
            ]
        }
        ipv4, _ipv6 = listing._extract_ips_from_interface(
            iface_data, "192.168.1.100", None
        )
        assert ipv4 == "192.168.1.100"

    def test_extract_preserves_existing_ipv6(self, listing):
        """Test that existing IPv6 is preserved."""
        iface_data = {
            "addresses": [
                {"family": "inet6", "address": "2001:db8::200"},
            ]
        }
        _ipv4, ipv6 = listing._extract_ips_from_interface(
            iface_data, None, "2001:db8::100"
        )
        assert ipv6 == "2001:db8::100"

    def test_extract_empty_addresses(self, listing):
        """Test extracting from interface with no addresses."""
        iface_data = {"addresses": []}
        ipv4, ipv6 = listing._extract_ips_from_interface(iface_data, None, None)
        assert ipv4 is None
        assert ipv6 is None


class TestGetLxdHostname:
    """Tests for _get_lxd_hostname method."""

    def test_get_hostname_from_etc_hostname(self, listing):
        """Test getting hostname from /etc/hostname."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "container.example.com"

        with patch("subprocess.run", return_value=mock_result):
            result = listing._get_lxd_hostname("container")

        assert result == "container.example.com"

    def test_get_hostname_fallback_to_hostname_f(self, listing):
        """Test fallback to hostname -f command."""
        mock_etc_fail = Mock(returncode=1, stdout="")
        mock_hostname_f = Mock(returncode=0, stdout="container.example.com")

        with patch("subprocess.run", side_effect=[mock_etc_fail, mock_hostname_f]):
            result = listing._get_lxd_hostname("container")

        assert result == "container.example.com"

    def test_get_hostname_skip_localhost(self, listing):
        """Test that localhost hostname is skipped."""
        mock_etc = Mock(returncode=0, stdout="")
        mock_hostname_f = Mock(returncode=0, stdout="localhost")
        mock_hostname = Mock(returncode=0, stdout="container")

        with patch(
            "subprocess.run", side_effect=[mock_etc, mock_hostname_f, mock_hostname]
        ):
            result = listing._get_lxd_hostname("container")

        assert result == "container"

    def test_get_hostname_fallback_to_hostname(self, listing):
        """Test fallback to hostname command."""
        mock_etc = Mock(returncode=0, stdout="")
        mock_hostname_f = Mock(returncode=1, stdout="")
        mock_hostname = Mock(returncode=0, stdout="container")

        with patch(
            "subprocess.run", side_effect=[mock_etc, mock_hostname_f, mock_hostname]
        ):
            result = listing._get_lxd_hostname("container")

        assert result == "container"

    def test_get_hostname_exception(self, listing):
        """Test hostname retrieval with exception."""
        with patch("subprocess.run", side_effect=Exception("Error")):
            result = listing._get_lxd_hostname("container")

        assert result is None


class TestParseLxdDistribution:
    """Tests for _parse_lxd_distribution method."""

    def test_parse_ubuntu_distribution(self, listing):
        """Test parsing Ubuntu distribution."""
        config = {
            "image.os": "ubuntu",
            "image.release": "jammy",
        }
        result = listing._parse_lxd_distribution(config)
        assert result["distribution_name"] == "Ubuntu"
        assert result["distribution_version"] == "22.04"

    def test_parse_debian_distribution(self, listing):
        """Test parsing Debian distribution."""
        config = {
            "image.os": "debian",
            "image.release": "bookworm",
        }
        result = listing._parse_lxd_distribution(config)
        assert result["distribution_name"] == "Debian"
        assert result["distribution_version"] == "12"

    def test_parse_rocky_linux_distribution(self, listing):
        """Test parsing Rocky Linux distribution."""
        config = {
            "image.os": "rockylinux",
            "image.release": "9",
        }
        result = listing._parse_lxd_distribution(config)
        assert result["distribution_name"] == "Rocky Linux"
        assert result["distribution_version"] == "9"

    def test_parse_oracle_linux_distribution(self, listing):
        """Test parsing Oracle Linux distribution."""
        config = {
            "image.os": "oraclelinux",
            "image.release": "9",
        }
        result = listing._parse_lxd_distribution(config)
        assert result["distribution_name"] == "Oracle Linux"
        assert result["distribution_version"] == "9"

    def test_parse_from_description(self, listing):
        """Test parsing distribution from description when os not available."""
        config = {
            "image.description": "Ubuntu 24.04 LTS amd64 (release)",
        }
        result = listing._parse_lxd_distribution(config)
        assert result["distribution_name"] == "Ubuntu"
        assert result["distribution_version"] == "24.04"

    def test_parse_unknown_distribution(self, listing):
        """Test parsing unknown distribution."""
        config = {
            "image.os": "customos",
            "image.release": "1.0",
        }
        result = listing._parse_lxd_distribution(config)
        assert result["distribution_name"] == "Customos"
        assert result["distribution_version"] == "1.0"

    def test_parse_empty_config(self, listing):
        """Test parsing empty config."""
        result = listing._parse_lxd_distribution({})
        assert result["distribution_name"] is None
        assert result["distribution_version"] is None


class TestParseKvmVmStatus:
    """Tests for _parse_kvm_vm_status method."""

    def test_running_status(self, listing):
        """Test parsing running status."""
        assert listing._parse_kvm_vm_status("running") == "running"

    def test_shut_off_status(self, listing):
        """Test parsing shut off status."""
        assert listing._parse_kvm_vm_status("shut off") == "stopped"

    def test_stopped_status(self, listing):
        """Test parsing stopped status."""
        assert listing._parse_kvm_vm_status("stopped") == "stopped"

    def test_other_status(self, listing):
        """Test parsing other status is passed through."""
        assert listing._parse_kvm_vm_status("paused") == "paused"


class TestParseKvmVmLine:
    """Tests for _parse_kvm_vm_line method."""

    def test_parse_running_vm(self, listing):
        """Test parsing running VM line."""
        line = "1    test-vm    running"
        result = listing._parse_kvm_vm_line(line)

        assert result["child_type"] == "kvm"
        assert result["child_name"] == "test-vm"
        assert result["status"] == "running"
        assert result["vm_id"] == "1"

    def test_parse_stopped_vm(self, listing):
        """Test parsing stopped VM line."""
        line = "-    stopped-vm    shut off"
        result = listing._parse_kvm_vm_line(line)

        assert result["child_name"] == "stopped-vm"
        assert result["status"] == "stopped"
        assert result["vm_id"] is None

    def test_parse_empty_line(self, listing):
        """Test parsing empty line returns None."""
        assert listing._parse_kvm_vm_line("") is None
        assert listing._parse_kvm_vm_line("   ") is None

    def test_parse_invalid_line(self, listing):
        """Test parsing invalid line with not enough parts."""
        assert listing._parse_kvm_vm_line("only_one") is None


class TestListKvmVms:
    """Tests for list_kvm_vms method."""

    def test_list_kvm_vms_success(self, listing):
        """Test listing KVM VMs successfully."""
        virsh_output = """ Id   Name       State
-----------------------------
 1    vm-1       running
 -    vm-2       shut off
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = virsh_output

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_kvm_vms()

        assert len(result) == 2
        assert result[0]["child_type"] == "kvm"
        assert result[0]["child_name"] == "vm-1"
        assert result[0]["status"] == "running"
        assert result[1]["child_name"] == "vm-2"
        assert result[1]["status"] == "stopped"

    def test_list_kvm_vms_command_failure(self, listing):
        """Test KVM listing when virsh fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_kvm_vms()

        assert result == []

    def test_list_kvm_vms_file_not_found(self, listing):
        """Test KVM listing when virsh not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = listing.list_kvm_vms()

        assert result == []

    def test_list_kvm_vms_exception(self, listing):
        """Test KVM listing with exception."""
        with patch("subprocess.run", side_effect=Exception("virsh error")):
            result = listing.list_kvm_vms()

        assert result == []


class TestFindVboxmanagePath:
    """Tests for _find_vboxmanage_path method."""

    def test_find_vboxmanage_in_path(self, listing):
        """Test finding VBoxManage in PATH."""
        with patch("shutil.which", return_value="/usr/bin/VBoxManage"):
            result = listing._find_vboxmanage_path()

        assert result == "/usr/bin/VBoxManage"

    def test_find_vboxmanage_not_found_linux(self, listing):
        """Test VBoxManage not found on Linux."""
        with patch("shutil.which", return_value=None):
            with patch("platform.system", return_value="Linux"):
                result = listing._find_vboxmanage_path()

        assert result is None

    def test_find_vboxmanage_windows_common_path(self, listing):
        """Test finding VBoxManage in Windows common path."""
        with patch("shutil.which", return_value=None):
            with patch("platform.system", return_value="Windows"):
                with patch.dict("os.environ", {"ProgramFiles": "C:\\Program Files"}):
                    with patch("os.path.exists", return_value=True):
                        result = listing._find_vboxmanage_path()

        # Check the result contains the expected components, regardless of separator
        assert result is not None
        assert "Program Files" in result
        assert "Oracle" in result
        assert "VirtualBox" in result
        assert "VBoxManage.exe" in result

    def test_find_vboxmanage_windows_not_found(self, listing):
        """Test VBoxManage not found on Windows."""
        with patch("shutil.which", return_value=None):
            with patch("platform.system", return_value="Windows"):
                with patch.dict(
                    "os.environ",
                    {
                        "ProgramFiles": "C:\\Program Files",
                        "ProgramFiles(x86)": "C:\\Program Files (x86)",
                    },
                ):
                    with patch("os.path.exists", return_value=False):
                        result = listing._find_vboxmanage_path()

        assert result is None


class TestGetSubprocessCreationflags:
    """Tests for _get_subprocess_creationflags method."""

    def test_creationflags_windows(self, listing):
        """Test creation flags on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch.object(
                __import__("subprocess"), "CREATE_NO_WINDOW", 0x08000000, create=True
            ):
                result = listing._get_subprocess_creationflags()

        # Should return CREATE_NO_WINDOW on Windows
        assert isinstance(result, int)

    def test_creationflags_linux(self, listing):
        """Test creation flags on Linux."""
        with patch("platform.system", return_value="Linux"):
            result = listing._get_subprocess_creationflags()

        assert result == 0


class TestParseVirtualboxVmLine:
    """Tests for _parse_virtualbox_vm_line method."""

    def test_parse_valid_vm_line(self, listing):
        """Test parsing valid VirtualBox VM line."""
        line = '"test-vm" {12345678-1234-1234-1234-123456789abc}'

        mock_state_result = Mock()
        mock_state_result.returncode = 0
        mock_state_result.stdout = 'VMState="running"'

        with patch("subprocess.run", return_value=mock_state_result):
            result = listing._parse_virtualbox_vm_line(line, "/usr/bin/VBoxManage", 0)

        assert result["child_type"] == "virtualbox"
        assert result["child_name"] == "test-vm"
        assert result["vm_id"] == "12345678-1234-1234-1234-123456789abc"
        assert result["status"] == "running"

    def test_parse_empty_line(self, listing):
        """Test parsing empty line returns None."""
        assert listing._parse_virtualbox_vm_line("", "/usr/bin/VBoxManage", 0) is None
        assert (
            listing._parse_virtualbox_vm_line("   ", "/usr/bin/VBoxManage", 0) is None
        )

    def test_parse_invalid_line(self, listing):
        """Test parsing invalid line returns None."""
        assert (
            listing._parse_virtualbox_vm_line("invalid line", "/usr/bin/VBoxManage", 0)
            is None
        )


class TestGetVirtualboxVmStatus:
    """Tests for _get_virtualbox_vm_status method."""

    def test_get_status_running(self, listing):
        """Test getting running status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'VMState="running"\nOther="data"'

        with patch("subprocess.run", return_value=mock_result):
            result = listing._get_virtualbox_vm_status("/usr/bin/VBoxManage", "uuid", 0)

        assert result == "running"

    def test_get_status_poweroff(self, listing):
        """Test getting poweroff status (mapped to stopped)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'VMState="poweroff"'

        with patch("subprocess.run", return_value=mock_result):
            result = listing._get_virtualbox_vm_status("/usr/bin/VBoxManage", "uuid", 0)

        assert result == "stopped"

    def test_get_status_aborted(self, listing):
        """Test getting aborted status (mapped to stopped)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'VMState="aborted"'

        with patch("subprocess.run", return_value=mock_result):
            result = listing._get_virtualbox_vm_status("/usr/bin/VBoxManage", "uuid", 0)

        assert result == "stopped"

    def test_get_status_saved(self, listing):
        """Test getting saved status (mapped to stopped)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'VMState="saved"'

        with patch("subprocess.run", return_value=mock_result):
            result = listing._get_virtualbox_vm_status("/usr/bin/VBoxManage", "uuid", 0)

        assert result == "stopped"

    def test_get_status_other(self, listing):
        """Test getting other status is passed through."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'VMState="paused"'

        with patch("subprocess.run", return_value=mock_result):
            result = listing._get_virtualbox_vm_status("/usr/bin/VBoxManage", "uuid", 0)

        assert result == "paused"

    def test_get_status_command_failure(self, listing):
        """Test getting status when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = listing._get_virtualbox_vm_status("/usr/bin/VBoxManage", "uuid", 0)

        assert result == "unknown"

    def test_get_status_no_vmstate(self, listing):
        """Test getting status when no VMState in output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'OtherKey="value"'

        with patch("subprocess.run", return_value=mock_result):
            result = listing._get_virtualbox_vm_status("/usr/bin/VBoxManage", "uuid", 0)

        assert result == "unknown"


class TestListVirtualboxVms:
    """Tests for list_virtualbox_vms method."""

    def test_list_virtualbox_vms_success(self, listing):
        """Test listing VirtualBox VMs successfully."""
        vbox_output = '"vm-1" {guid-1}\n"vm-2" {guid-2}'

        mock_list_result = Mock()
        mock_list_result.returncode = 0
        mock_list_result.stdout = vbox_output

        mock_state_result = Mock()
        mock_state_result.returncode = 0
        mock_state_result.stdout = 'VMState="running"'

        with patch.object(
            listing, "_find_vboxmanage_path", return_value="/usr/bin/VBoxManage"
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_listing.is_safe_vbox_path",
                return_value=True,
            ):
                with patch(
                    "subprocess.run",
                    side_effect=[
                        mock_list_result,
                        mock_state_result,
                        mock_state_result,
                    ],
                ):
                    result = listing.list_virtualbox_vms()

        assert len(result) == 2
        assert result[0]["child_type"] == "virtualbox"

    def test_list_virtualbox_vms_vboxmanage_not_found(self, listing):
        """Test VirtualBox listing when VBoxManage not found."""
        with patch.object(listing, "_find_vboxmanage_path", return_value=None):
            result = listing.list_virtualbox_vms()

        assert result == []

    def test_list_virtualbox_vms_unsafe_path(self, listing):
        """Test VirtualBox listing with unsafe VBoxManage path."""
        with patch.object(
            listing, "_find_vboxmanage_path", return_value="/tmp/VBoxManage"
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_listing.is_safe_vbox_path",
                return_value=False,
            ):
                result = listing.list_virtualbox_vms()

        assert result == []

    def test_list_virtualbox_vms_command_failure(self, listing):
        """Test VirtualBox listing when list command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch.object(
            listing, "_find_vboxmanage_path", return_value="/usr/bin/VBoxManage"
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_listing.is_safe_vbox_path",
                return_value=True,
            ):
                with patch("subprocess.run", return_value=mock_result):
                    result = listing.list_virtualbox_vms()

        assert result == []

    def test_list_virtualbox_vms_exception(self, listing):
        """Test VirtualBox listing with exception."""
        with patch.object(
            listing, "_find_vboxmanage_path", return_value="/usr/bin/VBoxManage"
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_listing.is_safe_vbox_path",
                return_value=True,
            ):
                with patch("subprocess.run", side_effect=Exception("VBox error")):
                    result = listing.list_virtualbox_vms()

        assert result == []


class TestParseVmmVmLine:
    """Tests for _parse_vmm_vm_line method."""

    def test_parse_running_vm(self, listing):
        """Test parsing running VMM VM line."""
        line = "1   12345   2   4G   2G   ttyp0   root   running   test-vm"

        with patch.object(listing, "_get_vmm_metadata", return_value=None):
            result = listing._parse_vmm_vm_line(line)

        assert result["child_type"] == "vmm"
        assert result["child_name"] == "test-vm"
        assert result["status"] == "running"
        assert result["vm_id"] == "1"
        assert result["vcpus"] == "2"
        assert result["memory"] == "4G"
        assert result["current_memory"] == "2G"
        assert result["tty"] == "ttyp0"
        assert result["owner"] == "root"

    def test_parse_stopped_vm(self, listing):
        """Test parsing stopped VMM VM line."""
        line = "-   -   2   2G   0   -   root   stopped   test-vm"

        with patch.object(listing, "_get_vmm_metadata", return_value=None):
            result = listing._parse_vmm_vm_line(line)

        assert result["child_name"] == "test-vm"
        assert result["status"] == "stopped"
        assert result["vm_id"] is None
        assert result["tty"] is None

    def test_parse_vm_with_metadata(self, listing):
        """Test parsing VMM VM with metadata."""
        line = "1   12345   2   4G   2G   -   root   running   test-vm"
        metadata = {
            "hostname": "test.example.com",
            "distribution": {
                "distribution_name": "OpenBSD",
                "distribution_version": "7.4",
            },
        }

        with patch.object(listing, "_get_vmm_metadata", return_value=metadata):
            result = listing._parse_vmm_vm_line(line)

        assert result["hostname"] == "test.example.com"
        assert result["distribution"]["distribution_name"] == "OpenBSD"

    def test_parse_empty_line(self, listing):
        """Test parsing empty line returns None."""
        assert listing._parse_vmm_vm_line("") is None
        assert listing._parse_vmm_vm_line("   ") is None

    def test_parse_invalid_line(self, listing):
        """Test parsing line with not enough columns."""
        assert listing._parse_vmm_vm_line("1 2 3 4") is None


class TestListVmmVms:
    """Tests for list_vmm_vms method."""

    def test_list_vmm_vms_success(self, listing):
        """Test listing VMM VMs successfully."""
        vmctl_output = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER     STATE NAME
    1  1234     2      4G      2G   ttyp0         root   running test-vm
    -     -     2      2G       0       -         root   stopped stopped-vm
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(listing, "_get_vmm_metadata", return_value=None):
                result = listing.list_vmm_vms()

        assert len(result) == 2
        assert result[0]["child_type"] == "vmm"
        assert result[0]["child_name"] == "test-vm"
        assert result[0]["status"] == "running"
        assert result[1]["child_name"] == "stopped-vm"
        assert result[1]["status"] == "stopped"

    def test_list_vmm_vms_command_failure(self, listing):
        """Test VMM listing when vmctl fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "vmctl: error"

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_vmm_vms()

        assert result == []

    def test_list_vmm_vms_empty_output(self, listing):
        """Test VMM listing with only header line."""
        vmctl_output = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER     STATE NAME
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch("subprocess.run", return_value=mock_result):
            result = listing.list_vmm_vms()

        assert result == []

    def test_list_vmm_vms_file_not_found(self, listing):
        """Test VMM listing when vmctl not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = listing.list_vmm_vms()

        assert result == []

    def test_list_vmm_vms_exception(self, listing):
        """Test VMM listing with exception."""
        with patch("subprocess.run", side_effect=Exception("vmctl error")):
            result = listing.list_vmm_vms()

        assert result == []


class TestGetVmmMetadata:
    """Tests for _get_vmm_metadata method."""

    def test_get_metadata_success(self, listing, tmp_path):
        """Test getting VMM metadata successfully."""
        metadata = {
            "hostname": "vm.example.com",
            "distribution": {
                "distribution_name": "OpenBSD",
                "distribution_version": "7.4",
            },
        }
        metadata_file = tmp_path / "test-vm.json"
        metadata_file.write_text(json.dumps(metadata))

        with patch(
            "src.sysmanage_agent.operations.child_host_listing.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            result = listing._get_vmm_metadata("test-vm")

        assert result["hostname"] == "vm.example.com"
        assert result["distribution"]["distribution_name"] == "OpenBSD"

    def test_get_metadata_file_not_found(self, listing, tmp_path):
        """Test getting VMM metadata when file doesn't exist."""
        with patch(
            "src.sysmanage_agent.operations.child_host_listing.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            result = listing._get_vmm_metadata("nonexistent-vm")

        assert result is None

    def test_get_metadata_invalid_json(self, listing, tmp_path):
        """Test getting VMM metadata with invalid JSON."""
        metadata_file = tmp_path / "test-vm.json"
        metadata_file.write_text("not valid json")

        with patch(
            "src.sysmanage_agent.operations.child_host_listing.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            result = listing._get_vmm_metadata("test-vm")

        assert result is None


class TestCreateBhyveVmDict:
    """Tests for _create_bhyve_vm_dict method."""

    def test_create_bhyve_vm_dict_running(self, listing):
        """Test creating bhyve VM dict for running VM."""
        with patch(
            "src.sysmanage_agent.operations.child_host_listing.load_bhyve_metadata",
            return_value={
                "hostname": "vm.example.com",
                "distribution": {
                    "distribution_name": "FreeBSD",
                    "distribution_version": "14.0",
                },
            },
        ):
            result = listing._create_bhyve_vm_dict("test-vm", "running")

        assert result["child_type"] == "bhyve"
        assert result["child_name"] == "test-vm"
        assert result["status"] == "running"
        assert result["hostname"] == "vm.example.com"
        assert result["distribution"]["distribution_name"] == "FreeBSD"

    def test_create_bhyve_vm_dict_no_metadata(self, listing):
        """Test creating bhyve VM dict without metadata."""
        with patch(
            "src.sysmanage_agent.operations.child_host_listing.load_bhyve_metadata",
            return_value=None,
        ):
            result = listing._create_bhyve_vm_dict("test-vm", "stopped")

        assert result["child_type"] == "bhyve"
        assert result["child_name"] == "test-vm"
        assert result["status"] == "stopped"
        assert result["hostname"] is None
        assert result["distribution"] is None


class TestListRunningBhyveVms:
    """Tests for _list_running_bhyve_vms method."""

    def test_list_running_vms_success(self, listing, tmp_path):
        """Test listing running bhyve VMs."""
        vmm_dir = tmp_path / "vmm"
        vmm_dir.mkdir()
        (vmm_dir / "vm1").touch()
        (vmm_dir / "vm2").touch()

        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=["vm1", "vm2"]):
                with patch.object(
                    listing, "_create_bhyve_vm_dict", return_value={"child_name": "vm"}
                ):
                    vms, running_names = listing._list_running_bhyve_vms()

        assert len(vms) == 2
        assert "vm1" in running_names
        assert "vm2" in running_names

    def test_list_running_vms_no_vmm_dir(self, listing):
        """Test listing running VMs when /dev/vmm doesn't exist."""
        with patch("os.path.isdir", return_value=False):
            vms, running_names = listing._list_running_bhyve_vms()

        assert vms == []
        assert running_names == set()

    def test_list_running_vms_permission_error(self, listing):
        """Test listing running VMs with permission error."""
        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", side_effect=PermissionError()):
                vms, running_names = listing._list_running_bhyve_vms()

        assert vms == []
        assert running_names == set()


class TestIsValidBhyveVmDir:
    """Tests for _is_valid_bhyve_vm_dir method."""

    def test_valid_vm_dir(self, listing, tmp_path):
        """Test valid bhyve VM directory."""
        vm_dir = tmp_path / "test-vm"
        vm_dir.mkdir()
        (vm_dir / "test-vm.img").touch()

        result = listing._is_valid_bhyve_vm_dir(str(tmp_path), "test-vm")
        assert result is True

    def test_hidden_directory_rejected(self, listing, tmp_path):
        """Test hidden directory is rejected."""
        result = listing._is_valid_bhyve_vm_dir(str(tmp_path), ".hidden")
        assert result is False

    def test_special_directories_rejected(self, listing, tmp_path):
        """Test special directories are rejected."""
        assert listing._is_valid_bhyve_vm_dir(str(tmp_path), "images") is False
        assert listing._is_valid_bhyve_vm_dir(str(tmp_path), "cloud-init") is False
        assert listing._is_valid_bhyve_vm_dir(str(tmp_path), "metadata") is False

    def test_not_a_directory_rejected(self, listing, tmp_path):
        """Test non-directory entry is rejected."""
        file_path = tmp_path / "not-a-dir"
        file_path.touch()

        result = listing._is_valid_bhyve_vm_dir(str(tmp_path), "not-a-dir")
        assert result is False

    def test_no_disk_image_rejected(self, listing, tmp_path):
        """Test VM directory without disk image is rejected."""
        vm_dir = tmp_path / "test-vm"
        vm_dir.mkdir()

        result = listing._is_valid_bhyve_vm_dir(str(tmp_path), "test-vm")
        assert result is False


class TestListStoppedBhyveVms:
    """Tests for _list_stopped_bhyve_vms method."""

    def test_list_stopped_vms_success(self, listing, tmp_path):
        """Test listing stopped bhyve VMs."""
        vm_dir = tmp_path / "stopped-vm"
        vm_dir.mkdir()
        (vm_dir / "stopped-vm.img").touch()

        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=["stopped-vm"]):
                with patch.object(listing, "_is_valid_bhyve_vm_dir", return_value=True):
                    with patch.object(
                        listing,
                        "_create_bhyve_vm_dict",
                        return_value={"child_name": "stopped-vm"},
                    ):
                        result = listing._list_stopped_bhyve_vms(set())

        assert len(result) == 1
        assert result[0]["child_name"] == "stopped-vm"

    def test_list_stopped_vms_excludes_running(self, listing, tmp_path):
        """Test listing stopped VMs excludes running ones."""
        vm_dir = tmp_path / "running-vm"
        vm_dir.mkdir()
        (vm_dir / "running-vm.img").touch()

        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=["running-vm"]):
                with patch.object(listing, "_is_valid_bhyve_vm_dir", return_value=True):
                    result = listing._list_stopped_bhyve_vms({"running-vm"})

        assert result == []

    def test_list_stopped_vms_no_vm_dir(self, listing):
        """Test listing stopped VMs when /vm doesn't exist."""
        with patch("os.path.isdir", return_value=False):
            result = listing._list_stopped_bhyve_vms(set())

        assert result == []

    def test_list_stopped_vms_permission_error(self, listing):
        """Test listing stopped VMs with permission error."""
        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", side_effect=PermissionError()):
                result = listing._list_stopped_bhyve_vms(set())

        assert result == []


class TestListBhyveVms:
    """Tests for list_bhyve_vms method."""

    def test_list_bhyve_vms_success(self, listing):
        """Test listing bhyve VMs successfully."""
        running_vm = {"child_name": "running-vm", "status": "running"}
        stopped_vm = {"child_name": "stopped-vm", "status": "stopped"}

        with patch.object(
            listing,
            "_list_running_bhyve_vms",
            return_value=([running_vm], {"running-vm"}),
        ):
            with patch.object(
                listing, "_list_stopped_bhyve_vms", return_value=[stopped_vm]
            ):
                result = listing.list_bhyve_vms()

        assert len(result) == 2
        assert result[0]["child_name"] == "running-vm"
        assert result[1]["child_name"] == "stopped-vm"

    def test_list_bhyve_vms_only_running(self, listing):
        """Test listing bhyve VMs with only running VMs."""
        running_vm = {"child_name": "running-vm", "status": "running"}

        with patch.object(
            listing,
            "_list_running_bhyve_vms",
            return_value=([running_vm], {"running-vm"}),
        ):
            with patch.object(listing, "_list_stopped_bhyve_vms", return_value=[]):
                result = listing.list_bhyve_vms()

        assert len(result) == 1
        assert result[0]["status"] == "running"

    def test_list_bhyve_vms_only_stopped(self, listing):
        """Test listing bhyve VMs with only stopped VMs."""
        stopped_vm = {"child_name": "stopped-vm", "status": "stopped"}

        with patch.object(listing, "_list_running_bhyve_vms", return_value=([], set())):
            with patch.object(
                listing, "_list_stopped_bhyve_vms", return_value=[stopped_vm]
            ):
                result = listing.list_bhyve_vms()

        assert len(result) == 1
        assert result[0]["status"] == "stopped"

    def test_list_bhyve_vms_empty(self, listing):
        """Test listing bhyve VMs when none exist."""
        with patch.object(listing, "_list_running_bhyve_vms", return_value=([], set())):
            with patch.object(listing, "_list_stopped_bhyve_vms", return_value=[]):
                result = listing.list_bhyve_vms()

        assert result == []

    def test_list_bhyve_vms_exception(self, listing):
        """Test listing bhyve VMs with exception."""
        with patch.object(
            listing, "_list_running_bhyve_vms", side_effect=Exception("Error")
        ):
            result = listing.list_bhyve_vms()

        assert result == []
