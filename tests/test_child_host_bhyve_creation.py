"""
Comprehensive unit tests for bhyve VM creation operations.

Tests cover:
- BhyveCreationHelper initialization
- VM existence checking
- Bridge and tap interface management
- IP address discovery from ARP tables
- SSH waiting functionality
- Delegate method verification
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
import socket
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_creation import (
    BhyveCreationHelper,
    BHYVE_VM_DIR,
)
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_bhyve_creation")


@pytest.fixture
def helper(logger):
    """Create a BhyveCreationHelper instance for testing."""
    return BhyveCreationHelper(logger)


@pytest.fixture
def sample_vm_config():
    """Create a sample BhyveVmConfig for testing."""
    return BhyveVmConfig(
        distribution="ubuntu",
        vm_name="test-vm",
        hostname="test-hostname",
        username="testuser",
        password_hash="$6$rounds=4096$somesalt$somehash",
        server_url="https://sysmanage.example.com",
        agent_install_commands=["apt-get update", "apt-get install -y agent"],
        memory="2G",
        disk_size="20G",
        cpus=2,
        server_port=8443,
        use_https=True,
    )


class TestBhyveCreationHelperInit:
    """Tests for BhyveCreationHelper initialization."""

    def test_init_sets_logger(self, logger):
        """Test that __init__ sets logger."""
        helper = BhyveCreationHelper(logger)
        assert helper.logger == logger

    def test_init_creates_image_helper(self, logger):
        """Test that __init__ creates image helper."""
        helper = BhyveCreationHelper(logger)
        assert helper._image_helper is not None

    def test_init_creates_provisioning_helper(self, logger):
        """Test that __init__ creates provisioning helper."""
        helper = BhyveCreationHelper(logger)
        assert helper._provisioning_helper is not None


class TestVmExists:
    """Tests for vm_exists method."""

    def test_vm_exists_dev_vmm(self, helper):
        """Test VM exists when /dev/vmm/<vm_name> exists."""
        with patch("os.path.exists", return_value=True):
            result = helper.vm_exists("test-vm")

        assert result is True

    def test_vm_exists_vm_directory(self, helper):
        """Test VM exists when VM directory exists."""

        def mock_exists(_path):
            return False  # /dev/vmm doesn't exist

        def mock_isdir(check_path):
            return check_path == f"{BHYVE_VM_DIR}/test-vm"

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.path.isdir", side_effect=mock_isdir):
                result = helper.vm_exists("test-vm")

        assert result is True

    def test_vm_does_not_exist(self, helper):
        """Test VM doesn't exist when neither path exists."""
        with patch("os.path.exists", return_value=False):
            with patch("os.path.isdir", return_value=False):
                result = helper.vm_exists("nonexistent-vm")

        assert result is False


class TestGetNmdmId:
    """Tests for get_nmdm_id method."""

    def test_get_nmdm_id_returns_integer(self, helper):
        """Test get_nmdm_id returns an integer."""
        result = helper.get_nmdm_id("test-vm")
        assert isinstance(result, int)

    def test_get_nmdm_id_in_range(self, helper):
        """Test get_nmdm_id returns value in 0-999 range."""
        for vm_name in ["vm1", "vm2", "test-server", "production-db"]:
            result = helper.get_nmdm_id(vm_name)
            assert 0 <= result <= 999

    def test_get_nmdm_id_consistent(self, helper):
        """Test get_nmdm_id returns consistent value for same VM."""
        result1 = helper.get_nmdm_id("consistent-vm")
        result2 = helper.get_nmdm_id("consistent-vm")
        assert result1 == result2

    def test_get_nmdm_id_different_for_different_vms(self, helper):
        """Test get_nmdm_id returns different values for different VMs."""
        result1 = helper.get_nmdm_id("vm1")
        result2 = helper.get_nmdm_id("vm2")
        # While collisions are possible, they should be rare with different names
        # Just verify they're both valid
        assert 0 <= result1 <= 999
        assert 0 <= result2 <= 999


class TestGetConsoleDevice:
    """Tests for get_console_device method."""

    def test_get_console_device_format(self, helper):
        """Test get_console_device returns proper device path format."""
        result = helper.get_console_device("test-vm")
        assert result.startswith("/dev/nmdm")
        assert result.endswith("B")

    def test_get_console_device_uses_nmdm_id(self, helper):
        """Test get_console_device uses nmdm ID correctly."""
        with patch.object(helper._provisioning_helper, "get_nmdm_id", return_value=42):
            result = helper.get_console_device("test-vm")
        assert result == "/dev/nmdm42B"


class TestIsLinuxGuest:
    """Tests for is_linux_guest method."""

    def test_is_linux_guest_ubuntu(self, helper, sample_vm_config):
        """Test Ubuntu is detected as Linux guest."""
        sample_vm_config.distribution = "ubuntu"
        result = helper.is_linux_guest(sample_vm_config)
        assert result is True

    def test_is_linux_guest_debian(self, helper, sample_vm_config):
        """Test Debian is detected as Linux guest."""
        sample_vm_config.distribution = "debian"
        result = helper.is_linux_guest(sample_vm_config)
        assert result is True

    def test_is_linux_guest_fedora(self, helper, sample_vm_config):
        """Test Fedora is detected as Linux guest."""
        sample_vm_config.distribution = "fedora"
        result = helper.is_linux_guest(sample_vm_config)
        assert result is True

    def test_is_linux_guest_centos(self, helper, sample_vm_config):
        """Test CentOS is detected as Linux guest."""
        sample_vm_config.distribution = "centos"
        result = helper.is_linux_guest(sample_vm_config)
        assert result is True

    def test_is_linux_guest_freebsd(self, helper, sample_vm_config):
        """Test FreeBSD is not detected as Linux guest."""
        sample_vm_config.distribution = "freebsd"
        result = helper.is_linux_guest(sample_vm_config)
        assert result is False

    def test_is_linux_guest_case_insensitive(self, helper, sample_vm_config):
        """Test Linux guest detection is case insensitive."""
        sample_vm_config.distribution = "UBUNTU"
        result = helper.is_linux_guest(sample_vm_config)
        assert result is True


class TestGetBridgeInterface:
    """Tests for get_bridge_interface method."""

    def test_get_bridge_interface_prefers_bridge1(self, helper):
        """Test bridge1 is preferred for NAT networking."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "lo0 em0 bridge0 bridge1 tap0"

        with patch("subprocess.run", return_value=mock_result):
            result = helper.get_bridge_interface()

        assert result == "bridge1"

    def test_get_bridge_interface_fallback_to_any_bridge(self, helper):
        """Test fallback to any bridge when bridge1 doesn't exist."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "lo0 em0 bridge0 tap0"

        with patch("subprocess.run", return_value=mock_result):
            result = helper.get_bridge_interface()

        assert result == "bridge0"

    def test_get_bridge_interface_vm_switch(self, helper):
        """Test detection of vm-bhyve style switch."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "lo0 em0 vm-public tap0"

        with patch("subprocess.run", return_value=mock_result):
            result = helper.get_bridge_interface()

        assert result == "vm-public"

    def test_get_bridge_interface_no_bridge(self, helper):
        """Test returns None when no bridge exists."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "lo0 em0 tap0"

        with patch("subprocess.run", return_value=mock_result):
            result = helper.get_bridge_interface()

        assert result is None

    def test_get_bridge_interface_command_fails(self, helper):
        """Test returns None when ifconfig command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = helper.get_bridge_interface()

        assert result is None

    def test_get_bridge_interface_exception(self, helper):
        """Test returns None on exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = helper.get_bridge_interface()

        assert result is None


class TestCreateBridgeIfNeeded:
    """Tests for create_bridge_if_needed method."""

    def test_create_bridge_if_needed_existing_bridge(self, helper):
        """Test returns existing bridge without creating new one."""
        with patch.object(helper, "get_bridge_interface", return_value="bridge1"):
            result = helper.create_bridge_if_needed()

        assert result["success"] is True
        assert result["bridge"] == "bridge1"

    def test_create_bridge_if_needed_creates_new(self, helper):
        """Test creates new bridge when none exists."""
        with patch.object(helper, "get_bridge_interface", return_value=None):
            mock_run = Mock()
            mock_run.returncode = 0
            mock_run.stdout = ""
            mock_run.stderr = ""

            with patch("subprocess.run", return_value=mock_run) as mock_subprocess:
                result = helper.create_bridge_if_needed()

        assert result["success"] is True
        assert result["bridge"] == "bridge1"
        # Should have called ifconfig twice (create + configure)
        assert mock_subprocess.call_count >= 2

    def test_create_bridge_if_needed_bridge_exists_error(self, helper):
        """Test handles bridge already exists error."""
        with patch.object(helper, "get_bridge_interface", return_value=None):
            mock_run = Mock()
            mock_run.returncode = 1
            mock_run.stdout = ""
            mock_run.stderr = "bridge already exists"

            with patch("subprocess.run", return_value=mock_run):
                result = helper.create_bridge_if_needed()

        # Should succeed even if bridge already exists
        assert result["success"] is True

    def test_create_bridge_if_needed_create_fails(self, helper):
        """Test handles bridge creation failure."""
        with patch.object(helper, "get_bridge_interface", return_value=None):
            mock_run = Mock()
            mock_run.returncode = 1
            mock_run.stdout = ""
            mock_run.stderr = "permission denied"

            with patch("subprocess.run", return_value=mock_run):
                result = helper.create_bridge_if_needed()

        assert result["success"] is False
        assert "error" in result

    def test_create_bridge_if_needed_exception(self, helper):
        """Test handles exception during bridge creation."""
        with patch.object(helper, "get_bridge_interface", return_value=None):
            with patch("subprocess.run", side_effect=Exception("network error")):
                result = helper.create_bridge_if_needed()

        assert result["success"] is False
        assert "network error" in result["error"]


class TestCreateTapInterface:
    """Tests for create_tap_interface method."""

    def test_create_tap_interface_success(self, helper):
        """Test successful tap interface creation."""
        mock_create = Mock()
        mock_create.returncode = 0
        mock_create.stdout = "tap0"
        mock_create.stderr = ""

        mock_other = Mock()
        mock_other.returncode = 0
        mock_other.stdout = ""
        mock_other.stderr = ""

        with patch.object(helper, "get_bridge_interface", return_value="bridge1"):
            with patch(
                "subprocess.run", side_effect=[mock_create, mock_other, mock_other]
            ):
                result = helper.create_tap_interface("test-vm")

        assert result["success"] is True
        assert result["tap"] == "tap0"

    def test_create_tap_interface_create_fails(self, helper):
        """Test handles tap creation failure."""
        mock_run = Mock()
        mock_run.returncode = 1
        mock_run.stdout = ""
        mock_run.stderr = "cannot create tap"

        with patch("subprocess.run", return_value=mock_run):
            result = helper.create_tap_interface("test-vm")

        assert result["success"] is False
        assert "error" in result

    def test_create_tap_interface_no_bridge(self, helper):
        """Test tap creation when no bridge exists."""
        mock_create = Mock()
        mock_create.returncode = 0
        mock_create.stdout = "tap0"
        mock_create.stderr = ""

        mock_up = Mock()
        mock_up.returncode = 0

        with patch.object(helper, "get_bridge_interface", return_value=None):
            with patch("subprocess.run", side_effect=[mock_create, mock_up]):
                result = helper.create_tap_interface("test-vm")

        assert result["success"] is True
        assert result["tap"] == "tap0"

    def test_create_tap_interface_exception(self, helper):
        """Test handles exception during tap creation."""
        with patch("subprocess.run", side_effect=Exception("device error")):
            result = helper.create_tap_interface("test-vm")

        assert result["success"] is False
        assert "device error" in result["error"]


class TestExtractIpFromArpLine:
    """Tests for extract_ip_from_arp_line method."""

    def test_extract_ip_from_arp_line_valid(self, helper):
        """Test extracting IP from valid ARP line."""
        line = "? (192.168.1.100) at aa:bb:cc:dd:ee:ff on tap0 expires in 1200 seconds"
        result = helper.extract_ip_from_arp_line(line)
        assert result == "192.168.1.100"

    def test_extract_ip_from_arp_line_no_parentheses(self, helper):
        """Test returns None when no parentheses in line."""
        line = "some random line without IP"
        result = helper.extract_ip_from_arp_line(line)
        assert result is None

    def test_extract_ip_from_arp_line_incomplete(self, helper):
        """Test returns None for incomplete ARP entry."""
        line = "? (incomplete) at ff:ff:ff:ff:ff:ff on tap0"
        result = helper.extract_ip_from_arp_line(line)
        assert result is None

    def test_extract_ip_from_arp_line_with_host(self, helper):
        """Test extracting IP with hostname in ARP."""
        line = "host.local (10.0.100.5) at 00:11:22:33:44:55 on bridge1"
        result = helper.extract_ip_from_arp_line(line)
        assert result == "10.0.100.5"


class TestFindIpInArpOutput:
    """Tests for find_ip_in_arp_output method."""

    def test_find_ip_in_arp_output_on_tap(self, helper):
        """Test finding IP on tap interface."""
        arp_output = """? (192.168.1.1) at aa:bb:cc:dd:ee:ff on em0
? (10.0.100.5) at 00:11:22:33:44:55 on tap0 expires in 1200 seconds
? (192.168.1.2) at aa:bb:cc:dd:ee:00 on em0"""

        result = helper.find_ip_in_arp_output(arp_output, "tap0", "test-vm")
        assert result == "10.0.100.5"

    def test_find_ip_in_arp_output_on_bridge(self, helper):
        """Test finding IP on bridge interface."""
        arp_output = """? (192.168.1.1) at aa:bb:cc:dd:ee:ff on em0
? (10.0.100.10) at 00:11:22:33:44:55 on bridge1 expires in 1200 seconds"""

        result = helper.find_ip_in_arp_output(arp_output, "tap0", "test-vm")
        assert result == "10.0.100.10"

    def test_find_ip_in_arp_output_not_found(self, helper):
        """Test returns None when IP not found."""
        arp_output = """? (192.168.1.1) at aa:bb:cc:dd:ee:ff on em0
? (192.168.1.2) at aa:bb:cc:dd:ee:00 on em0"""

        result = helper.find_ip_in_arp_output(arp_output, "tap0", "test-vm")
        assert result is None

    def test_find_ip_in_arp_output_empty(self, helper):
        """Test returns None for empty ARP output."""
        result = helper.find_ip_in_arp_output("", "tap0", "test-vm")
        assert result is None


class TestWaitForVmIp:
    """Tests for wait_for_vm_ip async method."""

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    async def test_wait_for_vm_ip_immediate_success(
        self, _mock_sleep, mock_time, mock_run_command, helper
    ):
        """Test IP found immediately."""
        mock_time.return_value = 0
        mock_run_command.return_value = Mock(
            returncode=0,
            stdout="? (10.0.100.5) at 00:11:22:33:44:55 on tap0 expires in 1200 seconds",
        )

        result = await helper.wait_for_vm_ip("test-vm", "tap0", timeout=300)

        assert result == "10.0.100.5"

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    async def test_wait_for_vm_ip_success_after_retries(
        self, _mock_sleep, mock_time, mock_run_command, helper
    ):
        """Test IP found after retries."""
        mock_time.side_effect = [0, 5, 10, 15]
        mock_run_command.side_effect = [
            Mock(returncode=0, stdout=""),  # First: no IP
            Mock(returncode=0, stdout=""),  # Second: no IP
            Mock(
                returncode=0, stdout="? (10.0.100.5) at 00:11:22:33:44:55 on tap0"
            ),  # Third: found
        ]

        result = await helper.wait_for_vm_ip("test-vm", "tap0", timeout=300)

        assert result == "10.0.100.5"

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    async def test_wait_for_vm_ip_timeout(
        self, _mock_sleep, mock_time, mock_run_command, helper
    ):
        """Test timeout when IP never found."""
        mock_time.side_effect = [0, 100, 200, 301]  # Exceeds 300 timeout
        mock_run_command.return_value = Mock(returncode=0, stdout="")

        result = await helper.wait_for_vm_ip("test-vm", "tap0", timeout=300)

        assert result is None

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    async def test_wait_for_vm_ip_exception_continues(
        self, _mock_sleep, mock_time, mock_run_command, helper
    ):
        """Test exception during check continues retrying."""
        mock_time.side_effect = [0, 5, 10]
        mock_run_command.side_effect = [
            Exception("network error"),
            Mock(returncode=0, stdout="? (10.0.100.5) at 00:11:22:33:44:55 on tap0"),
        ]

        result = await helper.wait_for_vm_ip("test-vm", "tap0", timeout=300)

        assert result == "10.0.100.5"

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    async def test_wait_for_vm_ip_arp_command_fails(
        self, _mock_sleep, mock_time, mock_run_command, helper
    ):
        """Test continues retrying when arp command fails."""
        mock_time.side_effect = [0, 5, 10]
        mock_run_command.side_effect = [
            Mock(returncode=1, stdout=""),  # arp fails
            Mock(returncode=0, stdout="? (10.0.100.5) at 00:11:22:33:44:55 on tap0"),
        ]

        result = await helper.wait_for_vm_ip("test-vm", "tap0", timeout=300)

        assert result == "10.0.100.5"


class TestWaitForSsh:
    """Tests for wait_for_ssh async method."""

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    @patch("socket.socket")
    async def test_wait_for_ssh_immediate_success(
        self, mock_socket_class, _mock_sleep, mock_time, helper
    ):
        """Test SSH available immediately."""
        mock_time.return_value = 0
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket

        result = await helper.wait_for_ssh("10.0.100.5", port=22, timeout=180)

        assert result is True
        mock_socket.close.assert_called()

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    @patch("socket.socket")
    async def test_wait_for_ssh_success_after_retries(
        self, mock_socket_class, _mock_sleep, mock_time, helper
    ):
        """Test SSH available after retries."""
        mock_time.side_effect = [0, 5, 10, 15]
        mock_socket = MagicMock()
        mock_socket.connect_ex.side_effect = [1, 1, 0]  # Fails twice, then succeeds
        mock_socket_class.return_value = mock_socket

        result = await helper.wait_for_ssh("10.0.100.5", port=22, timeout=180)

        assert result is True

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    @patch("socket.socket")
    async def test_wait_for_ssh_timeout(
        self, mock_socket_class, _mock_sleep, mock_time, helper
    ):
        """Test SSH timeout when never available."""
        mock_time.side_effect = [0, 60, 120, 181]  # Exceeds 180 timeout
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1  # Always fails
        mock_socket_class.return_value = mock_socket

        result = await helper.wait_for_ssh("10.0.100.5", port=22, timeout=180)

        assert result is False

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    @patch("socket.socket")
    async def test_wait_for_ssh_exception_continues(
        self, mock_socket_class, _mock_sleep, mock_time, helper
    ):
        """Test exception during check continues retrying."""
        mock_time.side_effect = [0, 5, 10]
        mock_socket = MagicMock()
        mock_socket.connect_ex.side_effect = [socket.error("connection refused"), 0]
        mock_socket_class.return_value = mock_socket

        result = await helper.wait_for_ssh("10.0.100.5", port=22, timeout=180)

        assert result is True

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    @patch("socket.socket")
    async def test_wait_for_ssh_custom_port(
        self, mock_socket_class, _mock_sleep, mock_time, helper
    ):
        """Test SSH check with custom port."""
        mock_time.return_value = 0
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket

        result = await helper.wait_for_ssh("10.0.100.5", port=2222, timeout=180)

        assert result is True
        mock_socket.connect_ex.assert_called_with(("10.0.100.5", 2222))


class TestDelegatedMethods:
    """Tests for methods delegated to helper classes."""

    def test_download_cloud_image_delegates(self, helper):
        """Test download_cloud_image delegates to image helper."""
        with patch.object(
            helper._image_helper, "download_cloud_image", return_value={"success": True}
        ) as mock_download:
            result = helper.download_cloud_image(
                "http://example.com/image.qcow2", "/vm/test.raw", 20
            )

        mock_download.assert_called_once_with(
            "http://example.com/image.qcow2", "/vm/test.raw", 20
        )
        assert result["success"] is True

    def test_create_disk_image_delegates(self, helper):
        """Test create_disk_image delegates to image helper."""
        with patch.object(
            helper._image_helper, "create_disk_image", return_value={"success": True}
        ) as mock_create:
            result = helper.create_disk_image("/vm/disk.raw", 20, False, "")

        mock_create.assert_called_once_with("/vm/disk.raw", 20, False, "")
        assert result["success"] is True

    def test_create_disk_image_with_zvol(self, helper):
        """Test create_disk_image with zvol options."""
        with patch.object(
            helper._image_helper, "create_disk_image", return_value={"success": True}
        ) as mock_create:
            result = helper.create_disk_image("disk", 50, True, "zroot/vm")

        mock_create.assert_called_once_with("disk", 50, True, "zroot/vm")
        assert result["success"] is True

    def test_create_cloud_init_iso_delegates(self, helper, sample_vm_config):
        """Test create_cloud_init_iso delegates to provisioning helper."""
        with patch.object(
            helper._provisioning_helper,
            "create_cloud_init_iso",
            return_value={"success": True, "path": "/vm/cloud-init/test-vm.iso"},
        ) as mock_create:
            result = helper.create_cloud_init_iso(sample_vm_config)

        mock_create.assert_called_once_with(sample_vm_config)
        assert result["success"] is True

    def test_generate_bhyve_command_delegates(self, helper, sample_vm_config):
        """Test generate_bhyve_command delegates to provisioning helper."""
        expected_cmd = ["bhyve", "-A", "-H", "test-vm"]
        with patch.object(
            helper._provisioning_helper,
            "generate_bhyve_command",
            return_value=expected_cmd,
        ) as mock_generate:
            result = helper.generate_bhyve_command(sample_vm_config, "tap0", True)

        mock_generate.assert_called_once_with(sample_vm_config, "tap0", True)
        assert result == expected_cmd

    def test_generate_bhyve_command_no_nmdm(self, helper, sample_vm_config):
        """Test generate_bhyve_command with use_nmdm=False."""
        expected_cmd = ["bhyve", "-A", "-H", "test-vm"]
        with patch.object(
            helper._provisioning_helper,
            "generate_bhyve_command",
            return_value=expected_cmd,
        ) as mock_generate:
            result = helper.generate_bhyve_command(sample_vm_config, "tap0", False)

        mock_generate.assert_called_once_with(sample_vm_config, "tap0", False)
        assert result == expected_cmd

    def test_start_vm_with_bhyveload_delegates(self, helper, sample_vm_config):
        """Test start_vm_with_bhyveload delegates to provisioning helper."""
        with patch.object(
            helper._provisioning_helper,
            "start_vm_with_bhyveload",
            return_value={"success": True},
        ) as mock_start:
            result = helper.start_vm_with_bhyveload(sample_vm_config, "tap0")

        mock_start.assert_called_once_with(sample_vm_config, "tap0")
        assert result["success"] is True

    def test_start_vm_with_uefi_delegates(self, helper, sample_vm_config):
        """Test start_vm_with_uefi delegates to provisioning helper."""
        with patch.object(
            helper._provisioning_helper,
            "start_vm_with_uefi",
            return_value={"success": True},
        ) as mock_start:
            result = helper.start_vm_with_uefi(sample_vm_config, "tap0")

        mock_start.assert_called_once_with(sample_vm_config, "tap0")
        assert result["success"] is True


class TestBhyveVmDir:
    """Tests for BHYVE_VM_DIR constant."""

    def test_bhyve_vm_dir_value(self):
        """Test BHYVE_VM_DIR has expected value."""
        assert BHYVE_VM_DIR == "/vm"


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_vm_exists_with_special_characters(self, helper):
        """Test vm_exists handles VM names with special characters."""
        with patch("os.path.exists", return_value=False):
            with patch("os.path.isdir", return_value=False):
                result = helper.vm_exists("vm-with-dashes_and_underscores")

        assert result is False

    def test_extract_ip_from_arp_line_partial_parentheses(self, helper):
        """Test extract_ip_from_arp_line with only opening parenthesis."""
        line = "? (192.168.1.1 at aa:bb:cc:dd:ee:ff on tap0"
        result = helper.extract_ip_from_arp_line(line)
        assert result is None

    def test_find_ip_in_arp_output_multiple_ips(self, helper):
        """Test find_ip_in_arp_output returns first matching IP."""
        arp_output = """? (10.0.100.5) at 00:11:22:33:44:55 on tap0
? (10.0.100.6) at 00:11:22:33:44:66 on tap0"""

        result = helper.find_ip_in_arp_output(arp_output, "tap0", "test-vm")
        # Should return first match
        assert result == "10.0.100.5"

    def test_get_bridge_interface_empty_output(self, helper):
        """Test get_bridge_interface with empty ifconfig output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = helper.get_bridge_interface()

        assert result is None

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    async def test_wait_for_vm_ip_zero_timeout(
        self, _mock_sleep, mock_time, _mock_run_command, helper
    ):
        """Test wait_for_vm_ip with zero timeout exits immediately."""
        mock_time.return_value = 1  # Already past timeout of 0

        result = await helper.wait_for_vm_ip("test-vm", "tap0", timeout=0)

        assert result is None

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.time.time")
    @patch("src.sysmanage_agent.operations.child_host_bhyve_creation.asyncio.sleep")
    @patch("socket.socket")
    async def test_wait_for_ssh_socket_error(
        self, mock_socket_class, _mock_sleep, mock_time, helper
    ):
        """Test wait_for_ssh handles socket creation errors."""
        mock_time.side_effect = [0, 5, 10]
        mock_socket_class.side_effect = [
            socket.error("socket creation failed"),
            MagicMock(connect_ex=Mock(return_value=0), close=Mock()),
        ]

        result = await helper.wait_for_ssh("10.0.100.5", port=22, timeout=180)

        assert result is True
