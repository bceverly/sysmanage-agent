"""
Comprehensive unit tests for ChildHostOperations.

Tests cover:
- Initialization
- Virtualization support checking (all platforms)
- Child host listing (all platforms)
- Child host creation (WSL, LXD, VMM, KVM, bhyve)
- Child host lifecycle operations (start, stop, restart, delete)
- Initialization of virtualization platforms (WSL, LXD, VMM, KVM, bhyve)
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_operations import ChildHostOperations


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    mock = Mock()
    mock.send_message = AsyncMock()
    mock.create_message = Mock(return_value={"type": "test"})
    mock.child_host_collector = Mock()
    mock.child_host_collector.send_child_hosts_update = AsyncMock()
    return mock


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock_checks = Mock()
    mock_checks.check_wsl_support = Mock(
        return_value={
            "available": True,
            "installed": True,
            "needs_enable": False,
        }
    )
    mock_checks.check_hyperv_support = Mock(
        return_value={
            "available": True,
            "installed": True,
        }
    )
    mock_checks.check_lxd_support = Mock(
        return_value={
            "available": True,
            "installed": True,
            "initialized": True,
        }
    )
    mock_checks.check_kvm_support = Mock(
        return_value={
            "available": True,
            "installed": True,
            "enabled": True,
        }
    )
    mock_checks.check_bhyve_support = Mock(
        return_value={
            "available": True,
            "loaded": True,
        }
    )
    mock_checks.check_vmm_support = Mock(
        return_value={
            "available": True,
            "enabled": True,
        }
    )
    mock_checks.check_virtualbox_support = Mock(
        return_value={
            "available": True,
            "installed": True,
        }
    )
    return mock_checks


@pytest.fixture
def child_host_ops(mock_agent):
    """Create a ChildHostOperations instance for testing."""
    with patch(
        "src.sysmanage_agent.operations.child_host_operations.VirtualizationChecks"
    ):
        with patch(
            "src.sysmanage_agent.operations.child_host_operations.ChildHostListing"
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_operations.WslOperations"
            ):
                with patch(
                    "src.sysmanage_agent.operations.child_host_operations.LxdOperations"
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_operations.VmmOperations"
                    ):
                        with patch(
                            "src.sysmanage_agent.operations.child_host_operations.KvmOperations"
                        ):
                            with patch(
                                "src.sysmanage_agent.operations.child_host_operations.BhyveOperations"
                            ):
                                ops = ChildHostOperations(mock_agent)
                                return ops


class TestChildHostOperationsInit:
    """Tests for ChildHostOperations initialization."""

    def test_init_sets_agent(self, child_host_ops, mock_agent):
        """Test that __init__ sets agent."""
        assert child_host_ops.agent == mock_agent

    def test_init_sets_logger(self, child_host_ops):
        """Test that __init__ sets logger."""
        assert child_host_ops.logger is not None

    def test_init_creates_virtualization_checks(self, child_host_ops):
        """Test that __init__ creates virtualization_checks."""
        assert child_host_ops.virtualization_checks is not None

    def test_init_creates_listing_helper(self, child_host_ops):
        """Test that __init__ creates listing_helper."""
        assert child_host_ops.listing_helper is not None

    def test_init_creates_wsl_ops(self, child_host_ops):
        """Test that __init__ creates wsl_ops."""
        assert child_host_ops.wsl_ops is not None

    def test_init_creates_lxd_ops(self, child_host_ops):
        """Test that __init__ creates lxd_ops."""
        assert child_host_ops.lxd_ops is not None

    def test_init_creates_vmm_ops(self, child_host_ops):
        """Test that __init__ creates vmm_ops."""
        assert child_host_ops.vmm_ops is not None

    def test_init_creates_kvm_ops(self, child_host_ops):
        """Test that __init__ creates kvm_ops."""
        assert child_host_ops.kvm_ops is not None

    def test_init_creates_bhyve_ops(self, child_host_ops):
        """Test that __init__ creates bhyve_ops."""
        assert child_host_ops.bhyve_ops is not None


class TestCheckVirtualizationSupport:
    """Tests for check_virtualization_support method."""

    @pytest.mark.asyncio
    async def test_check_virtualization_windows(self, child_host_ops):
        """Test checking virtualization on Windows."""
        child_host_ops.virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": False,
        }
        child_host_ops.virtualization_checks.check_hyperv_support.return_value = {
            "available": True,
        }
        child_host_ops.virtualization_checks.check_virtualbox_support.return_value = {
            "available": False,
        }

        with patch("platform.system", return_value="Windows"):
            result = await child_host_ops.check_virtualization_support({})

        assert result["success"] is True
        assert result["os_type"] == "windows"
        assert "wsl" in result["supported_types"]
        assert "hyperv" in result["supported_types"]

    @pytest.mark.asyncio
    async def test_check_virtualization_windows_needs_reboot(self, child_host_ops):
        """Test checking virtualization on Windows when WSL needs enabling."""
        child_host_ops.virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": True,
        }
        child_host_ops.virtualization_checks.check_hyperv_support.return_value = {
            "available": False,
        }
        child_host_ops.virtualization_checks.check_virtualbox_support.return_value = {
            "available": False,
        }

        with patch("platform.system", return_value="Windows"):
            result = await child_host_ops.check_virtualization_support({})

        assert result["success"] is True
        assert result["reboot_required"] is True

    @pytest.mark.asyncio
    async def test_check_virtualization_linux(self, child_host_ops):
        """Test checking virtualization on Linux."""
        child_host_ops.virtualization_checks.check_lxd_support.return_value = {
            "available": True,
        }
        child_host_ops.virtualization_checks.check_kvm_support.return_value = {
            "available": True,
        }
        child_host_ops.virtualization_checks.check_virtualbox_support.return_value = {
            "available": False,
        }

        with patch("platform.system", return_value="Linux"):
            result = await child_host_ops.check_virtualization_support({})

        assert result["success"] is True
        assert result["os_type"] == "linux"
        assert "lxd" in result["supported_types"]
        assert "kvm" in result["supported_types"]

    @pytest.mark.asyncio
    async def test_check_virtualization_freebsd(self, child_host_ops):
        """Test checking virtualization on FreeBSD."""
        child_host_ops.virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
        }
        child_host_ops.virtualization_checks.check_virtualbox_support.return_value = {
            "available": False,
        }

        with patch("platform.system", return_value="FreeBSD"):
            result = await child_host_ops.check_virtualization_support({})

        assert result["success"] is True
        assert result["os_type"] == "freebsd"
        assert "bhyve" in result["supported_types"]

    @pytest.mark.asyncio
    async def test_check_virtualization_openbsd(self, child_host_ops):
        """Test checking virtualization on OpenBSD."""
        child_host_ops.virtualization_checks.check_vmm_support.return_value = {
            "available": True,
        }
        child_host_ops.virtualization_checks.check_virtualbox_support.return_value = {
            "available": False,
        }

        with patch("platform.system", return_value="OpenBSD"):
            result = await child_host_ops.check_virtualization_support({})

        assert result["success"] is True
        assert result["os_type"] == "openbsd"
        assert "vmm" in result["supported_types"]

    @pytest.mark.asyncio
    async def test_check_virtualization_virtualbox(self, child_host_ops):
        """Test checking VirtualBox support (cross-platform)."""
        child_host_ops.virtualization_checks.check_virtualbox_support.return_value = {
            "available": True,
        }

        with patch("platform.system", return_value="Darwin"):  # macOS
            result = await child_host_ops.check_virtualization_support({})

        assert result["success"] is True
        assert "virtualbox" in result["supported_types"]

    @pytest.mark.asyncio
    async def test_check_virtualization_exception(self, child_host_ops):
        """Test checking virtualization with exception."""
        child_host_ops.virtualization_checks.check_virtualbox_support.side_effect = (
            Exception("Test error")
        )

        with patch("platform.system", return_value="Darwin"):
            result = await child_host_ops.check_virtualization_support({})

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_check_virtualization_no_types_available(self, child_host_ops):
        """Test checking virtualization when nothing is available."""
        child_host_ops.virtualization_checks.check_virtualbox_support.return_value = {
            "available": False,
        }

        with patch("platform.system", return_value="Darwin"):
            result = await child_host_ops.check_virtualization_support({})

        assert result["success"] is True
        assert result["supported_types"] == []


class TestListChildHosts:
    """Tests for list_child_hosts method."""

    @pytest.mark.asyncio
    async def test_list_child_hosts_windows(self, child_host_ops, mock_agent):
        """Test listing child hosts on Windows."""
        child_host_ops.listing_helper.list_wsl_instances.return_value = [
            {"name": "Ubuntu", "type": "wsl", "state": "Running"}
        ]
        child_host_ops.listing_helper.list_hyperv_vms.return_value = []
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = []

        with patch("platform.system", return_value="Windows"):
            result = await child_host_ops.list_child_hosts({})

        assert result["success"] is True
        assert result["count"] == 1
        assert result["child_hosts"][0]["name"] == "Ubuntu"
        mock_agent.child_host_collector.send_child_hosts_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_child_hosts_windows_with_filter(self, child_host_ops):
        """Test listing child hosts on Windows with type filter."""
        child_host_ops.listing_helper.list_wsl_instances.return_value = [
            {"name": "Ubuntu", "type": "wsl"}
        ]
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = []

        with patch("platform.system", return_value="Windows"):
            result = await child_host_ops.list_child_hosts({"child_type": "wsl"})

        assert result["success"] is True
        # Hyperv should not be called when filter is wsl
        child_host_ops.listing_helper.list_hyperv_vms.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_child_hosts_linux(self, child_host_ops):
        """Test listing child hosts on Linux."""
        child_host_ops.listing_helper.list_lxd_containers.return_value = [
            {"name": "test-container", "type": "lxd", "state": "Running"}
        ]
        child_host_ops.listing_helper.list_kvm_vms.return_value = []
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = []

        with patch("platform.system", return_value="Linux"):
            result = await child_host_ops.list_child_hosts({})

        assert result["success"] is True
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_list_child_hosts_linux_lxd_filter(self, child_host_ops):
        """Test listing child hosts on Linux with LXD filter."""
        child_host_ops.listing_helper.list_lxd_containers.return_value = [
            {"name": "test-container", "type": "lxd"}
        ]
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = []

        with patch("platform.system", return_value="Linux"):
            result = await child_host_ops.list_child_hosts({"child_type": "lxd"})

        assert result["success"] is True
        child_host_ops.listing_helper.list_kvm_vms.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_child_hosts_openbsd(self, child_host_ops):
        """Test listing child hosts on OpenBSD."""
        child_host_ops.listing_helper.list_vmm_vms.return_value = [
            {"name": "test-vm", "type": "vmm"}
        ]
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = []

        with patch("platform.system", return_value="OpenBSD"):
            result = await child_host_ops.list_child_hosts({})

        assert result["success"] is True
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_list_child_hosts_freebsd(self, child_host_ops):
        """Test listing child hosts on FreeBSD."""
        child_host_ops.listing_helper.list_bhyve_vms.return_value = [
            {"name": "test-vm", "type": "bhyve"}
        ]
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = []

        with patch("platform.system", return_value="FreeBSD"):
            result = await child_host_ops.list_child_hosts({})

        assert result["success"] is True
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_list_child_hosts_exception(self, child_host_ops):
        """Test listing child hosts with exception."""
        child_host_ops.listing_helper.list_virtualbox_vms.side_effect = Exception(
            "Listing error"
        )

        with patch("platform.system", return_value="Darwin"):
            result = await child_host_ops.list_child_hosts({})

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_list_child_hosts_no_collector(self, child_host_ops, mock_agent):
        """Test listing child hosts when agent has no child_host_collector."""
        del mock_agent.child_host_collector
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = []

        with patch("platform.system", return_value="Darwin"):
            result = await child_host_ops.list_child_hosts({})

        # Should still succeed
        assert result["success"] is True


class TestCreateChildHost:
    """Tests for create_child_host method."""

    @pytest.mark.asyncio
    async def test_create_vmm_vm(self, child_host_ops):
        """Test creating a VMM VM."""
        child_host_ops.vmm_ops.create_vmm_vm = AsyncMock(
            return_value={"success": True, "child_name": "test-vm"}
        )

        result = await child_host_ops.create_child_host(
            {
                "child_type": "vmm",
                "distribution": "openbsd-7.4",
                "hostname": "test.example.com",
                "vm_name": "test-vm",
                "username": "admin",
                "password_hash": "$6$...",
                "server_url": "https://server.example.com",
                "iso_url": "https://cdn.openbsd.org/pub/OpenBSD/7.4/amd64/install74.iso",
            }
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_kvm_vm(self, child_host_ops):
        """Test creating a KVM VM."""
        child_host_ops.kvm_ops.create_vm = AsyncMock(
            return_value={"success": True, "child_name": "test-vm"}
        )

        result = await child_host_ops.create_child_host(
            {
                "child_type": "kvm",
                "distribution": "ubuntu:22.04",
                "hostname": "test.example.com",
                "vm_name": "test-vm",
                "username": "admin",
                "password_hash": "$6$...",
                "server_url": "https://server.example.com",
            }
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_bhyve_vm(self, child_host_ops):
        """Test creating a bhyve VM."""
        child_host_ops.bhyve_ops.create_bhyve_vm = AsyncMock(
            return_value={"success": True, "child_name": "test-vm"}
        )

        result = await child_host_ops.create_child_host(
            {
                "child_type": "bhyve",
                "distribution": "freebsd-14.0",
                "hostname": "test.example.com",
                "vm_name": "test-vm",
                "username": "admin",
                "password_hash": "$6$...",
                "server_url": "https://server.example.com",
            }
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_unsupported_type(self, child_host_ops):
        """Test creating child host with unsupported type."""
        result = await child_host_ops.create_child_host(
            {
                "child_type": "docker",  # Not supported
                "distribution": "alpine:latest",
                "hostname": "test.example.com",
                "username": "admin",
                "password_hash": "$6$...",
                "server_url": "https://server.example.com",
            }
        )

        assert result["success"] is False
        assert "Unsupported" in result["error"]


class TestEnableWsl:
    """Tests for enable_wsl method."""

    @pytest.mark.asyncio
    async def test_enable_wsl_success(self, child_host_ops):
        """Test enabling WSL successfully."""
        child_host_ops.wsl_ops.enable_wsl = AsyncMock(
            return_value={"success": True, "reboot_required": True}
        )

        result = await child_host_ops.enable_wsl({})

        assert result["success"] is True
        assert result["reboot_required"] is True


class TestInitializeLxd:
    """Tests for initialize_lxd method."""

    @pytest.mark.asyncio
    async def test_initialize_lxd_success(self, child_host_ops):
        """Test initializing LXD successfully."""
        child_host_ops.lxd_ops.initialize_lxd = AsyncMock(
            return_value={"success": True, "needs_relogin": True}
        )

        result = await child_host_ops.initialize_lxd({})

        assert result["success"] is True


class TestInitializeVmm:
    """Tests for initialize_vmm method."""

    @pytest.mark.asyncio
    async def test_initialize_vmm_success(self, child_host_ops):
        """Test initializing VMM successfully."""
        child_host_ops.vmm_ops.initialize_vmd = AsyncMock(
            return_value={"success": True}
        )

        result = await child_host_ops.initialize_vmm({})

        assert result["success"] is True


class TestInitializeKvm:
    """Tests for initialize_kvm method."""

    @pytest.mark.asyncio
    async def test_initialize_kvm_success(self, child_host_ops):
        """Test initializing KVM successfully."""
        child_host_ops.kvm_ops.initialize_kvm = AsyncMock(
            return_value={"success": True}
        )

        result = await child_host_ops.initialize_kvm({})

        assert result["success"] is True


class TestInitializeBhyve:
    """Tests for initialize_bhyve method."""

    @pytest.mark.asyncio
    async def test_initialize_bhyve_success(self, child_host_ops):
        """Test initializing bhyve successfully."""
        child_host_ops.bhyve_ops.initialize_bhyve = AsyncMock(
            return_value={"success": True}
        )

        result = await child_host_ops.initialize_bhyve({})

        assert result["success"] is True


class TestDisableBhyve:
    """Tests for disable_bhyve method."""

    @pytest.mark.asyncio
    async def test_disable_bhyve_success(self, child_host_ops):
        """Test disabling bhyve successfully."""
        child_host_ops.bhyve_ops.disable_bhyve = AsyncMock(
            return_value={"success": True}
        )

        result = await child_host_ops.disable_bhyve({})

        assert result["success"] is True


class TestEnableKvmModules:
    """Tests for enable_kvm_modules method."""

    @pytest.mark.asyncio
    async def test_enable_kvm_modules_success(self, child_host_ops):
        """Test enabling KVM modules successfully."""
        child_host_ops.kvm_ops.enable_kvm_modules = AsyncMock(
            return_value={"success": True, "module": "kvm_intel"}
        )

        result = await child_host_ops.enable_kvm_modules({})

        assert result["success"] is True
        assert result["module"] == "kvm_intel"


class TestDisableKvmModules:
    """Tests for disable_kvm_modules method."""

    @pytest.mark.asyncio
    async def test_disable_kvm_modules_success(self, child_host_ops):
        """Test disabling KVM modules successfully."""
        child_host_ops.kvm_ops.disable_kvm_modules = AsyncMock(
            return_value={"success": True}
        )

        result = await child_host_ops.disable_kvm_modules({})

        assert result["success"] is True


class TestSetupKvmNetworking:
    """Tests for setup_kvm_networking method."""

    @pytest.mark.asyncio
    async def test_setup_kvm_networking_nat(self, child_host_ops):
        """Test setting up KVM NAT networking."""
        child_host_ops.kvm_ops.setup_kvm_networking = AsyncMock(
            return_value={"success": True, "mode": "nat", "network_name": "default"}
        )

        result = await child_host_ops.setup_kvm_networking({"mode": "nat"})

        assert result["success"] is True
        assert result["mode"] == "nat"

    @pytest.mark.asyncio
    async def test_setup_kvm_networking_bridged(self, child_host_ops):
        """Test setting up KVM bridged networking."""
        child_host_ops.kvm_ops.setup_kvm_networking = AsyncMock(
            return_value={"success": True, "mode": "bridged", "bridge": "br0"}
        )

        result = await child_host_ops.setup_kvm_networking(
            {"mode": "bridged", "bridge": "br0"}
        )

        assert result["success"] is True
        assert result["mode"] == "bridged"


class TestListKvmNetworks:
    """Tests for list_kvm_networks method."""

    @pytest.mark.asyncio
    async def test_list_kvm_networks_success(self, child_host_ops):
        """Test listing KVM networks successfully."""
        child_host_ops.kvm_ops.list_kvm_networks = AsyncMock(
            return_value={
                "success": True,
                "networks": [{"name": "default", "state": "active", "autostart": True}],
            }
        )

        result = await child_host_ops.list_kvm_networks({})

        assert result["success"] is True
        assert len(result["networks"]) == 1


class TestStartChildHost:
    """Tests for start_child_host method."""

    @pytest.mark.asyncio
    async def test_start_wsl_instance(self, child_host_ops):
        """Test starting a WSL instance."""
        child_host_ops.wsl_ops.start_child_host = AsyncMock(
            return_value={"success": True, "child_name": "Ubuntu", "child_type": "wsl"}
        )

        result = await child_host_ops.start_child_host(
            {"child_type": "wsl", "child_name": "Ubuntu"}
        )

        assert result["success"] is True
        assert result["child_type"] == "wsl"

    @pytest.mark.asyncio
    async def test_start_lxd_container(self, child_host_ops):
        """Test starting an LXD container."""
        child_host_ops.lxd_ops.start_child_host = AsyncMock(
            return_value={
                "success": True,
                "child_name": "test-container",
                "child_type": "lxd",
            }
        )

        result = await child_host_ops.start_child_host(
            {"child_type": "lxd", "child_name": "test-container"}
        )

        assert result["success"] is True
        assert result["child_type"] == "lxd"

    @pytest.mark.asyncio
    async def test_start_vmm_vm(self, child_host_ops):
        """Test starting a VMM VM."""
        child_host_ops.vmm_ops.start_child_host = AsyncMock(
            return_value={"success": True, "child_name": "test-vm", "child_type": "vmm"}
        )

        result = await child_host_ops.start_child_host(
            {"child_type": "vmm", "child_name": "test-vm"}
        )

        assert result["success"] is True
        assert result["child_type"] == "vmm"

    @pytest.mark.asyncio
    async def test_start_kvm_vm(self, child_host_ops):
        """Test starting a KVM VM."""
        child_host_ops.kvm_ops.start_child_host = AsyncMock(
            return_value={"success": True, "child_name": "test-vm", "child_type": "kvm"}
        )

        result = await child_host_ops.start_child_host(
            {"child_type": "kvm", "child_name": "test-vm"}
        )

        assert result["success"] is True
        assert result["child_type"] == "kvm"

    @pytest.mark.asyncio
    async def test_start_bhyve_vm(self, child_host_ops):
        """Test starting a bhyve VM."""
        child_host_ops.bhyve_ops.start_child_host = AsyncMock(
            return_value={
                "success": True,
                "child_name": "test-vm",
                "child_type": "bhyve",
            }
        )

        result = await child_host_ops.start_child_host(
            {"child_type": "bhyve", "child_name": "test-vm"}
        )

        assert result["success"] is True
        assert result["child_type"] == "bhyve"

    @pytest.mark.asyncio
    async def test_start_unsupported_type(self, child_host_ops):
        """Test starting child host with unsupported type."""
        result = await child_host_ops.start_child_host(
            {"child_type": "docker", "child_name": "test"}
        )

        assert result["success"] is False
        assert "Unsupported" in result["error"]


class TestStopChildHost:
    """Tests for stop_child_host method."""

    @pytest.mark.asyncio
    async def test_stop_wsl_instance(self, child_host_ops):
        """Test stopping a WSL instance."""
        child_host_ops.wsl_ops.stop_child_host = AsyncMock(
            return_value={"success": True, "child_name": "Ubuntu", "child_type": "wsl"}
        )

        result = await child_host_ops.stop_child_host(
            {"child_type": "wsl", "child_name": "Ubuntu"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_lxd_container(self, child_host_ops):
        """Test stopping an LXD container."""
        child_host_ops.lxd_ops.stop_child_host = AsyncMock(
            return_value={
                "success": True,
                "child_name": "test-container",
                "child_type": "lxd",
            }
        )

        result = await child_host_ops.stop_child_host(
            {"child_type": "lxd", "child_name": "test-container"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_vmm_vm(self, child_host_ops):
        """Test stopping a VMM VM."""
        child_host_ops.vmm_ops.stop_child_host = AsyncMock(
            return_value={"success": True, "child_name": "test-vm", "child_type": "vmm"}
        )

        result = await child_host_ops.stop_child_host(
            {"child_type": "vmm", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_kvm_vm(self, child_host_ops):
        """Test stopping a KVM VM."""
        child_host_ops.kvm_ops.stop_child_host = AsyncMock(
            return_value={"success": True, "child_name": "test-vm", "child_type": "kvm"}
        )

        result = await child_host_ops.stop_child_host(
            {"child_type": "kvm", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_bhyve_vm(self, child_host_ops):
        """Test stopping a bhyve VM."""
        child_host_ops.bhyve_ops.stop_child_host = AsyncMock(
            return_value={
                "success": True,
                "child_name": "test-vm",
                "child_type": "bhyve",
            }
        )

        result = await child_host_ops.stop_child_host(
            {"child_type": "bhyve", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_unsupported_type(self, child_host_ops):
        """Test stopping child host with unsupported type."""
        result = await child_host_ops.stop_child_host(
            {"child_type": "docker", "child_name": "test"}
        )

        assert result["success"] is False
        assert "Unsupported" in result["error"]


class TestRestartChildHost:
    """Tests for restart_child_host method."""

    @pytest.mark.asyncio
    async def test_restart_wsl_instance(self, child_host_ops):
        """Test restarting a WSL instance."""
        child_host_ops.wsl_ops.restart_child_host = AsyncMock(
            return_value={"success": True, "child_name": "Ubuntu", "child_type": "wsl"}
        )

        result = await child_host_ops.restart_child_host(
            {"child_type": "wsl", "child_name": "Ubuntu"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_lxd_container(self, child_host_ops):
        """Test restarting an LXD container."""
        child_host_ops.lxd_ops.restart_child_host = AsyncMock(
            return_value={
                "success": True,
                "child_name": "test-container",
                "child_type": "lxd",
            }
        )

        result = await child_host_ops.restart_child_host(
            {"child_type": "lxd", "child_name": "test-container"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_vmm_vm(self, child_host_ops):
        """Test restarting a VMM VM."""
        child_host_ops.vmm_ops.restart_child_host = AsyncMock(
            return_value={"success": True, "child_name": "test-vm", "child_type": "vmm"}
        )

        result = await child_host_ops.restart_child_host(
            {"child_type": "vmm", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_kvm_vm(self, child_host_ops):
        """Test restarting a KVM VM."""
        child_host_ops.kvm_ops.restart_child_host = AsyncMock(
            return_value={"success": True, "child_name": "test-vm", "child_type": "kvm"}
        )

        result = await child_host_ops.restart_child_host(
            {"child_type": "kvm", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_bhyve_vm(self, child_host_ops):
        """Test restarting a bhyve VM."""
        child_host_ops.bhyve_ops.restart_child_host = AsyncMock(
            return_value={
                "success": True,
                "child_name": "test-vm",
                "child_type": "bhyve",
            }
        )

        result = await child_host_ops.restart_child_host(
            {"child_type": "bhyve", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_unsupported_type(self, child_host_ops):
        """Test restarting child host with unsupported type."""
        result = await child_host_ops.restart_child_host(
            {"child_type": "docker", "child_name": "test"}
        )

        assert result["success"] is False
        assert "Unsupported" in result["error"]


class TestDeleteChildHost:
    """Tests for delete_child_host method."""

    @pytest.mark.asyncio
    async def test_delete_wsl_instance(self, child_host_ops, mock_agent):
        """Test deleting a WSL instance."""
        child_host_ops.wsl_ops.delete_child_host = AsyncMock(
            return_value={"success": True, "child_name": "Ubuntu", "child_type": "wsl"}
        )

        result = await child_host_ops.delete_child_host(
            {"child_type": "wsl", "child_name": "Ubuntu"}
        )

        assert result["success"] is True
        mock_agent.child_host_collector.send_child_hosts_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_lxd_container(self, child_host_ops):
        """Test deleting an LXD container."""
        child_host_ops.lxd_ops.delete_child_host = AsyncMock(
            return_value={
                "success": True,
                "child_name": "test-container",
                "child_type": "lxd",
            }
        )

        result = await child_host_ops.delete_child_host(
            {"child_type": "lxd", "child_name": "test-container"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_vmm_vm(self, child_host_ops):
        """Test deleting a VMM VM."""
        child_host_ops.vmm_ops.delete_child_host = AsyncMock(
            return_value={"success": True, "child_name": "test-vm", "child_type": "vmm"}
        )

        result = await child_host_ops.delete_child_host(
            {"child_type": "vmm", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_kvm_vm(self, child_host_ops):
        """Test deleting a KVM VM."""
        child_host_ops.kvm_ops.delete_child_host = AsyncMock(
            return_value={"success": True, "child_name": "test-vm", "child_type": "kvm"}
        )

        result = await child_host_ops.delete_child_host(
            {"child_type": "kvm", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_bhyve_vm(self, child_host_ops):
        """Test deleting a bhyve VM."""
        child_host_ops.bhyve_ops.delete_child_host = AsyncMock(
            return_value={
                "success": True,
                "child_name": "test-vm",
                "child_type": "bhyve",
            }
        )

        result = await child_host_ops.delete_child_host(
            {"child_type": "bhyve", "child_name": "test-vm"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_unsupported_type(self, child_host_ops):
        """Test deleting child host with unsupported type."""
        result = await child_host_ops.delete_child_host(
            {"child_type": "docker", "child_name": "test"}
        )

        assert result["success"] is False
        assert "Unsupported" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_failed_no_update_sent(self, child_host_ops, mock_agent):
        """Test that child host update is not sent on delete failure."""
        child_host_ops.wsl_ops.delete_child_host = AsyncMock(
            return_value={"success": False, "error": "Delete failed"}
        )

        result = await child_host_ops.delete_child_host(
            {"child_type": "wsl", "child_name": "Ubuntu"}
        )

        assert result["success"] is False
        mock_agent.child_host_collector.send_child_hosts_update.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_update_exception_handled(self, child_host_ops, mock_agent):
        """Test that exception in child host update is handled gracefully."""
        child_host_ops.wsl_ops.delete_child_host = AsyncMock(
            return_value={"success": True, "child_name": "Ubuntu"}
        )
        mock_agent.child_host_collector.send_child_hosts_update = AsyncMock(
            side_effect=Exception("Update failed")
        )

        result = await child_host_ops.delete_child_host(
            {"child_type": "wsl", "child_name": "Ubuntu"}
        )

        # Should still succeed despite update failure
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_no_collector(self, child_host_ops, mock_agent):
        """Test deleting when agent has no child_host_collector."""
        del mock_agent.child_host_collector
        child_host_ops.wsl_ops.delete_child_host = AsyncMock(
            return_value={"success": True, "child_name": "Ubuntu"}
        )

        result = await child_host_ops.delete_child_host(
            {"child_type": "wsl", "child_name": "Ubuntu"}
        )

        # Should still succeed
        assert result["success"] is True


class TestSendChildHostsUpdate:
    """Tests for _send_child_hosts_update method."""

    @pytest.mark.asyncio
    async def test_send_update_success(self, child_host_ops, mock_agent):
        """Test sending child hosts update successfully."""
        await child_host_ops._send_child_hosts_update()

        mock_agent.child_host_collector.send_child_hosts_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_update_no_collector(self, child_host_ops, mock_agent):
        """Test sending update when no collector exists."""
        del mock_agent.child_host_collector

        # Should not raise
        await child_host_ops._send_child_hosts_update()

    @pytest.mark.asyncio
    async def test_send_update_exception(self, child_host_ops, mock_agent):
        """Test sending update with exception."""
        mock_agent.child_host_collector.send_child_hosts_update = AsyncMock(
            side_effect=Exception("Network error")
        )

        # Should not raise
        await child_host_ops._send_child_hosts_update()


class TestPlatformVirtualizationHelpers:
    """Tests for platform-specific virtualization helper methods."""

    def test_check_windows_virtualization_wsl_available(self, child_host_ops):
        """Test Windows virtualization check with WSL available."""
        child_host_ops.virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": False,
        }
        child_host_ops.virtualization_checks.check_hyperv_support.return_value = {
            "available": False,
        }

        supported_types = []
        capabilities = {}
        reboot_required = child_host_ops._check_windows_virtualization(
            supported_types, capabilities
        )

        assert "wsl" in supported_types
        assert reboot_required is False

    def test_check_windows_virtualization_wsl_needs_enable(self, child_host_ops):
        """Test Windows virtualization check when WSL needs enabling."""
        child_host_ops.virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": True,
        }
        child_host_ops.virtualization_checks.check_hyperv_support.return_value = {
            "available": False,
        }

        supported_types = []
        capabilities = {}
        reboot_required = child_host_ops._check_windows_virtualization(
            supported_types, capabilities
        )

        assert reboot_required is True

    def test_check_windows_virtualization_hyperv_available(self, child_host_ops):
        """Test Windows virtualization check with Hyper-V available."""
        child_host_ops.virtualization_checks.check_wsl_support.return_value = {
            "available": False,
        }
        child_host_ops.virtualization_checks.check_hyperv_support.return_value = {
            "available": True,
        }

        supported_types = []
        capabilities = {}
        child_host_ops._check_windows_virtualization(supported_types, capabilities)

        assert "hyperv" in supported_types

    def test_check_linux_virtualization(self, child_host_ops):
        """Test Linux virtualization check."""
        child_host_ops.virtualization_checks.check_lxd_support.return_value = {
            "available": True,
        }
        child_host_ops.virtualization_checks.check_kvm_support.return_value = {
            "available": True,
        }

        supported_types = []
        capabilities = {}
        child_host_ops._check_linux_virtualization(supported_types, capabilities)

        assert "lxd" in supported_types
        assert "kvm" in supported_types

    def test_check_freebsd_virtualization(self, child_host_ops):
        """Test FreeBSD virtualization check."""
        child_host_ops.virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
        }

        supported_types = []
        capabilities = {}
        child_host_ops._check_freebsd_virtualization(supported_types, capabilities)

        assert "bhyve" in supported_types

    def test_check_openbsd_virtualization(self, child_host_ops):
        """Test OpenBSD virtualization check."""
        child_host_ops.virtualization_checks.check_vmm_support.return_value = {
            "available": True,
        }

        supported_types = []
        capabilities = {}
        child_host_ops._check_openbsd_virtualization(supported_types, capabilities)

        assert "vmm" in supported_types

    def test_check_virtualbox(self, child_host_ops):
        """Test VirtualBox check."""
        child_host_ops.virtualization_checks.check_virtualbox_support.return_value = {
            "available": True,
        }

        supported_types = []
        capabilities = {}
        child_host_ops._check_virtualbox(supported_types, capabilities)

        assert "virtualbox" in supported_types


class TestCollectPlatformChildHosts:
    """Tests for _collect_platform_child_hosts and related methods."""

    def test_collect_windows_child_hosts(self, child_host_ops):
        """Test collecting Windows child hosts."""
        child_host_ops.listing_helper.list_wsl_instances.return_value = [
            {"name": "Ubuntu"}
        ]
        child_host_ops.listing_helper.list_hyperv_vms.return_value = []

        child_hosts = []
        child_host_ops._collect_windows_child_hosts(child_hosts, None)

        assert len(child_hosts) == 1

    def test_collect_windows_child_hosts_with_wsl_filter(self, child_host_ops):
        """Test collecting Windows child hosts with WSL filter."""
        child_host_ops.listing_helper.list_wsl_instances.return_value = [
            {"name": "Ubuntu"}
        ]

        child_hosts = []
        child_host_ops._collect_windows_child_hosts(child_hosts, "wsl")

        assert len(child_hosts) == 1
        child_host_ops.listing_helper.list_hyperv_vms.assert_not_called()

    def test_collect_linux_child_hosts(self, child_host_ops):
        """Test collecting Linux child hosts."""
        child_host_ops.listing_helper.list_lxd_containers.return_value = [
            {"name": "test-container"}
        ]
        child_host_ops.listing_helper.list_kvm_vms.return_value = []

        child_hosts = []
        child_host_ops._collect_linux_child_hosts(child_hosts, None)

        assert len(child_hosts) == 1

    def test_collect_linux_child_hosts_with_kvm_filter(self, child_host_ops):
        """Test collecting Linux child hosts with KVM filter."""
        child_host_ops.listing_helper.list_kvm_vms.return_value = [{"name": "test-vm"}]

        child_hosts = []
        child_host_ops._collect_linux_child_hosts(child_hosts, "kvm")

        assert len(child_hosts) == 1
        child_host_ops.listing_helper.list_lxd_containers.assert_not_called()

    def test_collect_openbsd_child_hosts(self, child_host_ops):
        """Test collecting OpenBSD child hosts."""
        child_host_ops.listing_helper.list_vmm_vms.return_value = [{"name": "test-vm"}]

        child_hosts = []
        child_host_ops._collect_openbsd_child_hosts(child_hosts, None)

        assert len(child_hosts) == 1

    def test_collect_freebsd_child_hosts(self, child_host_ops):
        """Test collecting FreeBSD child hosts."""
        child_host_ops.listing_helper.list_bhyve_vms.return_value = [
            {"name": "test-vm"}
        ]

        child_hosts = []
        child_host_ops._collect_freebsd_child_hosts(child_hosts, None)

        assert len(child_hosts) == 1

    def test_collect_virtualbox_vms(self, child_host_ops):
        """Test collecting VirtualBox VMs."""
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = [
            {"name": "test-vm"}
        ]

        child_hosts = []
        child_host_ops._collect_virtualbox_vms(child_hosts, None)

        assert len(child_hosts) == 1

    def test_collect_virtualbox_vms_with_filter(self, child_host_ops):
        """Test collecting VirtualBox VMs with filter."""
        child_host_ops.listing_helper.list_virtualbox_vms.return_value = [
            {"name": "test-vm"}
        ]

        child_hosts = []
        child_host_ops._collect_virtualbox_vms(child_hosts, "virtualbox")

        assert len(child_hosts) == 1

    def test_collect_virtualbox_vms_with_different_filter(self, child_host_ops):
        """Test collecting VirtualBox VMs with different filter."""
        child_hosts = []
        child_host_ops._collect_virtualbox_vms(child_hosts, "lxd")

        # VirtualBox VMs should not be collected when filter is lxd
        child_host_ops.listing_helper.list_virtualbox_vms.assert_not_called()


class TestCheckPlatformVirtualization:
    """Tests for _check_platform_virtualization method."""

    def test_check_platform_virtualization_windows(self, child_host_ops):
        """Test platform virtualization check for Windows."""
        child_host_ops.virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": False,
        }
        child_host_ops.virtualization_checks.check_hyperv_support.return_value = {
            "available": False,
        }

        supported_types = []
        capabilities = {}
        reboot_required = child_host_ops._check_platform_virtualization(
            "windows", supported_types, capabilities
        )

        assert "wsl" in supported_types
        assert reboot_required is False

    def test_check_platform_virtualization_linux(self, child_host_ops):
        """Test platform virtualization check for Linux."""
        child_host_ops.virtualization_checks.check_lxd_support.return_value = {
            "available": True,
        }
        child_host_ops.virtualization_checks.check_kvm_support.return_value = {
            "available": True,
        }

        supported_types = []
        capabilities = {}
        reboot_required = child_host_ops._check_platform_virtualization(
            "linux", supported_types, capabilities
        )

        assert "lxd" in supported_types
        assert "kvm" in supported_types
        assert reboot_required is False

    def test_check_platform_virtualization_freebsd(self, child_host_ops):
        """Test platform virtualization check for FreeBSD."""
        child_host_ops.virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
        }

        supported_types = []
        capabilities = {}
        reboot_required = child_host_ops._check_platform_virtualization(
            "freebsd", supported_types, capabilities
        )

        assert "bhyve" in supported_types
        assert reboot_required is False

    def test_check_platform_virtualization_openbsd(self, child_host_ops):
        """Test platform virtualization check for OpenBSD."""
        child_host_ops.virtualization_checks.check_vmm_support.return_value = {
            "available": True,
        }

        supported_types = []
        capabilities = {}
        reboot_required = child_host_ops._check_platform_virtualization(
            "openbsd", supported_types, capabilities
        )

        assert "vmm" in supported_types
        assert reboot_required is False

    def test_check_platform_virtualization_unknown(self, child_host_ops):
        """Test platform virtualization check for unknown OS."""
        supported_types = []
        capabilities = {}
        reboot_required = child_host_ops._check_platform_virtualization(
            "haiku", supported_types, capabilities
        )

        assert not supported_types
        assert reboot_required is False


class TestCollectPlatformChildHostsMethod:
    """Tests for _collect_platform_child_hosts method."""

    def test_collect_platform_child_hosts_windows(self, child_host_ops):
        """Test collecting platform child hosts for Windows."""
        child_host_ops.listing_helper.list_wsl_instances.return_value = [
            {"name": "Ubuntu"}
        ]
        child_host_ops.listing_helper.list_hyperv_vms.return_value = []

        result = child_host_ops._collect_platform_child_hosts("windows", None)

        assert len(result) == 1

    def test_collect_platform_child_hosts_linux(self, child_host_ops):
        """Test collecting platform child hosts for Linux."""
        child_host_ops.listing_helper.list_lxd_containers.return_value = []
        child_host_ops.listing_helper.list_kvm_vms.return_value = [{"name": "test-vm"}]

        result = child_host_ops._collect_platform_child_hosts("linux", None)

        assert len(result) == 1

    def test_collect_platform_child_hosts_openbsd(self, child_host_ops):
        """Test collecting platform child hosts for OpenBSD."""
        child_host_ops.listing_helper.list_vmm_vms.return_value = [{"name": "test-vm"}]

        result = child_host_ops._collect_platform_child_hosts("openbsd", None)

        assert len(result) == 1

    def test_collect_platform_child_hosts_freebsd(self, child_host_ops):
        """Test collecting platform child hosts for FreeBSD."""
        child_host_ops.listing_helper.list_bhyve_vms.return_value = [
            {"name": "test-vm"}
        ]

        result = child_host_ops._collect_platform_child_hosts("freebsd", None)

        assert len(result) == 1

    def test_collect_platform_child_hosts_unknown(self, child_host_ops):
        """Test collecting platform child hosts for unknown OS."""
        result = child_host_ops._collect_platform_child_hosts("haiku", None)

        assert result == []
