"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_vmm module.

Tests cover:
- VmmOperations initialization
- VMM precondition checks
- Hostname file creation
- IP forwarding configuration
- Network interface setup
- vm.conf creation
- vmd service enabling and starting
- VM lifecycle operations (start, stop, restart, delete)
- Distribution detection (Alpine, Debian, Ubuntu, OpenBSD)
- VM creation routing
- Duplicate VM creation prevention
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import asyncio
import subprocess
from unittest.mock import AsyncMock, Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.operations.child_host_vmm import VmmOperations
from src.sysmanage_agent.operations.child_host_types import (
    VmmVmConfig,
    VmmServerConfig,
    VmmResourceConfig,
)


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    return Mock()


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock = Mock()
    mock.check_vmm_support = Mock(
        return_value={
            "available": True,
            "kernel_supported": True,
            "enabled": True,
            "running": True,
        }
    )
    return mock


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    mock = Mock()
    mock.send_message = AsyncMock()
    mock.create_message = Mock(return_value={"type": "test"})
    return mock


@pytest.fixture
def mock_db_manager():
    """Create a mock database manager."""
    mock_session = Mock()
    mock_manager = Mock()
    mock_manager.get_session.return_value = mock_session
    return mock_manager


@pytest.fixture
def vmm_ops(mock_agent, mock_logger, mock_virtualization_checks, mock_db_manager):
    """Create a VmmOperations instance for testing."""
    with patch(
        "src.sysmanage_agent.operations.child_host_vmm.get_database_manager",
        return_value=mock_db_manager,
    ):
        return VmmOperations(mock_agent, mock_logger, mock_virtualization_checks)


class TestVmmOperationsInit:
    """Tests for VmmOperations initialization."""

    def test_init_sets_agent(self, vmm_ops, mock_agent):
        """Test that __init__ sets agent."""
        assert vmm_ops.agent == mock_agent

    def test_init_sets_logger(self, vmm_ops, mock_logger):
        """Test that __init__ sets logger."""
        assert vmm_ops.logger == mock_logger

    def test_init_sets_virtualization_checks(self, vmm_ops, mock_virtualization_checks):
        """Test that __init__ sets virtualization_checks."""
        assert vmm_ops.virtualization_checks == mock_virtualization_checks

    def test_init_creates_ssh_ops(self, vmm_ops):
        """Test that __init__ creates ssh_ops."""
        assert vmm_ops.ssh_ops is not None

    def test_init_creates_lifecycle(self, vmm_ops):
        """Test that __init__ creates lifecycle operations."""
        assert vmm_ops.lifecycle is not None

    def test_init_creates_github_checker(self, vmm_ops):
        """Test that __init__ creates github checker."""
        assert vmm_ops.github_checker is not None

    def test_init_creates_site_builder(self, vmm_ops):
        """Test that __init__ creates site builder."""
        assert vmm_ops.site_builder is not None

    def test_init_creates_httpd_setup(self, vmm_ops):
        """Test that __init__ creates httpd setup."""
        assert vmm_ops.httpd_setup is not None

    def test_init_creates_vm_creator(self, vmm_ops):
        """Test that __init__ creates vm_creator."""
        assert vmm_ops.vm_creator is not None

    def test_init_creates_alpine_vm_creator(self, vmm_ops):
        """Test that __init__ creates alpine_vm_creator."""
        assert vmm_ops.alpine_vm_creator is not None

    def test_init_creates_debian_vm_creator(self, vmm_ops):
        """Test that __init__ creates debian_vm_creator."""
        assert vmm_ops.debian_vm_creator is not None

    def test_init_creates_ubuntu_vm_creator(self, vmm_ops):
        """Test that __init__ creates ubuntu_vm_creator."""
        assert vmm_ops.ubuntu_vm_creator is not None

    def test_init_creates_empty_in_progress_set(self, vmm_ops):
        """Test that __init__ creates empty in-progress VM set."""
        assert vmm_ops._in_progress_vms == set()


class TestRunSubprocess:
    """Tests for _run_subprocess method."""

    @pytest.mark.asyncio
    async def test_run_subprocess_success(self, vmm_ops):
        """Test successful subprocess execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""

        with patch("asyncio.to_thread", return_value=mock_result) as mock_to_thread:
            result = await vmm_ops._run_subprocess(["echo", "test"])

        assert result.returncode == 0
        assert result.stdout == "output"
        mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_subprocess_with_timeout(self, vmm_ops):
        """Test subprocess execution with custom timeout."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("asyncio.to_thread", return_value=mock_result) as mock_to_thread:
            await vmm_ops._run_subprocess(["test"], timeout=30)

        # Verify subprocess.run was called with correct timeout
        call_args = mock_to_thread.call_args
        assert call_args[1]["timeout"] == 30


class TestCheckVmmPreconditions:
    """Tests for _check_vmm_preconditions method."""

    def test_preconditions_vmm_not_available(self, vmm_ops):
        """Test preconditions when VMM is not available."""
        vmm_check = {"available": False}
        result = vmm_ops._check_vmm_preconditions(vmm_check)

        assert result is not None
        assert result["success"] is False
        assert "not available" in result["error"]

    def test_preconditions_kernel_not_supported(self, vmm_ops):
        """Test preconditions when kernel support is missing."""
        vmm_check = {"available": True, "kernel_supported": False}
        result = vmm_ops._check_vmm_preconditions(vmm_check)

        assert result is not None
        assert result["success"] is False
        assert "kernel support" in result["error"].lower()
        assert result.get("needs_reboot") is True

    def test_preconditions_already_running(self, vmm_ops):
        """Test preconditions when vmd is already running."""
        vmm_check = {"available": True, "kernel_supported": True, "running": True}
        result = vmm_ops._check_vmm_preconditions(vmm_check)

        assert result is not None
        assert result["success"] is True
        assert result["already_enabled"] is True
        vmm_ops.logger.info.assert_called()

    def test_preconditions_ok_to_proceed(self, vmm_ops):
        """Test preconditions when everything is OK to proceed."""
        vmm_check = {"available": True, "kernel_supported": True, "running": False}
        result = vmm_ops._check_vmm_preconditions(vmm_check)

        assert result is None  # None means OK to proceed


class TestCreateHostnameFiles:
    """Tests for _create_hostname_files method."""

    @pytest.mark.asyncio
    async def test_create_hostname_files_success(self, vmm_ops):
        """Test successful hostname file creation."""
        gateway_ip = "10.0.0.1"

        with patch("aiofiles.open", create=True) as mock_aiofiles:
            mock_file = AsyncMock()
            mock_aiofiles.return_value.__aenter__.return_value = mock_file
            with patch("os.chmod") as mock_chmod:
                result = await vmm_ops._create_hostname_files(gateway_ip)

        assert result is None  # None means success
        assert mock_chmod.call_count == 2  # vether0 and bridge0

    @pytest.mark.asyncio
    async def test_create_hostname_files_vether_error(self, vmm_ops):
        """Test hostname file creation with vether0 error."""
        gateway_ip = "10.0.0.1"

        with patch("aiofiles.open", create=True) as mock_aiofiles:
            mock_aiofiles.side_effect = IOError("Permission denied")
            result = await vmm_ops._create_hostname_files(gateway_ip)

        assert result is not None
        assert result["success"] is False
        assert "hostname.vether0" in result["error"]
        vmm_ops.logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_create_hostname_files_bridge_error(self, vmm_ops):
        """Test hostname file creation with bridge0 error."""
        gateway_ip = "10.0.0.1"

        call_count = [0]

        def mock_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call (vether0) succeeds
                mock_file = AsyncMock()
                mock_cm = MagicMock()
                mock_cm.__aenter__ = AsyncMock(return_value=mock_file)
                mock_cm.__aexit__ = AsyncMock(return_value=None)
                return mock_cm
            # Second call (bridge0) fails
            raise IOError("Permission denied")

        with patch("aiofiles.open", create=True, side_effect=mock_open_side_effect):
            with patch("os.chmod"):
                result = await vmm_ops._create_hostname_files(gateway_ip)

        assert result is not None
        assert result["success"] is False
        assert "hostname.bridge0" in result["error"]


class TestConfigureIpForwarding:
    """Tests for _configure_ip_forwarding method."""

    @pytest.mark.asyncio
    async def test_configure_ip_forwarding_new_config(self, vmm_ops):
        """Test configuring IP forwarding with new config entry."""
        mock_file = AsyncMock()
        mock_file.read.return_value = ""

        with patch("pathlib.Path.exists", return_value=True):
            with patch("aiofiles.open", create=True) as mock_aiofiles:
                mock_aiofiles.return_value.__aenter__.return_value = mock_file
                with patch.object(vmm_ops, "_run_subprocess") as mock_run:
                    mock_run.return_value = Mock(returncode=0)
                    await vmm_ops._configure_ip_forwarding()

        vmm_ops.logger.info.assert_called()
        mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_configure_ip_forwarding_already_set(self, vmm_ops):
        """Test IP forwarding when already configured."""
        mock_file = AsyncMock()
        mock_file.read.return_value = "net.inet.ip.forwarding=1\n"

        with patch("pathlib.Path.exists", return_value=True):
            with patch("aiofiles.open", create=True) as mock_aiofiles:
                mock_aiofiles.return_value.__aenter__.return_value = mock_file
                with patch.object(vmm_ops, "_run_subprocess") as mock_run:
                    mock_run.return_value = Mock(returncode=0)
                    await vmm_ops._configure_ip_forwarding()

        # Should still call sysctl to enable immediately
        mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_configure_ip_forwarding_file_not_exists(self, vmm_ops):
        """Test IP forwarding when sysctl.conf doesn't exist."""
        mock_file = AsyncMock()

        with patch("pathlib.Path.exists", return_value=False):
            with patch("aiofiles.open", create=True) as mock_aiofiles:
                mock_aiofiles.return_value.__aenter__.return_value = mock_file
                with patch.object(vmm_ops, "_run_subprocess") as mock_run:
                    mock_run.return_value = Mock(returncode=0)
                    await vmm_ops._configure_ip_forwarding()

        # Should write to file and call sysctl
        mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_configure_ip_forwarding_exception(self, vmm_ops):
        """Test IP forwarding with exception."""
        with patch("pathlib.Path.exists", return_value=True):
            with patch("aiofiles.open", side_effect=IOError("Error")):
                # Should not raise, just warn
                await vmm_ops._configure_ip_forwarding()

        vmm_ops.logger.warning.assert_called()


class TestSetupNetworkInterfaces:
    """Tests for _setup_network_interfaces method."""

    @pytest.mark.asyncio
    async def test_setup_network_interfaces_success(self, vmm_ops):
        """Test successful network interface setup."""
        with patch.object(vmm_ops, "_run_subprocess") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            await vmm_ops._setup_network_interfaces()

        # Should call for vether0 create, netstart vether0, netstart bridge0, bridge0 add
        assert mock_run.call_count == 4
        vmm_ops.logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_setup_network_interfaces_bridge_warning(self, vmm_ops):
        """Test network interface setup with bridge warning."""
        call_count = [0]

        def mock_run_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 3:  # bridge0 netstart
                return Mock(returncode=1, stdout="exists", stderr="already exists")
            return Mock(returncode=0, stdout="", stderr="")

        with patch.object(vmm_ops, "_run_subprocess", side_effect=mock_run_side_effect):
            await vmm_ops._setup_network_interfaces()

        vmm_ops.logger.warning.assert_called()


class TestCreateVmConf:
    """Tests for _create_vm_conf method."""

    @pytest.mark.asyncio
    async def test_create_vm_conf_success(self, vmm_ops):
        """Test successful vm.conf creation."""
        with patch("aiofiles.open", create=True) as mock_aiofiles:
            mock_file = AsyncMock()
            mock_aiofiles.return_value.__aenter__.return_value = mock_file
            result = await vmm_ops._create_vm_conf()

        assert result is None  # None means success
        mock_file.write.assert_called_once()
        vmm_ops.logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_create_vm_conf_error(self, vmm_ops):
        """Test vm.conf creation with error."""
        with patch("aiofiles.open", side_effect=IOError("Permission denied")):
            result = await vmm_ops._create_vm_conf()

        assert result is not None
        assert result["success"] is False
        assert "vm.conf" in result["error"]
        vmm_ops.logger.error.assert_called()


class TestEnableAndStartVmd:
    """Tests for _enable_and_start_vmd method."""

    @pytest.mark.asyncio
    async def test_enable_and_start_vmd_success(
        self, vmm_ops, mock_virtualization_checks
    ):
        """Test successful vmd enable and start."""
        vmm_check = {"enabled": False, "running": False}

        with patch.object(vmm_ops, "_run_subprocess") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            mock_virtualization_checks.check_vmm_support.return_value = {
                "running": True
            }
            result = await vmm_ops._enable_and_start_vmd(vmm_check)

        assert result["success"] is True
        assert result["needs_reboot"] is False
        assert mock_run.call_count == 2  # enable and start

    @pytest.mark.asyncio
    async def test_enable_and_start_vmd_already_enabled(
        self, vmm_ops, mock_virtualization_checks
    ):
        """Test vmd start when already enabled."""
        vmm_check = {"enabled": True, "running": False}

        with patch.object(vmm_ops, "_run_subprocess") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            mock_virtualization_checks.check_vmm_support.return_value = {
                "running": True
            }
            result = await vmm_ops._enable_and_start_vmd(vmm_check)

        assert result["success"] is True
        assert mock_run.call_count == 1  # Only start, not enable

    @pytest.mark.asyncio
    async def test_enable_and_start_vmd_enable_failure(self, vmm_ops):
        """Test vmd enable failure."""
        vmm_check = {"enabled": False, "running": False}

        with patch.object(vmm_ops, "_run_subprocess") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="failed to enable"
            )
            result = await vmm_ops._enable_and_start_vmd(vmm_check)

        assert result["success"] is False
        assert "enable" in result["error"].lower()
        vmm_ops.logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_enable_and_start_vmd_start_failure(self, vmm_ops):
        """Test vmd start failure."""
        vmm_check = {"enabled": True, "running": False}

        with patch.object(vmm_ops, "_run_subprocess") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="failed to start"
            )
            result = await vmm_ops._enable_and_start_vmd(vmm_check)

        assert result["success"] is False
        assert "start" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_and_start_vmd_verification_failure(
        self, vmm_ops, mock_virtualization_checks
    ):
        """Test vmd verification failure after start."""
        vmm_check = {"enabled": True, "running": False}

        with patch.object(vmm_ops, "_run_subprocess") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            mock_virtualization_checks.check_vmm_support.return_value = {
                "running": False
            }
            result = await vmm_ops._enable_and_start_vmd(vmm_check)

        assert result["success"] is False
        assert "verification" in result["error"].lower()


class TestInitializeVmd:
    """Tests for initialize_vmd method."""

    @pytest.mark.asyncio
    async def test_initialize_vmd_precondition_failure(
        self, vmm_ops, mock_virtualization_checks
    ):
        """Test initialize_vmd with precondition failure."""
        mock_virtualization_checks.check_vmm_support.return_value = {"available": False}
        result = await vmm_ops.initialize_vmd({})

        assert result["success"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_initialize_vmd_already_running(
        self, vmm_ops, mock_virtualization_checks
    ):
        """Test initialize_vmd when vmd is already running."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": True,
        }
        result = await vmm_ops.initialize_vmd({})

        assert result["success"] is True
        assert result["already_enabled"] is True

    @pytest.mark.asyncio
    async def test_initialize_vmd_success(self, vmm_ops, mock_virtualization_checks):
        """Test successful vmd initialization."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": False,
            "enabled": False,
        }

        with patch(
            "src.sysmanage_agent.operations.child_host_vmm.select_unused_subnet"
        ) as mock_subnet:
            mock_subnet.return_value = {"gateway_ip": "10.0.0.1"}
            with patch.object(vmm_ops, "_create_hostname_files", return_value=None):
                with patch.object(vmm_ops, "_configure_ip_forwarding"):
                    with patch.object(vmm_ops, "_setup_network_interfaces"):
                        with patch.object(
                            vmm_ops, "_create_vm_conf", return_value=None
                        ):
                            with patch.object(
                                vmm_ops, "_enable_and_start_vmd"
                            ) as mock_start:
                                mock_start.return_value = {"success": True}
                                result = await vmm_ops.initialize_vmd({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_initialize_vmd_hostname_failure(
        self, vmm_ops, mock_virtualization_checks
    ):
        """Test initialize_vmd with hostname file failure."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": False,
        }

        with patch(
            "src.sysmanage_agent.operations.child_host_vmm.select_unused_subnet"
        ) as mock_subnet:
            mock_subnet.return_value = {"gateway_ip": "10.0.0.1"}
            with patch.object(
                vmm_ops,
                "_create_hostname_files",
                return_value={"success": False, "error": "Permission denied"},
            ):
                result = await vmm_ops.initialize_vmd({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_initialize_vmd_timeout(self, vmm_ops, mock_virtualization_checks):
        """Test initialize_vmd with timeout."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": False,
        }

        with patch(
            "src.sysmanage_agent.operations.child_host_vmm.select_unused_subnet"
        ) as mock_subnet:
            mock_subnet.side_effect = subprocess.TimeoutExpired("cmd", 60)
            result = await vmm_ops.initialize_vmd({})

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_initialize_vmd_exception(self, vmm_ops, mock_virtualization_checks):
        """Test initialize_vmd with general exception."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": False,
        }

        with patch(
            "src.sysmanage_agent.operations.child_host_vmm.select_unused_subnet"
        ) as mock_subnet:
            mock_subnet.side_effect = Exception("Unexpected error")
            result = await vmm_ops.initialize_vmd({})

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestCheckVmdReady:
    """Tests for check_vmd_ready method."""

    @pytest.mark.asyncio
    async def test_check_vmd_ready_delegates_to_lifecycle(self, vmm_ops):
        """Test that check_vmd_ready delegates to lifecycle."""
        expected_result = {"success": True, "ready": True}
        with patch.object(
            vmm_ops.lifecycle, "check_vmd_ready", return_value=expected_result
        ):
            result = await vmm_ops.check_vmd_ready()

        assert result == expected_result


class TestGetVmStatus:
    """Tests for get_vm_status method."""

    @pytest.mark.asyncio
    async def test_get_vm_status_delegates_to_lifecycle(self, vmm_ops):
        """Test that get_vm_status delegates to lifecycle."""
        expected_result = {"success": True, "running": True}
        with patch.object(
            vmm_ops.lifecycle, "get_vm_status", return_value=expected_result
        ):
            result = await vmm_ops.get_vm_status("test-vm")

        assert result == expected_result


class TestStartChildHost:
    """Tests for start_child_host method."""

    @pytest.mark.asyncio
    async def test_start_child_host_no_name(self, vmm_ops):
        """Test start_child_host without name."""
        result = await vmm_ops.start_child_host({})

        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_child_host_success(self, vmm_ops):
        """Test successful start_child_host."""
        expected_result = {"success": True}
        with patch.object(
            vmm_ops.lifecycle, "start_vm", return_value=expected_result
        ) as mock_start:
            result = await vmm_ops.start_child_host(
                {"child_name": "test-vm", "wait": True}
            )

        assert result["success"] is True
        mock_start.assert_called_once_with("test-vm", wait=True)

    @pytest.mark.asyncio
    async def test_start_child_host_default_wait(self, vmm_ops):
        """Test start_child_host with default wait value."""
        with patch.object(
            vmm_ops.lifecycle, "start_vm", return_value={"success": True}
        ) as mock_start:
            await vmm_ops.start_child_host({"child_name": "test-vm"})

        mock_start.assert_called_once_with("test-vm", wait=True)


class TestStopChildHost:
    """Tests for stop_child_host method."""

    @pytest.mark.asyncio
    async def test_stop_child_host_no_name(self, vmm_ops):
        """Test stop_child_host without name."""
        result = await vmm_ops.stop_child_host({})

        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_stop_child_host_success(self, vmm_ops):
        """Test successful stop_child_host."""
        expected_result = {"success": True}
        with patch.object(
            vmm_ops.lifecycle, "stop_vm", return_value=expected_result
        ) as mock_stop:
            result = await vmm_ops.stop_child_host(
                {"child_name": "test-vm", "force": True, "wait": True}
            )

        assert result["success"] is True
        mock_stop.assert_called_once_with("test-vm", force=True, wait=True)

    @pytest.mark.asyncio
    async def test_stop_child_host_default_values(self, vmm_ops):
        """Test stop_child_host with default values."""
        with patch.object(
            vmm_ops.lifecycle, "stop_vm", return_value={"success": True}
        ) as mock_stop:
            await vmm_ops.stop_child_host({"child_name": "test-vm"})

        mock_stop.assert_called_once_with("test-vm", force=False, wait=True)


class TestRestartChildHost:
    """Tests for restart_child_host method."""

    @pytest.mark.asyncio
    async def test_restart_child_host_no_name(self, vmm_ops):
        """Test restart_child_host without name."""
        result = await vmm_ops.restart_child_host({})

        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_restart_child_host_success(self, vmm_ops):
        """Test successful restart_child_host."""
        expected_result = {"success": True}
        with patch.object(
            vmm_ops.lifecycle, "restart_vm", return_value=expected_result
        ) as mock_restart:
            result = await vmm_ops.restart_child_host({"child_name": "test-vm"})

        assert result["success"] is True
        mock_restart.assert_called_once_with("test-vm")


class TestDeleteChildHost:
    """Tests for delete_child_host method."""

    @pytest.mark.asyncio
    async def test_delete_child_host_no_name(self, vmm_ops):
        """Test delete_child_host without name."""
        result = await vmm_ops.delete_child_host({})

        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_child_host_success(self, vmm_ops):
        """Test successful delete_child_host."""
        expected_result = {"success": True}
        with patch.object(
            vmm_ops.lifecycle, "delete_vm", return_value=expected_result
        ) as mock_delete:
            result = await vmm_ops.delete_child_host(
                {"child_name": "test-vm", "delete_disk": True}
            )

        assert result["success"] is True
        mock_delete.assert_called_once_with("test-vm", delete_disk=True)

    @pytest.mark.asyncio
    async def test_delete_child_host_default_delete_disk(self, vmm_ops):
        """Test delete_child_host with default delete_disk value."""
        with patch.object(
            vmm_ops.lifecycle, "delete_vm", return_value={"success": True}
        ) as mock_delete:
            await vmm_ops.delete_child_host({"child_name": "test-vm"})

        mock_delete.assert_called_once_with("test-vm", delete_disk=True)


class TestIsAlpineDistribution:
    """Tests for _is_alpine_distribution method."""

    def test_is_alpine_lowercase(self, vmm_ops):
        """Test Alpine detection with lowercase."""
        assert vmm_ops._is_alpine_distribution("alpine linux 3.20") is True

    def test_is_alpine_uppercase(self, vmm_ops):
        """Test Alpine detection with uppercase."""
        assert vmm_ops._is_alpine_distribution("ALPINE LINUX 3.20") is True

    def test_is_alpine_mixed_case(self, vmm_ops):
        """Test Alpine detection with mixed case."""
        assert vmm_ops._is_alpine_distribution("Alpine Linux 3.20") is True

    def test_is_not_alpine(self, vmm_ops):
        """Test non-Alpine distribution."""
        assert vmm_ops._is_alpine_distribution("OpenBSD 7.6") is False

    def test_is_alpine_empty_string(self, vmm_ops):
        """Test Alpine detection with empty string."""
        assert vmm_ops._is_alpine_distribution("") is False

    def test_is_alpine_none(self, vmm_ops):
        """Test Alpine detection with None."""
        assert vmm_ops._is_alpine_distribution(None) is False


class TestIsDebianDistribution:
    """Tests for _is_debian_distribution method."""

    def test_is_debian_lowercase(self, vmm_ops):
        """Test Debian detection with lowercase."""
        assert vmm_ops._is_debian_distribution("debian 12") is True

    def test_is_debian_uppercase(self, vmm_ops):
        """Test Debian detection with uppercase."""
        assert vmm_ops._is_debian_distribution("DEBIAN 12") is True

    def test_is_debian_bookworm(self, vmm_ops):
        """Test Debian detection with codename Bookworm."""
        assert vmm_ops._is_debian_distribution("Bookworm") is True

    def test_is_not_debian(self, vmm_ops):
        """Test non-Debian distribution."""
        assert vmm_ops._is_debian_distribution("Ubuntu 24.04") is False

    def test_is_debian_empty_string(self, vmm_ops):
        """Test Debian detection with empty string."""
        assert vmm_ops._is_debian_distribution("") is False

    def test_is_debian_none(self, vmm_ops):
        """Test Debian detection with None."""
        assert vmm_ops._is_debian_distribution(None) is False


class TestIsUbuntuDistribution:
    """Tests for _is_ubuntu_distribution method."""

    def test_is_ubuntu_lowercase(self, vmm_ops):
        """Test Ubuntu detection with lowercase."""
        assert vmm_ops._is_ubuntu_distribution("ubuntu 24.04") is True

    def test_is_ubuntu_uppercase(self, vmm_ops):
        """Test Ubuntu detection with uppercase."""
        assert vmm_ops._is_ubuntu_distribution("UBUNTU 24.04") is True

    def test_is_ubuntu_noble(self, vmm_ops):
        """Test Ubuntu detection with codename Noble."""
        assert vmm_ops._is_ubuntu_distribution("Noble Numbat") is True

    def test_is_not_ubuntu(self, vmm_ops):
        """Test non-Ubuntu distribution."""
        assert vmm_ops._is_ubuntu_distribution("Debian 12") is False

    def test_is_ubuntu_empty_string(self, vmm_ops):
        """Test Ubuntu detection with empty string."""
        assert vmm_ops._is_ubuntu_distribution("") is False

    def test_is_ubuntu_none(self, vmm_ops):
        """Test Ubuntu detection with None."""
        assert vmm_ops._is_ubuntu_distribution(None) is False


class TestCreateVmmVm:
    """Tests for create_vmm_vm method."""

    def _create_config(self, distribution="OpenBSD 7.6", vm_name="test-vm"):
        """Helper to create a VmmVmConfig."""
        return VmmVmConfig(
            distribution=distribution,
            vm_name=vm_name,
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=["pkg_add sysmanage-agent"],
            server_config=VmmServerConfig(
                server_url="https://server.example.com",
                server_port=8443,
                use_https=True,
            ),
            resource_config=VmmResourceConfig(memory="2G", disk_size="20G", cpus=2),
        )

    @pytest.mark.asyncio
    async def test_create_vmm_vm_duplicate_in_progress(self, vmm_ops):
        """Test VM creation when already in progress."""
        config = self._create_config(vm_name="test-vm")
        vmm_ops._in_progress_vms.add("test-vm")

        result = await vmm_ops.create_vmm_vm(config)

        assert result["success"] is False
        assert "already in progress" in result["error"]
        vmm_ops.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_create_vmm_vm_openbsd(self, vmm_ops):
        """Test VM creation for OpenBSD."""
        config = self._create_config(distribution="OpenBSD 7.6")
        expected_result = {"success": True, "ip_address": "10.0.0.10"}

        with patch.object(
            vmm_ops.vm_creator, "create_vmm_vm", return_value=expected_result
        ) as mock_create:
            result = await vmm_ops.create_vmm_vm(config)

        assert result["success"] is True
        mock_create.assert_called_once_with(config)
        # Verify in-progress tracking
        assert "test-vm" not in vmm_ops._in_progress_vms

    @pytest.mark.asyncio
    async def test_create_vmm_vm_alpine(self, vmm_ops):
        """Test VM creation for Alpine Linux."""
        config = self._create_config(distribution="Alpine Linux 3.20")
        expected_result = {"success": True, "ip_address": "10.0.0.10"}

        with patch.object(
            vmm_ops.alpine_vm_creator, "create_alpine_vm", return_value=expected_result
        ) as mock_create:
            result = await vmm_ops.create_vmm_vm(config)

        assert result["success"] is True
        mock_create.assert_called_once_with(config)
        vmm_ops.logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_create_vmm_vm_debian(self, vmm_ops):
        """Test VM creation for Debian."""
        config = self._create_config(distribution="Debian 12")
        expected_result = {"success": True, "ip_address": "10.0.0.10"}

        with patch.object(
            vmm_ops.debian_vm_creator, "create_debian_vm", return_value=expected_result
        ) as mock_create:
            result = await vmm_ops.create_vmm_vm(config)

        assert result["success"] is True
        mock_create.assert_called_once_with(config)

    @pytest.mark.asyncio
    async def test_create_vmm_vm_ubuntu(self, vmm_ops):
        """Test VM creation for Ubuntu."""
        config = self._create_config(distribution="Ubuntu 24.04")
        expected_result = {"success": True, "ip_address": "10.0.0.10"}

        with patch.object(
            vmm_ops.ubuntu_vm_creator, "create_ubuntu_vm", return_value=expected_result
        ) as mock_create:
            result = await vmm_ops.create_vmm_vm(config)

        assert result["success"] is True
        mock_create.assert_called_once_with(config)

    @pytest.mark.asyncio
    async def test_create_vmm_vm_removes_from_in_progress_on_success(self, vmm_ops):
        """Test that VM is removed from in-progress set on success."""
        config = self._create_config(vm_name="success-vm")

        with patch.object(
            vmm_ops.vm_creator, "create_vmm_vm", return_value={"success": True}
        ):
            await vmm_ops.create_vmm_vm(config)

        assert "success-vm" not in vmm_ops._in_progress_vms

    @pytest.mark.asyncio
    async def test_create_vmm_vm_removes_from_in_progress_on_failure(self, vmm_ops):
        """Test that VM is removed from in-progress set on failure."""
        config = self._create_config(vm_name="failure-vm")

        with patch.object(
            vmm_ops.vm_creator, "create_vmm_vm", return_value={"success": False}
        ):
            await vmm_ops.create_vmm_vm(config)

        assert "failure-vm" not in vmm_ops._in_progress_vms

    @pytest.mark.asyncio
    async def test_create_vmm_vm_removes_from_in_progress_on_exception(self, vmm_ops):
        """Test that VM is removed from in-progress set on exception."""
        config = self._create_config(vm_name="exception-vm")

        with patch.object(
            vmm_ops.vm_creator, "create_vmm_vm", side_effect=Exception("Error")
        ):
            try:
                await vmm_ops.create_vmm_vm(config)
            except Exception:
                pass

        assert "exception-vm" not in vmm_ops._in_progress_vms

    @pytest.mark.asyncio
    async def test_create_vmm_vm_logs_start_and_completion(self, vmm_ops):
        """Test that VM creation logs start and completion."""
        config = self._create_config(vm_name="log-test-vm")

        with patch.object(
            vmm_ops.vm_creator, "create_vmm_vm", return_value={"success": True}
        ):
            await vmm_ops.create_vmm_vm(config)

        # Check that logger.info was called with start and completion messages
        info_calls = [call[0][0] for call in vmm_ops.logger.info.call_args_list]
        assert any("Started VM creation" in str(call) for call in info_calls)
        assert any("Completed VM creation" in str(call) for call in info_calls)


class TestVmmVmConfigProperties:
    """Tests for VmmVmConfig property accessors."""

    def test_server_url_property(self):
        """Test server_url property."""
        config = VmmVmConfig(
            distribution="OpenBSD 7.6",
            vm_name="test",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
            server_config=VmmServerConfig(
                server_url="https://server.example.com",
                server_port=8443,
                use_https=True,
            ),
        )
        assert config.server_url == "https://server.example.com"

    def test_server_port_property(self):
        """Test server_port property."""
        config = VmmVmConfig(
            distribution="OpenBSD 7.6",
            vm_name="test",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
            server_config=VmmServerConfig(
                server_url="https://server.example.com",
                server_port=9000,
                use_https=True,
            ),
        )
        assert config.server_port == 9000

    def test_use_https_property(self):
        """Test use_https property."""
        config = VmmVmConfig(
            distribution="OpenBSD 7.6",
            vm_name="test",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
            server_config=VmmServerConfig(
                server_url="https://server.example.com",
                server_port=8443,
                use_https=False,
            ),
        )
        assert config.use_https is False

    def test_memory_property(self):
        """Test memory property."""
        config = VmmVmConfig(
            distribution="OpenBSD 7.6",
            vm_name="test",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
            resource_config=VmmResourceConfig(memory="4G", disk_size="20G", cpus=2),
        )
        assert config.memory == "4G"

    def test_disk_size_property(self):
        """Test disk_size property."""
        config = VmmVmConfig(
            distribution="OpenBSD 7.6",
            vm_name="test",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
            resource_config=VmmResourceConfig(memory="2G", disk_size="50G", cpus=2),
        )
        assert config.disk_size == "50G"

    def test_cpus_property(self):
        """Test cpus property."""
        config = VmmVmConfig(
            distribution="OpenBSD 7.6",
            vm_name="test",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
            resource_config=VmmResourceConfig(memory="2G", disk_size="20G", cpus=4),
        )
        assert config.cpus == 4


class TestEdgeCases:
    """Edge case tests for VmmOperations."""

    @pytest.mark.asyncio
    async def test_vm_conf_creation_error(self, vmm_ops, mock_virtualization_checks):
        """Test initialize_vmd when vm.conf creation fails."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": False,
        }

        with patch(
            "src.sysmanage_agent.operations.child_host_vmm.select_unused_subnet"
        ) as mock_subnet:
            mock_subnet.return_value = {"gateway_ip": "10.0.0.1"}
            with patch.object(vmm_ops, "_create_hostname_files", return_value=None):
                with patch.object(vmm_ops, "_configure_ip_forwarding"):
                    with patch.object(vmm_ops, "_setup_network_interfaces"):
                        with patch.object(
                            vmm_ops,
                            "_create_vm_conf",
                            return_value={
                                "success": False,
                                "error": "Permission denied",
                            },
                        ):
                            result = await vmm_ops.initialize_vmd({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_multiple_vms_in_progress(self, vmm_ops):
        """Test tracking multiple VMs in progress."""
        vmm_ops._in_progress_vms.add("vm1")
        vmm_ops._in_progress_vms.add("vm2")

        config1 = VmmVmConfig(
            distribution="OpenBSD 7.6",
            vm_name="vm1",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
        )
        config3 = VmmVmConfig(
            distribution="OpenBSD 7.6",
            vm_name="vm3",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
        )

        # vm1 should fail (in progress)
        result1 = await vmm_ops.create_vmm_vm(config1)
        assert result1["success"] is False

        # vm3 should proceed (not in progress)
        with patch.object(
            vmm_ops.vm_creator, "create_vmm_vm", return_value={"success": True}
        ):
            result3 = await vmm_ops.create_vmm_vm(config3)
        assert result3["success"] is True

    @pytest.mark.asyncio
    async def test_distribution_detection_precedence(self, vmm_ops):
        """Test that distribution detection follows correct order."""
        # Should detect Alpine first
        config_alpine = VmmVmConfig(
            distribution="alpine",
            vm_name="test",
            hostname="test.example.com",
            username="admin",
            password_hash="$2b$12$test",
            agent_install_commands=[],
        )

        with patch.object(
            vmm_ops.alpine_vm_creator,
            "create_alpine_vm",
            return_value={"success": True},
        ) as mock_alpine:
            await vmm_ops.create_vmm_vm(config_alpine)
        mock_alpine.assert_called_once()

    def test_enable_start_vmd_empty_error_message(self, vmm_ops):
        """Test handling of empty error messages."""
        vmm_check = {"enabled": False, "running": False}

        async def run_test():
            with patch.object(vmm_ops, "_run_subprocess") as mock_run:
                mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
                result = await vmm_ops._enable_and_start_vmd(vmm_check)
            return result

        result = asyncio.get_event_loop().run_until_complete(run_test())
        assert result["success"] is False
        assert "Unknown error" in result["error"]
