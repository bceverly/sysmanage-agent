"""
Comprehensive unit tests for bhyve VM operations on FreeBSD.

Tests cover:
- BhyveOperations initialization
- bhyve initialization (loading vmm.ko, UEFI firmware, etc.)
- bhyve disable operations
- VM creation
- VM lifecycle operations (start, stop, restart, delete)
- Networking setup
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import logging
import subprocess
from unittest.mock import AsyncMock, Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.operations.child_host_bhyve import (
    BhyveOperations,
)
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig
from src.sysmanage_agent.operations.child_host_bhyve_lifecycle import (
    BhyveLifecycleHelper,
    _is_valid_vm_name,
    _validate_path_in_allowed_dirs,
)
from src.sysmanage_agent.operations.child_host_bhyve_persistence import (
    BhyvePersistenceHelper,
    BhyveVmPersistentConfig,
)
from src.sysmanage_agent.operations.child_host_bhyve_networking import (
    BhyveNetworking,
    BHYVE_BRIDGE_NAME,
    BHYVE_GATEWAY_IP,
    BHYVE_SUBNET,
)
from src.sysmanage_agent.operations.child_host_bhyve_creation import (
    BhyveCreationHelper,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock_checks = Mock()
    mock_checks.check_bhyve_support = Mock(
        return_value={
            "available": True,
            "installed": True,
            "enabled": True,
            "running": True,
            "initialized": True,
            "cpu_supported": True,
        }
    )
    return mock_checks


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    mock = Mock()
    mock.send_message = AsyncMock()
    mock.registration_manager = Mock()
    mock.registration_manager.get_host_approval_from_db = Mock(
        return_value=Mock(host_id="test-host-id")
    )
    mock.registration = Mock()
    mock.registration.get_system_info = Mock(return_value={"hostname": "test-host"})
    mock.message_handler = Mock()
    mock.message_handler.create_message = Mock(return_value={"type": "test"})
    mock.message_handler.queue_outbound_message = AsyncMock()
    return mock


@pytest.fixture
def bhyve_ops(mock_agent, logger, mock_virtualization_checks):
    """Create a BhyveOperations instance for testing."""
    return BhyveOperations(mock_agent, logger, mock_virtualization_checks)


@pytest.fixture
def bhyve_lifecycle(logger):
    """Create a BhyveLifecycleHelper instance for testing."""
    creation_helper = Mock(spec=BhyveCreationHelper)
    return BhyveLifecycleHelper(logger, creation_helper)


@pytest.fixture
def bhyve_persistence(logger):
    """Create a BhyvePersistenceHelper instance for testing."""
    return BhyvePersistenceHelper(logger)


@pytest.fixture
def bhyve_networking(logger):
    """Create a BhyveNetworking instance for testing."""
    return BhyveNetworking(logger)


@pytest.fixture
def sample_bhyve_config():
    """Create a sample bhyve VM configuration."""
    return BhyveVmConfig(
        distribution="freebsd:14.0",
        vm_name="test-vm",
        hostname="test.example.com",
        username="admin",
        password_hash="$6$rounds=5000$...",
        server_url="https://server.example.com",
        agent_install_commands=["pkg update", "pkg install -y sysmanage-agent"],
    )


class TestBhyveOperationsInit:
    """Tests for BhyveOperations initialization."""

    def test_init_sets_agent(self, bhyve_ops, mock_agent):
        """Test that __init__ sets agent."""
        assert bhyve_ops.agent == mock_agent

    def test_init_sets_logger(self, bhyve_ops, logger):
        """Test that __init__ sets logger."""
        assert bhyve_ops.logger == logger

    def test_init_sets_virtualization_checks(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test that __init__ sets virtualization_checks."""
        assert bhyve_ops.virtualization_checks == mock_virtualization_checks

    def test_init_creates_networking_helper(self, bhyve_ops):
        """Test that __init__ creates networking helper."""
        assert bhyve_ops._networking is not None
        assert isinstance(bhyve_ops._networking, BhyveNetworking)

    def test_init_creates_creation_helper(self, bhyve_ops):
        """Test that __init__ creates creation helper."""
        assert bhyve_ops._creation_helper is not None

    def test_init_creates_lifecycle_helper(self, bhyve_ops):
        """Test that __init__ creates lifecycle helper."""
        assert bhyve_ops._lifecycle_helper is not None

    def test_init_creates_persistence_helper(self, bhyve_ops):
        """Test that __init__ creates persistence helper."""
        assert bhyve_ops._persistence_helper is not None

    def test_init_empty_in_progress_vms(self, bhyve_ops):
        """Test that __init__ initializes empty in-progress VMs set."""
        assert bhyve_ops._in_progress_vms == set()


class TestBhyveOperationsRunSubprocess:
    """Tests for _run_subprocess method."""

    @pytest.mark.asyncio
    async def test_run_subprocess_success(self, bhyve_ops):
        """Test running subprocess successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""

        with patch("asyncio.to_thread", return_value=mock_result) as mock_thread:
            result = await bhyve_ops._run_subprocess(["echo", "test"])

        assert result.returncode == 0
        mock_thread.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_subprocess_with_timeout(self, bhyve_ops):
        """Test running subprocess with custom timeout."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""

        with patch("asyncio.to_thread", return_value=mock_result) as mock_thread:
            result = await bhyve_ops._run_subprocess(["echo", "test"], timeout=120)

        assert result.returncode == 0
        mock_thread.assert_called_once()


class TestBhyveOperationsInitializeBhyve:
    """Tests for initialize_bhyve method."""

    @pytest.mark.asyncio
    async def test_initialize_bhyve_already_initialized(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test initialize_bhyve when already initialized."""
        mock_virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
            "enabled": True,
            "running": True,
        }

        with patch.object(
            bhyve_ops, "_install_uefi_firmware", return_value=True
        ) as mock_uefi:
            with patch.object(
                bhyve_ops, "_install_qemu_img", return_value=True
            ) as mock_qemu:
                with patch.object(
                    bhyve_ops._networking, "setup_nat_networking"
                ) as mock_nat:
                    mock_nat.return_value = {
                        "success": True,
                        "bridge": "bridge1",
                        "gateway": "10.0.100.1",
                        "subnet": "10.0.100.0/24",
                    }
                    with patch.object(
                        bhyve_ops, "_send_virtualization_status_update"
                    ) as mock_status:
                        mock_status.return_value = None
                        result = await bhyve_ops.initialize_bhyve({})

        assert result["success"] is True
        assert result["already_initialized"] is True
        mock_uefi.assert_called_once()
        mock_qemu.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_bhyve_load_vmm_success(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test initialize_bhyve loading vmm.ko successfully."""
        mock_virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
            "enabled": False,
            "running": False,
        }

        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 0
        mock_subprocess_result.stdout = ""
        mock_subprocess_result.stderr = ""

        with patch.object(
            bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
        ):
            with patch.object(bhyve_ops, "_install_uefi_firmware", return_value=True):
                with patch.object(bhyve_ops, "_install_qemu_img", return_value=True):
                    with patch.object(
                        bhyve_ops._networking, "setup_nat_networking"
                    ) as mock_nat:
                        mock_nat.return_value = {"success": True}
                        with patch("os.path.exists", return_value=False):
                            with patch("os.path.isdir", return_value=True):
                                with patch("os.makedirs"):
                                    with patch("aiofiles.open", new_callable=MagicMock):
                                        with patch.object(
                                            bhyve_ops._persistence_helper,
                                            "enable_autostart_service",
                                        ) as mock_autostart:
                                            mock_autostart.return_value = {
                                                "success": True
                                            }
                                            with patch.object(
                                                bhyve_ops,
                                                "_send_virtualization_status_update",
                                            ):
                                                result = (
                                                    await bhyve_ops.initialize_bhyve({})
                                                )

        assert result["success"] is True
        assert result["vmm_loaded"] is True

    @pytest.mark.asyncio
    async def test_initialize_bhyve_vmm_load_failure(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test initialize_bhyve when vmm.ko fails to load."""
        mock_virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
            "enabled": False,
            "running": False,
        }

        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 1
        mock_subprocess_result.stdout = ""
        mock_subprocess_result.stderr = "kldload: can't load vmm: No such file"

        with patch.object(
            bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
        ):
            result = await bhyve_ops.initialize_bhyve({})

        assert result["success"] is False
        assert "vmm.ko" in result["error"]

    @pytest.mark.asyncio
    async def test_initialize_bhyve_vmm_already_loaded(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test initialize_bhyve when vmm.ko is already loaded."""
        mock_virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
            "enabled": False,
            "running": False,
        }

        mock_vmm_result = Mock()
        mock_vmm_result.returncode = 1
        mock_vmm_result.stdout = ""
        mock_vmm_result.stderr = "module already loaded"

        mock_nmdm_result = Mock()
        mock_nmdm_result.returncode = 0
        mock_nmdm_result.stdout = ""
        mock_nmdm_result.stderr = ""

        with patch.object(
            bhyve_ops,
            "_run_subprocess",
            side_effect=[mock_vmm_result, mock_nmdm_result],
        ):
            with patch.object(bhyve_ops, "_install_uefi_firmware", return_value=True):
                with patch.object(bhyve_ops, "_install_qemu_img", return_value=True):
                    with patch.object(
                        bhyve_ops._networking, "setup_nat_networking"
                    ) as mock_nat:
                        mock_nat.return_value = {"success": True}
                        with patch("os.path.exists", return_value=False):
                            with patch("os.path.isdir", return_value=True):
                                with patch("os.makedirs"):
                                    with patch("aiofiles.open", new_callable=MagicMock):
                                        with patch.object(
                                            bhyve_ops._persistence_helper,
                                            "enable_autostart_service",
                                        ) as mock_autostart:
                                            mock_autostart.return_value = {
                                                "success": True
                                            }
                                            with patch.object(
                                                bhyve_ops,
                                                "_send_virtualization_status_update",
                                            ):
                                                result = (
                                                    await bhyve_ops.initialize_bhyve({})
                                                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_initialize_bhyve_dev_vmm_not_created(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test initialize_bhyve when /dev/vmm not created (no VT-x)."""
        mock_virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
            "enabled": False,
            "running": False,
        }

        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 0
        mock_subprocess_result.stdout = ""
        mock_subprocess_result.stderr = ""

        with patch.object(
            bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
        ):
            with patch.object(bhyve_ops, "_install_uefi_firmware", return_value=True):
                with patch.object(bhyve_ops, "_install_qemu_img", return_value=True):
                    with patch.object(
                        bhyve_ops._networking, "setup_nat_networking"
                    ) as mock_nat:
                        mock_nat.return_value = {"success": True}
                        with patch("os.path.exists", return_value=False):
                            with patch("os.path.isdir", return_value=False):
                                with patch("os.makedirs"):
                                    with patch("aiofiles.open", new_callable=MagicMock):
                                        result = await bhyve_ops.initialize_bhyve({})

        assert result["success"] is False
        assert "VT-x" in result["error"] or "/dev/vmm" in result["error"]

    @pytest.mark.asyncio
    async def test_initialize_bhyve_timeout(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test initialize_bhyve with timeout."""
        mock_virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
            "enabled": False,
            "running": False,
        }

        with patch.object(
            bhyve_ops,
            "_run_subprocess",
            side_effect=subprocess.TimeoutExpired("cmd", 30),
        ):
            result = await bhyve_ops.initialize_bhyve({})

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_initialize_bhyve_exception(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test initialize_bhyve with exception."""
        mock_virtualization_checks.check_bhyve_support.side_effect = Exception(
            "Unexpected error"
        )

        result = await bhyve_ops.initialize_bhyve({})

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestBhyveOperationsDisableBhyve:
    """Tests for disable_bhyve method."""

    @pytest.mark.asyncio
    async def test_disable_bhyve_success(self, bhyve_ops):
        """Test disabling bhyve successfully."""
        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 0
        mock_subprocess_result.stdout = ""
        mock_subprocess_result.stderr = ""

        # Mock aiofiles.open properly for async context manager
        mock_file = MagicMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_file.read = AsyncMock(return_value='vmm_load="YES"')
        mock_file.writelines = AsyncMock()

        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=[]):
                with patch.object(
                    bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
                ):
                    with patch("os.path.exists", return_value=True):
                        with patch(
                            "src.sysmanage_agent.operations.child_host_bhyve.aiofiles.open",
                            return_value=mock_file,
                        ):
                            with patch.object(
                                bhyve_ops,
                                "_send_virtualization_status_update",
                                new_callable=AsyncMock,
                            ):
                                result = await bhyve_ops.disable_bhyve({})

        assert result["success"] is True
        assert result["vmm_unloaded"] is True
        assert result["loader_conf_updated"] is True

    @pytest.mark.asyncio
    async def test_disable_bhyve_vms_running(self, bhyve_ops):
        """Test disabling bhyve when VMs are running."""
        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=["test-vm", "another-vm"]):
                result = await bhyve_ops.disable_bhyve({})

        assert result["success"] is False
        assert "VMs are running" in result["error"]
        assert "test-vm" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_bhyve_vmm_not_loaded(self, bhyve_ops):
        """Test disabling bhyve when vmm.ko is not loaded."""
        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 1
        mock_subprocess_result.stdout = ""
        mock_subprocess_result.stderr = "module not loaded"

        # Mock aiofiles.open properly for async context manager
        mock_file = MagicMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_file.read = AsyncMock(return_value='vmm_load="YES"')
        mock_file.writelines = AsyncMock()

        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=[]):
                with patch.object(
                    bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
                ):
                    with patch("os.path.exists", return_value=True):
                        with patch(
                            "src.sysmanage_agent.operations.child_host_bhyve.aiofiles.open",
                            return_value=mock_file,
                        ):
                            with patch.object(
                                bhyve_ops,
                                "_send_virtualization_status_update",
                                new_callable=AsyncMock,
                            ):
                                result = await bhyve_ops.disable_bhyve({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_bhyve_unload_failure(self, bhyve_ops):
        """Test disabling bhyve when kldunload fails."""
        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 1
        mock_subprocess_result.stdout = ""
        mock_subprocess_result.stderr = "kldunload: can't unload"

        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=[]):
                with patch.object(
                    bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
                ):
                    result = await bhyve_ops.disable_bhyve({})

        assert result["success"] is False
        assert "unload vmm.ko" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_bhyve_timeout(self, bhyve_ops):
        """Test disabling bhyve with timeout."""
        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=[]):
                with patch.object(
                    bhyve_ops,
                    "_run_subprocess",
                    side_effect=subprocess.TimeoutExpired("cmd", 30),
                ):
                    result = await bhyve_ops.disable_bhyve({})

        assert result["success"] is False
        assert "Timeout" in result["error"]


class TestBhyveOperationsInstallUefiFirmware:
    """Tests for _install_uefi_firmware method."""

    @pytest.mark.asyncio
    async def test_uefi_firmware_already_installed(self, bhyve_ops):
        """Test when UEFI firmware is already installed."""
        with patch(
            "os.path.exists",
            side_effect=lambda p: p == "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd",
        ):
            result = await bhyve_ops._install_uefi_firmware()

        assert result is True

    @pytest.mark.asyncio
    async def test_uefi_firmware_install_success(self, bhyve_ops):
        """Test installing UEFI firmware successfully."""
        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 0
        mock_subprocess_result.stdout = "installed"
        mock_subprocess_result.stderr = ""

        with patch("os.path.exists", return_value=False):
            with patch.object(
                bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
            ):
                result = await bhyve_ops._install_uefi_firmware()

        assert result is True

    @pytest.mark.asyncio
    async def test_uefi_firmware_already_installed_via_pkg(self, bhyve_ops):
        """Test when UEFI firmware package is already installed."""
        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 1
        mock_subprocess_result.stdout = "bhyve-firmware-1.0 is already installed"
        mock_subprocess_result.stderr = ""

        with patch("os.path.exists", return_value=False):
            with patch.object(
                bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
            ):
                result = await bhyve_ops._install_uefi_firmware()

        assert result is True

    @pytest.mark.asyncio
    async def test_uefi_firmware_install_failure(self, bhyve_ops):
        """Test when UEFI firmware installation fails."""
        mock_subprocess_result = Mock()
        mock_subprocess_result.returncode = 1
        mock_subprocess_result.stdout = ""
        mock_subprocess_result.stderr = "pkg: No matching packages found"

        with patch("os.path.exists", return_value=False):
            with patch.object(
                bhyve_ops, "_run_subprocess", return_value=mock_subprocess_result
            ):
                result = await bhyve_ops._install_uefi_firmware()

        assert result is False

    @pytest.mark.asyncio
    async def test_uefi_firmware_install_timeout(self, bhyve_ops):
        """Test when UEFI firmware installation times out."""
        with patch("os.path.exists", return_value=False):
            with patch.object(
                bhyve_ops,
                "_run_subprocess",
                side_effect=subprocess.TimeoutExpired("cmd", 120),
            ):
                result = await bhyve_ops._install_uefi_firmware()

        assert result is False


class TestBhyveOperationsInstallQemuImg:
    """Tests for _install_qemu_img method."""

    @pytest.mark.asyncio
    async def test_qemu_img_already_installed(self, bhyve_ops):
        """Test when qemu-img is already installed."""
        mock_which_result = Mock()
        mock_which_result.returncode = 0
        mock_which_result.stdout = "/usr/local/bin/qemu-img"
        mock_which_result.stderr = ""

        with patch.object(bhyve_ops, "_run_subprocess", return_value=mock_which_result):
            result = await bhyve_ops._install_qemu_img()

        assert result is True

    @pytest.mark.asyncio
    async def test_qemu_img_install_qemu_nox11_success(self, bhyve_ops):
        """Test installing qemu-nox11 successfully."""
        mock_which_result = Mock()
        mock_which_result.returncode = 1
        mock_which_result.stdout = ""
        mock_which_result.stderr = ""

        mock_install_result = Mock()
        mock_install_result.returncode = 0
        mock_install_result.stdout = "installed"
        mock_install_result.stderr = ""

        with patch.object(
            bhyve_ops,
            "_run_subprocess",
            side_effect=[mock_which_result, mock_install_result],
        ):
            result = await bhyve_ops._install_qemu_img()

        assert result is True

    @pytest.mark.asyncio
    async def test_qemu_img_fallback_to_qemu(self, bhyve_ops):
        """Test falling back to qemu package when qemu-nox11 fails."""
        mock_which_result = Mock()
        mock_which_result.returncode = 1
        mock_which_result.stdout = ""
        mock_which_result.stderr = ""

        mock_nox11_fail = Mock()
        mock_nox11_fail.returncode = 1
        mock_nox11_fail.stdout = ""
        mock_nox11_fail.stderr = "No matching packages"

        mock_qemu_success = Mock()
        mock_qemu_success.returncode = 0
        mock_qemu_success.stdout = "installed"
        mock_qemu_success.stderr = ""

        with patch.object(
            bhyve_ops,
            "_run_subprocess",
            side_effect=[mock_which_result, mock_nox11_fail, mock_qemu_success],
        ):
            result = await bhyve_ops._install_qemu_img()

        assert result is True

    @pytest.mark.asyncio
    async def test_qemu_img_install_failure(self, bhyve_ops):
        """Test when both qemu packages fail to install."""
        mock_which_result = Mock()
        mock_which_result.returncode = 1
        mock_which_result.stdout = ""
        mock_which_result.stderr = ""

        mock_fail = Mock()
        mock_fail.returncode = 1
        mock_fail.stdout = ""
        mock_fail.stderr = "No matching packages"

        with patch.object(
            bhyve_ops,
            "_run_subprocess",
            side_effect=[mock_which_result, mock_fail, mock_fail],
        ):
            result = await bhyve_ops._install_qemu_img()

        assert result is False


class TestBhyveOperationsIsFreeBSDDistribution:
    """Tests for _is_freebsd_distribution method."""

    def test_freebsd_in_distribution(self, bhyve_ops, sample_bhyve_config):
        """Test detecting FreeBSD in distribution field."""
        sample_bhyve_config.distribution = "freebsd:14.0"
        result = bhyve_ops._is_freebsd_distribution(sample_bhyve_config)
        assert result is True

    def test_bsd_in_distribution(self, bhyve_ops, sample_bhyve_config):
        """Test detecting BSD in distribution field."""
        sample_bhyve_config.distribution = "openbsd:7.0"
        result = bhyve_ops._is_freebsd_distribution(sample_bhyve_config)
        assert result is True

    def test_freebsd_in_cloud_image_url(self, bhyve_ops, sample_bhyve_config):
        """Test detecting FreeBSD in cloud image URL."""
        sample_bhyve_config.distribution = "generic"
        sample_bhyve_config.cloud_image_url = (
            "https://download.freebsd.org/cloud-images/14.0.qcow2"
        )
        result = bhyve_ops._is_freebsd_distribution(sample_bhyve_config)
        assert result is True

    def test_linux_distribution(self, bhyve_ops, sample_bhyve_config):
        """Test non-FreeBSD distribution."""
        sample_bhyve_config.distribution = "ubuntu:22.04"
        sample_bhyve_config.cloud_image_url = ""
        result = bhyve_ops._is_freebsd_distribution(sample_bhyve_config)
        assert result is False


class TestBhyveOperationsCreateBhyveVm:
    """Tests for create_bhyve_vm method."""

    @pytest.mark.asyncio
    async def test_create_vm_already_exists(self, bhyve_ops, sample_bhyve_config):
        """Test creating VM that already exists."""
        with patch.object(bhyve_ops._creation_helper, "vm_exists", return_value=True):
            result = await bhyve_ops.create_bhyve_vm(sample_bhyve_config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    async def test_create_vm_already_in_progress(self, bhyve_ops, sample_bhyve_config):
        """Test creating VM that is already being created."""
        bhyve_ops._in_progress_vms.add("test-vm")

        with patch.object(bhyve_ops._creation_helper, "vm_exists", return_value=False):
            result = await bhyve_ops.create_bhyve_vm(sample_bhyve_config)

        assert result["success"] is False
        assert "already in progress" in result["error"]

        bhyve_ops._in_progress_vms.discard("test-vm")

    @pytest.mark.asyncio
    async def test_create_vm_disk_failure(self, bhyve_ops, sample_bhyve_config):
        """Test creating VM when disk creation fails (empty disk path)."""
        # When cloud_image_url is empty, create_disk_image is called
        sample_bhyve_config.cloud_image_url = ""

        with patch.object(bhyve_ops._creation_helper, "vm_exists", return_value=False):
            with patch("os.makedirs"):
                with patch.object(
                    bhyve_ops._creation_helper,
                    "create_disk_image",
                    return_value={"success": False, "error": "Disk creation failed"},
                ):
                    result = await bhyve_ops.create_bhyve_vm(sample_bhyve_config)

        assert result["success"] is False
        assert "Disk creation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_create_vm_cloud_image_download_failure(
        self, bhyve_ops, sample_bhyve_config
    ):
        """Test creating VM when cloud image download fails."""
        sample_bhyve_config.cloud_image_url = "https://example.com/image.qcow2"

        with patch.object(bhyve_ops._creation_helper, "vm_exists", return_value=False):
            with patch("os.makedirs"):
                with patch.object(
                    bhyve_ops._creation_helper,
                    "download_cloud_image",
                    return_value={"success": False, "error": "Download failed"},
                ):
                    result = await bhyve_ops.create_bhyve_vm(sample_bhyve_config)

        assert result["success"] is False
        assert "Download failed" in result["error"]

    @pytest.mark.asyncio
    async def test_create_vm_tap_interface_failure(
        self, bhyve_ops, sample_bhyve_config
    ):
        """Test creating VM when tap interface creation fails."""
        # Use Linux distribution to avoid FreeBSD-specific provisioner
        sample_bhyve_config.distribution = "ubuntu:22.04"
        sample_bhyve_config.cloud_image_url = ""

        with patch.object(bhyve_ops._creation_helper, "vm_exists", return_value=False):
            with patch("os.makedirs"):
                with patch.object(
                    bhyve_ops._creation_helper,
                    "create_disk_image",
                    return_value={"success": True, "path": "/vm/test-vm/test-vm.img"},
                ):
                    with patch.object(
                        bhyve_ops._creation_helper,
                        "create_cloud_init_iso",
                        return_value={"success": True},
                    ):
                        with patch.object(
                            bhyve_ops._creation_helper,
                            "create_bridge_if_needed",
                            return_value={"success": True},
                        ):
                            with patch.object(
                                bhyve_ops._creation_helper,
                                "create_tap_interface",
                                return_value={
                                    "success": False,
                                    "error": "Failed to create tap",
                                },
                            ):
                                result = await bhyve_ops.create_bhyve_vm(
                                    sample_bhyve_config
                                )

        assert result["success"] is False
        assert "network interface" in result["error"]

    @pytest.mark.asyncio
    async def test_create_vm_exception(self, bhyve_ops, sample_bhyve_config):
        """Test creating VM with exception."""
        with patch.object(
            bhyve_ops._creation_helper, "vm_exists", side_effect=Exception("Test error")
        ):
            result = await bhyve_ops.create_bhyve_vm(sample_bhyve_config)

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestBhyveOperationsLifecycleOperations:
    """Tests for lifecycle operation delegation."""

    @pytest.mark.asyncio
    async def test_start_child_host_delegates(self, bhyve_ops):
        """Test that start_child_host delegates to lifecycle helper."""
        mock_result = {"success": True, "child_name": "test-vm"}

        with patch.object(
            bhyve_ops._lifecycle_helper,
            "start_child_host",
            return_value=mock_result,
        ) as mock_start:
            result = await bhyve_ops.start_child_host({"child_name": "test-vm"})

        mock_start.assert_called_once_with({"child_name": "test-vm"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_child_host_delegates(self, bhyve_ops):
        """Test that stop_child_host delegates to lifecycle helper."""
        mock_result = {"success": True, "child_name": "test-vm"}

        with patch.object(
            bhyve_ops._lifecycle_helper,
            "stop_child_host",
            return_value=mock_result,
        ) as mock_stop:
            result = await bhyve_ops.stop_child_host({"child_name": "test-vm"})

        mock_stop.assert_called_once_with({"child_name": "test-vm"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_child_host_delegates(self, bhyve_ops):
        """Test that restart_child_host delegates to lifecycle helper."""
        mock_result = {"success": True, "child_name": "test-vm"}

        with patch.object(
            bhyve_ops._lifecycle_helper,
            "restart_child_host",
            return_value=mock_result,
        ) as mock_restart:
            result = await bhyve_ops.restart_child_host({"child_name": "test-vm"})

        mock_restart.assert_called_once_with({"child_name": "test-vm"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_child_host_delegates(self, bhyve_ops):
        """Test that delete_child_host delegates to lifecycle helper."""
        mock_result = {"success": True, "child_name": "test-vm"}

        with patch.object(
            bhyve_ops._lifecycle_helper,
            "delete_child_host",
            return_value=mock_result,
        ) as mock_delete:
            result = await bhyve_ops.delete_child_host({"child_name": "test-vm"})

        mock_delete.assert_called_once_with({"child_name": "test-vm"})
        assert result["success"] is True


class TestBhyveLifecycleHelperValidation:
    """Tests for BhyveLifecycleHelper validation functions."""

    def test_is_valid_vm_name_valid(self):
        """Test valid VM names."""
        assert _is_valid_vm_name("test-vm") is True
        assert _is_valid_vm_name("test_vm") is True
        assert _is_valid_vm_name("TestVM123") is True
        assert _is_valid_vm_name("a") is True

    def test_is_valid_vm_name_invalid(self):
        """Test invalid VM names."""
        assert _is_valid_vm_name("") is False
        assert _is_valid_vm_name("a" * 65) is False  # Too long
        assert _is_valid_vm_name("../test") is False
        assert _is_valid_vm_name("test/vm") is False
        assert _is_valid_vm_name("test vm") is False
        assert _is_valid_vm_name("test.vm") is False

    def test_validate_path_in_allowed_dirs_valid(self):
        """Test valid paths within allowed directories."""
        allowed_dirs = ["/vm", "/vm/cloud-init"]
        assert (
            _validate_path_in_allowed_dirs("/vm/test-vm/disk.img", allowed_dirs) is True
        )
        assert (
            _validate_path_in_allowed_dirs("/vm/cloud-init/test.iso", allowed_dirs)
            is True
        )

    def test_validate_path_in_allowed_dirs_invalid(self):
        """Test invalid paths outside allowed directories."""
        allowed_dirs = ["/vm", "/vm/cloud-init"]
        assert _validate_path_in_allowed_dirs("/etc/passwd", allowed_dirs) is False
        assert _validate_path_in_allowed_dirs("/tmp/evil.img", allowed_dirs) is False


class TestBhyveLifecycleHelperStartVm:
    """Tests for BhyveLifecycleHelper.start_child_host method."""

    @pytest.mark.asyncio
    async def test_start_vm_no_name(self, bhyve_lifecycle):
        """Test starting VM without name."""
        result = await bhyve_lifecycle.start_child_host({})
        assert result["success"] is False
        assert "No child_name specified" in result["error"]

    @pytest.mark.asyncio
    async def test_start_vm_invalid_name(self, bhyve_lifecycle):
        """Test starting VM with invalid name."""
        result = await bhyve_lifecycle.start_child_host({"child_name": "../etc/passwd"})
        assert result["success"] is False
        assert "Invalid VM name" in result["error"]

    @pytest.mark.asyncio
    async def test_start_vm_already_running(self, bhyve_lifecycle):
        """Test starting VM that is already running."""
        with patch("os.path.exists", return_value=True):
            result = await bhyve_lifecycle.start_child_host({"child_name": "test-vm"})

        assert result["success"] is True
        assert "already running" in result["message"]

    @pytest.mark.asyncio
    async def test_start_vm_disk_not_found(self, bhyve_lifecycle):
        """Test starting VM when disk is not found."""
        # First call: check if VM is already running (/dev/vmm/test-vm) - False
        # Second call: check if disk exists - False
        with patch.object(
            bhyve_lifecycle,
            "_get_vm_start_params",
            return_value={
                "memory_mb": 1024,
                "cpus": 1,
                "use_uefi": True,
                "disk_path": "/vm/test-vm/test-vm.img",
                "cloudinit_iso": "/vm/cloud-init/test-vm.iso",
            },
        ):
            with patch("os.path.exists", side_effect=[False, False]):
                result = await bhyve_lifecycle.start_child_host(
                    {"child_name": "test-vm"}
                )

        assert result["success"] is False
        assert "disk not found" in result["error"]


class TestBhyveLifecycleHelperStopVm:
    """Tests for BhyveLifecycleHelper.stop_child_host method."""

    @pytest.mark.asyncio
    async def test_stop_vm_no_name(self, bhyve_lifecycle):
        """Test stopping VM without name."""
        result = await bhyve_lifecycle.stop_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_stop_vm_not_running(self, bhyve_lifecycle):
        """Test stopping VM that is not running."""
        with patch("os.path.exists", return_value=False):
            result = await bhyve_lifecycle.stop_child_host({"child_name": "test-vm"})

        assert result["success"] is True
        assert "not running" in result["message"]

    @pytest.mark.asyncio
    async def test_stop_vm_success(self, bhyve_lifecycle):
        """Test stopping VM successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("os.path.exists", return_value=True):
            with patch.object(
                bhyve_lifecycle, "_run_subprocess", return_value=mock_result
            ):
                result = await bhyve_lifecycle.stop_child_host(
                    {"child_name": "test-vm"}
                )

        assert result["success"] is True
        assert result["status"] == "stopped"


class TestBhyveLifecycleHelperRestartVm:
    """Tests for BhyveLifecycleHelper.restart_child_host method."""

    @pytest.mark.asyncio
    async def test_restart_vm_no_name(self, bhyve_lifecycle):
        """Test restarting VM without name."""
        result = await bhyve_lifecycle.restart_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_restart_vm_stop_failure(self, bhyve_lifecycle):
        """Test restarting VM when stop fails."""
        with patch.object(
            bhyve_lifecycle,
            "stop_child_host",
            return_value={"success": False, "error": "Stop failed"},
        ):
            result = await bhyve_lifecycle.restart_child_host({"child_name": "test-vm"})

        assert result["success"] is False


class TestBhyveLifecycleHelperDeleteVm:
    """Tests for BhyveLifecycleHelper.delete_child_host method."""

    @pytest.mark.asyncio
    async def test_delete_vm_no_name(self, bhyve_lifecycle):
        """Test deleting VM without name."""
        result = await bhyve_lifecycle.delete_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_vm_success(self, bhyve_lifecycle):
        """Test deleting VM successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("os.path.exists", side_effect=[False, False, False]):
            with patch("os.path.isdir", return_value=False):
                with patch.object(
                    bhyve_lifecycle, "_run_subprocess", return_value=mock_result
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.delete_bhyve_metadata"
                    ):
                        result = await bhyve_lifecycle.delete_child_host(
                            {"child_name": "test-vm"}
                        )

        assert result["success"] is True
        assert result["child_type"] == "bhyve"


class TestBhyvePersistenceHelper:
    """Tests for BhyvePersistenceHelper class."""

    def test_get_config_path(self, bhyve_persistence):
        """Test getting config path."""
        path = bhyve_persistence.get_config_path("test-vm")
        assert path == "/vm/test-vm/vm-config.json"

    @pytest.mark.asyncio
    async def test_save_vm_config_success(self, bhyve_persistence):
        """Test saving VM config successfully."""
        config = BhyveVmPersistentConfig(
            vm_name="test-vm",
            hostname="test.example.com",
            distribution="freebsd:14.0",
        )

        with patch("os.makedirs"):
            with patch("aiofiles.open", new_callable=MagicMock):
                result = await bhyve_persistence.save_vm_config(config)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_load_vm_config_not_found(self, bhyve_persistence):
        """Test loading VM config when not found."""
        with patch("os.path.exists", return_value=False):
            result = await bhyve_persistence.load_vm_config("nonexistent-vm")

        assert result is None

    @pytest.mark.asyncio
    async def test_delete_vm_config_success(self, bhyve_persistence):
        """Test deleting VM config successfully."""
        with patch("os.path.exists", return_value=True):
            with patch("os.remove"):
                result = await bhyve_persistence.delete_vm_config("test-vm")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_set_autostart_config_not_found(self, bhyve_persistence):
        """Test setting autostart when config not found."""
        with patch.object(bhyve_persistence, "load_vm_config", return_value=None):
            result = await bhyve_persistence.set_autostart("test-vm", True)

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_list_autostart_vms_empty(self, bhyve_persistence):
        """Test listing autostart VMs when directory is empty."""
        with patch("os.path.isdir", return_value=False):
            result = await bhyve_persistence.list_autostart_vms()

        assert result == []

    def test_generate_rc_script(self, bhyve_persistence):
        """Test generating RC script."""
        script = bhyve_persistence.generate_rc_script()

        assert "#!/bin/sh" in script
        assert "sysmanage_bhyve" in script
        assert "PROVIDE: sysmanage_bhyve" in script


class TestBhyveNetworking:
    """Tests for BhyveNetworking class."""

    @pytest.mark.asyncio
    async def test_get_host_dns_server_found(self, bhyve_networking):
        """Test getting DNS server from resolv.conf."""
        resolv_content = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"

        mock_file = MagicMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_file.read = AsyncMock(return_value=resolv_content)

        with patch("aiofiles.open", return_value=mock_file):
            result = await bhyve_networking.get_host_dns_server()

        assert result == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_get_host_dns_server_not_found(self, bhyve_networking):
        """Test getting DNS server when not found."""
        resolv_content = "# No nameservers configured\n"

        mock_file = MagicMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_file.read = AsyncMock(return_value=resolv_content)

        with patch("aiofiles.open", return_value=mock_file):
            result = await bhyve_networking.get_host_dns_server()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_egress_interface_success(self, bhyve_networking):
        """Test getting egress interface successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "   route to: 0.0.0.0\n   interface: em0\n"
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_networking.run_command_async",
            return_value=mock_result,
        ):
            result = await bhyve_networking.get_egress_interface()

        assert result == "em0"

    @pytest.mark.asyncio
    async def test_get_egress_interface_failure(self, bhyve_networking):
        """Test getting egress interface when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "route: not found"

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_networking.run_command_async",
            return_value=mock_result,
        ):
            result = await bhyve_networking.get_egress_interface()

        assert result is None

    def test_get_bridge_name(self, bhyve_networking):
        """Test getting bridge name."""
        assert bhyve_networking.get_bridge_name() == BHYVE_BRIDGE_NAME

    def test_get_gateway_ip(self, bhyve_networking):
        """Test getting gateway IP."""
        assert bhyve_networking.get_gateway_ip() == BHYVE_GATEWAY_IP

    def test_get_subnet(self, bhyve_networking):
        """Test getting subnet."""
        assert bhyve_networking.get_subnet() == f"{BHYVE_SUBNET}.0/24"


class TestBhyveVmConfig:
    """Tests for BhyveVmConfig dataclass."""

    def test_valid_config(self):
        """Test creating a valid config."""
        config = BhyveVmConfig(
            distribution="freebsd:14.0",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=["pkg install sysmanage-agent"],
        )
        assert config.vm_name == "test-vm"
        assert config.memory == "1G"
        assert config.cpus == 1

    def test_invalid_vm_name(self):
        """Test config with empty VM name."""
        with pytest.raises(ValueError, match="VM name is required"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$rounds=...",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_invalid_hostname(self):
        """Test config with empty hostname."""
        with pytest.raises(ValueError, match="Hostname is required"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="",
                username="admin",
                password_hash="$6$rounds=...",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_invalid_memory_format(self):
        """Test config with invalid memory format."""
        with pytest.raises(ValueError, match="Invalid memory format"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$rounds=...",
                server_url="https://server.example.com",
                agent_install_commands=[],
                memory="invalid",
            )

    def test_invalid_cpus(self):
        """Test config with invalid CPU count."""
        with pytest.raises(ValueError, match="CPUs must be at least 1"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$rounds=...",
                server_url="https://server.example.com",
                agent_install_commands=[],
                cpus=0,
            )

    def test_invalid_cpus_too_many(self):
        """Test config with too many CPUs."""
        with pytest.raises(ValueError, match="CPUs cannot exceed 64"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$rounds=...",
                server_url="https://server.example.com",
                agent_install_commands=[],
                cpus=100,
            )

    def test_get_memory_mb(self):
        """Test getting memory in MB."""
        config = BhyveVmConfig(
            distribution="freebsd:14.0",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="4G",
        )
        assert config.get_memory_mb() == 4096

    def test_get_memory_gb(self):
        """Test getting memory in GB."""
        config = BhyveVmConfig(
            distribution="freebsd:14.0",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="8G",
        )
        assert config.get_memory_gb() == 8.0

    def test_get_disk_gb(self):
        """Test getting disk size in GB."""
        config = BhyveVmConfig(
            distribution="freebsd:14.0",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            disk_size="50G",
        )
        assert config.get_disk_gb() == 50

    def test_memory_format_mb(self):
        """Test memory format with MB suffix."""
        config = BhyveVmConfig(
            distribution="freebsd:14.0",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="2048M",
        )
        assert config.get_memory_mb() == 2048

    def test_disk_format_tb(self):
        """Test disk format with TB suffix."""
        config = BhyveVmConfig(
            distribution="freebsd:14.0",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            disk_size="1T",
        )
        assert config.get_disk_gb() == 1024


class TestBhyveVmPersistentConfig:
    """Tests for BhyveVmPersistentConfig dataclass."""

    def test_to_dict(self):
        """Test converting config to dict."""
        config = BhyveVmPersistentConfig(
            vm_name="test-vm",
            hostname="test.example.com",
            distribution="freebsd:14.0",
        )
        data = config.to_dict()

        assert data["vm_name"] == "test-vm"
        assert data["hostname"] == "test.example.com"
        assert data["distribution"] == "freebsd:14.0"
        assert "created_at" in data

    def test_from_dict(self):
        """Test creating config from dict."""
        data = {
            "vm_name": "test-vm",
            "hostname": "test.example.com",
            "distribution": "freebsd:14.0",
            "memory": "2G",
            "cpus": 2,
        }
        config = BhyveVmPersistentConfig.from_dict(data)

        assert config.vm_name == "test-vm"
        assert config.hostname == "test.example.com"
        assert config.memory == "2G"
        assert config.cpus == 2

    def test_from_dict_unknown_fields_ignored(self):
        """Test that unknown fields are ignored when creating from dict."""
        data = {
            "vm_name": "test-vm",
            "hostname": "test.example.com",
            "distribution": "freebsd:14.0",
            "unknown_field": "should be ignored",
        }
        config = BhyveVmPersistentConfig.from_dict(data)

        assert config.vm_name == "test-vm"
        assert not hasattr(config, "unknown_field")


class TestBhyveOperationsSendVirtualizationStatusUpdate:
    """Tests for _send_virtualization_status_update method."""

    @pytest.mark.asyncio
    async def test_send_status_update_success(
        self, bhyve_ops, mock_virtualization_checks
    ):
        """Test sending virtualization status update successfully."""
        mock_virtualization_checks.check_bhyve_support.return_value = {
            "available": True,
            "enabled": True,
        }

        await bhyve_ops._send_virtualization_status_update()

        bhyve_ops.agent.message_handler.create_message.assert_called_once()
        bhyve_ops.agent.message_handler.queue_outbound_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_status_update_no_host_approval(self, bhyve_ops):
        """Test sending status update when host not approved."""
        bhyve_ops.agent.registration_manager.get_host_approval_from_db.return_value = (
            None
        )

        await bhyve_ops._send_virtualization_status_update()

        bhyve_ops.agent.message_handler.queue_outbound_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_status_update_exception(self, bhyve_ops):
        """Test sending status update with exception."""
        bhyve_ops.agent.registration_manager.get_host_approval_from_db.side_effect = (
            Exception("Test error")
        )

        # Should not raise
        await bhyve_ops._send_virtualization_status_update()


class TestBhyveNetworkingSetupNatBridge:
    """Tests for BhyveNetworking.setup_nat_bridge method."""

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_already_exists(self, bhyve_networking):
        """Test setting up NAT bridge when it already exists."""
        mock_run_subprocess = AsyncMock()
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run_subprocess.return_value = mock_result

        with patch("os.path.exists", return_value=True):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.read = AsyncMock(return_value="")

            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        assert result["success"] is True
        assert result["bridge"] == BHYVE_BRIDGE_NAME

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_create_failure(self, bhyve_networking):
        """Test setting up NAT bridge when creation fails."""
        mock_run_subprocess = AsyncMock()

        # First call: bridge doesn't exist
        check_result = Mock()
        check_result.returncode = 1
        check_result.stdout = ""
        check_result.stderr = "interface does not exist"

        # Second call: create fails
        create_result = Mock()
        create_result.returncode = 1
        create_result.stdout = ""
        create_result.stderr = "cannot create bridge"

        mock_run_subprocess.side_effect = [check_result, create_result]

        result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        assert result["success"] is False
        assert "Failed to create bridge" in result["error"]


class TestBhyveNetworkingSetupIpForwarding:
    """Tests for BhyveNetworking.setup_ip_forwarding method."""

    @pytest.mark.asyncio
    async def test_setup_ip_forwarding_success(self, bhyve_networking):
        """Test enabling IP forwarding successfully."""
        mock_run_subprocess = AsyncMock()
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run_subprocess.return_value = mock_result

        with patch("os.path.exists", return_value=True):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.read = AsyncMock(return_value="")
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_ip_forwarding(mock_run_subprocess)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_ip_forwarding_already_set(self, bhyve_networking):
        """Test when IP forwarding is already configured."""
        mock_run_subprocess = AsyncMock()
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run_subprocess.return_value = mock_result

        with patch("os.path.exists", return_value=True):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.read = AsyncMock(return_value="net.inet.ip.forwarding=1")

            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_ip_forwarding(mock_run_subprocess)

        assert result["success"] is True


class TestBhyveNetworkingSetupNatNetworking:
    """Tests for BhyveNetworking.setup_nat_networking method."""

    @pytest.mark.asyncio
    async def test_setup_nat_networking_success(self, bhyve_networking):
        """Test complete NAT networking setup."""
        mock_run_subprocess = AsyncMock()

        with patch.object(
            bhyve_networking,
            "setup_nat_bridge",
            return_value={"success": True, "bridge": "bridge1"},
        ):
            with patch.object(
                bhyve_networking,
                "setup_ip_forwarding",
                return_value={"success": True},
            ):
                with patch.object(
                    bhyve_networking,
                    "setup_pf_nat",
                    return_value={"success": True},
                ):
                    with patch.object(
                        bhyve_networking,
                        "setup_dhcpd",
                        return_value={"success": True},
                    ):
                        result = await bhyve_networking.setup_nat_networking(
                            mock_run_subprocess
                        )

        assert result["success"] is True
        assert result["bridge"] == BHYVE_BRIDGE_NAME

    @pytest.mark.asyncio
    async def test_setup_nat_networking_bridge_failure(self, bhyve_networking):
        """Test NAT networking setup when bridge fails."""
        mock_run_subprocess = AsyncMock()

        with patch.object(
            bhyve_networking,
            "setup_nat_bridge",
            return_value={"success": False, "error": "Bridge creation failed"},
        ):
            result = await bhyve_networking.setup_nat_networking(mock_run_subprocess)

        assert result["success"] is False
        assert "NAT bridge" in result["error"]
