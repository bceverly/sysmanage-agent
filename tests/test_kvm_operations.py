"""
Comprehensive unit tests for KVM/libvirt VM operations.

Tests cover:
- KVM module loading and detection
- VM lifecycle operations (start, stop, restart, delete)
- KVM initialization
- Status checks
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import asyncio
import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_kvm import KvmOperations, DEV_KVM_PATH
from src.sysmanage_agent.operations.child_host_kvm_lifecycle import KvmLifecycle
from src.sysmanage_agent.operations.child_host_kvm_creation import KvmCreation
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock_checks = Mock()
    mock_checks.check_kvm_support = Mock(
        return_value={
            "available": True,
            "installed": True,
            "enabled": True,
            "running": True,
            "initialized": True,
            "cpu_supported": True,
            "kernel_supported": True,
            "user_in_group": True,
            "management": "libvirt",
        }
    )
    return mock_checks


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    mock = Mock()
    mock.send_message = AsyncMock()
    mock.create_message = Mock(return_value={"type": "test"})
    return mock


@pytest.fixture
def kvm_ops(mock_agent, logger, mock_virtualization_checks):
    """Create a KvmOperations instance for testing."""
    return KvmOperations(mock_agent, logger, mock_virtualization_checks)


@pytest.fixture
def kvm_lifecycle(logger):
    """Create a KvmLifecycle instance for testing."""
    return KvmLifecycle(logger)


@pytest.fixture
def kvm_creation(logger):
    """Create a KvmCreation instance for testing."""
    return KvmCreation(logger)


class TestKvmOperationsInit:
    """Tests for KvmOperations initialization."""

    def test_init_sets_agent(self, kvm_ops, mock_agent):
        """Test that __init__ sets agent."""
        assert kvm_ops.agent == mock_agent

    def test_init_sets_logger(self, kvm_ops, logger):
        """Test that __init__ sets logger."""
        assert kvm_ops.logger == logger

    def test_init_sets_virtualization_checks(self, kvm_ops, mock_virtualization_checks):
        """Test that __init__ sets virtualization_checks."""
        assert kvm_ops.virtualization_checks == mock_virtualization_checks

    def test_init_creates_networking(self, kvm_ops):
        """Test that __init__ creates networking helper."""
        assert kvm_ops.networking is not None

    def test_init_creates_lifecycle(self, kvm_ops):
        """Test that __init__ creates lifecycle helper."""
        assert kvm_ops.lifecycle is not None

    def test_init_creates_creation(self, kvm_ops):
        """Test that __init__ creates creation helper."""
        assert kvm_ops.creation is not None


class TestReadCpuFlags:
    """Tests for _read_cpu_flags method."""

    def test_read_cpu_flags_success(self, kvm_ops):
        """Test reading CPU flags successfully."""
        mock_content = "flags\t\t: vmx sse sse2 avx\nother: data\n"
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value = iter(
                mock_content.split("\n")
            )
            result = kvm_ops._read_cpu_flags()

        assert result["success"] is True
        assert "vmx" in result["cpu_flags"]

    def test_read_cpu_flags_no_flags_line(self, kvm_ops):
        """Test reading CPU flags when no flags line exists."""
        mock_content = "model name: Intel\nprocessor: 0\n"
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value = iter(
                mock_content.split("\n")
            )
            result = kvm_ops._read_cpu_flags()

        assert result["success"] is True
        assert result["cpu_flags"] == ""

    def test_read_cpu_flags_exception(self, kvm_ops):
        """Test reading CPU flags with exception."""
        with patch("builtins.open", side_effect=IOError("Cannot read file")):
            result = kvm_ops._read_cpu_flags()

        assert result["success"] is False
        assert "error" in result


class TestDetectKvmModule:
    """Tests for _detect_kvm_module method."""

    def test_detect_intel_vmx(self, kvm_ops):
        """Test detecting Intel VMX CPU."""
        result = kvm_ops._detect_kvm_module("flags: vmx sse sse2")
        assert result == "kvm_intel"

    def test_detect_amd_svm(self, kvm_ops):
        """Test detecting AMD SVM CPU."""
        result = kvm_ops._detect_kvm_module("flags: svm sse sse2")
        assert result == "kvm_amd"

    def test_detect_no_virtualization(self, kvm_ops):
        """Test detecting CPU without virtualization."""
        result = kvm_ops._detect_kvm_module("flags: sse sse2 avx")
        assert result is None


class TestLoadKvmModuleWithModprobe:
    """Tests for _load_kvm_module_with_modprobe method."""

    def test_load_module_success(self, kvm_ops):
        """Test loading KVM module successfully."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            result = kvm_ops._load_kvm_module_with_modprobe("kvm_intel")

        assert result["success"] is True

    def test_load_module_failure(self, kvm_ops):
        """Test loading KVM module failure."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout="",
                stderr="modprobe: FATAL: Module kvm_intel not found.",
            )
            result = kvm_ops._load_kvm_module_with_modprobe("kvm_intel")

        assert result["success"] is False
        assert "error" in result


class TestLoadKvmModule:
    """Tests for _load_kvm_module method."""

    def test_kvm_already_exists(self, kvm_ops):
        """Test when /dev/kvm already exists."""
        with patch("os.path.exists", return_value=True):
            result = kvm_ops._load_kvm_module()

        assert result["success"] is True
        assert "already" in result["message"].lower()

    def test_kvm_load_intel_module(self, kvm_ops):
        """Test loading Intel KVM module."""
        mock_cpuinfo = "flags: vmx sse sse2"

        def mock_exists(path):
            if path == DEV_KVM_PATH:
                return mock_exists.call_count > 1
            return True

        mock_exists.call_count = 0

        def _side_effect(path):
            mock_exists.call_count += 1
            return mock_exists(path)

        with patch("os.path.exists", side_effect=[False, True]):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter([mock_cpuinfo])
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    with patch("time.sleep"):
                        result = kvm_ops._load_kvm_module()

        assert result["success"] is True
        assert result["module"] == "kvm_intel"

    def test_kvm_no_cpu_support(self, kvm_ops):
        """Test when CPU doesn't support virtualization."""
        mock_cpuinfo = "flags: sse sse2 avx"

        with patch("os.path.exists", return_value=False):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter([mock_cpuinfo])
                result = kvm_ops._load_kvm_module()

        assert result["success"] is False
        assert "vmx" in result["error"].lower() or "svm" in result["error"].lower()


class TestEnableKvmModules:
    """Tests for enable_kvm_modules method."""

    @pytest.mark.asyncio
    async def test_enable_kvm_modules_success(self, kvm_ops):
        """Test enabling KVM modules successfully."""
        with patch.object(kvm_ops, "_load_kvm_module") as mock_load:
            mock_load.return_value = {
                "success": True,
                "module": "kvm_intel",
                "nested_enabled": True,
                "nested_persistent": True,
            }
            result = await kvm_ops.enable_kvm_modules({})

        assert result["success"] is True
        assert result["module"] == "kvm_intel"

    @pytest.mark.asyncio
    async def test_enable_kvm_modules_failure(self, kvm_ops):
        """Test enabling KVM modules when it fails."""
        with patch.object(kvm_ops, "_load_kvm_module") as mock_load:
            mock_load.return_value = {
                "success": False,
                "error": "No virtualization support",
            }
            result = await kvm_ops.enable_kvm_modules({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_enable_kvm_modules_exception(self, kvm_ops):
        """Test enabling KVM modules with exception."""
        with patch.object(
            kvm_ops, "_load_kvm_module", side_effect=Exception("Test error")
        ):
            result = await kvm_ops.enable_kvm_modules({})

        assert result["success"] is False
        assert "error" in result


class TestDisableKvmModules:
    """Tests for disable_kvm_modules method."""

    @pytest.mark.asyncio
    async def test_disable_kvm_modules_with_running_vms(self, kvm_ops):
        """Test disabling KVM modules when VMs are running."""
        with patch.object(kvm_ops, "_check_running_vms") as mock_check:
            mock_check.return_value = {
                "success": False,
                "error": "Cannot disable KVM while VMs are running: test-vm",
            }
            result = await kvm_ops.disable_kvm_modules({})

        assert result["success"] is False
        assert "running" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_disable_kvm_modules_success(self, kvm_ops):
        """Test disabling KVM modules successfully."""
        with patch.object(kvm_ops, "_check_running_vms", return_value=None):
            with patch.object(
                kvm_ops, "_detect_loaded_vendor_module", return_value="kvm_intel"
            ):
                with patch.object(kvm_ops, "_unload_module", return_value=None):
                    with patch.object(
                        kvm_ops, "_verify_kvm_removed", return_value=None
                    ):
                        result = await kvm_ops.disable_kvm_modules({})

        assert result["success"] is True


class TestKvmLifecycleStartVm:
    """Tests for KvmLifecycle start_vm method."""

    @pytest.mark.asyncio
    async def test_start_vm_no_name(self, kvm_lifecycle):
        """Test starting VM without name."""
        result = await kvm_lifecycle.start_vm({})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_vm_success(self, kvm_lifecycle):
        """Test starting VM successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Domain test-vm started"
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            return_value=mock_result,
        ):
            result = await kvm_lifecycle.start_vm({"child_name": "test-vm"})

        assert result["success"] is True
        assert result["child_name"] == "test-vm"
        assert result["child_type"] == "kvm"

    @pytest.mark.asyncio
    async def test_start_vm_with_vm_name_param(self, kvm_lifecycle):
        """Test starting VM using vm_name parameter."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Domain test-vm started"
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            return_value=mock_result,
        ):
            result = await kvm_lifecycle.start_vm({"vm_name": "test-vm"})

        assert result["success"] is True
        assert result["child_name"] == "test-vm"

    @pytest.mark.asyncio
    async def test_start_vm_failure(self, kvm_lifecycle):
        """Test starting VM when virsh fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error: Domain 'test-vm' already active"

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            return_value=mock_result,
        ):
            result = await kvm_lifecycle.start_vm({"child_name": "test-vm"})

        assert result["success"] is False
        assert "already active" in result["error"]

    @pytest.mark.asyncio
    async def test_start_vm_timeout(self, kvm_lifecycle):
        """Test starting VM with timeout."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await kvm_lifecycle.start_vm({"child_name": "test-vm"})

        assert result["success"] is False
        assert "timed out" in result["error"].lower()


class TestKvmLifecycleStopVm:
    """Tests for KvmLifecycle stop_vm method."""

    @pytest.mark.asyncio
    async def test_stop_vm_no_name(self, kvm_lifecycle):
        """Test stopping VM without name."""
        result = await kvm_lifecycle.stop_vm({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_stop_vm_success(self, kvm_lifecycle):
        """Test stopping VM successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Domain test-vm is being shutdown"
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            return_value=mock_result,
        ):
            result = await kvm_lifecycle.stop_vm({"child_name": "test-vm"})

        assert result["success"] is True
        assert result["child_name"] == "test-vm"

    @pytest.mark.asyncio
    async def test_stop_vm_failure(self, kvm_lifecycle):
        """Test stopping VM when it fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error: Domain 'test-vm' is not running"

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            return_value=mock_result,
        ):
            result = await kvm_lifecycle.stop_vm({"child_name": "test-vm"})

        assert result["success"] is False


class TestKvmLifecycleRestartVm:
    """Tests for KvmLifecycle restart_vm method."""

    @pytest.mark.asyncio
    async def test_restart_vm_no_name(self, kvm_lifecycle):
        """Test restarting VM without name."""
        result = await kvm_lifecycle.restart_vm({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_restart_vm_success(self, kvm_lifecycle):
        """Test restarting VM successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Domain test-vm is being rebooted"
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            return_value=mock_result,
        ):
            result = await kvm_lifecycle.restart_vm({"child_name": "test-vm"})

        assert result["success"] is True
        assert result["child_name"] == "test-vm"

    @pytest.mark.asyncio
    async def test_restart_vm_exception(self, kvm_lifecycle):
        """Test restarting VM with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            side_effect=Exception("Unexpected error"),
        ):
            result = await kvm_lifecycle.restart_vm({"child_name": "test-vm"})

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestKvmLifecycleDeleteVm:
    """Tests for KvmLifecycle delete_vm method."""

    @pytest.mark.asyncio
    async def test_delete_vm_no_name(self, kvm_lifecycle):
        """Test deleting VM without name."""
        result = await kvm_lifecycle.delete_vm({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_vm_success(self, kvm_lifecycle):
        """Test deleting VM successfully."""
        mock_destroy_result = Mock(returncode=0, stdout="", stderr="")
        mock_undefine_result = Mock(returncode=0, stdout="", stderr="")

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            side_effect=[mock_destroy_result, mock_undefine_result],
        ):
            with patch("os.path.exists", return_value=False):
                result = await kvm_lifecycle.delete_vm({"child_name": "test-vm"})

        assert result["success"] is True
        assert result["child_name"] == "test-vm"

    @pytest.mark.asyncio
    async def test_delete_vm_undefine_failure_fallback(self, kvm_lifecycle):
        """Test deleting VM with fallback to undefine without storage removal."""
        mock_destroy_result = Mock(returncode=0, stdout="", stderr="")
        mock_undefine_fail = Mock(
            returncode=1, stdout="", stderr="error: --remove-all-storage not supported"
        )
        mock_undefine_success = Mock(returncode=0, stdout="", stderr="")

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            side_effect=[
                mock_destroy_result,
                mock_undefine_fail,
                mock_undefine_success,
            ],
        ):
            with patch("os.path.exists", return_value=False):
                result = await kvm_lifecycle.delete_vm({"child_name": "test-vm"})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_vm_cleanup_cloudinit_iso(self, kvm_lifecycle):
        """Test that cloud-init ISO is cleaned up on delete."""
        mock_destroy_result = Mock(returncode=0, stdout="", stderr="")
        mock_undefine_result = Mock(returncode=0, stdout="", stderr="")

        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_lifecycle.run_command_async",
            side_effect=[mock_destroy_result, mock_undefine_result],
        ):
            with patch("os.path.exists", return_value=True):
                with patch("os.remove") as mock_remove:
                    result = await kvm_lifecycle.delete_vm({"child_name": "test-vm"})

        assert result["success"] is True
        mock_remove.assert_called_once()


class TestKvmLifecycleCheckReady:
    """Tests for KvmLifecycle check_ready method."""

    def test_check_ready_fully_initialized(
        self, kvm_lifecycle, mock_virtualization_checks
    ):
        """Test check_ready when KVM is fully initialized."""
        result = kvm_lifecycle.check_ready(mock_virtualization_checks)

        assert result["success"] is True
        assert result["ready"] is True
        assert result["initialized"] is True

    def test_check_ready_not_initialized(self, kvm_lifecycle):
        """Test check_ready when KVM is not initialized."""
        mock_checks = Mock()
        mock_checks.check_kvm_support = Mock(
            return_value={
                "available": True,
                "installed": True,
                "enabled": True,
                "running": True,
                "initialized": False,
                "management": "libvirt",
            }
        )

        result = kvm_lifecycle.check_ready(mock_checks)

        assert result["success"] is True
        assert result["ready"] is False
        assert result["initialized"] is False


class TestKvmCreation:
    """Tests for KvmCreation class."""

    def test_vm_exists_true(self, kvm_creation):
        """Test _vm_exists returns True when VM exists."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            result = kvm_creation._vm_exists("test-vm")

        assert result is True

    def test_vm_exists_false(self, kvm_creation):
        """Test _vm_exists returns False when VM doesn't exist."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1)
            result = kvm_creation._vm_exists("test-vm")

        assert result is False

    def test_vm_exists_exception(self, kvm_creation):
        """Test _vm_exists handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Error")):
            result = kvm_creation._vm_exists("test-vm")

        assert result is False

    def test_create_disk_image_success(self, kvm_creation):
        """Test creating disk image successfully."""
        with patch("os.makedirs"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = kvm_creation._create_disk_image(
                    "/var/lib/libvirt/images/test.qcow2", "20G"
                )

        assert result["success"] is True

    def test_create_disk_image_failure(self, kvm_creation):
        """Test creating disk image failure."""
        with patch("os.makedirs"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="", stderr="qemu-img: Could not create"
                )
                result = kvm_creation._create_disk_image(
                    "/var/lib/libvirt/images/test.qcow2", "20G"
                )

        assert result["success"] is False

    def test_extract_ip_from_domifaddr(self, kvm_creation):
        """Test extracting IP from domifaddr output."""
        output = """
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:ab:cd:ef    ipv4         192.168.122.100/24
"""
        result = kvm_creation._extract_ip_from_domifaddr(output)
        assert result == "192.168.122.100"

    def test_extract_ip_from_domifaddr_no_ip(self, kvm_creation):
        """Test extracting IP when no IP available."""
        output = """
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
"""
        result = kvm_creation._extract_ip_from_domifaddr(output)
        assert result is None

    def test_list_vms_success(self, kvm_creation):
        """Test listing VMs successfully."""
        virsh_output = """ Id   Name       State
-----------------------------
 1    test-vm1   running
 -    test-vm2   shut off
"""
        with patch("subprocess.run") as mock_run:
            # Mock for list --all
            mock_run.return_value = Mock(returncode=0, stdout=virsh_output, stderr="")
            with patch.object(kvm_creation, "_get_vm_info", return_value={}):
                result = kvm_creation.list_vms()

        assert result["success"] is True
        assert len(result["vms"]) == 2

    def test_list_vms_failure(self, kvm_creation):
        """Test listing VMs when virsh fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="error: failed to connect"
            )
            result = kvm_creation.list_vms()

        assert result["success"] is False


class TestKvmVmConfig:
    """Tests for KvmVmConfig dataclass."""

    def test_valid_config(self):
        """Test creating a valid config."""
        config = KvmVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=["apt install sysmanage-agent"],
        )
        assert config.vm_name == "test-vm"
        assert config.memory == "2G"
        assert config.cpus == 2

    def test_invalid_vm_name(self):
        """Test config with empty VM name."""
        with pytest.raises(ValueError, match="VM name is required"):
            KvmVmConfig(
                distribution="ubuntu:22.04",
                vm_name="",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$rounds=...",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_invalid_memory_format(self):
        """Test config with invalid memory format."""
        with pytest.raises(ValueError, match="Invalid memory format"):
            KvmVmConfig(
                distribution="ubuntu:22.04",
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
            KvmVmConfig(
                distribution="ubuntu:22.04",
                vm_name="test-vm",
                hostname="test.example.com",
                username="admin",
                password_hash="$6$rounds=...",
                server_url="https://server.example.com",
                agent_install_commands=[],
                cpus=0,
            )

    def test_get_memory_mb(self):
        """Test getting memory in MB."""
        config = KvmVmConfig(
            distribution="ubuntu:22.04",
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
        config = KvmVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="8G",
        )
        assert config.get_memory_gb() == 8.0


class TestKvmOperationsInitializeKvm:
    """Tests for initialize_kvm method."""

    @pytest.mark.asyncio
    async def test_initialize_kvm_not_linux(self, kvm_ops):
        """Test initialize_kvm on non-Linux system."""
        with patch("platform.system", return_value="Darwin"):
            result = await kvm_ops.initialize_kvm({})

        assert result["success"] is False
        assert "linux" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_initialize_kvm_already_initialized(self, kvm_ops):
        """Test initialize_kvm when already initialized."""
        with patch("platform.system", return_value="Linux"):
            with patch("os.path.exists", return_value=True):
                result = await kvm_ops.initialize_kvm({})

        assert result["success"] is True
        assert result["already_initialized"] is True

    @pytest.mark.asyncio
    async def test_initialize_kvm_needs_install(
        self, kvm_ops, mock_virtualization_checks
    ):
        """Test initialize_kvm when packages need to be installed."""
        mock_virtualization_checks.check_kvm_support.return_value = {
            "available": True,
            "installed": False,
            "enabled": False,
            "running": False,
            "initialized": False,
        }

        with patch("platform.system", return_value="Linux"):
            with patch("os.path.exists", return_value=True):
                with patch.object(kvm_ops, "_detect_package_manager") as mock_pkg:
                    mock_pkg.return_value = {
                        "name": "apt",
                        "packages": ["qemu-kvm"],
                        "install_cmd": ["apt-get", "install", "-y"],
                        "update_cmd": ["apt-get", "update"],
                    }
                    with patch.object(
                        kvm_ops, "_install_libvirt_packages"
                    ) as mock_install:
                        mock_install.return_value = {"success": True}
                        with patch.object(
                            kvm_ops, "_enable_libvirtd_service"
                        ) as mock_enable:
                            mock_enable.return_value = {"success": True}
                            with patch.object(
                                kvm_ops, "_add_user_to_groups"
                            ) as mock_groups:
                                mock_groups.return_value = {
                                    "success": True,
                                    "needs_relogin": True,
                                }
                                with patch.object(
                                    kvm_ops.networking, "setup_default_network"
                                ) as mock_net:
                                    mock_net.return_value = {"success": True}
                                    # Final verification returns initialized
                                    mock_virtualization_checks.check_kvm_support.side_effect = [
                                        {
                                            "available": True,
                                            "installed": False,
                                            "enabled": False,
                                            "running": False,
                                            "initialized": False,
                                        },
                                        {
                                            "available": True,
                                            "installed": True,
                                            "enabled": True,
                                            "running": True,
                                            "initialized": True,
                                        },
                                    ]
                                    result = await kvm_ops.initialize_kvm({})

        assert result["success"] is True


class TestKvmOperationsDetectPackageManager:
    """Tests for _detect_package_manager method."""

    def test_detect_apt(self, kvm_ops):
        """Test detecting apt package manager."""

        def mock_which(cmd):
            return "/usr/bin/apt-get" if cmd == "apt-get" else None

        with patch("shutil.which", side_effect=mock_which):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter(["ID=ubuntu\n"])
                result = kvm_ops._detect_package_manager()

        assert result["name"] == "apt"
        assert "qemu-kvm" in result["packages"]

    def test_detect_dnf(self, kvm_ops):
        """Test detecting dnf package manager."""

        def mock_which(cmd):
            if cmd == "apt-get":
                return None
            if cmd == "dnf":
                return "/usr/bin/dnf"
            return None

        with patch("shutil.which", side_effect=mock_which):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter(["ID=fedora\n"])
                result = kvm_ops._detect_package_manager()

        assert result["name"] == "dnf"

    def test_detect_no_package_manager(self, kvm_ops):
        """Test when no package manager is found."""
        with patch("shutil.which", return_value=None):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter(["ID=unknown\n"])
                result = kvm_ops._detect_package_manager()

        assert result["name"] is None


class TestKvmCreationAsync:
    """Tests for async KvmCreation methods."""

    @pytest.mark.asyncio
    async def test_wait_for_vm_ip_found(self, kvm_creation):
        """Test waiting for VM IP when IP is found."""
        with patch.object(
            kvm_creation, "_get_vm_ip_once", return_value="192.168.122.100"
        ):
            result = await kvm_creation._wait_for_vm_ip("test-vm", timeout=10)

        assert result == "192.168.122.100"

    @pytest.mark.asyncio
    async def test_wait_for_vm_ip_timeout(self, kvm_creation):
        """Test waiting for VM IP with timeout."""
        with patch.object(kvm_creation, "_get_vm_ip_once", return_value=None):
            result = await kvm_creation._wait_for_vm_ip(
                "test-vm", timeout=1, interval=0.1
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_wait_for_ssh_available(self, kvm_creation):
        """Test waiting for SSH when it's available."""
        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect_ex.return_value = 0
            mock_socket.return_value = mock_sock
            result = await kvm_creation._wait_for_ssh("192.168.122.100", timeout=10)

        assert result is True

    @pytest.mark.asyncio
    async def test_wait_for_ssh_timeout(self, kvm_creation):
        """Test waiting for SSH with timeout."""
        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect_ex.return_value = 1  # Connection refused
            mock_socket.return_value = mock_sock
            result = await kvm_creation._wait_for_ssh(
                "192.168.122.100", timeout=1, interval=0.1
            )

        assert result is False

    @pytest.mark.asyncio
    async def test_create_vm_already_exists(self, kvm_creation):
        """Test creating VM that already exists."""
        config = KvmVmConfig(
            distribution="ubuntu:22.04",
            vm_name="existing-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$rounds=...",
            server_url="https://server.example.com",
            agent_install_commands=[],
        )

        with patch.object(kvm_creation, "_vm_exists", return_value=True):
            result = await kvm_creation.create_vm(config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    async def test_cleanup_failed_vm(self, kvm_creation):
        """Test cleanup of failed VM creation."""
        with patch.object(kvm_creation, "_vm_exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_creation.run_command_async"
            ) as mock_cmd:
                mock_cmd.return_value = Mock(returncode=0)
                await kvm_creation._cleanup_failed_vm("test-vm")

        # Verify both destroy and undefine were called
        assert mock_cmd.call_count == 2
