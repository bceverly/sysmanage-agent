"""
Comprehensive unit tests for bhyve VM lifecycle operations.

Tests cover:
- VM name validation
- Path validation
- VM lifecycle operations (start, stop, restart, delete)
- Config loading
- Memory parsing
- Command building
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import asyncio
import json
import logging
from unittest.mock import Mock, patch, mock_open

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_lifecycle import (
    BhyveLifecycleHelper,
    _is_valid_vm_name,
    _validate_path_in_allowed_dirs,
    _NO_CHILD_NAME_MSG,
    _INVALID_VM_NAME_MSG,
)
from src.sysmanage_agent.operations.child_host_bhyve_creation import (
    BhyveCreationHelper,
    BHYVE_VM_DIR,
    BHYVE_CLOUDINIT_DIR,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_bhyve_lifecycle")


@pytest.fixture
def mock_creation_helper(logger):
    """Create a mock BhyveCreationHelper."""
    mock_helper = Mock(spec=BhyveCreationHelper)
    mock_helper.logger = logger
    mock_helper.create_tap_interface = Mock(
        return_value={"success": True, "tap": "tap0"}
    )
    return mock_helper


@pytest.fixture
def lifecycle_helper(logger, mock_creation_helper):
    """Create a BhyveLifecycleHelper instance for testing."""
    return BhyveLifecycleHelper(logger, mock_creation_helper)


class TestIsValidVmName:
    """Tests for _is_valid_vm_name function."""

    def test_valid_alphanumeric_name(self):
        """Test valid alphanumeric VM name."""
        assert _is_valid_vm_name("testvm") is True
        assert _is_valid_vm_name("TestVM123") is True

    def test_valid_name_with_hyphens(self):
        """Test valid VM name with hyphens."""
        assert _is_valid_vm_name("test-vm") is True
        assert _is_valid_vm_name("my-test-vm-01") is True

    def test_valid_name_with_underscores(self):
        """Test valid VM name with underscores."""
        assert _is_valid_vm_name("test_vm") is True
        assert _is_valid_vm_name("my_test_vm_01") is True

    def test_valid_mixed_name(self):
        """Test valid VM name with mixed characters."""
        assert _is_valid_vm_name("test-vm_01") is True
        assert _is_valid_vm_name("My_Test-VM-2024") is True

    def test_empty_name(self):
        """Test empty VM name is rejected."""
        assert _is_valid_vm_name("") is False

    def test_name_too_long(self):
        """Test VM name exceeding 64 characters is rejected."""
        long_name = "a" * 65
        assert _is_valid_vm_name(long_name) is False

    def test_name_exactly_64_chars(self):
        """Test VM name exactly 64 characters is accepted."""
        exact_name = "a" * 64
        assert _is_valid_vm_name(exact_name) is True

    def test_name_with_path_traversal(self):
        """Test VM names with path traversal are rejected."""
        assert _is_valid_vm_name("../etc/passwd") is False
        assert _is_valid_vm_name("test/../other") is False
        assert _is_valid_vm_name("..") is False

    def test_name_with_slash(self):
        """Test VM names with slashes are rejected."""
        assert _is_valid_vm_name("test/vm") is False
        assert _is_valid_vm_name("/absolute/path") is False

    def test_name_with_special_chars(self):
        """Test VM names with special characters are rejected."""
        assert _is_valid_vm_name("test vm") is False  # space
        assert _is_valid_vm_name("test@vm") is False
        assert _is_valid_vm_name("test#vm") is False
        assert _is_valid_vm_name("test$vm") is False
        assert _is_valid_vm_name("test&vm") is False
        assert _is_valid_vm_name("test;vm") is False
        assert _is_valid_vm_name("test|vm") is False


class TestValidatePathInAllowedDirs:
    """Tests for _validate_path_in_allowed_dirs function."""

    def test_path_in_allowed_dir(self):
        """Test path within allowed directory is valid."""
        allowed_dirs = ["/vm", "/cloudinit"]
        assert (
            _validate_path_in_allowed_dirs("/vm/testvm/disk.img", allowed_dirs) is True
        )
        assert (
            _validate_path_in_allowed_dirs("/cloudinit/testvm.iso", allowed_dirs)
            is True
        )

    def test_path_outside_allowed_dirs(self):
        """Test path outside allowed directories is rejected."""
        allowed_dirs = ["/vm", "/cloudinit"]
        assert _validate_path_in_allowed_dirs("/etc/passwd", allowed_dirs) is False
        assert _validate_path_in_allowed_dirs("/root/file", allowed_dirs) is False

    def test_path_with_traversal_attack(self):
        """Test path traversal attacks are rejected.

        The function uses os.path.realpath which resolves '..' correctly,
        so '/vm/../etc/passwd' becomes '/etc/passwd' which is not under '/vm'.
        We test this by checking that a path traversal attempt that would
        escape to a directory outside allowed_dirs is properly rejected.
        """

        # Create a mock that simulates real path resolution behavior
        # /vm/../etc/passwd resolves to /etc/passwd which is not under /vm
        def mock_realpath(path):
            if path == "/vm/../etc/passwd":
                return "/etc/passwd"
            if path == "/vm":
                return "/vm"
            return path

        allowed_dirs = ["/vm"]
        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.os.path.realpath",
            side_effect=mock_realpath,
        ):
            assert (
                _validate_path_in_allowed_dirs("/vm/../etc/passwd", allowed_dirs)
                is False
            )

    def test_exact_match_of_allowed_dir(self):
        """Test exact match of allowed directory is valid."""
        allowed_dirs = ["/vm"]
        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.os.path.realpath",
            side_effect=lambda x: x,
        ):
            assert _validate_path_in_allowed_dirs("/vm", allowed_dirs) is True

    def test_empty_allowed_dirs(self):
        """Test with empty allowed directories list."""
        assert _validate_path_in_allowed_dirs("/any/path", []) is False

    def test_os_error_handling(self):
        """Test OSError during path resolution."""
        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.os.path.realpath",
            side_effect=OSError("Permission denied"),
        ):
            assert _validate_path_in_allowed_dirs("/vm/test", ["/vm"]) is False

    def test_value_error_handling(self):
        """Test ValueError during path resolution."""
        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.os.path.realpath",
            side_effect=ValueError("Invalid path"),
        ):
            assert _validate_path_in_allowed_dirs("/vm/test", ["/vm"]) is False


class TestBhyveLifecycleHelperInit:
    """Tests for BhyveLifecycleHelper initialization."""

    def test_init_sets_logger(self, lifecycle_helper, logger):
        """Test that __init__ sets logger."""
        assert lifecycle_helper.logger == logger

    def test_init_sets_creation_helper(self, lifecycle_helper, mock_creation_helper):
        """Test that __init__ sets creation_helper."""
        assert lifecycle_helper.creation_helper == mock_creation_helper


class TestLoadVmConfig:
    """Tests for _load_vm_config method."""

    def test_config_file_not_found(self, lifecycle_helper):
        """Test when config file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = lifecycle_helper._load_vm_config("testvm")
        assert result is None

    def test_config_loaded_successfully(self, lifecycle_helper):
        """Test successful config loading."""
        config_data = {"memory": "2G", "cpus": 4, "use_uefi": True}
        mock_file = mock_open(read_data=json.dumps(config_data))

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_file):
                result = lifecycle_helper._load_vm_config("testvm")

        assert result == config_data

    def test_config_json_parse_error(self, lifecycle_helper):
        """Test JSON parse error during config loading."""
        mock_file = mock_open(read_data="not valid json")

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_file):
                result = lifecycle_helper._load_vm_config("testvm")

        assert result is None

    def test_config_file_read_error(self, lifecycle_helper):
        """Test file read error during config loading."""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", side_effect=IOError("Cannot read file")):
                result = lifecycle_helper._load_vm_config("testvm")

        assert result is None


class TestParseMemoryString:
    """Tests for _parse_memory_string method."""

    def test_parse_gigabytes(self, lifecycle_helper):
        """Test parsing memory in gigabytes."""
        assert lifecycle_helper._parse_memory_string("1G") == 1024
        assert lifecycle_helper._parse_memory_string("2G") == 2048
        assert lifecycle_helper._parse_memory_string("4g") == 4096  # lowercase

    def test_parse_megabytes(self, lifecycle_helper):
        """Test parsing memory in megabytes."""
        assert lifecycle_helper._parse_memory_string("512M") == 512
        assert lifecycle_helper._parse_memory_string("1024M") == 1024
        assert lifecycle_helper._parse_memory_string("2048m") == 2048  # lowercase

    def test_parse_fractional_gigabytes(self, lifecycle_helper):
        """Test parsing fractional gigabytes."""
        assert lifecycle_helper._parse_memory_string("1.5G") == 1536
        assert lifecycle_helper._parse_memory_string("0.5G") == 512

    def test_parse_unknown_unit(self, lifecycle_helper):
        """Test parsing unknown unit returns default."""
        assert lifecycle_helper._parse_memory_string("1024") == 1024
        assert lifecycle_helper._parse_memory_string("unknown") == 1024

    def test_parse_empty_string(self, lifecycle_helper):
        """Test parsing empty string returns default."""
        # Empty string with no suffix returns default
        assert lifecycle_helper._parse_memory_string("") == 1024


class TestGetVmStartParams:
    """Tests for _get_vm_start_params method."""

    def test_default_params_no_config(self, lifecycle_helper):
        """Test default parameters when no config exists."""
        with patch.object(lifecycle_helper, "_load_vm_config", return_value=None):
            params = lifecycle_helper._get_vm_start_params("testvm")

        assert params["memory_mb"] == 1024
        assert params["cpus"] == 1
        assert params["use_uefi"] is True
        assert params["disk_path"] == f"{BHYVE_VM_DIR}/testvm/testvm.img"
        assert params["cloudinit_iso"] == f"{BHYVE_CLOUDINIT_DIR}/testvm.iso"

    def test_params_from_config(self, lifecycle_helper):
        """Test parameters loaded from config."""
        config = {"memory": "4G", "cpus": 2, "use_uefi": False}
        with patch.object(lifecycle_helper, "_load_vm_config", return_value=config):
            params = lifecycle_helper._get_vm_start_params("testvm")

        assert params["memory_mb"] == 4096
        assert params["cpus"] == 2
        assert params["use_uefi"] is False

    def test_valid_disk_path_from_config(self, lifecycle_helper):
        """Test valid disk_path from config is used."""
        config = {"disk_path": f"{BHYVE_VM_DIR}/testvm/custom.img"}

        def mock_validate(path, _allowed):
            return path.startswith(BHYVE_VM_DIR)

        with patch.object(lifecycle_helper, "_load_vm_config", return_value=config):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_lifecycle._validate_path_in_allowed_dirs",
                side_effect=mock_validate,
            ):
                params = lifecycle_helper._get_vm_start_params("testvm")

        assert params["disk_path"] == f"{BHYVE_VM_DIR}/testvm/custom.img"

    def test_invalid_disk_path_from_config(self, lifecycle_helper):
        """Test invalid disk_path from config is rejected."""
        config = {"disk_path": "/etc/passwd"}

        with patch.object(lifecycle_helper, "_load_vm_config", return_value=config):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_lifecycle._validate_path_in_allowed_dirs",
                return_value=False,
            ):
                params = lifecycle_helper._get_vm_start_params("testvm")

        # Should use default path, not the invalid one
        assert params["disk_path"] == f"{BHYVE_VM_DIR}/testvm/testvm.img"

    def test_valid_cloudinit_path_from_config(self, lifecycle_helper):
        """Test valid cloud_init_iso_path from config is used."""
        config = {"cloud_init_iso_path": f"{BHYVE_CLOUDINIT_DIR}/custom.iso"}

        def mock_validate(path, _allowed):
            return path.startswith(BHYVE_CLOUDINIT_DIR)

        with patch.object(lifecycle_helper, "_load_vm_config", return_value=config):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_lifecycle._validate_path_in_allowed_dirs",
                side_effect=mock_validate,
            ):
                params = lifecycle_helper._get_vm_start_params("testvm")

        assert params["cloudinit_iso"] == f"{BHYVE_CLOUDINIT_DIR}/custom.iso"

    def test_invalid_cloudinit_path_from_config(self, lifecycle_helper):
        """Test invalid cloud_init_iso_path from config is rejected."""
        config = {"cloud_init_iso_path": "/etc/shadow"}

        with patch.object(lifecycle_helper, "_load_vm_config", return_value=config):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_lifecycle._validate_path_in_allowed_dirs",
                return_value=False,
            ):
                params = lifecycle_helper._get_vm_start_params("testvm")

        # Should use default path, not the invalid one
        assert params["cloudinit_iso"] == f"{BHYVE_CLOUDINIT_DIR}/testvm.iso"


class TestBuildBhyveCommand:
    """Tests for _build_bhyve_command method."""

    def test_basic_command_structure(self, lifecycle_helper):
        """Test basic bhyve command structure."""
        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": False,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        with patch("os.path.exists", return_value=False):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap0", params)

        assert "bhyve" in cmd
        assert "-A" in cmd
        assert "-H" in cmd
        assert "-P" in cmd
        assert "testvm" == cmd[-1]

    def test_command_with_memory_and_cpus(self, lifecycle_helper):
        """Test command includes correct memory and CPU settings."""
        params = {
            "memory_mb": 2048,
            "cpus": 4,
            "use_uefi": False,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        with patch("os.path.exists", return_value=False):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap0", params)

        assert "-m" in cmd
        assert "2048M" in cmd
        assert "-c" in cmd
        assert "4" in cmd

    def test_command_with_network_interface(self, lifecycle_helper):
        """Test command includes network interface."""
        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": False,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        with patch("os.path.exists", return_value=False):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap5", params)

        # Find the virtio-net argument
        assert "2:0,virtio-net,tap5" in cmd

    def test_command_with_disk(self, lifecycle_helper):
        """Test command includes disk."""
        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": False,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        with patch("os.path.exists", return_value=False):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap0", params)

        assert "3:0,virtio-blk,/vm/testvm/testvm.img" in cmd

    def test_command_with_cloudinit_iso(self, lifecycle_helper):
        """Test command includes cloud-init ISO when it exists."""
        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": False,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        def mock_exists(path):
            return path == "/cloudinit/testvm.iso"

        with patch("os.path.exists", side_effect=mock_exists):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap0", params)

        assert "4:0,ahci-cd,/cloudinit/testvm.iso" in cmd

    def test_command_without_cloudinit_iso(self, lifecycle_helper):
        """Test command excludes cloud-init ISO when it doesn't exist."""
        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": False,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        with patch("os.path.exists", return_value=False):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap0", params)

        # Verify no ahci-cd entry
        assert not any("ahci-cd" in str(arg) for arg in cmd)

    def test_command_with_uefi(self, lifecycle_helper):
        """Test command includes UEFI bootrom when available."""
        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        def mock_exists(path):
            return path == "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd"

        with patch("os.path.exists", side_effect=mock_exists):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap0", params)

        assert "bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI.fd" in cmd

    def test_command_without_uefi_firmware(self, lifecycle_helper):
        """Test command excludes UEFI when firmware not available."""
        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        with patch("os.path.exists", return_value=False):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap0", params)

        assert not any("bootrom" in str(arg) for arg in cmd)

    def test_command_uefi_disabled(self, lifecycle_helper):
        """Test command excludes UEFI when disabled in params."""
        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": False,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        # Even if firmware exists, should not use it
        with patch("os.path.exists", return_value=True):
            cmd = lifecycle_helper._build_bhyve_command("testvm", "tap0", params)

        assert not any("bootrom" in str(arg) for arg in cmd)


class TestRunSubprocess:
    """Tests for _run_subprocess method."""

    @pytest.mark.asyncio
    async def test_run_subprocess_success(self, lifecycle_helper):
        """Test successful subprocess execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "success output"
        mock_result.stderr = ""

        with patch("asyncio.to_thread", return_value=mock_result):
            result = await lifecycle_helper._run_subprocess(["echo", "test"])

        assert result.returncode == 0
        assert result.stdout == "success output"

    @pytest.mark.asyncio
    async def test_run_subprocess_failure(self, lifecycle_helper):
        """Test failed subprocess execution."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error message"

        with patch("asyncio.to_thread", return_value=mock_result):
            result = await lifecycle_helper._run_subprocess(["false"])

        assert result.returncode == 1
        assert result.stderr == "error message"

    @pytest.mark.asyncio
    async def test_run_subprocess_with_custom_timeout(self, lifecycle_helper):
        """Test subprocess execution with custom timeout."""
        mock_result = Mock()
        mock_result.returncode = 0

        async def mock_to_thread(_func, *_args, **kwargs):
            # Verify timeout is passed correctly
            assert kwargs.get("timeout") == 120
            return mock_result

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            await lifecycle_helper._run_subprocess(["cmd"], timeout=120)


class TestStartChildHost:
    """Tests for start_child_host method."""

    @pytest.mark.asyncio
    async def test_start_no_child_name(self, lifecycle_helper):
        """Test starting VM without child_name."""
        result = await lifecycle_helper.start_child_host({})
        assert result["success"] is False
        assert _NO_CHILD_NAME_MSG in result["error"]

    @pytest.mark.asyncio
    async def test_start_invalid_vm_name(self, lifecycle_helper):
        """Test starting VM with invalid name."""
        result = await lifecycle_helper.start_child_host(
            {"child_name": "../etc/passwd"}
        )
        assert result["success"] is False
        assert _INVALID_VM_NAME_MSG in result["error"]

    @pytest.mark.asyncio
    async def test_start_vm_already_running(self, lifecycle_helper):
        """Test starting VM that is already running."""
        with patch("os.path.exists", return_value=True):
            result = await lifecycle_helper.start_child_host({"child_name": "testvm"})

        assert result["success"] is True
        assert result["status"] == "running"
        assert "already running" in result["message"]

    @pytest.mark.asyncio
    async def test_start_vm_disk_not_found(self, lifecycle_helper):
        """Test starting VM when disk doesn't exist."""

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            return False

        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        with patch("os.path.exists", side_effect=mock_exists):
            with patch.object(
                lifecycle_helper, "_get_vm_start_params", return_value=params
            ):
                result = await lifecycle_helper.start_child_host(
                    {"child_name": "testvm"}
                )

        assert result["success"] is False
        assert "disk not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_vm_tap_creation_fails(
        self, lifecycle_helper, mock_creation_helper
    ):
        """Test starting VM when tap interface creation fails."""
        mock_creation_helper.create_tap_interface.return_value = {
            "success": False,
            "error": "Failed to create tap interface",
        }

        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            if path == "/vm/testvm/testvm.img":
                return True
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            with patch.object(
                lifecycle_helper, "_get_vm_start_params", return_value=params
            ):
                result = await lifecycle_helper.start_child_host(
                    {"child_name": "testvm"}
                )

        assert result["success"] is False
        assert "tap" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_vm_success(self, lifecycle_helper, mock_creation_helper):
        """Test starting VM successfully."""
        mock_creation_helper.create_tap_interface.return_value = {
            "success": True,
            "tap": "tap0",
        }

        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            if path == "/vm/testvm/testvm.img":
                return True
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            with patch.object(
                lifecycle_helper, "_get_vm_start_params", return_value=params
            ):
                with patch.object(
                    lifecycle_helper,
                    "_build_bhyve_command",
                    return_value=["bhyve", "testvm"],
                ):
                    with patch.object(
                        lifecycle_helper, "_run_subprocess", return_value=mock_result
                    ):
                        result = await lifecycle_helper.start_child_host(
                            {"child_name": "testvm"}
                        )

        assert result["success"] is True
        assert result["status"] == "running"
        assert result["child_name"] == "testvm"

    @pytest.mark.asyncio
    async def test_start_vm_daemon_fails(self, lifecycle_helper, mock_creation_helper):
        """Test starting VM when daemon command fails."""
        mock_creation_helper.create_tap_interface.return_value = {
            "success": True,
            "tap": "tap0",
        }

        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "bhyve: device memory mapping failed"

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            if path == "/vm/testvm/testvm.img":
                return True
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            with patch.object(
                lifecycle_helper, "_get_vm_start_params", return_value=params
            ):
                with patch.object(
                    lifecycle_helper,
                    "_build_bhyve_command",
                    return_value=["bhyve", "testvm"],
                ):
                    with patch.object(
                        lifecycle_helper, "_run_subprocess", return_value=mock_result
                    ):
                        result = await lifecycle_helper.start_child_host(
                            {"child_name": "testvm"}
                        )

        assert result["success"] is False
        assert "device memory mapping failed" in result["error"]

    @pytest.mark.asyncio
    async def test_start_vm_exception(self, lifecycle_helper):
        """Test starting VM with exception."""

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            raise RuntimeError("Unexpected error")

        with patch("os.path.exists", side_effect=mock_exists):
            result = await lifecycle_helper.start_child_host({"child_name": "testvm"})

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestStopChildHost:
    """Tests for stop_child_host method."""

    @pytest.mark.asyncio
    async def test_stop_no_child_name(self, lifecycle_helper):
        """Test stopping VM without child_name."""
        result = await lifecycle_helper.stop_child_host({})
        assert result["success"] is False
        assert _NO_CHILD_NAME_MSG in result["error"]

    @pytest.mark.asyncio
    async def test_stop_invalid_vm_name(self, lifecycle_helper):
        """Test stopping VM with invalid name."""
        result = await lifecycle_helper.stop_child_host({"child_name": "../etc/passwd"})
        assert result["success"] is False
        assert _INVALID_VM_NAME_MSG in result["error"]

    @pytest.mark.asyncio
    async def test_stop_vm_not_running(self, lifecycle_helper):
        """Test stopping VM that is not running."""
        with patch("os.path.exists", return_value=False):
            result = await lifecycle_helper.stop_child_host({"child_name": "testvm"})

        assert result["success"] is True
        assert result["status"] == "stopped"
        assert "not running" in result["message"]

    @pytest.mark.asyncio
    async def test_stop_vm_success(self, lifecycle_helper):
        """Test stopping VM successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("os.path.exists", return_value=True):
            with patch.object(
                lifecycle_helper, "_run_subprocess", return_value=mock_result
            ):
                result = await lifecycle_helper.stop_child_host(
                    {"child_name": "testvm"}
                )

        assert result["success"] is True
        assert result["status"] == "stopped"
        assert result["child_name"] == "testvm"

    @pytest.mark.asyncio
    async def test_stop_vm_calls_poweroff_and_destroy(self, lifecycle_helper):
        """Test stopping VM calls both poweroff and destroy."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        calls = []

        async def track_subprocess(cmd, timeout=60):  # pylint: disable=unused-argument
            calls.append(cmd)
            return mock_result

        with patch("os.path.exists", return_value=True):
            with patch.object(
                lifecycle_helper, "_run_subprocess", side_effect=track_subprocess
            ):
                await lifecycle_helper.stop_child_host({"child_name": "testvm"})

        # Should have called both poweroff and destroy
        assert len(calls) == 2
        assert "--force-poweroff" in calls[0]
        assert "--destroy" in calls[1]

    @pytest.mark.asyncio
    async def test_stop_vm_exception(self, lifecycle_helper):
        """Test stopping VM with exception."""
        with patch("os.path.exists", side_effect=Exception("Unexpected error")):
            result = await lifecycle_helper.stop_child_host({"child_name": "testvm"})

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestRestartChildHost:
    """Tests for restart_child_host method."""

    @pytest.mark.asyncio
    async def test_restart_no_child_name(self, lifecycle_helper):
        """Test restarting VM without child_name."""
        result = await lifecycle_helper.restart_child_host({})
        assert result["success"] is False
        assert _NO_CHILD_NAME_MSG in result["error"]

    @pytest.mark.asyncio
    async def test_restart_invalid_vm_name(self, lifecycle_helper):
        """Test restarting VM with invalid name."""
        result = await lifecycle_helper.restart_child_host({"child_name": "../etc"})
        assert result["success"] is False
        assert _INVALID_VM_NAME_MSG in result["error"]

    @pytest.mark.asyncio
    async def test_restart_stop_fails(self, lifecycle_helper):
        """Test restart when stop fails."""
        with patch.object(
            lifecycle_helper,
            "stop_child_host",
            return_value={"success": False, "error": "Stop failed"},
        ):
            result = await lifecycle_helper.restart_child_host({"child_name": "testvm"})

        assert result["success"] is False
        assert result["error"] == "Stop failed"

    @pytest.mark.asyncio
    async def test_restart_success(self, lifecycle_helper):
        """Test successful restart."""
        stop_result = {"success": True, "status": "stopped"}
        start_result = {"success": True, "status": "running", "child_name": "testvm"}

        with patch.object(
            lifecycle_helper, "stop_child_host", return_value=stop_result
        ):
            with patch.object(
                lifecycle_helper, "start_child_host", return_value=start_result
            ):
                with patch("asyncio.sleep", return_value=None):
                    result = await lifecycle_helper.restart_child_host(
                        {"child_name": "testvm"}
                    )

        assert result["success"] is True
        assert result["status"] == "running"

    @pytest.mark.asyncio
    async def test_restart_calls_sleep(self, lifecycle_helper):
        """Test restart includes sleep between stop and start."""
        stop_result = {"success": True, "status": "stopped"}
        start_result = {"success": True, "status": "running", "child_name": "testvm"}
        sleep_called = False

        async def mock_sleep(seconds):
            nonlocal sleep_called
            sleep_called = True
            assert seconds == 2

        with patch.object(
            lifecycle_helper, "stop_child_host", return_value=stop_result
        ):
            with patch.object(
                lifecycle_helper, "start_child_host", return_value=start_result
            ):
                with patch("asyncio.sleep", side_effect=mock_sleep):
                    await lifecycle_helper.restart_child_host({"child_name": "testvm"})

        assert sleep_called


class TestDeleteChildHost:
    """Tests for delete_child_host method."""

    @pytest.mark.asyncio
    async def test_delete_no_child_name(self, lifecycle_helper):
        """Test deleting VM without child_name."""
        result = await lifecycle_helper.delete_child_host({})
        assert result["success"] is False
        assert _NO_CHILD_NAME_MSG in result["error"]

    @pytest.mark.asyncio
    async def test_delete_invalid_vm_name(self, lifecycle_helper):
        """Test deleting VM with invalid name."""
        result = await lifecycle_helper.delete_child_host({"child_name": "../../etc"})
        assert result["success"] is False
        assert _INVALID_VM_NAME_MSG in result["error"]

    @pytest.mark.asyncio
    async def test_delete_stops_running_vm(self, lifecycle_helper):
        """Test delete stops running VM first."""
        stop_called = False

        async def mock_stop(_params):
            nonlocal stop_called
            stop_called = True
            return {"success": True}

        def mock_exists(path):
            if "/dev/vmm/testvm" in path:
                return True
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.path.isdir", return_value=False):
                with patch.object(
                    lifecycle_helper, "stop_child_host", side_effect=mock_stop
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.delete_bhyve_metadata"
                    ):
                        await lifecycle_helper.delete_child_host(
                            {"child_name": "testvm"}
                        )

        assert stop_called

    @pytest.mark.asyncio
    async def test_delete_removes_vm_directory(self, lifecycle_helper):
        """Test delete removes VM directory."""
        rmtree_called = False
        removed_path = None

        def mock_rmtree(path):
            nonlocal rmtree_called, removed_path
            rmtree_called = True
            removed_path = path

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            return False

        def mock_isdir(path):
            return path == f"{BHYVE_VM_DIR}/testvm"

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.path.isdir", side_effect=mock_isdir):
                with patch("shutil.rmtree", side_effect=mock_rmtree):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.delete_bhyve_metadata"
                    ):
                        await lifecycle_helper.delete_child_host(
                            {"child_name": "testvm"}
                        )

        assert rmtree_called
        assert removed_path == f"{BHYVE_VM_DIR}/testvm"

    @pytest.mark.asyncio
    async def test_delete_removes_cloudinit_iso(self, lifecycle_helper):
        """Test delete removes cloud-init ISO."""
        removed_files = []

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            if path == f"{BHYVE_CLOUDINIT_DIR}/testvm.iso":
                return True
            return False

        def mock_remove(path):
            removed_files.append(path)

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.path.isdir", return_value=False):
                with patch("os.remove", side_effect=mock_remove):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.delete_bhyve_metadata"
                    ):
                        await lifecycle_helper.delete_child_host(
                            {"child_name": "testvm"}
                        )

        assert f"{BHYVE_CLOUDINIT_DIR}/testvm.iso" in removed_files

    @pytest.mark.asyncio
    async def test_delete_removes_cloudinit_directory(self, lifecycle_helper):
        """Test delete removes cloud-init directory."""
        rmtree_paths = []

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            return False

        def mock_isdir(path):
            return path == f"{BHYVE_CLOUDINIT_DIR}/testvm"

        def mock_rmtree(path):
            rmtree_paths.append(path)

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.path.isdir", side_effect=mock_isdir):
                with patch("shutil.rmtree", side_effect=mock_rmtree):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.delete_bhyve_metadata"
                    ):
                        await lifecycle_helper.delete_child_host(
                            {"child_name": "testvm"}
                        )

        assert f"{BHYVE_CLOUDINIT_DIR}/testvm" in rmtree_paths

    @pytest.mark.asyncio
    async def test_delete_calls_delete_metadata(self, lifecycle_helper):
        """Test delete calls delete_bhyve_metadata."""
        metadata_deleted = False
        deleted_name = None

        def mock_delete_metadata(name, _logger):
            nonlocal metadata_deleted, deleted_name
            metadata_deleted = True
            deleted_name = name

        def mock_exists(_path):
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.path.isdir", return_value=False):
                with patch(
                    "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.delete_bhyve_metadata",
                    side_effect=mock_delete_metadata,
                ):
                    await lifecycle_helper.delete_child_host({"child_name": "testvm"})

        assert metadata_deleted
        assert deleted_name == "testvm"

    @pytest.mark.asyncio
    async def test_delete_success(self, lifecycle_helper):
        """Test successful delete."""

        def mock_exists(_path):
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.path.isdir", return_value=False):
                with patch(
                    "src.sysmanage_agent.operations.child_host_bhyve_lifecycle.delete_bhyve_metadata"
                ):
                    result = await lifecycle_helper.delete_child_host(
                        {"child_name": "testvm"}
                    )

        assert result["success"] is True
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "bhyve"

    @pytest.mark.asyncio
    async def test_delete_exception(self, lifecycle_helper):
        """Test delete with exception."""
        with patch("os.path.exists", side_effect=Exception("Permission denied")):
            result = await lifecycle_helper.delete_child_host({"child_name": "testvm"})

        assert result["success"] is False
        assert "Permission denied" in result["error"]


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    @pytest.mark.asyncio
    async def test_vm_name_with_special_allowed_chars(
        self, lifecycle_helper, mock_creation_helper
    ):
        """Test VM names with all allowed special characters."""
        # Reset the mock to return success
        mock_creation_helper.create_tap_interface.return_value = {
            "success": True,
            "tap": "tap0",
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": "/vm/test-vm_01/test-vm_01.img",
            "cloudinit_iso": "/cloudinit/test-vm_01.iso",
        }

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            if "test-vm_01.img" in path:
                return True
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            with patch.object(
                lifecycle_helper, "_get_vm_start_params", return_value=params
            ):
                with patch.object(
                    lifecycle_helper,
                    "_build_bhyve_command",
                    return_value=["bhyve", "test-vm_01"],
                ):
                    with patch.object(
                        lifecycle_helper, "_run_subprocess", return_value=mock_result
                    ):
                        result = await lifecycle_helper.start_child_host(
                            {"child_name": "test-vm_01"}
                        )

        assert result["success"] is True

    def test_memory_parsing_edge_cases(self, lifecycle_helper):
        """Test memory parsing with various edge cases."""
        # Very large values
        assert lifecycle_helper._parse_memory_string("64G") == 65536

        # Zero-ish values (defaults to 1024)
        assert lifecycle_helper._parse_memory_string("0M") == 0
        assert lifecycle_helper._parse_memory_string("0G") == 0

    @pytest.mark.asyncio
    async def test_concurrent_vm_operations(
        self, lifecycle_helper, mock_creation_helper
    ):
        """Test that concurrent operations don't interfere."""
        mock_creation_helper.create_tap_interface.return_value = {
            "success": True,
            "tap": "tap0",
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": "/vm/testvm/testvm.img",
            "cloudinit_iso": "/cloudinit/testvm.iso",
        }

        def mock_exists(path):
            if "/dev/vmm/" in path:
                return False
            if ".img" in path:
                return True
            return False

        with patch("os.path.exists", side_effect=mock_exists):
            with patch.object(
                lifecycle_helper, "_get_vm_start_params", return_value=params
            ):
                with patch.object(
                    lifecycle_helper,
                    "_build_bhyve_command",
                    return_value=["bhyve", "testvm"],
                ):
                    with patch.object(
                        lifecycle_helper, "_run_subprocess", return_value=mock_result
                    ):
                        # Run multiple operations concurrently
                        results = await asyncio.gather(
                            lifecycle_helper.start_child_host({"child_name": "vm1"}),
                            lifecycle_helper.start_child_host({"child_name": "vm2"}),
                            lifecycle_helper.start_child_host({"child_name": "vm3"}),
                        )

        # All should succeed
        for result in results:
            assert result["success"] is True
