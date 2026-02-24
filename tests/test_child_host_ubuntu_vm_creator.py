"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.

Tests the Ubuntu VMM VM creation workflow including:
- Configuration validation
- VM environment preparation
- Installation resource preparation
- VM installation execution
- Metadata saving and cleanup
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_types import (
    VmmResourceConfig,
    VmmServerConfig,
    VmmVmConfig,
)
from src.sysmanage_agent.operations.child_host_ubuntu_vm_creator import UbuntuVmCreator
from src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers import (
    cleanup_installation_artifacts,
    get_disk_size,
    get_gateway_ip,
    get_next_vm_ip,
    parse_memory_gb,
    save_vm_metadata,
    validate_vm_config,
)


def create_valid_config(config_params=None):
    """Create a valid VmmVmConfig for testing.

    Args:
        config_params: Optional dict of config parameters to override defaults
    """
    defaults = {
        "distribution": "Ubuntu 24.04 LTS",
        "vm_name": "test-ubuntu-vm",
        "hostname": "test-ubuntu",
        "username": "testuser",
        "password_hash": "$6$rounds=5000$salt$hash",
        "server_url": "https://sysmanage.example.com",
        "server_port": 8443,
        "use_https": True,
        "memory": "2G",
        "disk_size": "20G",
        "auto_approve_token": "test-token-12345",
    }
    if config_params:
        defaults.update(config_params)
    return VmmVmConfig(
        distribution=defaults["distribution"],
        vm_name=defaults["vm_name"],
        hostname=defaults["hostname"],
        username=defaults["username"],
        password_hash=defaults["password_hash"],
        agent_install_commands=["apt-get update", "apt-get install -y sysmanage-agent"],
        server_config=VmmServerConfig(
            server_url=defaults["server_url"],
            server_port=defaults["server_port"],
            use_https=defaults["use_https"],
        ),
        resource_config=VmmResourceConfig(
            memory=defaults["memory"],
            disk_size=defaults["disk_size"],
            cpus=1,
        ),
        auto_approve_token=defaults["auto_approve_token"],
    )


class TestUbuntuVmCreatorInit:
    """Test cases for UbuntuVmCreator initialization."""

    def test_init_sets_attributes(self):
        """Test that __init__ correctly sets all attributes."""
        mock_agent = Mock()
        mock_logger = Mock()
        mock_virt_checks = Mock()
        mock_github = Mock()
        mock_db = Mock()

        creator = UbuntuVmCreator(
            mock_agent, mock_logger, mock_virt_checks, mock_github, mock_db
        )

        assert creator.agent == mock_agent
        assert creator.logger == mock_logger
        assert creator.virtualization_checks == mock_virt_checks
        assert creator.github_checker == mock_github
        assert creator.db_session == mock_db

    def test_init_creates_helper_objects(self):
        """Test that __init__ creates helper objects."""
        mock_agent = Mock()
        mock_logger = Mock()
        mock_virt_checks = Mock()
        mock_github = Mock()
        mock_db = Mock()

        creator = UbuntuVmCreator(
            mock_agent, mock_logger, mock_virt_checks, mock_github, mock_db
        )

        assert creator.disk_ops is not None
        assert creator.vmconf_manager is not None
        assert creator.launcher is not None
        assert creator.autoinstall_setup is not None

    def test_default_constants(self):
        """Test default resource constants."""
        assert UbuntuVmCreator.DEFAULT_DISK_SIZE == "20G"
        assert UbuntuVmCreator.DEFAULT_MEMORY == "2G"
        assert UbuntuVmCreator.MIN_INSTALLED_DISK_SIZE == 2 * 1024 * 1024 * 1024


class TestValidateConfig:
    """Test cases for configuration validation."""

    def test_validate_config_success(self):
        """Test validation succeeds with valid config."""
        config = create_valid_config()
        result = validate_vm_config(config)

        assert result["success"] is True

    def test_validate_config_missing_distribution(self):
        """Test validation fails without distribution."""
        config = create_valid_config({"distribution": ""})
        result = validate_vm_config(config)

        assert result["success"] is False
        assert "Distribution" in result["error"]

    def test_validate_config_missing_vm_name(self):
        """Test validation fails without VM name."""
        config = create_valid_config({"vm_name": ""})
        result = validate_vm_config(config)

        assert result["success"] is False
        assert "VM name" in result["error"]

    def test_validate_config_missing_hostname(self):
        """Test validation fails without hostname."""
        config = create_valid_config({"hostname": ""})
        result = validate_vm_config(config)

        assert result["success"] is False
        assert "Hostname" in result["error"]

    def test_validate_config_missing_username(self):
        """Test validation fails without username."""
        config = create_valid_config({"username": ""})
        result = validate_vm_config(config)

        assert result["success"] is False
        assert "Username" in result["error"]

    def test_validate_config_missing_password(self):
        """Test validation fails without password hash."""
        config = create_valid_config({"password_hash": ""})
        result = validate_vm_config(config)

        assert result["success"] is False
        assert "Password" in result["error"]

    def test_validate_config_missing_server_url(self):
        """Test validation fails without server URL."""
        config = create_valid_config({"server_url": ""})
        result = validate_vm_config(config)

        assert result["success"] is False
        assert "Server URL" in result["error"]


class TestParseMemoryGb:
    """Test cases for memory string parsing."""

    def test_parse_memory_gb_gigabytes(self):
        """Test parsing gigabyte memory strings."""
        assert parse_memory_gb("1G") == 1.0
        assert parse_memory_gb("2G") == 2.0
        assert parse_memory_gb("4g") == 4.0
        assert parse_memory_gb("0.5G") == 0.5

    def test_parse_memory_gb_megabytes(self):
        """Test parsing megabyte memory strings."""
        assert parse_memory_gb("1024M") == 1.0
        assert parse_memory_gb("512M") == 0.5
        assert parse_memory_gb("2048m") == 2.0

    def test_parse_memory_gb_kilobytes(self):
        """Test parsing kilobyte memory strings."""
        result = parse_memory_gb("1048576K")
        assert result == pytest.approx(1.0, rel=1e-6)

    def test_parse_memory_gb_bytes(self):
        """Test parsing byte values (no suffix)."""
        result = parse_memory_gb("1073741824")
        assert result == pytest.approx(1.0, rel=1e-6)

    def test_parse_memory_gb_invalid(self):
        """Test parsing invalid memory strings."""
        assert parse_memory_gb("invalid") == 0.0
        assert parse_memory_gb("") == 0.0
        assert parse_memory_gb("abc") == 0.0

    def test_parse_memory_gb_whitespace(self):
        """Test parsing memory strings with whitespace."""
        assert parse_memory_gb("  2G  ") == 2.0


class TestCheckVmmReady:
    """Test cases for VMM readiness checking."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.creator = UbuntuVmCreator(
            Mock(), self.mock_logger, self.mock_virt_checks, Mock(), Mock()
        )
        self.creator.launcher = Mock()
        self.creator.launcher.send_progress = AsyncMock()

    @pytest.mark.asyncio
    async def test_check_vmm_ready_success(self):
        """Test VMM check succeeds when available and running."""
        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        result = await self.creator._check_vmm_ready()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_check_vmm_ready_not_available(self):
        """Test VMM check fails when not available."""
        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": False,
            "running": False,
        }

        result = await self.creator._check_vmm_ready()

        assert result["success"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_check_vmm_ready_not_running(self):
        """Test VMM check fails when not running."""
        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": False,
        }

        result = await self.creator._check_vmm_ready()

        assert result["success"] is False
        assert "not running" in result["error"]


class TestGetGatewayIp:
    """Test cases for gateway IP extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.subprocess.run")
    def test_get_gateway_ip_success(self, mock_run):
        """Test successful gateway IP extraction."""
        mock_run.return_value = Mock(
            stdout="vether0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "        lladdr fe:e1:ba:d8:12:34\n"
            "        inet 192.168.100.1 netmask 0xffffff00 broadcast 192.168.100.255\n"
        )

        result = get_gateway_ip(self.mock_logger)

        assert result == "192.168.100.1"

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.subprocess.run")
    def test_get_gateway_ip_no_interface(self, mock_run):
        """Test gateway IP when vether0 doesn't exist."""
        mock_run.return_value = Mock(stdout="")

        result = get_gateway_ip(self.mock_logger)

        assert result is None

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.subprocess.run")
    def test_get_gateway_ip_exception(self, mock_run):
        """Test gateway IP extraction with exception."""
        mock_run.side_effect = Exception("Command failed")

        result = get_gateway_ip(self.mock_logger)

        assert result is None
        self.mock_logger.error.assert_called()


class TestGetNextVmIp:
    """Test cases for VM IP allocation."""

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.Path")
    def test_get_next_vm_ip_first_vm(self, mock_path_class):
        """Test getting first VM IP when no VMs exist."""
        mock_metadata_dir = Mock()
        mock_metadata_dir.exists.return_value = False
        mock_path_class.return_value = mock_metadata_dir

        result = get_next_vm_ip("192.168.100.1")

        assert result == "192.168.100.100"

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.Path")
    def test_get_next_vm_ip_with_existing(self, mock_path_class):
        """Test getting next VM IP with existing VMs."""
        mock_metadata_dir = Mock()
        mock_metadata_dir.exists.return_value = True

        # Mock glob to return two existing VM metadata files
        mock_file1 = Mock()
        mock_file2 = Mock()
        mock_metadata_dir.glob.return_value = [mock_file1, mock_file2]

        mock_path_class.return_value = mock_metadata_dir

        # Mock file reading
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = Mock(
                side_effect=[
                    Mock(read=Mock(return_value='{"vm_ip": "192.168.100.100"}')),
                    Mock(read=Mock(return_value='{"vm_ip": "192.168.100.101"}')),
                ]
            )
            mock_open.return_value.__exit__ = Mock(return_value=False)

            with patch("json.load") as mock_json_load:
                mock_json_load.side_effect = [
                    {"vm_ip": "192.168.100.100"},
                    {"vm_ip": "192.168.100.101"},
                ]

                result = get_next_vm_ip("192.168.100.1")

        assert result == "192.168.100.102"

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.Path")
    def test_get_next_vm_ip_json_error(self, mock_path_class):
        """Test getting VM IP when metadata file is corrupt."""
        mock_metadata_dir = Mock()
        mock_metadata_dir.exists.return_value = True

        mock_file1 = Mock()
        mock_metadata_dir.glob.return_value = [mock_file1]

        mock_path_class.return_value = mock_metadata_dir

        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = Mock()
            mock_open.return_value.__exit__ = Mock(return_value=False)

            with patch("json.load") as mock_json_load:
                mock_json_load.side_effect = json.JSONDecodeError("error", "doc", 0)

                result = get_next_vm_ip("192.168.100.1")

        # Should still return first available IP since error is silently handled
        assert result == "192.168.100.100"


class TestGetDiskSize:
    """Test cases for disk size retrieval."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.subprocess.run")
    def test_get_disk_size_success(self, mock_run):
        """Test successful disk size retrieval."""
        # du -k returns size in KB
        mock_run.return_value = Mock(
            returncode=0,
            stdout="2097152\t/var/vmm/test.qcow2\n",
        )

        result = get_disk_size("/var/vmm/test.qcow2", self.mock_logger)

        # 2097152 KB = 2GB in bytes
        assert result == 2097152 * 1024

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.subprocess.run")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.Path")
    def test_get_disk_size_du_fails_fallback_stat(self, mock_path_class, mock_run):
        """Test fallback to stat when du fails."""
        mock_run.return_value = Mock(returncode=1, stdout="")

        mock_path = Mock()
        mock_path.stat.return_value = Mock(st_size=1073741824)  # 1GB
        mock_path_class.return_value = mock_path

        result = get_disk_size("/var/vmm/test.qcow2", self.mock_logger)

        assert result == 1073741824

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.subprocess.run")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.Path")
    def test_get_disk_size_all_fail(self, mock_path_class, mock_run):
        """Test disk size returns 0 when all methods fail."""
        mock_run.side_effect = Exception("Command failed")

        mock_path = Mock()
        mock_path.stat.side_effect = Exception("Stat failed")
        mock_path_class.return_value = mock_path

        result = get_disk_size("/var/vmm/test.qcow2", self.mock_logger)

        assert result == 0


class TestGetAgentVersion:
    """Test cases for agent version retrieval."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_github = Mock()
        self.creator = UbuntuVmCreator(
            Mock(), self.mock_logger, Mock(), self.mock_github, Mock()
        )
        self.creator.launcher = Mock()
        self.creator.launcher.send_progress = AsyncMock()

    @pytest.mark.asyncio
    async def test_get_agent_version_success(self):
        """Test successful agent version retrieval."""
        self.mock_github.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }

        version, tag = await self.creator._get_agent_version()

        assert version == "1.2.3"
        assert tag == "v1.2.3"

    @pytest.mark.asyncio
    async def test_get_agent_version_failure(self):
        """Test agent version retrieval failure falls back to 'unknown'."""
        self.mock_github.get_latest_version.return_value = {
            "success": False,
            "error": "Rate limited",
        }

        version, tag = await self.creator._get_agent_version()

        assert version == "unknown"
        assert tag == "unknown"
        self.mock_logger.warning.assert_called()


class TestStopVmForRestart:
    """Test cases for stopping VM for restart."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = UbuntuVmCreator(Mock(), self.mock_logger, Mock(), Mock(), Mock())

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    async def test_stop_vm_graceful_success(self, mock_run_cmd):
        """Test graceful VM stop succeeds."""
        mock_run_cmd.return_value = Mock(returncode=0)

        result = await self.creator._stop_vm_for_restart("test-vm")

        assert result["success"] is True
        mock_run_cmd.assert_called_once()

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    async def test_stop_vm_force_stop(self, mock_run_cmd):
        """Test force stop when graceful fails."""
        mock_run_cmd.side_effect = [
            Mock(returncode=1, stderr="Failed", stdout=""),  # Graceful fails
            Mock(returncode=0),  # Force succeeds
        ]

        result = await self.creator._stop_vm_for_restart("test-vm")

        assert result["success"] is True
        assert mock_run_cmd.call_count == 2

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    async def test_stop_vm_already_stopped(self, mock_run_cmd):
        """Test when VM is already stopped."""
        mock_run_cmd.side_effect = [
            Mock(returncode=1, stderr="VM not found", stdout=""),  # Graceful fails
            Mock(returncode=1, stderr="", stdout=""),  # Force fails
            Mock(returncode=0, stdout="ID NAME STATUS\n"),  # Status shows no VM
        ]

        result = await self.creator._stop_vm_for_restart("test-vm")

        assert result["success"] is True

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    async def test_stop_vm_timeout(self, mock_run_cmd):
        """Test timeout during VM stop."""
        mock_run_cmd.side_effect = asyncio.TimeoutError()

        result = await self.creator._stop_vm_for_restart("test-vm")

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    async def test_stop_vm_exception(self, mock_run_cmd):
        """Test exception during VM stop."""
        mock_run_cmd.side_effect = Exception("Unknown error")

        result = await self.creator._stop_vm_for_restart("test-vm")

        assert result["success"] is False
        assert "Unknown error" in result["error"]


class TestWaitForInstallationComplete:
    """Test cases for waiting for installation completion."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = UbuntuVmCreator(Mock(), self.mock_logger, Mock(), Mock(), Mock())

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.time.time")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.sleep")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_disk_size")
    async def test_wait_installation_complete_success(
        self, mock_disk_size, _mock_sleep, mock_time, mock_run_cmd
    ):
        """Test successful installation completion."""
        # Need enough time values for all calls in the loop
        mock_time.side_effect = [0, 0, 100, 100, 200, 200, 200, 200]
        mock_run_cmd.side_effect = [
            Mock(returncode=0, stdout="1 test-ubuntu running"),  # Still running
            Mock(returncode=0, stdout="ID NAME STATUS"),  # VM stopped
        ]
        mock_disk_size.return_value = 3 * 1024 * 1024 * 1024  # 3GB (success)

        result = await self.creator._wait_for_installation_complete(
            "test-ubuntu", "/var/vmm/test.qcow2", timeout=1500
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.time.time")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.sleep")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_disk_size")
    async def test_wait_installation_vm_crashed(
        self, mock_disk_size, _mock_sleep, mock_time, mock_run_cmd
    ):
        """Test detection of VM crash (disk too small)."""
        # Need enough time values for the loop and elapsed calculation
        mock_time.side_effect = [0, 0, 30, 30, 30]
        mock_run_cmd.return_value = Mock(returncode=0, stdout="ID NAME STATUS")
        mock_disk_size.return_value = 100 * 1024  # Only 100KB (crash)

        result = await self.creator._wait_for_installation_complete(
            "test-ubuntu", "/var/vmm/test.qcow2", timeout=1500
        )

        assert result["success"] is False
        assert "stopped prematurely" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.time.time")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.sleep")
    async def test_wait_installation_timeout(
        self, _mock_sleep, mock_time, mock_run_cmd
    ):
        """Test installation timeout."""
        # Use return_value to return a constant value that exceeds timeout
        # after initial start_time of 0
        call_count = [0]

        def time_side_effect():
            call_count[0] += 1
            # First call sets start_time, subsequent calls exceed timeout
            if call_count[0] == 1:
                return 0
            return 2000  # Always exceed the 1500 timeout

        mock_time.side_effect = time_side_effect
        mock_run_cmd.return_value = Mock(returncode=0, stdout="1 test-ubuntu running")

        result = await self.creator._wait_for_installation_complete(
            "test-ubuntu", "/var/vmm/test.qcow2", timeout=1500
        )

        assert result["success"] is False
        assert "Timeout" in result["error"]


class TestLaunchVmFromIso:
    """Test cases for launching VM from ISO."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = UbuntuVmCreator(Mock(), self.mock_logger, Mock(), Mock(), Mock())

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    async def test_launch_vm_success(self, mock_run_cmd):
        """Test successful VM launch from ISO."""
        mock_run_cmd.return_value = Mock(returncode=0, stderr="")

        config = create_valid_config()
        result = await self.creator._launch_vm_from_iso(
            config,
            "/var/vmm/test.qcow2",
            "/var/vmm/iso/ubuntu-serial.iso",
            "/var/vmm/cidata/cidata-test.iso",
            "2G",
        )

        assert result["success"] is True
        mock_run_cmd.assert_called_once()

        # Verify correct command structure
        call_args = mock_run_cmd.call_args[0][0]
        assert "vmctl" in call_args
        assert "start" in call_args
        assert "-d" in call_args  # Disk parameter
        assert "-m" in call_args  # Memory parameter

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    async def test_launch_vm_failure(self, mock_run_cmd):
        """Test VM launch failure."""
        mock_run_cmd.return_value = Mock(
            returncode=1, stderr="vmctl: vm already exists"
        )

        config = create_valid_config()
        result = await self.creator._launch_vm_from_iso(
            config,
            "/var/vmm/test.qcow2",
            "/var/vmm/iso/ubuntu-serial.iso",
            "/var/vmm/cidata/cidata-test.iso",
            "2G",
        )

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.run_command_async"
    )
    async def test_launch_vm_exception(self, mock_run_cmd):
        """Test VM launch with exception."""
        mock_run_cmd.side_effect = Exception("vmctl not found")

        config = create_valid_config()
        result = await self.creator._launch_vm_from_iso(
            config,
            "/var/vmm/test.qcow2",
            "/var/vmm/iso/ubuntu-serial.iso",
            "/var/vmm/cidata/cidata-test.iso",
            "2G",
        )

        assert result["success"] is False
        assert "vmctl not found" in result["error"]


class TestSaveVmMetadata:
    """Test cases for saving VM metadata."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.time.strftime")
    def test_save_metadata_success(self, mock_strftime):
        """Test successful metadata saving."""
        mock_strftime.return_value = "2024-01-15T12:00:00Z"

        # Use a real temporary directory for this test
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(
                "src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.VMM_METADATA_DIR",
                tmpdir,
            ):
                save_vm_metadata(
                    "test-ubuntu",
                    "test-ubuntu.example.com",
                    "Ubuntu 24.04 LTS",
                    "24.04",
                    "192.168.100.100",
                    self.mock_logger,
                )

                # Verify the file was created
                metadata_file = Path(tmpdir) / "test-ubuntu.json"
                assert metadata_file.exists()

                # Verify the content
                with open(metadata_file, "r", encoding="utf-8") as metadata_handle:
                    metadata = json.load(metadata_handle)

                assert metadata["vm_name"] == "test-ubuntu"
                assert metadata["hostname"] == "test-ubuntu.example.com"
                assert metadata["vm_ip"] == "192.168.100.100"
                assert metadata["distribution"]["distribution_name"] == "Ubuntu"
                assert metadata["distribution"]["distribution_version"] == "24.04"


class TestCleanupInstallationArtifacts:
    """Test cases for cleanup of installation artifacts."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.shutil.rmtree")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.Path")
    def test_cleanup_success(self, mock_path_class, mock_rmtree):
        """Test successful cleanup of installation artifacts."""
        mock_iso_path = Mock()
        mock_iso_path.exists.return_value = True
        mock_iso_path.stat.return_value = Mock(st_size=3 * 1024 * 1024 * 1024)

        mock_cidata_path = Mock()
        mock_cidata_path.exists.return_value = True

        mock_httpd_path = Mock()
        mock_httpd_path.exists.return_value = True

        mock_path_class.side_effect = [
            mock_iso_path,
            mock_cidata_path,
            mock_httpd_path,
        ]

        cleanup_installation_artifacts(
            "/var/vmm/iso/ubuntu-serial.iso", "test-ubuntu", self.mock_logger
        )

        mock_iso_path.unlink.assert_called_once()
        mock_cidata_path.unlink.assert_called_once()
        mock_rmtree.assert_called_once()

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.shutil.rmtree")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.Path")
    def test_cleanup_file_not_exists(self, mock_path_class, mock_rmtree):
        """Test cleanup when files don't exist."""
        mock_iso_path = Mock()
        mock_iso_path.exists.return_value = False

        mock_cidata_path = Mock()
        mock_cidata_path.exists.return_value = False

        mock_httpd_path = Mock()
        mock_httpd_path.exists.return_value = False

        mock_path_class.side_effect = [
            mock_iso_path,
            mock_cidata_path,
            mock_httpd_path,
        ]

        cleanup_installation_artifacts(
            "/var/vmm/iso/ubuntu-serial.iso", "test-ubuntu", self.mock_logger
        )

        mock_iso_path.unlink.assert_not_called()
        mock_cidata_path.unlink.assert_not_called()
        mock_rmtree.assert_not_called()

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.shutil.rmtree")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.Path")
    def test_cleanup_handles_exceptions(self, mock_path_class, mock_rmtree):
        """Test cleanup handles exceptions gracefully."""
        mock_iso_path = Mock()
        mock_iso_path.exists.return_value = True
        mock_iso_path.stat.return_value = Mock(st_size=1024)
        mock_iso_path.unlink.side_effect = PermissionError("Cannot delete")

        mock_cidata_path = Mock()
        mock_cidata_path.exists.return_value = True
        mock_cidata_path.unlink.side_effect = OSError("File busy")

        mock_httpd_path = Mock()
        mock_httpd_path.exists.return_value = True
        mock_rmtree.side_effect = Exception("Cannot remove directory")

        mock_path_class.side_effect = [
            mock_iso_path,
            mock_cidata_path,
            mock_httpd_path,
        ]

        # Should not raise, just log warnings
        cleanup_installation_artifacts(
            "/var/vmm/iso/ubuntu-serial.iso", "test-ubuntu", self.mock_logger
        )

        # Verify warnings were logged
        assert self.mock_logger.warning.call_count == 3


class TestPrepareVmEnvironment:
    """Test cases for VM environment preparation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_github = Mock()
        self.creator = UbuntuVmCreator(
            Mock(), self.mock_logger, self.mock_virt_checks, self.mock_github, Mock()
        )
        self.creator.launcher = Mock()
        self.creator.launcher.send_progress = AsyncMock()

    @pytest.mark.asyncio
    async def test_prepare_environment_success(self):
        """Test successful environment preparation."""
        module_path = "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator"
        with patch(
            f"{module_path}.extract_ubuntu_version"
        ) as mock_extract_version, patch(
            f"{module_path}.get_fqdn_hostname"
        ) as mock_get_fqdn, patch(
            f"{module_path}.vm_exists"
        ) as mock_vm_exists, patch(
            f"{module_path}.ensure_vmm_directories"
        ), patch(
            f"{module_path}.get_host_dns_server"
        ) as mock_get_dns, patch.object(
            UbuntuVmCreator, "_check_vmm_ready"
        ) as mock_check_vmm, patch.object(
            UbuntuVmCreator, "_get_agent_version"
        ) as mock_get_agent, patch(
            f"{module_path}.get_gateway_ip"
        ) as mock_get_gateway, patch(
            f"{module_path}.get_next_vm_ip"
        ) as mock_get_vm_ip:

            mock_extract_version.return_value = "24.04"
            mock_get_fqdn.return_value = "test-ubuntu.example.com"
            mock_check_vmm.return_value = {"success": True}
            mock_vm_exists.return_value = False
            mock_get_agent.return_value = ("1.0.0", "v1.0.0")
            mock_get_gateway.return_value = "192.168.100.1"
            mock_get_dns.return_value = "8.8.8.8"
            mock_get_vm_ip.return_value = "192.168.100.100"

            config = create_valid_config()
            result = await self.creator._prepare_vm_environment(config)

            assert result["success"] is True
            assert result["ubuntu_version"] == "24.04"
            assert result["fqdn_hostname"] == "test-ubuntu.example.com"
            assert result["agent_version"] == "1.0.0"
            assert result["gateway_ip"] == "192.168.100.1"
            assert result["dns_server"] == "8.8.8.8"
            assert result["vm_ip"] == "192.168.100.100"

    @pytest.mark.asyncio
    async def test_prepare_environment_invalid_config(self):
        """Test environment prep fails with invalid config."""
        config = create_valid_config({"distribution": ""})
        result = await self.creator._prepare_vm_environment(config)

        assert result["success"] is False
        assert "Distribution" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.extract_ubuntu_version"
    )
    async def test_prepare_environment_invalid_version(self, mock_extract_version):
        """Test environment prep fails with invalid Ubuntu version."""
        mock_extract_version.return_value = None

        config = create_valid_config()
        result = await self.creator._prepare_vm_environment(config)

        assert result["success"] is False
        assert "Could not parse Ubuntu version" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.extract_ubuntu_version"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_fqdn_hostname"
    )
    @patch.object(UbuntuVmCreator, "_check_vmm_ready")
    async def test_prepare_environment_vmm_not_ready(
        self, mock_check_vmm, mock_get_fqdn, mock_extract_version
    ):
        """Test environment prep fails when VMM not ready."""
        mock_extract_version.return_value = "24.04"
        mock_get_fqdn.return_value = "test.example.com"
        mock_check_vmm.return_value = {
            "success": False,
            "error": "VMM is not available",
        }

        config = create_valid_config()
        result = await self.creator._prepare_vm_environment(config)

        assert result["success"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.extract_ubuntu_version"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_fqdn_hostname"
    )
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.vm_exists")
    @patch.object(UbuntuVmCreator, "_check_vmm_ready")
    async def test_prepare_environment_vm_exists(
        self, mock_check_vmm, mock_vm_exists, mock_get_fqdn, mock_extract_version
    ):
        """Test environment prep fails when VM already exists."""
        mock_extract_version.return_value = "24.04"
        mock_get_fqdn.return_value = "test.example.com"
        mock_check_vmm.return_value = {"success": True}
        mock_vm_exists.return_value = True

        config = create_valid_config()
        result = await self.creator._prepare_vm_environment(config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.extract_ubuntu_version"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_fqdn_hostname"
    )
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.ensure_vmm_directories"
    )
    @patch.object(UbuntuVmCreator, "_check_vmm_ready")
    @patch.object(UbuntuVmCreator, "_get_agent_version")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_gateway_ip")
    async def test_prepare_environment_no_gateway(
        self,
        mock_get_gateway,
        mock_get_agent,
        mock_check_vmm,
        _mock_ensure_dirs,
        mock_vm_exists,
        mock_get_fqdn,
        mock_extract_version,
    ):
        """Test environment prep fails without gateway IP."""
        mock_extract_version.return_value = "24.04"
        mock_get_fqdn.return_value = "test.example.com"
        mock_check_vmm.return_value = {"success": True}
        mock_vm_exists.return_value = False
        mock_get_agent.return_value = ("1.0.0", "v1.0.0")
        mock_get_gateway.return_value = None

        config = create_valid_config()
        result = await self.creator._prepare_vm_environment(config)

        assert result["success"] is False
        assert "gateway" in result["error"].lower()

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.extract_ubuntu_version"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_fqdn_hostname"
    )
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.ensure_vmm_directories"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_host_dns_server"
    )
    @patch.object(UbuntuVmCreator, "_check_vmm_ready")
    @patch.object(UbuntuVmCreator, "_get_agent_version")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.get_gateway_ip")
    async def test_prepare_environment_no_dns(
        self,
        mock_get_gateway,
        mock_get_agent,
        mock_check_vmm,
        mock_get_dns,
        _mock_ensure_dirs,
        mock_vm_exists,
        mock_get_fqdn,
        mock_extract_version,
    ):
        """Test environment prep fails without DNS server."""
        mock_extract_version.return_value = "24.04"
        mock_get_fqdn.return_value = "test.example.com"
        mock_check_vmm.return_value = {"success": True}
        mock_vm_exists.return_value = False
        mock_get_agent.return_value = ("1.0.0", "v1.0.0")
        mock_get_gateway.return_value = "192.168.100.1"
        mock_get_dns.return_value = None

        config = create_valid_config()
        result = await self.creator._prepare_vm_environment(config)

        assert result["success"] is False
        assert "DNS" in result["error"]


class TestPrepareInstallationResources:
    """Test cases for installation resource preparation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = UbuntuVmCreator(Mock(), self.mock_logger, Mock(), Mock(), Mock())
        self.creator.launcher = Mock()
        self.creator.launcher.send_progress = AsyncMock()
        self.creator.disk_ops = Mock()
        self.creator.autoinstall_setup = Mock()

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.to_thread"
    )
    async def test_prepare_resources_success(self, mock_to_thread):
        """Test successful resource preparation."""
        # Mock ISO download
        mock_to_thread.side_effect = [
            {"success": True, "iso_path": "/var/vmm/iso/ubuntu.iso"},  # download
            {"success": True, "iso_path": "/var/vmm/iso/ubuntu-serial.iso"},  # serial
            {
                "success": True,
                "cidata_iso_path": "/var/vmm/cidata/cidata.iso",
            },  # cidata
        ]

        self.creator.disk_ops.create_disk_image.return_value = {"success": True}
        self.creator.autoinstall_setup.generate_enhanced_autoinstall.return_value = {
            "success": True,
            "autoinstall": "autoinstall content",
        }
        self.creator.autoinstall_setup.create_ubuntu_data_dir.return_value = {
            "success": True,
            "data_dir": "/var/vmm/ubuntu-data/test",
        }

        config = create_valid_config()
        result = await self.creator._prepare_installation_resources(
            config,
            "24.04",
            "test.example.com",
            "192.168.100.1",
            "192.168.100.100",
            "8.8.8.8",
        )

        assert result["success"] is True
        assert result["disk_path"] == "/var/vmm/test-ubuntu-vm.qcow2"
        assert result["serial_iso_path"] == "/var/vmm/iso/ubuntu-serial.iso"
        assert result["cidata_iso_path"] == "/var/vmm/cidata/cidata.iso"

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.to_thread"
    )
    async def test_prepare_resources_iso_download_fails(self, mock_to_thread):
        """Test resource prep fails when ISO download fails."""
        mock_to_thread.return_value = {
            "success": False,
            "error": "Download failed - 404",
        }

        config = create_valid_config()
        result = await self.creator._prepare_installation_resources(
            config,
            "24.04",
            "test.example.com",
            "192.168.100.1",
            "192.168.100.100",
            "8.8.8.8",
        )

        assert result["success"] is False
        assert "Failed to download Ubuntu ISO" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.to_thread"
    )
    async def test_prepare_resources_disk_creation_fails(self, mock_to_thread):
        """Test resource prep fails when disk creation fails."""
        mock_to_thread.return_value = {
            "success": True,
            "iso_path": "/var/vmm/iso/ubuntu.iso",
        }
        self.creator.disk_ops.create_disk_image.return_value = {
            "success": False,
            "error": "Not enough space",
        }

        config = create_valid_config()
        result = await self.creator._prepare_installation_resources(
            config,
            "24.04",
            "test.example.com",
            "192.168.100.1",
            "192.168.100.100",
            "8.8.8.8",
        )

        assert result["success"] is False
        assert "Failed to create disk" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.to_thread"
    )
    async def test_prepare_resources_autoinstall_fails(self, mock_to_thread):
        """Test resource prep fails when autoinstall generation fails."""
        mock_to_thread.return_value = {
            "success": True,
            "iso_path": "/var/vmm/iso/ubuntu.iso",
        }
        self.creator.disk_ops.create_disk_image.return_value = {"success": True}
        self.creator.autoinstall_setup.generate_enhanced_autoinstall.return_value = {
            "success": False,
            "error": "Invalid config",
        }

        config = create_valid_config()
        result = await self.creator._prepare_installation_resources(
            config,
            "24.04",
            "test.example.com",
            "192.168.100.1",
            "192.168.100.100",
            "8.8.8.8",
        )

        assert result["success"] is False


class TestRunInstallation:
    """Test cases for running VM installation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_agent = Mock()
        self.creator = UbuntuVmCreator(
            self.mock_agent, self.mock_logger, Mock(), Mock(), Mock()
        )
        self.creator.launcher = Mock()
        self.creator.launcher.send_progress = AsyncMock()
        self.creator.launcher.launch_vm_from_disk = AsyncMock()

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_launch_vm_from_iso")
    @patch.object(UbuntuVmCreator, "_wait_for_installation_complete")
    @patch.object(UbuntuVmCreator, "_stop_vm_for_restart")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.sleep")
    async def test_run_installation_success(
        self, _mock_sleep, mock_stop, mock_wait, mock_launch
    ):
        """Test successful installation run."""
        mock_launch.return_value = {"success": True}
        mock_wait.return_value = {"success": True}
        mock_stop.return_value = {"success": True}
        self.creator.launcher.launch_vm_from_disk.return_value = {"success": True}

        config = create_valid_config()
        result = await self.creator._run_installation(
            config,
            "/var/vmm/test.qcow2",
            "/var/vmm/iso/ubuntu-serial.iso",
            "/var/vmm/cidata/cidata.iso",
        )

        assert result["success"] is True
        assert result["memory"] == "2G"

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_launch_vm_from_iso")
    async def test_run_installation_launch_fails(self, mock_launch):
        """Test installation fails when launch fails."""
        mock_launch.return_value = {
            "success": False,
            "error": "Failed to start VM",
        }

        config = create_valid_config()
        result = await self.creator._run_installation(
            config,
            "/var/vmm/test.qcow2",
            "/var/vmm/iso/ubuntu-serial.iso",
            "/var/vmm/cidata/cidata.iso",
        )

        assert result["success"] is False
        assert "Failed to start VM" in result["error"]

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_launch_vm_from_iso")
    @patch.object(UbuntuVmCreator, "_wait_for_installation_complete")
    async def test_run_installation_crash_detected(self, mock_wait, mock_launch):
        """Test installation fails when VM crashes."""
        mock_launch.return_value = {"success": True}
        mock_wait.return_value = {
            "success": False,
            "error": "VM crashed during boot",
        }

        config = create_valid_config()
        result = await self.creator._run_installation(
            config,
            "/var/vmm/test.qcow2",
            "/var/vmm/iso/ubuntu-serial.iso",
            "/var/vmm/cidata/cidata.iso",
        )

        assert result["success"] is False
        assert "crashed" in result["error"].lower()

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_launch_vm_from_iso")
    @patch.object(UbuntuVmCreator, "_wait_for_installation_complete")
    @patch.object(UbuntuVmCreator, "_stop_vm_for_restart")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.sleep")
    async def test_run_installation_restart_fails(
        self, _mock_sleep, mock_stop, mock_wait, mock_launch
    ):
        """Test installation fails when restart from disk fails."""
        mock_launch.return_value = {"success": True}
        mock_wait.return_value = {"success": True}
        mock_stop.return_value = {"success": True}
        self.creator.launcher.launch_vm_from_disk.return_value = {
            "success": False,
            "error": "Failed to boot from disk",
        }

        config = create_valid_config()
        result = await self.creator._run_installation(
            config,
            "/var/vmm/test.qcow2",
            "/var/vmm/iso/ubuntu-serial.iso",
            "/var/vmm/cidata/cidata.iso",
        )

        assert result["success"] is False
        assert "Failed to boot from disk" in result["error"]

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_launch_vm_from_iso")
    @patch.object(UbuntuVmCreator, "_wait_for_installation_complete")
    @patch.object(UbuntuVmCreator, "_stop_vm_for_restart")
    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.asyncio.sleep")
    async def test_run_installation_memory_override(
        self, _mock_sleep, mock_stop, mock_wait, mock_launch
    ):
        """Test memory is overridden to minimum 2G for Ubuntu."""
        mock_launch.return_value = {"success": True}
        mock_wait.return_value = {"success": True}
        mock_stop.return_value = {"success": True}
        self.creator.launcher.launch_vm_from_disk.return_value = {"success": True}

        # Create config with insufficient memory
        config = create_valid_config({"memory": "512M"})
        result = await self.creator._run_installation(
            config,
            "/var/vmm/test.qcow2",
            "/var/vmm/iso/ubuntu-serial.iso",
            "/var/vmm/cidata/cidata.iso",
        )

        assert result["success"] is True
        assert result["memory"] == "2G"  # Should be overridden


class TestCreateUbuntuVm:
    """Test cases for the main create_ubuntu_vm method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_agent = Mock()
        self.creator = UbuntuVmCreator(
            self.mock_agent, self.mock_logger, Mock(), Mock(), Mock()
        )
        self.creator.launcher = Mock()
        self.creator.launcher.send_progress = AsyncMock()
        self.creator.vmconf_manager = Mock()

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_prepare_vm_environment")
    @patch.object(UbuntuVmCreator, "_prepare_installation_resources")
    @patch.object(UbuntuVmCreator, "_run_installation")
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.save_vm_metadata"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.cleanup_installation_artifacts"
    )
    async def test_create_ubuntu_vm_success(
        self,
        mock_cleanup,
        mock_save_meta,
        mock_run_install,
        mock_prep_resources,
        mock_prep_env,
    ):
        """Test successful Ubuntu VM creation."""
        mock_prep_env.return_value = {
            "success": True,
            "ubuntu_version": "24.04",
            "fqdn_hostname": "test.example.com",
            "agent_version": "1.0.0",
            "gateway_ip": "192.168.100.1",
            "dns_server": "8.8.8.8",
            "vm_ip": "192.168.100.100",
        }
        mock_prep_resources.return_value = {
            "success": True,
            "disk_path": "/var/vmm/test.qcow2",
            "serial_iso_path": "/var/vmm/iso/serial.iso",
            "cidata_iso_path": "/var/vmm/cidata/cidata.iso",
        }
        mock_run_install.return_value = {
            "success": True,
            "memory": "2G",
        }
        self.creator.vmconf_manager.persist_vm.return_value = True

        config = create_valid_config()
        result = await self.creator.create_ubuntu_vm(config)

        assert result["success"] is True
        assert result["child_name"] == "test-ubuntu-vm"
        assert result["child_type"] == "vmm"
        assert result["ubuntu_version"] == "24.04"
        mock_cleanup.assert_called_once()
        mock_save_meta.assert_called_once()

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_prepare_vm_environment")
    async def test_create_ubuntu_vm_env_prep_fails(self, mock_prep_env):
        """Test VM creation fails when environment prep fails."""
        mock_prep_env.return_value = {
            "success": False,
            "error": "VMM not available",
        }

        config = create_valid_config()
        result = await self.creator.create_ubuntu_vm(config)

        assert result["success"] is False
        assert "VMM not available" in result["error"]

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_prepare_vm_environment")
    @patch.object(UbuntuVmCreator, "_prepare_installation_resources")
    async def test_create_ubuntu_vm_resources_prep_fails(
        self, mock_prep_resources, mock_prep_env
    ):
        """Test VM creation fails when resource prep fails."""
        mock_prep_env.return_value = {
            "success": True,
            "ubuntu_version": "24.04",
            "fqdn_hostname": "test.example.com",
            "agent_version": "1.0.0",
            "gateway_ip": "192.168.100.1",
            "dns_server": "8.8.8.8",
            "vm_ip": "192.168.100.100",
        }
        mock_prep_resources.return_value = {
            "success": False,
            "error": "ISO download failed",
        }

        config = create_valid_config()
        result = await self.creator.create_ubuntu_vm(config)

        assert result["success"] is False
        assert "ISO download failed" in result["error"]

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_prepare_vm_environment")
    @patch.object(UbuntuVmCreator, "_prepare_installation_resources")
    @patch.object(UbuntuVmCreator, "_run_installation")
    async def test_create_ubuntu_vm_installation_fails(
        self, mock_run_install, mock_prep_resources, mock_prep_env
    ):
        """Test VM creation fails when installation fails."""
        mock_prep_env.return_value = {
            "success": True,
            "ubuntu_version": "24.04",
            "fqdn_hostname": "test.example.com",
            "agent_version": "1.0.0",
            "gateway_ip": "192.168.100.1",
            "dns_server": "8.8.8.8",
            "vm_ip": "192.168.100.100",
        }
        mock_prep_resources.return_value = {
            "success": True,
            "disk_path": "/var/vmm/test.qcow2",
            "serial_iso_path": "/var/vmm/iso/serial.iso",
            "cidata_iso_path": "/var/vmm/cidata/cidata.iso",
        }
        mock_run_install.return_value = {
            "success": False,
            "error": "Installation timeout",
        }

        config = create_valid_config()
        result = await self.creator.create_ubuntu_vm(config)

        assert result["success"] is False
        assert "Installation timeout" in result["error"]

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_prepare_vm_environment")
    async def test_create_ubuntu_vm_exception(self, mock_prep_env):
        """Test VM creation handles exceptions."""
        mock_prep_env.side_effect = Exception("Unexpected error")

        config = create_valid_config()
        result = await self.creator.create_ubuntu_vm(config)

        assert result["success"] is False
        assert "Unexpected error" in result["error"]
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    @patch.object(UbuntuVmCreator, "_prepare_vm_environment")
    @patch.object(UbuntuVmCreator, "_prepare_installation_resources")
    @patch.object(UbuntuVmCreator, "_run_installation")
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.save_vm_metadata"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_ubuntu_vm_creator.cleanup_installation_artifacts"
    )
    async def test_create_ubuntu_vm_persist_fails(
        self,
        _mock_cleanup,
        _mock_save_meta,
        mock_run_install,
        mock_prep_resources,
        mock_prep_env,
    ):
        """Test VM creation succeeds even if persist to vm.conf fails."""
        mock_prep_env.return_value = {
            "success": True,
            "ubuntu_version": "24.04",
            "fqdn_hostname": "test.example.com",
            "agent_version": "1.0.0",
            "gateway_ip": "192.168.100.1",
            "dns_server": "8.8.8.8",
            "vm_ip": "192.168.100.100",
        }
        mock_prep_resources.return_value = {
            "success": True,
            "disk_path": "/var/vmm/test.qcow2",
            "serial_iso_path": "/var/vmm/iso/serial.iso",
            "cidata_iso_path": "/var/vmm/cidata/cidata.iso",
        }
        mock_run_install.return_value = {
            "success": True,
            "memory": "2G",
        }
        self.creator.vmconf_manager.persist_vm.return_value = False  # Persist fails

        config = create_valid_config()
        result = await self.creator.create_ubuntu_vm(config)

        # Should still succeed, just with warning
        assert result["success"] is True
        self.mock_logger.warning.assert_called()


class TestEdgeCases:
    """Edge case tests for UbuntuVmCreator."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_parse_memory_unusual_values(self):
        """Test parsing unusual memory values."""
        # Very large value
        assert parse_memory_gb("64G") == 64.0

        # Decimal values
        assert parse_memory_gb("1.5G") == 1.5

        # Mixed case
        assert parse_memory_gb("2g") == 2.0
        assert parse_memory_gb("1024m") == 1.0

    def test_validate_config_all_missing(self):
        """Test validation with completely empty config."""
        # Create minimal invalid config
        config = VmmVmConfig(
            distribution="",
            vm_name="",
            hostname="",
            username="",
            password_hash="",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url=""),
        )

        result = validate_vm_config(config)

        assert result["success"] is False
        # Should fail on first missing field (distribution)
        assert "Distribution" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.subprocess.run")
    def test_get_gateway_ip_multiple_interfaces(self, mock_run):
        """Test gateway IP extraction with multiple IPs."""
        mock_run.return_value = Mock(
            stdout="vether0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n"
            "        lladdr fe:e1:ba:d8:12:34\n"
            "        inet 192.168.100.1 netmask 0xffffff00 broadcast 192.168.100.255\n"
            "        inet6 fe80::1%vether0 prefixlen 64 scopeid 0x4\n"
        )

        result = get_gateway_ip(self.mock_logger)

        # Should return first inet address
        assert result == "192.168.100.1"

    @patch("src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers.subprocess.run")
    def test_get_disk_size_large_disk(self, mock_run):
        """Test disk size retrieval for large disk."""
        # 100GB in KB
        mock_run.return_value = Mock(
            returncode=0,
            stdout="104857600\t/var/vmm/large.qcow2\n",
        )

        result = get_disk_size("/var/vmm/large.qcow2", self.mock_logger)

        assert result == 104857600 * 1024  # 100GB in bytes
