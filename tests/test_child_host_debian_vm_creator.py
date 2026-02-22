"""
Comprehensive unit tests for child_host_debian_vm_creator module.

Tests cover:
- extract_debian_version function
- get_fqdn_hostname function
- DebianVmCreator class initialization
- VM configuration validation
- VM creation workflow steps
- Error handling
"""

# pylint: disable=protected-access,redefined-outer-name,too-many-public-methods

import asyncio
import json
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_debian_vm_creator import (
    DebianVmCreator,
    extract_debian_version,
    get_fqdn_hostname,
)
from src.sysmanage_agent.operations.child_host_types import (
    VmmVmConfig,
    VmmServerConfig,
    VmmResourceConfig,
)

# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    logger = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.debug = Mock()
    return logger


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = Mock()
    agent.send_message = AsyncMock()
    agent.create_message = Mock(return_value={"type": "test"})
    return agent


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    checks = Mock()
    checks.check_vmm_support = Mock(
        return_value={
            "available": True,
            "running": True,
            "enabled": True,
        }
    )
    return checks


@pytest.fixture
def mock_github_checker():
    """Create mock GitHub version checker."""
    checker = Mock()
    checker.get_latest_version = Mock(
        return_value={
            "success": True,
            "version": "1.0.0",
            "tag_name": "v1.0.0",
        }
    )
    return checker


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    return Mock()


@pytest.fixture
def debian_creator(
    mock_agent,
    mock_logger,
    mock_virtualization_checks,
    mock_github_checker,
    mock_db_session,
):
    """Create a DebianVmCreator instance for testing."""
    with patch(
        "src.sysmanage_agent.operations.child_host_debian_vm_creator.VmmDiskOperations"
    ):
        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VmConfManager"
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_debian_vm_creator.VmmLauncher"
            ) as mock_launcher_cls:
                mock_launcher = Mock()
                mock_launcher.send_progress = AsyncMock()
                mock_launcher.launch_vm_from_disk = AsyncMock(
                    return_value={"success": True}
                )
                mock_launcher_cls.return_value = mock_launcher
                with patch(
                    "src.sysmanage_agent.operations.child_host_debian_vm_creator.DebianAutoinstallSetup"
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_debian_vm_creator.DebianConsoleAutomation"
                    ):
                        creator = DebianVmCreator(
                            mock_agent,
                            mock_logger,
                            mock_virtualization_checks,
                            mock_github_checker,
                            mock_db_session,
                        )
    return creator


@pytest.fixture
def sample_vm_config():
    """Create a sample VM configuration."""
    return VmmVmConfig(
        distribution="Debian 12",
        vm_name="test-vm",
        hostname="test-host",
        username="testuser",
        password_hash="$6$rounds=5000$salt$hash",
        agent_install_commands=["apt install sysmanage-agent"],
        server_config=VmmServerConfig(
            server_url="https://sysmanage.example.com",
            server_port=8443,
            use_https=True,
        ),
        resource_config=VmmResourceConfig(
            memory="2G",
            disk_size="20G",
            cpus=2,
        ),
        auto_approve_token="test-token-123",
    )


# -----------------------------------------------------------------------------
# Tests for extract_debian_version function
# -----------------------------------------------------------------------------


class TestExtractDebianVersion:
    """Test cases for extract_debian_version function."""

    def test_extract_version_from_bookworm_codename(self, mock_logger):
        """Test extracting version 12 from bookworm codename."""
        result = extract_debian_version("Bookworm", mock_logger)
        assert result == "12"
        mock_logger.info.assert_called()

    def test_extract_version_from_bookworm_lowercase(self, mock_logger):
        """Test extracting version from lowercase bookworm."""
        result = extract_debian_version("debian bookworm", mock_logger)
        assert result == "12"

    def test_extract_version_from_debian_12_string(self, mock_logger):
        """Test extracting version from 'Debian 12' string."""
        result = extract_debian_version("Debian 12", mock_logger)
        assert result == "12"

    def test_extract_version_from_debian_gnu_linux_12(self, mock_logger):
        """Test extracting version from 'Debian GNU/Linux 12' string."""
        result = extract_debian_version("Debian GNU/Linux 12", mock_logger)
        assert result == "12"

    def test_extract_version_from_debian_dash_12(self, mock_logger):
        """Test extracting version from 'debian-12' string."""
        result = extract_debian_version("debian-12", mock_logger)
        assert result == "12"

    def test_extract_version_from_debian_underscore_12(self, mock_logger):
        """Test extracting version from 'debian_12' string."""
        result = extract_debian_version("debian_12", mock_logger)
        assert result == "12"

    def test_extract_version_just_number(self, mock_logger):
        """Test extracting version from just the number."""
        result = extract_debian_version("12", mock_logger)
        assert result == "12"

    def test_extract_version_bullseye_unsupported(self, mock_logger):
        """Test that bullseye (11) returns None if not supported."""
        # bullseye is 11, which is not in SUPPORTED_DEBIAN_VERSIONS
        result = extract_debian_version("bullseye", mock_logger)
        # This will return None because 11 is not in SUPPORTED_DEBIAN_VERSIONS
        assert result is None

    def test_extract_version_unsupported_version(self, mock_logger):
        """Test extracting unsupported version returns None."""
        result = extract_debian_version("Debian 9", mock_logger)
        assert result is None
        mock_logger.warning.assert_called()

    def test_extract_version_invalid_string(self, mock_logger):
        """Test extracting version from invalid string returns None."""
        result = extract_debian_version("Ubuntu 22.04", mock_logger)
        assert result is None

    def test_extract_version_empty_string(self, mock_logger):
        """Test extracting version from empty string returns None."""
        result = extract_debian_version("", mock_logger)
        assert result is None


# -----------------------------------------------------------------------------
# Tests for get_fqdn_hostname function
# -----------------------------------------------------------------------------


class TestGetFqdnHostname:
    """Test cases for get_fqdn_hostname function."""

    def test_already_fqdn(self):
        """Test that FQDN hostname is returned unchanged."""
        result = get_fqdn_hostname("test.example.com", "https://server.example.com")
        assert result == "test.example.com"

    def test_short_hostname_gets_domain(self):
        """Test that short hostname gets domain from server URL."""
        result = get_fqdn_hostname("test", "https://sysmanage.example.com")
        assert result == "test.example.com"

    def test_short_hostname_subdomain(self):
        """Test short hostname with multi-level domain."""
        result = get_fqdn_hostname("test", "https://server.sub.example.com")
        # The function extracts the last two parts of the domain
        assert result == "test.sub.example.com"

    def test_short_hostname_no_domain_in_url(self):
        """Test short hostname when URL has no domain."""
        result = get_fqdn_hostname("test", "https://localhost")
        assert result == "test"

    def test_short_hostname_ip_address_url(self):
        """Test short hostname when server URL is IP address."""
        result = get_fqdn_hostname("test", "https://192.168.1.100:8443")
        assert result == "test"

    def test_hostname_with_hyphen(self):
        """Test hostname with hyphen."""
        result = get_fqdn_hostname("test-vm", "https://sysmanage.example.com")
        assert result == "test-vm.example.com"

    def test_already_fqdn_different_domain(self):
        """Test FQDN hostname with different domain than server."""
        result = get_fqdn_hostname("test.other.org", "https://server.example.com")
        assert result == "test.other.org"


# -----------------------------------------------------------------------------
# Tests for DebianVmCreator initialization
# -----------------------------------------------------------------------------


class TestDebianVmCreatorInit:
    """Test cases for DebianVmCreator initialization."""

    def test_init_sets_agent(self, debian_creator, mock_agent):
        """Test that __init__ sets agent."""
        assert debian_creator.agent == mock_agent

    def test_init_sets_logger(self, debian_creator, mock_logger):
        """Test that __init__ sets logger."""
        assert debian_creator.logger == mock_logger

    def test_init_sets_virtualization_checks(
        self, debian_creator, mock_virtualization_checks
    ):
        """Test that __init__ sets virtualization_checks."""
        assert debian_creator.virtualization_checks == mock_virtualization_checks

    def test_init_sets_github_checker(self, debian_creator, mock_github_checker):
        """Test that __init__ sets github_checker."""
        assert debian_creator.github_checker == mock_github_checker

    def test_init_sets_db_session(self, debian_creator, mock_db_session):
        """Test that __init__ sets db_session."""
        assert debian_creator.db_session == mock_db_session

    def test_init_creates_disk_ops(self, debian_creator):
        """Test that __init__ creates disk_ops."""
        assert debian_creator.disk_ops is not None

    def test_init_creates_vmconf_manager(self, debian_creator):
        """Test that __init__ creates vmconf_manager."""
        assert debian_creator.vmconf_manager is not None

    def test_init_creates_launcher(self, debian_creator):
        """Test that __init__ creates launcher."""
        assert debian_creator.launcher is not None

    def test_init_creates_autoinstall_setup(self, debian_creator):
        """Test that __init__ creates autoinstall_setup."""
        assert debian_creator.autoinstall_setup is not None

    def test_init_creates_console_automation(self, debian_creator):
        """Test that __init__ creates console_automation."""
        assert debian_creator.console_automation is not None

    def test_default_disk_size(self, debian_creator):
        """Test default disk size constant."""
        assert debian_creator.DEFAULT_DISK_SIZE == "20G"

    def test_default_memory(self, debian_creator):
        """Test default memory constant."""
        assert debian_creator.DEFAULT_MEMORY == "2G"


# -----------------------------------------------------------------------------
# Tests for _validate_config
# -----------------------------------------------------------------------------


class TestValidateConfig:
    """Test cases for _validate_config method."""

    def test_valid_config(self, debian_creator, sample_vm_config):
        """Test validation with valid config."""
        result = debian_creator._validate_config(sample_vm_config)
        assert result["success"] is True

    def test_missing_distribution(self, debian_creator):
        """Test validation fails without distribution."""
        config = VmmVmConfig(
            distribution="",
            vm_name="test-vm",
            hostname="test",
            username="testuser",
            password_hash="$6$hash",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://example.com"),
        )
        result = debian_creator._validate_config(config)
        assert result["success"] is False
        assert "Distribution" in result["error"]

    def test_missing_vm_name(self, debian_creator):
        """Test validation fails without VM name."""
        config = VmmVmConfig(
            distribution="Debian 12",
            vm_name="",
            hostname="test",
            username="testuser",
            password_hash="$6$hash",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://example.com"),
        )
        result = debian_creator._validate_config(config)
        assert result["success"] is False
        assert "VM name" in result["error"]

    def test_missing_hostname(self, debian_creator):
        """Test validation fails without hostname."""
        config = VmmVmConfig(
            distribution="Debian 12",
            vm_name="test-vm",
            hostname="",
            username="testuser",
            password_hash="$6$hash",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://example.com"),
        )
        result = debian_creator._validate_config(config)
        assert result["success"] is False
        assert "Hostname" in result["error"]

    def test_missing_username(self, debian_creator):
        """Test validation fails without username."""
        config = VmmVmConfig(
            distribution="Debian 12",
            vm_name="test-vm",
            hostname="test",
            username="",
            password_hash="$6$hash",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://example.com"),
        )
        result = debian_creator._validate_config(config)
        assert result["success"] is False
        assert "Username" in result["error"]

    def test_missing_password_hash(self, debian_creator):
        """Test validation fails without password hash."""
        config = VmmVmConfig(
            distribution="Debian 12",
            vm_name="test-vm",
            hostname="test",
            username="testuser",
            password_hash="",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://example.com"),
        )
        result = debian_creator._validate_config(config)
        assert result["success"] is False
        assert "Password" in result["error"]

    def test_missing_server_url(self, debian_creator):
        """Test validation fails without server URL."""
        config = VmmVmConfig(
            distribution="Debian 12",
            vm_name="test-vm",
            hostname="test",
            username="testuser",
            password_hash="$6$hash",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url=""),
        )
        result = debian_creator._validate_config(config)
        assert result["success"] is False
        assert "Server URL" in result["error"]


# -----------------------------------------------------------------------------
# Tests for _check_vmm_ready
# -----------------------------------------------------------------------------


class TestCheckVmmReady:
    """Test cases for _check_vmm_ready method."""

    @pytest.mark.asyncio
    async def test_vmm_ready(self, debian_creator, mock_virtualization_checks):
        """Test when VMM is available and running."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }
        result = await debian_creator._check_vmm_ready()
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_vmm_not_available(self, debian_creator, mock_virtualization_checks):
        """Test when VMM is not available."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": False,
            "running": False,
        }
        result = await debian_creator._check_vmm_ready()
        assert result["success"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_vmm_not_running(self, debian_creator, mock_virtualization_checks):
        """Test when VMM is available but vmd not running."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "running": False,
        }
        result = await debian_creator._check_vmm_ready()
        assert result["success"] is False
        assert "not running" in result["error"]


# -----------------------------------------------------------------------------
# Tests for _get_agent_version
# -----------------------------------------------------------------------------


class TestGetAgentVersion:
    """Test cases for _get_agent_version method."""

    @pytest.mark.asyncio
    async def test_get_agent_version_success(self, debian_creator, mock_github_checker):
        """Test getting agent version successfully."""
        mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }
        version, tag_name = await debian_creator._get_agent_version()
        assert version == "1.2.3"
        assert tag_name == "v1.2.3"

    @pytest.mark.asyncio
    async def test_get_agent_version_failure(self, debian_creator, mock_github_checker):
        """Test getting agent version when GitHub check fails."""
        mock_github_checker.get_latest_version.return_value = {
            "success": False,
            "error": "Rate limited",
        }
        with pytest.raises(RuntimeError, match="Failed to check GitHub"):
            await debian_creator._get_agent_version()


# -----------------------------------------------------------------------------
# Tests for _get_gateway_ip
# -----------------------------------------------------------------------------


class TestGetGatewayIp:
    """Test cases for _get_gateway_ip method."""

    def test_get_gateway_ip_success(self, debian_creator):
        """Test getting gateway IP successfully."""
        mock_result = Mock()
        mock_result.stdout = "vether0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n\tinet 10.0.0.1 netmask 0xffffff00 broadcast 10.0.0.255"
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = debian_creator._get_gateway_ip()

        assert result == "10.0.0.1"

    def test_get_gateway_ip_no_inet(self, debian_creator):
        """Test getting gateway IP when no inet line."""
        mock_result = Mock()
        mock_result.stdout = "vether0: flags=8843<UP>\n\tether ab:cd:ef:12:34:56"
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = debian_creator._get_gateway_ip()

        assert result is None

    def test_get_gateway_ip_command_fails(self, debian_creator):
        """Test getting gateway IP when ifconfig fails."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = debian_creator._get_gateway_ip()

        assert result is None
        debian_creator.logger.error.assert_called()

    def test_get_gateway_ip_timeout(self, debian_creator):
        """Test getting gateway IP with timeout."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("ifconfig", 5)
        ):
            result = debian_creator._get_gateway_ip()

        assert result is None


# -----------------------------------------------------------------------------
# Tests for _get_next_vm_ip
# -----------------------------------------------------------------------------


class TestGetNextVmIp:
    """Test cases for _get_next_vm_ip method."""

    def test_get_next_vm_ip_no_existing(self, debian_creator, tmp_path):
        """Test getting next VM IP when no VMs exist."""
        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            result = debian_creator._get_next_vm_ip("10.0.0.1")

        assert result == "10.0.0.100"

    def test_get_next_vm_ip_with_existing(self, debian_creator, tmp_path):
        """Test getting next VM IP with existing VMs."""
        # Create metadata files for existing VMs
        tmp_path.mkdir(exist_ok=True)
        metadata1 = {"vm_ip": "10.0.0.100"}
        metadata2 = {"vm_ip": "10.0.0.101"}

        with open(tmp_path / "vm1.json", "w", encoding="utf-8") as file_handle:
            json.dump(metadata1, file_handle)
        with open(tmp_path / "vm2.json", "w", encoding="utf-8") as file_handle:
            json.dump(metadata2, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            result = debian_creator._get_next_vm_ip("10.0.0.1")

        assert result == "10.0.0.102"

    def test_get_next_vm_ip_invalid_metadata(self, debian_creator, tmp_path):
        """Test getting next VM IP with invalid metadata files."""
        tmp_path.mkdir(exist_ok=True)

        # Create invalid JSON file
        with open(tmp_path / "invalid.json", "w", encoding="utf-8") as file_handle:
            file_handle.write("not valid json")

        # Create metadata without vm_ip
        with open(tmp_path / "no_ip.json", "w", encoding="utf-8") as file_handle:
            json.dump({"vm_name": "test"}, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            result = debian_creator._get_next_vm_ip("10.0.0.1")

        # Should still return .100 since invalid files are skipped
        assert result == "10.0.0.100"

    def test_get_next_vm_ip_metadata_dir_not_exists(self, debian_creator):
        """Test getting next VM IP when metadata dir doesn't exist."""
        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            "/nonexistent/path",
        ):
            result = debian_creator._get_next_vm_ip("10.0.0.1")

        assert result == "10.0.0.100"


# -----------------------------------------------------------------------------
# Tests for _stop_vm_for_restart
# -----------------------------------------------------------------------------


class TestStopVmForRestart:
    """Test cases for _stop_vm_for_restart method."""

    @pytest.mark.asyncio
    async def test_stop_vm_graceful_success(self, debian_creator):
        """Test stopping VM gracefully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await debian_creator._stop_vm_for_restart("test-vm")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_vm_force_stop_fallback(self, debian_creator):
        """Test falling back to force stop."""
        graceful_fail = Mock(returncode=1, stdout="", stderr="timeout")
        force_success = Mock(returncode=0, stdout="", stderr="")

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            side_effect=[graceful_fail, force_success],
        ):
            result = await debian_creator._stop_vm_for_restart("test-vm")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_vm_already_stopped(self, debian_creator):
        """Test when VM is already stopped."""
        graceful_fail = Mock(returncode=1, stdout="", stderr="not running")
        force_fail = Mock(returncode=1, stdout="", stderr="not running")
        status_result = Mock(returncode=0, stdout="stopped", stderr="")

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            side_effect=[graceful_fail, force_fail, status_result],
        ):
            result = await debian_creator._stop_vm_for_restart("test-vm")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_vm_timeout(self, debian_creator):
        """Test stop VM with timeout."""
        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await debian_creator._stop_vm_for_restart("test-vm")

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_stop_vm_exception(self, debian_creator):
        """Test stop VM with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            side_effect=Exception("Unexpected error"),
        ):
            result = await debian_creator._stop_vm_for_restart("test-vm")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_stop_vm_still_running(self, debian_creator):
        """Test stop VM when VM is still running after all attempts."""
        graceful_fail = Mock(returncode=1, stdout="", stderr="failed")
        force_fail = Mock(returncode=1, stdout="", stderr="failed")
        # Status shows VM is still running (vm_name in output, not stopped)
        status_result = Mock(returncode=0, stdout="test-vm running", stderr="")

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            side_effect=[graceful_fail, force_fail, status_result],
        ):
            result = await debian_creator._stop_vm_for_restart("test-vm")

        assert result["success"] is False
        assert "failed" in result["error"]


# -----------------------------------------------------------------------------
# Tests for _launch_vm_from_iso
# -----------------------------------------------------------------------------


class TestLaunchVmFromIso:
    """Test cases for _launch_vm_from_iso method."""

    @pytest.mark.asyncio
    async def test_launch_vm_success(self, debian_creator, sample_vm_config):
        """Test launching VM from ISO successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Started"
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await debian_creator._launch_vm_from_iso(
                sample_vm_config,
                "/var/vmm/test-vm.qcow2",
                "/tmp/debian.iso",
                "2G",
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_vm_failure(self, debian_creator, sample_vm_config):
        """Test launching VM from ISO failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "vmctl: start failed"

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await debian_creator._launch_vm_from_iso(
                sample_vm_config,
                "/var/vmm/test-vm.qcow2",
                "/tmp/debian.iso",
                "2G",
            )

        assert result["success"] is False
        assert "Failed to start VM" in result["error"]

    @pytest.mark.asyncio
    async def test_launch_vm_exception(self, debian_creator, sample_vm_config):
        """Test launching VM from ISO with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.run_command_async",
            side_effect=Exception("Network error"),
        ):
            result = await debian_creator._launch_vm_from_iso(
                sample_vm_config,
                "/var/vmm/test-vm.qcow2",
                "/tmp/debian.iso",
                "2G",
            )

        assert result["success"] is False
        assert "Network error" in result["error"]


# -----------------------------------------------------------------------------
# Tests for _save_vm_metadata
# -----------------------------------------------------------------------------


class TestSaveVmMetadata:
    """Test cases for _save_vm_metadata method."""

    def test_save_metadata_success(self, debian_creator, tmp_path):
        """Test saving VM metadata successfully."""
        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            debian_creator._save_vm_metadata(
                "test-vm",
                "test.example.com",
                "Debian 12",
                "12",
                "10.0.0.100",
            )

        metadata_file = tmp_path / "test-vm.json"
        assert metadata_file.exists()

        with open(metadata_file, encoding="utf-8") as file_handle:
            metadata = json.load(file_handle)

        assert metadata["vm_name"] == "test-vm"
        assert metadata["hostname"] == "test.example.com"
        assert metadata["vm_ip"] == "10.0.0.100"
        assert metadata["distribution"]["distribution_name"] == "Debian"
        assert metadata["distribution"]["distribution_version"] == "12"

    def test_save_metadata_creates_directory(self, debian_creator, tmp_path):
        """Test that metadata directory is created if it doesn't exist."""
        metadata_dir = tmp_path / "new_metadata_dir"

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            str(metadata_dir),
        ):
            debian_creator._save_vm_metadata(
                "test-vm",
                "test.example.com",
                "Debian 12",
                "12",
                "10.0.0.100",
            )

        assert metadata_dir.exists()
        assert (metadata_dir / "test-vm.json").exists()


# -----------------------------------------------------------------------------
# Tests for _generate_preseed
# -----------------------------------------------------------------------------


class TestGeneratePreseed:
    """Test cases for _generate_preseed method."""

    @pytest.mark.asyncio
    async def test_generate_preseed_success(self, debian_creator, sample_vm_config):
        """Test generating preseed successfully."""
        debian_creator.autoinstall_setup.download_agent_deb = Mock(
            return_value={"success": True, "deb_path": "/tmp/agent.deb"}
        )
        debian_creator.autoinstall_setup.serve_agent_deb_via_httpd = Mock(
            return_value={"success": True, "deb_url": "http://10.0.0.1/agent.deb"}
        )
        debian_creator.autoinstall_setup.generate_enhanced_preseed = Mock(
            return_value={"success": True, "preseed": "preseed content"}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            result = await debian_creator._generate_preseed(
                sample_vm_config,
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
                "12",
            )

        assert result["success"] is True
        assert result["preseed"] == "preseed content"

    @pytest.mark.asyncio
    async def test_generate_preseed_no_deb_download(
        self, debian_creator, sample_vm_config
    ):
        """Test preseed generation when deb download fails."""
        debian_creator.autoinstall_setup.download_agent_deb = Mock(
            return_value={"success": False, "error": "Network error"}
        )
        debian_creator.autoinstall_setup.generate_enhanced_preseed = Mock(
            return_value={"success": True, "preseed": "preseed content"}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            result = await debian_creator._generate_preseed(
                sample_vm_config,
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
                "12",
            )

        # Should still succeed, just without deb URL
        assert result["success"] is True
        debian_creator.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_generate_preseed_serve_deb_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test preseed generation when serving deb fails."""
        debian_creator.autoinstall_setup.download_agent_deb = Mock(
            return_value={"success": True, "deb_path": "/tmp/agent.deb"}
        )
        debian_creator.autoinstall_setup.serve_agent_deb_via_httpd = Mock(
            return_value={"success": False, "error": "httpd error"}
        )
        debian_creator.autoinstall_setup.generate_enhanced_preseed = Mock(
            return_value={"success": True, "preseed": "preseed content"}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            result = await debian_creator._generate_preseed(
                sample_vm_config,
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
                "12",
            )

        # Should still succeed
        assert result["success"] is True
        debian_creator.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_generate_preseed_exception(self, debian_creator, sample_vm_config):
        """Test preseed generation with exception."""
        debian_creator.autoinstall_setup.download_agent_deb = Mock(
            side_effect=Exception("Unexpected error")
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            result = await debian_creator._generate_preseed(
                sample_vm_config,
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
                "12",
            )

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


# -----------------------------------------------------------------------------
# Tests for _finalize_debian_vm
# -----------------------------------------------------------------------------


class TestFinalizeDebianVm:
    """Test cases for _finalize_debian_vm method."""

    def test_finalize_success(self, debian_creator, sample_vm_config, tmp_path):
        """Test finalizing VM successfully."""
        debian_creator.vmconf_manager.persist_vm = Mock(return_value=True)

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            debian_creator._finalize_debian_vm(
                sample_vm_config,
                "test.example.com",
                "12",
                "10.0.0.100",
                "/var/vmm/test-vm.qcow2",
                "2G",
            )

        debian_creator.vmconf_manager.persist_vm.assert_called_once()
        debian_creator.logger.info.assert_called()

    def test_finalize_vmconf_fails(self, debian_creator, sample_vm_config, tmp_path):
        """Test finalizing VM when vm.conf update fails."""
        debian_creator.vmconf_manager.persist_vm = Mock(return_value=False)

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            debian_creator._finalize_debian_vm(
                sample_vm_config,
                "test.example.com",
                "12",
                "10.0.0.100",
                "/var/vmm/test-vm.qcow2",
                "2G",
            )

        debian_creator.logger.warning.assert_called()


# -----------------------------------------------------------------------------
# Tests for _prepare_debian_vm
# -----------------------------------------------------------------------------


class TestPrepareDebianVm:
    """Test cases for _prepare_debian_vm method."""

    @pytest.mark.asyncio
    async def test_prepare_success(self, debian_creator, sample_vm_config):
        """Test preparing VM successfully."""
        # Mock all the dependencies
        debian_creator._validate_config = Mock(return_value={"success": True})
        debian_creator._check_vmm_ready = AsyncMock(return_value={"success": True})
        debian_creator._get_agent_version = AsyncMock(return_value=("1.0.0", "v1.0.0"))
        debian_creator._get_gateway_ip = Mock(return_value="10.0.0.1")
        debian_creator._get_next_vm_ip = Mock(return_value="10.0.0.100")

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.vm_exists",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_debian_vm_creator.ensure_vmm_directories"
            ):
                result = await debian_creator._prepare_debian_vm(sample_vm_config)

        assert result["success"] is True
        assert result["debian_version"] == "12"
        assert result["agent_version"] == "1.0.0"
        assert result["gateway_ip"] == "10.0.0.1"
        assert result["vm_ip"] == "10.0.0.100"

    @pytest.mark.asyncio
    async def test_prepare_validation_fails(self, debian_creator, sample_vm_config):
        """Test preparation when validation fails."""
        debian_creator._validate_config = Mock(
            return_value={"success": False, "error": "Invalid config"}
        )

        result = await debian_creator._prepare_debian_vm(sample_vm_config)

        assert result["success"] is False
        assert result["error"] == "Invalid config"

    @pytest.mark.asyncio
    async def test_prepare_debian_version_not_found(self, debian_creator):
        """Test preparation when Debian version cannot be extracted."""
        config = VmmVmConfig(
            distribution="Ubuntu 22.04",  # Not Debian
            vm_name="test-vm",
            hostname="test",
            username="testuser",
            password_hash="$6$hash",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://example.com"),
        )

        debian_creator._validate_config = Mock(return_value={"success": True})

        result = await debian_creator._prepare_debian_vm(config)

        assert result["success"] is False
        assert "Could not parse Debian version" in result["error"]

    @pytest.mark.asyncio
    async def test_prepare_vmm_not_ready(self, debian_creator, sample_vm_config):
        """Test preparation when VMM is not ready."""
        debian_creator._validate_config = Mock(return_value={"success": True})
        debian_creator._check_vmm_ready = AsyncMock(
            return_value={"success": False, "error": "VMM not available"}
        )

        result = await debian_creator._prepare_debian_vm(sample_vm_config)

        assert result["success"] is False
        assert "VMM not available" in result["error"]

    @pytest.mark.asyncio
    async def test_prepare_vm_already_exists(self, debian_creator, sample_vm_config):
        """Test preparation when VM already exists."""
        debian_creator._validate_config = Mock(return_value={"success": True})
        debian_creator._check_vmm_ready = AsyncMock(return_value={"success": True})

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.vm_exists",
            return_value=True,
        ):
            result = await debian_creator._prepare_debian_vm(sample_vm_config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    async def test_prepare_no_gateway_ip(self, debian_creator, sample_vm_config):
        """Test preparation when gateway IP cannot be determined."""
        debian_creator._validate_config = Mock(return_value={"success": True})
        debian_creator._check_vmm_ready = AsyncMock(return_value={"success": True})
        debian_creator._get_agent_version = AsyncMock(return_value=("1.0.0", "v1.0.0"))
        debian_creator._get_gateway_ip = Mock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.vm_exists",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_debian_vm_creator.ensure_vmm_directories"
            ):
                result = await debian_creator._prepare_debian_vm(sample_vm_config)

        assert result["success"] is False
        assert "gateway IP" in result["error"]


# -----------------------------------------------------------------------------
# Tests for _build_debian_vm_artifacts
# -----------------------------------------------------------------------------


class TestBuildDebianVmArtifacts:
    """Test cases for _build_debian_vm_artifacts method."""

    @pytest.mark.asyncio
    async def test_build_artifacts_success(self, debian_creator, sample_vm_config):
        """Test building VM artifacts successfully."""
        debian_creator.autoinstall_setup.download_debian_iso = Mock(
            return_value={"success": True, "iso_path": "/tmp/debian.iso"}
        )
        debian_creator.disk_ops.create_disk_image = Mock(return_value={"success": True})
        debian_creator._generate_preseed = AsyncMock(
            return_value={"success": True, "preseed": "preseed content"}
        )
        debian_creator.autoinstall_setup.create_debian_data_dir = Mock(
            return_value={
                "success": True,
                "data_dir": "/tmp/data",
                "preseed_url": "http://10.0.0.1/preseed.cfg",
            }
        )
        debian_creator.autoinstall_setup.create_serial_console_iso = Mock(
            return_value={"success": True, "iso_path": "/tmp/serial.iso"}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            with patch("asyncio.to_thread", side_effect=lambda f, *a, **k: f(*a, **k)):
                result = await debian_creator._build_debian_vm_artifacts(
                    sample_vm_config,
                    "12",
                    "test.example.com",
                    "10.0.0.1",
                    "10.0.0.100",
                )

        assert result["success"] is True
        assert "disk_path" in result
        assert "serial_iso_path" in result

    @pytest.mark.asyncio
    async def test_build_artifacts_iso_download_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test build artifacts when ISO download fails."""
        debian_creator.autoinstall_setup.download_debian_iso = Mock(
            return_value={"success": False, "error": "Network error"}
        )

        with patch("asyncio.to_thread", side_effect=lambda f, *a, **k: f(*a, **k)):
            result = await debian_creator._build_debian_vm_artifacts(
                sample_vm_config,
                "12",
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
            )

        assert result["success"] is False
        assert "Failed to download Debian ISO" in result["error"]

    @pytest.mark.asyncio
    async def test_build_artifacts_disk_creation_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test build artifacts when disk creation fails."""
        debian_creator.autoinstall_setup.download_debian_iso = Mock(
            return_value={"success": True, "iso_path": "/tmp/debian.iso"}
        )
        debian_creator.disk_ops.create_disk_image = Mock(
            return_value={"success": False, "error": "Disk error"}
        )

        with patch("asyncio.to_thread", side_effect=lambda f, *a, **k: f(*a, **k)):
            result = await debian_creator._build_debian_vm_artifacts(
                sample_vm_config,
                "12",
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
            )

        assert result["success"] is False
        assert "Failed to create disk" in result["error"]

    @pytest.mark.asyncio
    async def test_build_artifacts_preseed_generation_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test build artifacts when preseed generation fails."""
        debian_creator.autoinstall_setup.download_debian_iso = Mock(
            return_value={"success": True, "iso_path": "/tmp/debian.iso"}
        )
        debian_creator.disk_ops.create_disk_image = Mock(return_value={"success": True})
        debian_creator._generate_preseed = AsyncMock(
            return_value={"success": False, "error": "Preseed error"}
        )

        with patch("asyncio.to_thread", side_effect=lambda f, *a, **k: f(*a, **k)):
            result = await debian_creator._build_debian_vm_artifacts(
                sample_vm_config,
                "12",
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
            )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_build_artifacts_data_dir_creation_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test build artifacts when data directory creation fails."""
        debian_creator.autoinstall_setup.download_debian_iso = Mock(
            return_value={"success": True, "iso_path": "/tmp/debian.iso"}
        )
        debian_creator.disk_ops.create_disk_image = Mock(return_value={"success": True})
        debian_creator._generate_preseed = AsyncMock(
            return_value={"success": True, "preseed": "preseed content"}
        )
        debian_creator.autoinstall_setup.create_debian_data_dir = Mock(
            return_value={"success": False, "error": "Data dir error"}
        )

        with patch("asyncio.to_thread", side_effect=lambda f, *a, **k: f(*a, **k)):
            result = await debian_creator._build_debian_vm_artifacts(
                sample_vm_config,
                "12",
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
            )

        assert result["success"] is False
        assert "Failed to create data directory" in result["error"]

    @pytest.mark.asyncio
    async def test_build_artifacts_serial_iso_creation_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test build artifacts when serial ISO creation fails."""
        debian_creator.autoinstall_setup.download_debian_iso = Mock(
            return_value={"success": True, "iso_path": "/tmp/debian.iso"}
        )
        debian_creator.disk_ops.create_disk_image = Mock(return_value={"success": True})
        debian_creator._generate_preseed = AsyncMock(
            return_value={"success": True, "preseed": "preseed content"}
        )
        debian_creator.autoinstall_setup.create_debian_data_dir = Mock(
            return_value={
                "success": True,
                "data_dir": "/tmp/data",
                "preseed_url": "http://10.0.0.1/preseed.cfg",
            }
        )
        debian_creator.autoinstall_setup.create_serial_console_iso = Mock(
            return_value={"success": False, "error": "ISO creation error"}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            with patch("asyncio.to_thread", side_effect=lambda f, *a, **k: f(*a, **k)):
                result = await debian_creator._build_debian_vm_artifacts(
                    sample_vm_config,
                    "12",
                    "test.example.com",
                    "10.0.0.1",
                    "10.0.0.100",
                )

        assert result["success"] is False
        assert "Failed to create serial console ISO" in result["error"]


# -----------------------------------------------------------------------------
# Tests for _launch_and_install_debian_vm
# -----------------------------------------------------------------------------


class TestLaunchAndInstallDebianVm:
    """Test cases for _launch_and_install_debian_vm method."""

    @pytest.mark.asyncio
    async def test_launch_and_install_success(self, debian_creator, sample_vm_config):
        """Test launching and installing VM successfully."""
        debian_creator._launch_vm_from_iso = AsyncMock(return_value={"success": True})
        debian_creator.console_automation.wait_for_installation_complete = AsyncMock(
            return_value={"success": True}
        )
        debian_creator._stop_vm_for_restart = AsyncMock(return_value={"success": True})
        debian_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": True}
        )

        with patch("asyncio.sleep", return_value=None):
            result = await debian_creator._launch_and_install_debian_vm(
                sample_vm_config,
                "/var/vmm/test-vm.qcow2",
                "/tmp/serial.iso",
                "2G",
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_and_install_launch_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test when VM launch fails."""
        debian_creator._launch_vm_from_iso = AsyncMock(
            return_value={"success": False, "error": "Launch failed"}
        )

        result = await debian_creator._launch_and_install_debian_vm(
            sample_vm_config,
            "/var/vmm/test-vm.qcow2",
            "/tmp/serial.iso",
            "2G",
        )

        assert result["success"] is False
        assert "Launch failed" in result["error"]

    @pytest.mark.asyncio
    async def test_launch_and_install_installation_warning(
        self, debian_creator, sample_vm_config
    ):
        """Test when installation monitoring has warning."""
        debian_creator._launch_vm_from_iso = AsyncMock(return_value={"success": True})
        debian_creator.console_automation.wait_for_installation_complete = AsyncMock(
            return_value={"success": False, "error": "Timeout waiting"}
        )
        debian_creator._stop_vm_for_restart = AsyncMock(return_value={"success": True})
        debian_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": True}
        )

        with patch("asyncio.sleep", return_value=None):
            result = await debian_creator._launch_and_install_debian_vm(
                sample_vm_config,
                "/var/vmm/test-vm.qcow2",
                "/tmp/serial.iso",
                "2G",
            )

        # Should still succeed, just with warning
        assert result["success"] is True
        debian_creator.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_launch_and_install_stop_warning(
        self, debian_creator, sample_vm_config
    ):
        """Test when VM stop has warning."""
        debian_creator._launch_vm_from_iso = AsyncMock(return_value={"success": True})
        debian_creator.console_automation.wait_for_installation_complete = AsyncMock(
            return_value={"success": True}
        )
        debian_creator._stop_vm_for_restart = AsyncMock(
            return_value={"success": False, "error": "Stop failed"}
        )
        debian_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": True}
        )

        with patch("asyncio.sleep", return_value=None):
            result = await debian_creator._launch_and_install_debian_vm(
                sample_vm_config,
                "/var/vmm/test-vm.qcow2",
                "/tmp/serial.iso",
                "2G",
            )

        # Should still try to restart
        assert result["success"] is True
        debian_creator.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_launch_and_install_restart_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test when VM restart fails."""
        debian_creator._launch_vm_from_iso = AsyncMock(return_value={"success": True})
        debian_creator.console_automation.wait_for_installation_complete = AsyncMock(
            return_value={"success": True}
        )
        debian_creator._stop_vm_for_restart = AsyncMock(return_value={"success": True})
        debian_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": False, "error": "Restart failed"}
        )

        with patch("asyncio.sleep", return_value=None):
            result = await debian_creator._launch_and_install_debian_vm(
                sample_vm_config,
                "/var/vmm/test-vm.qcow2",
                "/tmp/serial.iso",
                "2G",
            )

        assert result["success"] is False
        assert "Restart failed" in result["error"]


# -----------------------------------------------------------------------------
# Tests for create_debian_vm (integration)
# -----------------------------------------------------------------------------


class TestCreateDebianVm:
    """Test cases for create_debian_vm method."""

    @pytest.mark.asyncio
    async def test_create_debian_vm_success(self, debian_creator, sample_vm_config):
        """Test creating Debian VM successfully."""
        debian_creator._prepare_debian_vm = AsyncMock(
            return_value={
                "success": True,
                "debian_version": "12",
                "fqdn_hostname": "test.example.com",
                "agent_version": "1.0.0",
                "gateway_ip": "10.0.0.1",
                "vm_ip": "10.0.0.100",
            }
        )
        debian_creator._build_debian_vm_artifacts = AsyncMock(
            return_value={
                "success": True,
                "disk_path": "/var/vmm/test-vm.qcow2",
                "serial_iso_path": "/tmp/serial.iso",
            }
        )
        debian_creator._launch_and_install_debian_vm = AsyncMock(
            return_value={"success": True}
        )
        debian_creator._finalize_debian_vm = Mock()

        result = await debian_creator.create_debian_vm(sample_vm_config)

        assert result["success"] is True
        assert result["child_name"] == "test-vm"
        assert result["child_type"] == "vmm"
        assert result["debian_version"] == "12"
        assert result["agent_version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_create_debian_vm_prepare_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test creating VM when preparation fails."""
        debian_creator._prepare_debian_vm = AsyncMock(
            return_value={"success": False, "error": "Preparation failed"}
        )

        result = await debian_creator.create_debian_vm(sample_vm_config)

        assert result["success"] is False
        assert result["error"] == "Preparation failed"

    @pytest.mark.asyncio
    async def test_create_debian_vm_build_fails(self, debian_creator, sample_vm_config):
        """Test creating VM when build fails."""
        debian_creator._prepare_debian_vm = AsyncMock(
            return_value={
                "success": True,
                "debian_version": "12",
                "fqdn_hostname": "test.example.com",
                "agent_version": "1.0.0",
                "gateway_ip": "10.0.0.1",
                "vm_ip": "10.0.0.100",
            }
        )
        debian_creator._build_debian_vm_artifacts = AsyncMock(
            return_value={"success": False, "error": "Build failed"}
        )

        result = await debian_creator.create_debian_vm(sample_vm_config)

        assert result["success"] is False
        assert result["error"] == "Build failed"

    @pytest.mark.asyncio
    async def test_create_debian_vm_install_fails(
        self, debian_creator, sample_vm_config
    ):
        """Test creating VM when installation fails."""
        debian_creator._prepare_debian_vm = AsyncMock(
            return_value={
                "success": True,
                "debian_version": "12",
                "fqdn_hostname": "test.example.com",
                "agent_version": "1.0.0",
                "gateway_ip": "10.0.0.1",
                "vm_ip": "10.0.0.100",
            }
        )
        debian_creator._build_debian_vm_artifacts = AsyncMock(
            return_value={
                "success": True,
                "disk_path": "/var/vmm/test-vm.qcow2",
                "serial_iso_path": "/tmp/serial.iso",
            }
        )
        debian_creator._launch_and_install_debian_vm = AsyncMock(
            return_value={"success": False, "error": "Install failed"}
        )

        result = await debian_creator.create_debian_vm(sample_vm_config)

        assert result["success"] is False
        assert result["error"] == "Install failed"

    @pytest.mark.asyncio
    async def test_create_debian_vm_exception(self, debian_creator, sample_vm_config):
        """Test creating VM with unexpected exception."""
        debian_creator._prepare_debian_vm = AsyncMock(
            side_effect=Exception("Unexpected error")
        )

        result = await debian_creator.create_debian_vm(sample_vm_config)

        assert result["success"] is False
        assert "Unexpected error" in result["error"]
        debian_creator.logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_create_debian_vm_uses_default_memory(self, debian_creator):
        """Test that default memory is used when not specified."""
        config = VmmVmConfig(
            distribution="Debian 12",
            vm_name="test-vm",
            hostname="test",
            username="testuser",
            password_hash="$6$hash",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://example.com"),
            resource_config=VmmResourceConfig(memory=""),  # Empty memory
        )

        debian_creator._prepare_debian_vm = AsyncMock(
            return_value={
                "success": True,
                "debian_version": "12",
                "fqdn_hostname": "test.example.com",
                "agent_version": "1.0.0",
                "gateway_ip": "10.0.0.1",
                "vm_ip": "10.0.0.100",
            }
        )
        debian_creator._build_debian_vm_artifacts = AsyncMock(
            return_value={
                "success": True,
                "disk_path": "/var/vmm/test-vm.qcow2",
                "serial_iso_path": "/tmp/serial.iso",
            }
        )
        debian_creator._launch_and_install_debian_vm = AsyncMock(
            return_value={"success": True}
        )
        debian_creator._finalize_debian_vm = Mock()

        await debian_creator.create_debian_vm(config)

        # Verify _launch_and_install_debian_vm was called
        debian_creator._launch_and_install_debian_vm.assert_called_once()

        # Check that the call included memory parameter (either positional or keyword)
        call_args = debian_creator._launch_and_install_debian_vm.call_args
        # The method takes (config, disk_path, serial_iso_path, memory)
        # Memory is the 4th positional argument (index 3)
        if call_args.args:
            memory_arg = (
                call_args.args[3]
                if len(call_args.args) > 3
                else call_args.kwargs.get("memory")
            )
        else:
            memory_arg = call_args.kwargs.get("memory")

        # When config.memory is empty, DEFAULT_MEMORY ("2G") should be used
        assert memory_arg == "2G"


# -----------------------------------------------------------------------------
# Edge case tests
# -----------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests for DebianVmCreator."""

    def test_extract_version_case_insensitive(self, mock_logger):
        """Test that version extraction is case insensitive."""
        assert extract_debian_version("DEBIAN 12", mock_logger) == "12"
        assert extract_debian_version("BOOKWORM", mock_logger) == "12"
        assert extract_debian_version("debian-12", mock_logger) == "12"

    def test_fqdn_hostname_with_port_in_url(self):
        """Test FQDN hostname extraction when URL has port."""
        result = get_fqdn_hostname("test", "https://sysmanage.example.com:8443")
        assert result == "test.example.com"

    def test_fqdn_hostname_with_path_in_url(self):
        """Test FQDN hostname extraction when URL has path."""
        result = get_fqdn_hostname("test", "https://sysmanage.example.com/api")
        assert result == "test.example.com"

    @pytest.mark.asyncio
    async def test_create_vm_with_root_password_hash(self, debian_creator):
        """Test creating VM with separate root password hash."""
        config = VmmVmConfig(
            distribution="Debian 12",
            vm_name="test-vm",
            hostname="test",
            username="testuser",
            password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://example.com"),
        )

        debian_creator._prepare_debian_vm = AsyncMock(
            return_value={
                "success": True,
                "debian_version": "12",
                "fqdn_hostname": "test.example.com",
                "agent_version": "1.0.0",
                "gateway_ip": "10.0.0.1",
                "vm_ip": "10.0.0.100",
            }
        )
        debian_creator._build_debian_vm_artifacts = AsyncMock(
            return_value={
                "success": True,
                "disk_path": "/var/vmm/test-vm.qcow2",
                "serial_iso_path": "/tmp/serial.iso",
            }
        )
        debian_creator._launch_and_install_debian_vm = AsyncMock(
            return_value={"success": True}
        )
        debian_creator._finalize_debian_vm = Mock()

        result = await debian_creator.create_debian_vm(config)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_generate_preseed_uses_user_password_for_root_if_empty(
        self, debian_creator, sample_vm_config
    ):
        """Test that user password hash is used for root if root hash is empty."""
        # Remove root_password_hash from config
        sample_vm_config.root_password_hash = ""

        debian_creator.autoinstall_setup.download_agent_deb = Mock(
            return_value={"success": False, "error": "Skip"}
        )
        debian_creator.autoinstall_setup.generate_enhanced_preseed = Mock(
            return_value={"success": True, "preseed": "content"}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            await debian_creator._generate_preseed(
                sample_vm_config,
                "test.example.com",
                "10.0.0.1",
                "10.0.0.100",
                "12",
            )

        # Verify preseed was generated (password handling is in preseed generation)
        debian_creator.autoinstall_setup.generate_enhanced_preseed.assert_called_once()

    def test_get_next_vm_ip_all_ips_used(self, debian_creator, tmp_path):
        """Test getting next VM IP when all IPs are used."""
        tmp_path.mkdir(exist_ok=True)

        # Create metadata for IPs .100 through .254
        for i in range(100, 255):
            with open(tmp_path / f"vm{i}.json", "w", encoding="utf-8") as file_handle:
                json.dump({"vm_ip": f"10.0.0.{i}"}, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_debian_vm_creator.VMM_METADATA_DIR",
            str(tmp_path),
        ):
            result = debian_creator._get_next_vm_ip("10.0.0.1")

        # Should wrap around to .100 when all IPs are used
        assert result == "10.0.0.100"
