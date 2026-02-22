"""
Comprehensive unit tests for Alpine Linux VMM VM creation orchestration.

Tests cover:
- Alpine version extraction and validation
- FQDN hostname derivation
- AlpineVmCreator initialization
- Configuration validation
- VMM availability checks
- Gateway IP extraction
- Next VM IP calculation
- Setup data creation
- ISO launch
- Automated installation
- VM shutdown waiting
- Metadata saving
- Full VM creation workflow
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.operations.child_host_alpine_vm_creator import (
    AlpineVmCreator,
    extract_alpine_version,
    get_fqdn_hostname,
)
from src.sysmanage_agent.operations.child_host_types import (
    VmmVmConfig,
    VmmServerConfig,
    VmmResourceConfig,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_alpine_vm_creator")


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    mock = Mock()
    mock.send_message = AsyncMock()
    mock.create_message = Mock(return_value={"type": "test"})
    return mock


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock_checks = Mock()
    mock_checks.check_vmm_support = Mock(
        return_value={
            "available": True,
            "running": True,
            "initialized": True,
        }
    )
    return mock_checks


@pytest.fixture
def mock_github_checker():
    """Create mock GitHub version checker."""
    mock_checker = Mock()
    mock_checker.get_latest_version = Mock(
        return_value={
            "success": True,
            "version": "1.0.0",
            "tag_name": "v1.0.0",
        }
    )
    return mock_checker


@pytest.fixture
def mock_db_session():
    """Create mock database session."""
    return Mock()


@pytest.fixture
def alpine_creator(
    mock_agent, logger, mock_virtualization_checks, mock_github_checker, mock_db_session
):
    """Create an AlpineVmCreator instance for testing."""
    return AlpineVmCreator(
        mock_agent,
        logger,
        mock_virtualization_checks,
        mock_github_checker,
        mock_db_session,
    )


@pytest.fixture
def sample_server_config():
    """Create a sample server configuration."""
    return VmmServerConfig(
        server_url="https://sysmanage.example.com",
        server_port=8443,
        use_https=True,
    )


@pytest.fixture
def sample_resource_config():
    """Create a sample resource configuration."""
    return VmmResourceConfig(
        memory="2G",
        disk_size="20G",
        cpus=2,
    )


@pytest.fixture
def sample_vm_config(sample_server_config, sample_resource_config):
    """Create a sample VMM VM configuration."""
    return VmmVmConfig(
        distribution="Alpine Linux 3.20",
        vm_name="test-alpine-vm",
        hostname="alpine-vm",
        username="admin",
        password_hash="test_password",
        agent_install_commands=[],
        root_password_hash="root_password",
        server_config=sample_server_config,
        resource_config=sample_resource_config,
        auto_approve_token="test-token-12345",
    )


class TestExtractAlpineVersion:
    """Tests for extract_alpine_version function."""

    def test_extract_version_alpine_linux_format(self, logger):
        """Test extraction from 'Alpine Linux 3.20' format."""
        result = extract_alpine_version("Alpine Linux 3.20", logger)
        assert result == "3.20"

    def test_extract_version_alpine_only_format(self, logger):
        """Test extraction from 'Alpine 3.21' format."""
        result = extract_alpine_version("Alpine 3.21", logger)
        assert result == "3.21"

    def test_extract_version_dash_format(self, logger):
        """Test extraction from 'alpine-3.19' format."""
        result = extract_alpine_version("alpine-3.19", logger)
        assert result == "3.19"

    def test_extract_version_underscore_format(self, logger):
        """Test extraction from 'alpine_3.20' format."""
        result = extract_alpine_version("alpine_3.20", logger)
        assert result == "3.20"

    def test_extract_version_number_only(self, logger):
        """Test extraction from version number only."""
        result = extract_alpine_version("3.21", logger)
        assert result == "3.21"

    def test_extract_version_case_insensitive(self, logger):
        """Test case-insensitive matching."""
        result = extract_alpine_version("ALPINE LINUX 3.20", logger)
        assert result == "3.20"

    def test_extract_version_unsupported(self, logger):
        """Test extraction of unsupported version returns None."""
        result = extract_alpine_version("Alpine Linux 3.18", logger)
        assert result is None

    def test_extract_version_invalid_string(self, logger):
        """Test extraction from invalid string returns None."""
        result = extract_alpine_version("Ubuntu 22.04", logger)
        assert result is None

    def test_extract_version_empty_string(self, logger):
        """Test extraction from empty string returns None."""
        result = extract_alpine_version("", logger)
        assert result is None

    def test_extract_version_with_extra_text(self, logger):
        """Test extraction with additional text."""
        result = extract_alpine_version("Alpine Linux 3.20 (Standard)", logger)
        assert result == "3.20"


class TestGetFqdnHostname:
    """Tests for get_fqdn_hostname function."""

    def test_already_fqdn(self):
        """Test with already FQDN hostname."""
        result = get_fqdn_hostname("vm1.example.com", "https://sysmanage.example.com")
        assert result == "vm1.example.com"

    def test_short_hostname_with_domain(self):
        """Test short hostname gets domain from server URL."""
        result = get_fqdn_hostname("vm1", "https://sysmanage.example.com")
        assert result == "vm1.example.com"

    def test_short_hostname_with_subdomain(self):
        """Test short hostname with subdomain in server URL."""
        result = get_fqdn_hostname("vm1", "https://manage.sub.example.com:8443")
        assert result == "vm1.sub.example.com"

    def test_short_hostname_no_domain(self):
        """Test short hostname when no domain can be extracted."""
        result = get_fqdn_hostname("vm1", "http://localhost")
        assert result == "vm1"

    def test_short_hostname_ip_address(self):
        """Test short hostname with IP address server."""
        result = get_fqdn_hostname("vm1", "https://192.168.1.100:8443")
        assert result == "vm1"


class TestAlpineVmCreatorInit:
    """Tests for AlpineVmCreator initialization."""

    def test_init_sets_agent(self, alpine_creator, mock_agent):
        """Test that __init__ sets agent."""
        assert alpine_creator.agent == mock_agent

    def test_init_sets_logger(self, alpine_creator, logger):
        """Test that __init__ sets logger."""
        assert alpine_creator.logger == logger

    def test_init_sets_virtualization_checks(
        self, alpine_creator, mock_virtualization_checks
    ):
        """Test that __init__ sets virtualization_checks."""
        assert alpine_creator.virtualization_checks == mock_virtualization_checks

    def test_init_sets_github_checker(self, alpine_creator, mock_github_checker):
        """Test that __init__ sets github_checker."""
        assert alpine_creator.github_checker == mock_github_checker

    def test_init_sets_db_session(self, alpine_creator, mock_db_session):
        """Test that __init__ sets db_session."""
        assert alpine_creator.db_session == mock_db_session

    def test_init_creates_disk_ops(self, alpine_creator):
        """Test that __init__ creates disk operations helper."""
        assert alpine_creator.disk_ops is not None

    def test_init_creates_vmconf_manager(self, alpine_creator):
        """Test that __init__ creates vmconf manager."""
        assert alpine_creator.vmconf_manager is not None

    def test_init_creates_launcher(self, alpine_creator):
        """Test that __init__ creates launcher."""
        assert alpine_creator.launcher is not None

    def test_init_creates_autoinstall_setup(self, alpine_creator):
        """Test that __init__ creates autoinstall setup."""
        assert alpine_creator.autoinstall_setup is not None

    def test_init_creates_site_builder(self, alpine_creator):
        """Test that __init__ creates site builder."""
        assert alpine_creator.site_builder is not None

    def test_init_creates_console_automation(self, alpine_creator):
        """Test that __init__ creates console automation."""
        assert alpine_creator.console_automation is not None


class TestValidateConfig:
    """Tests for _validate_config method."""

    def test_validate_config_success(self, alpine_creator, sample_vm_config):
        """Test successful configuration validation."""
        result = alpine_creator._validate_config(sample_vm_config)
        assert result["success"] is True

    def test_validate_config_missing_distribution(
        self, alpine_creator, sample_server_config, sample_resource_config
    ):
        """Test validation fails without distribution."""
        config = VmmVmConfig(
            distribution="",
            vm_name="test-vm",
            hostname="test",
            username="admin",
            password_hash="password",
            agent_install_commands=[],
            server_config=sample_server_config,
            resource_config=sample_resource_config,
        )
        result = alpine_creator._validate_config(config)
        assert result["success"] is False
        assert "Distribution is required" in result["error"]

    def test_validate_config_missing_vm_name(
        self, alpine_creator, sample_server_config, sample_resource_config
    ):
        """Test validation fails without VM name."""
        config = VmmVmConfig(
            distribution="Alpine Linux 3.20",
            vm_name="",
            hostname="test",
            username="admin",
            password_hash="password",
            agent_install_commands=[],
            server_config=sample_server_config,
            resource_config=sample_resource_config,
        )
        result = alpine_creator._validate_config(config)
        assert result["success"] is False
        assert "VM name is required" in result["error"]

    def test_validate_config_missing_hostname(
        self, alpine_creator, sample_server_config, sample_resource_config
    ):
        """Test validation fails without hostname."""
        config = VmmVmConfig(
            distribution="Alpine Linux 3.20",
            vm_name="test-vm",
            hostname="",
            username="admin",
            password_hash="password",
            agent_install_commands=[],
            server_config=sample_server_config,
            resource_config=sample_resource_config,
        )
        result = alpine_creator._validate_config(config)
        assert result["success"] is False
        assert "Hostname is required" in result["error"]

    def test_validate_config_missing_username(
        self, alpine_creator, sample_server_config, sample_resource_config
    ):
        """Test validation fails without username."""
        config = VmmVmConfig(
            distribution="Alpine Linux 3.20",
            vm_name="test-vm",
            hostname="test",
            username="",
            password_hash="password",
            agent_install_commands=[],
            server_config=sample_server_config,
            resource_config=sample_resource_config,
        )
        result = alpine_creator._validate_config(config)
        assert result["success"] is False
        assert "Username is required" in result["error"]

    def test_validate_config_missing_password(
        self, alpine_creator, sample_server_config, sample_resource_config
    ):
        """Test validation fails without password."""
        config = VmmVmConfig(
            distribution="Alpine Linux 3.20",
            vm_name="test-vm",
            hostname="test",
            username="admin",
            password_hash="",
            agent_install_commands=[],
            server_config=sample_server_config,
            resource_config=sample_resource_config,
        )
        result = alpine_creator._validate_config(config)
        assert result["success"] is False
        assert "Password is required" in result["error"]

    def test_validate_config_missing_server_url(
        self, alpine_creator, sample_resource_config
    ):
        """Test validation fails without server URL."""
        config = VmmVmConfig(
            distribution="Alpine Linux 3.20",
            vm_name="test-vm",
            hostname="test",
            username="admin",
            password_hash="password",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url=""),
            resource_config=sample_resource_config,
        )
        result = alpine_creator._validate_config(config)
        assert result["success"] is False
        assert "Server URL is required" in result["error"]


class TestCheckVmmReady:
    """Tests for _check_vmm_ready method."""

    @pytest.mark.asyncio
    async def test_vmm_ready_success(self, alpine_creator, mock_virtualization_checks):
        """Test VMM ready check when available and running."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }
        alpine_creator.launcher.send_progress = AsyncMock()

        result = await alpine_creator._check_vmm_ready()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_vmm_not_available(self, alpine_creator, mock_virtualization_checks):
        """Test VMM ready check when not available."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": False,
            "running": False,
        }
        alpine_creator.launcher.send_progress = AsyncMock()

        result = await alpine_creator._check_vmm_ready()

        assert result["success"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_vmm_not_running(self, alpine_creator, mock_virtualization_checks):
        """Test VMM ready check when not running."""
        mock_virtualization_checks.check_vmm_support.return_value = {
            "available": True,
            "running": False,
        }
        alpine_creator.launcher.send_progress = AsyncMock()

        result = await alpine_creator._check_vmm_ready()

        assert result["success"] is False
        assert "not running" in result["error"]


class TestGetAgentVersion:
    """Tests for _get_agent_version method."""

    @pytest.mark.asyncio
    async def test_get_agent_version_success(self, alpine_creator, mock_github_checker):
        """Test getting agent version successfully."""
        mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "2.0.0",
            "tag_name": "v2.0.0",
        }
        alpine_creator.launcher.send_progress = AsyncMock()

        version, tag_name = await alpine_creator._get_agent_version()

        assert version == "2.0.0"
        assert tag_name == "v2.0.0"

    @pytest.mark.asyncio
    async def test_get_agent_version_failure(self, alpine_creator, mock_github_checker):
        """Test getting agent version when GitHub check fails."""
        mock_github_checker.get_latest_version.return_value = {
            "success": False,
            "error": "Network error",
        }
        alpine_creator.launcher.send_progress = AsyncMock()

        with pytest.raises(RuntimeError, match="Failed to check GitHub version"):
            await alpine_creator._get_agent_version()


class TestGetGatewayIp:
    """Tests for _get_gateway_ip method."""

    def test_get_gateway_ip_success(self, alpine_creator):
        """Test getting gateway IP successfully."""
        mock_output = """vether0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        lladdr fe:e1:ba:d0:62:c4
        index 7 priority 0 llprio 3
        groups: vether
        media: Ethernet autoselect
        status: active
        inet 10.0.10.1 netmask 0xffffff00 broadcast 10.0.10.255
        inet6 fe80::fce1:baff:fed0:62c4%vether0 prefixlen 64 scopeid 0x7
"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=mock_output, stderr="")
            result = alpine_creator._get_gateway_ip()

        assert result == "10.0.10.1"

    def test_get_gateway_ip_no_inet(self, alpine_creator):
        """Test getting gateway IP when no inet line."""
        mock_output = "vether0: flags=8843<UP> mtu 1500\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=mock_output, stderr="")
            result = alpine_creator._get_gateway_ip()

        assert result is None

    def test_get_gateway_ip_exception(self, alpine_creator):
        """Test getting gateway IP with exception."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = alpine_creator._get_gateway_ip()

        assert result is None

    def test_get_gateway_ip_timeout(self, alpine_creator):
        """Test getting gateway IP with timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            result = alpine_creator._get_gateway_ip()

        assert result is None


class TestGetNextVmIp:
    """Tests for _get_next_vm_ip method."""

    def test_get_next_vm_ip_no_existing(self, alpine_creator):
        """Test getting next VM IP with no existing VMs."""
        with patch.object(Path, "exists", return_value=False):
            result = alpine_creator._get_next_vm_ip("10.0.10.1")

        assert result == "10.0.10.100"

    def test_get_next_vm_ip_with_existing(self, alpine_creator):
        """Test getting next VM IP with existing VMs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_dir = Path(tmpdir)

            # Create mock metadata file
            metadata_file = metadata_dir / "vm1.json"
            metadata_file.write_text(json.dumps({"vm_ip": "10.0.10.100"}))

            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.VMM_METADATA_DIR",
                str(metadata_dir),
            ):
                with patch.object(Path, "exists", return_value=True):
                    with patch.object(
                        Path,
                        "glob",
                        return_value=[metadata_file],
                    ):
                        # Re-patch the directory path
                        with patch(
                            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.Path"
                        ) as mock_path:
                            mock_dir = Mock()
                            mock_dir.exists.return_value = True
                            mock_dir.glob.return_value = [metadata_file]
                            mock_path.return_value = mock_dir
                            result = alpine_creator._get_next_vm_ip("10.0.10.1")

        # Should skip 100 and return 101
        assert result == "10.0.10.101"

    def test_get_next_vm_ip_all_ips_taken(self, alpine_creator):
        """Test getting next VM IP when all IPs from 100-254 are taken."""
        # Create a set of all possible IPs from 100-254
        all_used_ips = {f"10.0.10.{i}" for i in range(100, 255)}

        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_dir = Path(tmpdir)

            # Create metadata files for all IPs
            metadata_files = []
            for idx, ip_addr in enumerate(all_used_ips):
                metadata_file = metadata_dir / f"vm{idx}.json"
                metadata_file.write_text(json.dumps({"vm_ip": ip_addr}))
                metadata_files.append(metadata_file)

            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.Path"
            ) as mock_path:
                mock_dir = Mock()
                mock_dir.exists.return_value = True
                mock_dir.glob.return_value = metadata_files
                mock_path.return_value = mock_dir

                # Mock open to return the metadata content
                def mock_open_side_effect(file_path, *_args, **_kwargs):
                    file_idx = (
                        metadata_files.index(file_path)
                        if file_path in metadata_files
                        else 0
                    )
                    vm_ip_address = f"10.0.10.{100 + file_idx}"
                    mock_file = MagicMock()
                    mock_file.__enter__.return_value = MagicMock()
                    mock_file.__enter__.return_value.read.return_value = json.dumps(
                        {"vm_ip": vm_ip_address}
                    )
                    return mock_file

                with patch("builtins.open", side_effect=mock_open_side_effect):
                    result = alpine_creator._get_next_vm_ip("10.0.10.1")

        # Should fallback to .100 when all IPs are taken
        assert result == "10.0.10.100"

    def test_get_next_vm_ip_invalid_metadata(self, alpine_creator):
        """Test getting next VM IP with invalid metadata file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_dir = Path(tmpdir)

            # Create invalid metadata file
            metadata_file = metadata_dir / "vm1.json"
            metadata_file.write_text("invalid json")

            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.Path"
            ) as mock_path:
                mock_dir = Mock()
                mock_dir.exists.return_value = True
                mock_dir.glob.return_value = [metadata_file]
                mock_path.return_value = mock_dir
                result = alpine_creator._get_next_vm_ip("10.0.10.1")

        assert result == "10.0.10.100"


class TestValidateAndExtractVersion:
    """Tests for _validate_and_extract_version method."""

    @pytest.mark.asyncio
    async def test_validate_and_extract_success(self, alpine_creator, sample_vm_config):
        """Test successful validation and version extraction."""
        alpine_creator.launcher.send_progress = AsyncMock()

        error_result, alpine_version = (
            await alpine_creator._validate_and_extract_version(sample_vm_config)
        )

        assert error_result is None
        assert alpine_version == "3.20"

    @pytest.mark.asyncio
    async def test_validate_and_extract_validation_fails(
        self, alpine_creator, sample_server_config, sample_resource_config
    ):
        """Test validation and extraction when validation fails."""
        config = VmmVmConfig(
            distribution="Alpine Linux 3.20",
            vm_name="",  # Invalid - empty
            hostname="test",
            username="admin",
            password_hash="password",
            agent_install_commands=[],
            server_config=sample_server_config,
            resource_config=sample_resource_config,
        )

        error_result, alpine_version = (
            await alpine_creator._validate_and_extract_version(config)
        )

        assert error_result is not None
        assert error_result["success"] is False
        assert alpine_version is None

    @pytest.mark.asyncio
    async def test_validate_and_extract_version_fails(
        self, alpine_creator, sample_server_config, sample_resource_config
    ):
        """Test validation and extraction when version parsing fails."""
        config = VmmVmConfig(
            distribution="Ubuntu 22.04",  # Not Alpine
            vm_name="test-vm",
            hostname="test",
            username="admin",
            password_hash="password",
            agent_install_commands=[],
            server_config=sample_server_config,
            resource_config=sample_resource_config,
        )
        alpine_creator.launcher.send_progress = AsyncMock()

        error_result, alpine_version = (
            await alpine_creator._validate_and_extract_version(config)
        )

        assert error_result is not None
        assert error_result["success"] is False
        assert "Could not parse Alpine version" in error_result["error"]
        assert alpine_version is None


class TestBuildSiteTarball:
    """Tests for _build_site_tarball method."""

    @pytest.mark.asyncio
    async def test_build_site_tarball_success(self, alpine_creator, sample_vm_config):
        """Test building site tarball successfully."""
        alpine_creator.launcher.send_progress = AsyncMock()
        alpine_creator.site_builder.get_or_build_site_tarball = Mock(
            return_value={
                "success": True,
                "site_tgz_path": "/var/vmm/site-3.20.tgz",
            }
        )

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = {
                "success": True,
                "site_tgz_path": "/var/vmm/site-3.20.tgz",
            }
            result = await alpine_creator._build_site_tarball(
                "3.20", "1.0.0", sample_vm_config
            )

        assert result["success"] is True
        assert result["site_tgz_path"] == "/var/vmm/site-3.20.tgz"

    @pytest.mark.asyncio
    async def test_build_site_tarball_failure(self, alpine_creator, sample_vm_config):
        """Test building site tarball when it fails."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = {
                "success": False,
                "error": "Build failed",
            }
            result = await alpine_creator._build_site_tarball(
                "3.20", "1.0.0", sample_vm_config
            )

        assert result["success"] is False


class TestCreateSetupData:
    """Tests for _create_setup_data method."""

    @pytest.mark.asyncio
    async def test_create_setup_data_success(self, alpine_creator, sample_vm_config):
        """Test creating setup data successfully."""
        alpine_creator.autoinstall_setup.create_setup_script = Mock(
            return_value="#!/bin/sh\necho setup"
        )
        alpine_creator.autoinstall_setup.create_agent_config = Mock(
            return_value="hostname: test"
        )
        alpine_creator.autoinstall_setup.create_firstboot_setup = Mock(
            return_value="#!/bin/sh\necho firstboot"
        )
        alpine_creator.autoinstall_setup.create_alpine_data_disk = Mock(
            return_value={"success": True}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            result = await alpine_creator._create_setup_data(
                sample_vm_config,
                "alpine-vm.example.com",
                "10.0.10.1",
                "10.0.10.100",
                "3.20",
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_setup_data_exception(self, alpine_creator, sample_vm_config):
        """Test creating setup data with exception."""
        alpine_creator.autoinstall_setup.create_setup_script = Mock(
            side_effect=Exception("Script creation failed")
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            result = await alpine_creator._create_setup_data(
                sample_vm_config,
                "alpine-vm.example.com",
                "10.0.10.1",
                "10.0.10.100",
                "3.20",
            )

        assert result["success"] is False
        assert "Script creation failed" in result["error"]


class TestLaunchVmFromIso:
    """Tests for _launch_vm_from_iso method."""

    @pytest.mark.asyncio
    async def test_launch_vm_from_iso_success(self, alpine_creator, sample_vm_config):
        """Test launching VM from ISO successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VM started"
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.run_command_async",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await alpine_creator._launch_vm_from_iso(
                sample_vm_config, "/var/vmm/test.qcow2", "/var/vmm/alpine.iso"
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_vm_from_iso_failure(self, alpine_creator, sample_vm_config):
        """Test launching VM from ISO when vmctl fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "vmctl: could not start VM"

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.run_command_async",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await alpine_creator._launch_vm_from_iso(
                sample_vm_config, "/var/vmm/test.qcow2", "/var/vmm/alpine.iso"
            )

        assert result["success"] is False
        assert "Failed to start VM" in result["error"]

    @pytest.mark.asyncio
    async def test_launch_vm_from_iso_exception(self, alpine_creator, sample_vm_config):
        """Test launching VM from ISO with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.run_command_async",
            new_callable=AsyncMock,
            side_effect=Exception("Command failed"),
        ):
            result = await alpine_creator._launch_vm_from_iso(
                sample_vm_config, "/var/vmm/test.qcow2", "/var/vmm/alpine.iso"
            )

        assert result["success"] is False
        assert "Command failed" in result["error"]


class TestRunAutomatedInstall:
    """Tests for _run_automated_install method."""

    @pytest.mark.asyncio
    async def test_run_automated_install_success(self, alpine_creator):
        """Test running automated install successfully."""
        alpine_creator.autoinstall_setup.create_setup_script = Mock(
            return_value="#!/bin/sh\necho setup"
        )
        alpine_creator.console_automation.run_automated_setup = AsyncMock(
            return_value={"success": True}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.write_file_async",
                new_callable=AsyncMock,
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await alpine_creator._run_automated_install(
                        vm_name="test-vm",
                        hostname="test.example.com",
                        username="admin",
                        user_password="password",
                        root_password="rootpassword",
                        gateway_ip="10.0.10.1",
                        vm_ip="10.0.10.100",
                        alpine_version="3.20",
                        server_hostname="sysmanage.example.com",
                        server_port=8443,
                        use_https=True,
                        auto_approve_token="test-token",
                    )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_automated_install_console_failure(self, alpine_creator):
        """Test running automated install when console automation fails."""
        alpine_creator.autoinstall_setup.create_setup_script = Mock(
            return_value="#!/bin/sh\necho setup"
        )
        alpine_creator.console_automation.run_automated_setup = AsyncMock(
            return_value={"success": False, "error": "Console timeout"}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.write_file_async",
                new_callable=AsyncMock,
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await alpine_creator._run_automated_install(
                        vm_name="test-vm",
                        hostname="test.example.com",
                        username="admin",
                        user_password="password",
                        root_password="rootpassword",
                        gateway_ip="10.0.10.1",
                        vm_ip="10.0.10.100",
                        alpine_version="3.20",
                    )

        assert result["success"] is False
        assert "Console timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_run_automated_install_exception(self, alpine_creator):
        """Test running automated install with exception."""
        alpine_creator.autoinstall_setup.create_setup_script = Mock(
            side_effect=Exception("Setup script creation failed")
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.get_host_dns_server",
            return_value="8.8.8.8",
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await alpine_creator._run_automated_install(
                    vm_name="test-vm",
                    hostname="test.example.com",
                    username="admin",
                    user_password="password",
                    root_password="rootpassword",
                    gateway_ip="10.0.10.1",
                    vm_ip="10.0.10.100",
                    alpine_version="3.20",
                )

        assert result["success"] is False
        assert "Setup script creation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_run_automated_install_no_dns_server(self, alpine_creator):
        """Test running automated install when DNS detection fails."""
        alpine_creator.autoinstall_setup.create_setup_script = Mock(
            return_value="#!/bin/sh\necho setup"
        )
        alpine_creator.console_automation.run_automated_setup = AsyncMock(
            return_value={"success": True}
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.get_host_dns_server",
            return_value=None,  # DNS detection failed
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.write_file_async",
                new_callable=AsyncMock,
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await alpine_creator._run_automated_install(
                        vm_name="test-vm",
                        hostname="test.example.com",
                        username="admin",
                        user_password="password",
                        root_password="rootpassword",
                        gateway_ip="10.0.10.1",
                        vm_ip="10.0.10.100",
                        alpine_version="3.20",
                    )

        assert result["success"] is True


class TestWaitForVmShutdown:
    """Tests for _wait_for_vm_shutdown method."""

    @pytest.mark.asyncio
    async def test_wait_for_vm_shutdown_success(self, alpine_creator):
        """Test waiting for VM shutdown successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""  # VM name not in output (shutdown)

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.run_command_async",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_result
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await alpine_creator._wait_for_vm_shutdown(
                    "test-vm", timeout=10
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_wait_for_vm_shutdown_stopped_status(self, alpine_creator):
        """Test waiting for VM with stopped status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test-vm stopped"

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.run_command_async",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_result
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await alpine_creator._wait_for_vm_shutdown(
                    "test-vm", timeout=10
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_wait_for_vm_shutdown_timeout(self, alpine_creator):
        """Test waiting for VM shutdown with timeout."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test-vm running"

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.run_command_async",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_result
            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.time.time"
            ) as mock_time:
                mock_time.side_effect = [0, 100, 200, 901]  # Last exceeds 900 timeout
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await alpine_creator._wait_for_vm_shutdown(
                        "test-vm", timeout=900
                    )

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_wait_for_vm_shutdown_exception(self, alpine_creator):
        """Test waiting for VM shutdown with exception (continues polling)."""
        call_count = 0
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        async def mock_run_cmd(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Temporary error")
            return mock_result

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_vm_creator.run_command_async",
            side_effect=mock_run_cmd,
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.time.time"
            ) as mock_time:
                mock_time.side_effect = [0, 5, 10]
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await alpine_creator._wait_for_vm_shutdown(
                        "test-vm", timeout=60
                    )

        assert result["success"] is True


class TestSaveVmMetadata:
    """Tests for _save_vm_metadata method."""

    def test_save_vm_metadata_success(self, alpine_creator):
        """Test saving VM metadata successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(
                "src.sysmanage_agent.operations.child_host_alpine_vm_creator.VMM_METADATA_DIR",
                tmpdir,
            ):
                alpine_creator._save_vm_metadata(
                    vm_name="test-vm",
                    hostname="test.example.com",
                    distribution="Alpine Linux 3.20",
                    alpine_version="3.20",
                    vm_ip="10.0.10.100",
                )

            # Verify metadata file was created
            metadata_path = Path(tmpdir) / "test-vm.json"
            assert metadata_path.exists()

            # Verify content
            with open(metadata_path, "r", encoding="utf-8") as file_handle:
                metadata = json.load(file_handle)

            assert metadata["vm_name"] == "test-vm"
            assert metadata["hostname"] == "test.example.com"
            assert metadata["vm_ip"] == "10.0.10.100"
            assert metadata["distribution"]["distribution_name"] == "Alpine Linux"
            assert metadata["distribution"]["distribution_version"] == "3.20"
            assert "created_at" in metadata


class TestCreateAlpineVmWorkflow:
    """Tests for full create_alpine_vm workflow."""

    @pytest.mark.asyncio
    async def test_create_alpine_vm_success(self, alpine_creator, sample_vm_config):
        """Test successful Alpine VM creation workflow."""
        # Mock all helper methods
        alpine_creator.launcher.send_progress = AsyncMock()
        alpine_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": True}
        )

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": True,
                                                "iso_path": "/var/vmm/alpine.iso",
                                            }

                                            with patch.object(
                                                alpine_creator.disk_ops,
                                                "create_disk_image",
                                            ) as mock_disk:
                                                mock_disk.return_value = {
                                                    "success": True
                                                }

                                                with patch.object(
                                                    alpine_creator,
                                                    "_create_setup_data",
                                                    new_callable=AsyncMock,
                                                ) as mock_setup:
                                                    mock_setup.return_value = {
                                                        "success": True
                                                    }

                                                    with patch.object(
                                                        alpine_creator,
                                                        "_launch_vm_from_iso",
                                                        new_callable=AsyncMock,
                                                    ) as mock_launch:
                                                        mock_launch.return_value = {
                                                            "success": True
                                                        }

                                                        with patch.object(
                                                            alpine_creator,
                                                            "_run_automated_install",
                                                            new_callable=AsyncMock,
                                                        ) as mock_install:
                                                            mock_install.return_value = {
                                                                "success": True
                                                            }

                                                            with patch.object(
                                                                alpine_creator,
                                                                "_wait_for_vm_shutdown",
                                                                new_callable=AsyncMock,
                                                            ) as mock_shutdown:
                                                                mock_shutdown.return_value = {
                                                                    "success": True
                                                                }

                                                                with patch.object(
                                                                    alpine_creator,
                                                                    "_save_vm_metadata",
                                                                ):
                                                                    with patch.object(
                                                                        alpine_creator.vmconf_manager,
                                                                        "persist_vm",
                                                                        return_value=True,
                                                                    ):
                                                                        result = await alpine_creator.create_alpine_vm(
                                                                            sample_vm_config
                                                                        )

        assert result["success"] is True
        assert result["child_name"] == "test-alpine-vm"
        assert result["child_type"] == "vmm"
        assert result["alpine_version"] == "3.20"

    @pytest.mark.asyncio
    async def test_create_alpine_vm_validation_fails(
        self, alpine_creator, sample_server_config, sample_resource_config
    ):
        """Test Alpine VM creation when validation fails."""
        config = VmmVmConfig(
            distribution="Alpine Linux 3.20",
            vm_name="",  # Invalid
            hostname="test",
            username="admin",
            password_hash="password",
            agent_install_commands=[],
            server_config=sample_server_config,
            resource_config=sample_resource_config,
        )
        alpine_creator.launcher.send_progress = AsyncMock()

        result = await alpine_creator.create_alpine_vm(config)

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_alpine_vm_vmm_not_ready(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when VMM is not ready."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {
                    "success": False,
                    "error": "VMM is not available",
                }
                result = await alpine_creator.create_alpine_vm(sample_vm_config)

        assert result["success"] is False
        assert "VMM is not available" in result["error"]

    @pytest.mark.asyncio
    async def test_create_alpine_vm_already_exists(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when VM already exists."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=True,  # VM exists
                ):
                    result = await alpine_creator.create_alpine_vm(sample_vm_config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    async def test_create_alpine_vm_no_gateway_ip(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when gateway IP cannot be determined."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = None  # No gateway
                                    result = await alpine_creator.create_alpine_vm(
                                        sample_vm_config
                                    )

        assert result["success"] is False
        assert "gateway IP" in result["error"]

    @pytest.mark.asyncio
    async def test_create_alpine_vm_iso_download_fails(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when ISO download fails."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": False,
                                                "error": "Download failed",
                                            }
                                            result = (
                                                await alpine_creator.create_alpine_vm(
                                                    sample_vm_config
                                                )
                                            )

        assert result["success"] is False
        assert "ISO" in result["error"]

    @pytest.mark.asyncio
    async def test_create_alpine_vm_disk_creation_fails(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when disk creation fails."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": True,
                                                "iso_path": "/var/vmm/alpine.iso",
                                            }

                                            with patch.object(
                                                alpine_creator.disk_ops,
                                                "create_disk_image",
                                            ) as mock_disk:
                                                mock_disk.return_value = {
                                                    "success": False,
                                                    "error": "Disk creation failed",
                                                }
                                                result = await alpine_creator.create_alpine_vm(
                                                    sample_vm_config
                                                )

        assert result["success"] is False
        assert "disk" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_create_alpine_vm_exception(self, alpine_creator, sample_vm_config):
        """Test Alpine VM creation handles unexpected exception."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch.object(
            alpine_creator,
            "_validate_and_extract_version",
            new_callable=AsyncMock,
            side_effect=Exception("Unexpected error"),
        ):
            result = await alpine_creator.create_alpine_vm(sample_vm_config)

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestCreateAlpineVmEdgeCases:
    """Test edge cases in Alpine VM creation."""

    @pytest.mark.asyncio
    async def test_create_alpine_vm_site_tarball_fails(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when site tarball building fails."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": False,
                                    "error": "Site tarball build failed",
                                }
                                result = await alpine_creator.create_alpine_vm(
                                    sample_vm_config
                                )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_alpine_vm_setup_data_fails(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when setup data creation fails."""
        alpine_creator.launcher.send_progress = AsyncMock()

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": True,
                                                "iso_path": "/var/vmm/alpine.iso",
                                            }

                                            with patch.object(
                                                alpine_creator.disk_ops,
                                                "create_disk_image",
                                            ) as mock_disk:
                                                mock_disk.return_value = {
                                                    "success": True
                                                }

                                                with patch.object(
                                                    alpine_creator,
                                                    "_create_setup_data",
                                                    new_callable=AsyncMock,
                                                ) as mock_setup:
                                                    mock_setup.return_value = {
                                                        "success": False,
                                                        "error": "Setup data failed",
                                                    }
                                                    result = await alpine_creator.create_alpine_vm(
                                                        sample_vm_config
                                                    )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_alpine_vm_launch_fails(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when VM launch fails."""
        alpine_creator.launcher.send_progress = AsyncMock()
        alpine_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": True}
        )

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": True,
                                                "iso_path": "/var/vmm/alpine.iso",
                                            }

                                            with patch.object(
                                                alpine_creator.disk_ops,
                                                "create_disk_image",
                                            ) as mock_disk:
                                                mock_disk.return_value = {
                                                    "success": True
                                                }

                                                with patch.object(
                                                    alpine_creator,
                                                    "_create_setup_data",
                                                    new_callable=AsyncMock,
                                                ) as mock_setup:
                                                    mock_setup.return_value = {
                                                        "success": True
                                                    }

                                                    with patch.object(
                                                        alpine_creator,
                                                        "_launch_vm_from_iso",
                                                        new_callable=AsyncMock,
                                                    ) as mock_launch:
                                                        mock_launch.return_value = {
                                                            "success": False,
                                                            "error": "Launch failed",
                                                        }
                                                        result = await alpine_creator.create_alpine_vm(
                                                            sample_vm_config
                                                        )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_alpine_vm_restart_fails(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when VM restart fails."""
        alpine_creator.launcher.send_progress = AsyncMock()
        alpine_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": False, "error": "Restart failed"}
        )

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": True,
                                                "iso_path": "/var/vmm/alpine.iso",
                                            }

                                            with patch.object(
                                                alpine_creator.disk_ops,
                                                "create_disk_image",
                                            ) as mock_disk:
                                                mock_disk.return_value = {
                                                    "success": True
                                                }

                                                with patch.object(
                                                    alpine_creator,
                                                    "_create_setup_data",
                                                    new_callable=AsyncMock,
                                                ) as mock_setup:
                                                    mock_setup.return_value = {
                                                        "success": True
                                                    }

                                                    with patch.object(
                                                        alpine_creator,
                                                        "_launch_vm_from_iso",
                                                        new_callable=AsyncMock,
                                                    ) as mock_launch:
                                                        mock_launch.return_value = {
                                                            "success": True
                                                        }

                                                        with patch.object(
                                                            alpine_creator,
                                                            "_run_automated_install",
                                                            new_callable=AsyncMock,
                                                        ) as mock_install:
                                                            mock_install.return_value = {
                                                                "success": True
                                                            }

                                                            with patch.object(
                                                                alpine_creator,
                                                                "_wait_for_vm_shutdown",
                                                                new_callable=AsyncMock,
                                                            ) as mock_shutdown:
                                                                mock_shutdown.return_value = {
                                                                    "success": True
                                                                }
                                                                result = await alpine_creator.create_alpine_vm(
                                                                    sample_vm_config
                                                                )

        assert result["success"] is False
        assert "Restart failed" in result["error"]

    @pytest.mark.asyncio
    async def test_create_alpine_vm_install_warning(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation logs warning when install has issues."""
        alpine_creator.launcher.send_progress = AsyncMock()
        alpine_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": True}
        )

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": True,
                                                "iso_path": "/var/vmm/alpine.iso",
                                            }

                                            with patch.object(
                                                alpine_creator.disk_ops,
                                                "create_disk_image",
                                            ) as mock_disk:
                                                mock_disk.return_value = {
                                                    "success": True
                                                }

                                                with patch.object(
                                                    alpine_creator,
                                                    "_create_setup_data",
                                                    new_callable=AsyncMock,
                                                ) as mock_setup:
                                                    mock_setup.return_value = {
                                                        "success": True
                                                    }

                                                    with patch.object(
                                                        alpine_creator,
                                                        "_launch_vm_from_iso",
                                                        new_callable=AsyncMock,
                                                    ) as mock_launch:
                                                        mock_launch.return_value = {
                                                            "success": True
                                                        }

                                                        with patch.object(
                                                            alpine_creator,
                                                            "_run_automated_install",
                                                            new_callable=AsyncMock,
                                                        ) as mock_install:
                                                            # Install returns failure but workflow continues
                                                            mock_install.return_value = {
                                                                "success": False,
                                                                "error": "Install warning",
                                                            }

                                                            with patch.object(
                                                                alpine_creator,
                                                                "_wait_for_vm_shutdown",
                                                                new_callable=AsyncMock,
                                                            ) as mock_shutdown:
                                                                mock_shutdown.return_value = {
                                                                    "success": True
                                                                }

                                                                with patch.object(
                                                                    alpine_creator,
                                                                    "_save_vm_metadata",
                                                                ):
                                                                    with patch.object(
                                                                        alpine_creator.vmconf_manager,
                                                                        "persist_vm",
                                                                        return_value=True,
                                                                    ):
                                                                        result = await alpine_creator.create_alpine_vm(
                                                                            sample_vm_config
                                                                        )

        # Still succeeds, just with warning logged
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_alpine_vm_vmconf_persist_fails(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation when vm.conf persist fails (logs warning but succeeds)."""
        alpine_creator.launcher.send_progress = AsyncMock()
        alpine_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": True}
        )

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": True,
                                                "iso_path": "/var/vmm/alpine.iso",
                                            }

                                            with patch.object(
                                                alpine_creator.disk_ops,
                                                "create_disk_image",
                                            ) as mock_disk:
                                                mock_disk.return_value = {
                                                    "success": True
                                                }

                                                with patch.object(
                                                    alpine_creator,
                                                    "_create_setup_data",
                                                    new_callable=AsyncMock,
                                                ) as mock_setup:
                                                    mock_setup.return_value = {
                                                        "success": True
                                                    }

                                                    with patch.object(
                                                        alpine_creator,
                                                        "_launch_vm_from_iso",
                                                        new_callable=AsyncMock,
                                                    ) as mock_launch:
                                                        mock_launch.return_value = {
                                                            "success": True
                                                        }

                                                        with patch.object(
                                                            alpine_creator,
                                                            "_run_automated_install",
                                                            new_callable=AsyncMock,
                                                        ) as mock_install:
                                                            mock_install.return_value = {
                                                                "success": True
                                                            }

                                                            with patch.object(
                                                                alpine_creator,
                                                                "_wait_for_vm_shutdown",
                                                                new_callable=AsyncMock,
                                                            ) as mock_shutdown:
                                                                mock_shutdown.return_value = {
                                                                    "success": True
                                                                }

                                                                with patch.object(
                                                                    alpine_creator,
                                                                    "_save_vm_metadata",
                                                                ):
                                                                    with patch.object(
                                                                        alpine_creator.vmconf_manager,
                                                                        "persist_vm",
                                                                        return_value=False,  # Persist fails
                                                                    ):
                                                                        result = await alpine_creator.create_alpine_vm(
                                                                            sample_vm_config
                                                                        )

        # Still succeeds, persist failure is just a warning
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_alpine_vm_shutdown_warning(
        self, alpine_creator, sample_vm_config
    ):
        """Test Alpine VM creation logs warning when shutdown times out but continues."""
        alpine_creator.launcher.send_progress = AsyncMock()
        alpine_creator.launcher.launch_vm_from_disk = AsyncMock(
            return_value={"success": True}
        )

        with patch.object(
            alpine_creator, "_validate_and_extract_version", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = (None, "3.20")

            with patch.object(
                alpine_creator, "_check_vmm_ready", new_callable=AsyncMock
            ) as mock_vmm:
                mock_vmm.return_value = {"success": True}

                with patch(
                    "src.sysmanage_agent.operations.child_host_alpine_vm_creator.vm_exists",
                    return_value=False,
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_alpine_vm_creator.ensure_vmm_directories"
                    ):
                        with patch.object(
                            alpine_creator, "_get_agent_version", new_callable=AsyncMock
                        ) as mock_version:
                            mock_version.return_value = ("1.0.0", "v1.0.0")

                            with patch.object(
                                alpine_creator,
                                "_build_site_tarball",
                                new_callable=AsyncMock,
                            ) as mock_site:
                                mock_site.return_value = {
                                    "success": True,
                                    "site_tgz_path": "/var/vmm/site.tgz",
                                }

                                with patch.object(
                                    alpine_creator, "_get_gateway_ip"
                                ) as mock_gateway:
                                    mock_gateway.return_value = "10.0.10.1"

                                    with patch.object(
                                        alpine_creator, "_get_next_vm_ip"
                                    ) as mock_ip:
                                        mock_ip.return_value = "10.0.10.100"

                                        with patch(
                                            "asyncio.to_thread", new_callable=AsyncMock
                                        ) as mock_thread:
                                            mock_thread.return_value = {
                                                "success": True,
                                                "iso_path": "/var/vmm/alpine.iso",
                                            }

                                            with patch.object(
                                                alpine_creator.disk_ops,
                                                "create_disk_image",
                                            ) as mock_disk:
                                                mock_disk.return_value = {
                                                    "success": True
                                                }

                                                with patch.object(
                                                    alpine_creator,
                                                    "_create_setup_data",
                                                    new_callable=AsyncMock,
                                                ) as mock_setup:
                                                    mock_setup.return_value = {
                                                        "success": True
                                                    }

                                                    with patch.object(
                                                        alpine_creator,
                                                        "_launch_vm_from_iso",
                                                        new_callable=AsyncMock,
                                                    ) as mock_launch:
                                                        mock_launch.return_value = {
                                                            "success": True
                                                        }

                                                        with patch.object(
                                                            alpine_creator,
                                                            "_run_automated_install",
                                                            new_callable=AsyncMock,
                                                        ) as mock_install:
                                                            mock_install.return_value = {
                                                                "success": True
                                                            }

                                                            with patch.object(
                                                                alpine_creator,
                                                                "_wait_for_vm_shutdown",
                                                                new_callable=AsyncMock,
                                                            ) as mock_shutdown:
                                                                # Shutdown times out but workflow continues
                                                                mock_shutdown.return_value = {
                                                                    "success": False,
                                                                    "error": "Timeout waiting for VM to shutdown",
                                                                }

                                                                with patch.object(
                                                                    alpine_creator,
                                                                    "_save_vm_metadata",
                                                                ):
                                                                    with patch.object(
                                                                        alpine_creator.vmconf_manager,
                                                                        "persist_vm",
                                                                        return_value=True,
                                                                    ):
                                                                        result = await alpine_creator.create_alpine_vm(
                                                                            sample_vm_config
                                                                        )

        # Still succeeds, shutdown timeout is just a warning
        assert result["success"] is True
        assert result["child_name"] == "test-alpine-vm"
