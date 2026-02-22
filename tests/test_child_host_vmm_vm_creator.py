"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_vmm_vm_creator module.
Tests VMM VM creation orchestration for OpenBSD.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, mock_open, patch

import pytest

from src.sysmanage_agent.operations.child_host_types import (
    VmmResourceConfig,
    VmmServerConfig,
    VmmVmConfig,
)
from src.sysmanage_agent.operations.child_host_vmm_vm_creator import VmmVmCreator


class TestVmmVmCreatorInit:
    """Test cases for VmmVmCreator initialization."""

    def test_init_with_all_dependencies(self):
        """Test VmmVmCreator initialization with all dependencies."""
        mock_agent = Mock()
        mock_logger = Mock()
        mock_virt_checks = Mock()
        mock_httpd_setup = Mock()
        mock_github_checker = Mock()
        mock_site_builder = Mock()

        creator = VmmVmCreator(
            mock_agent,
            mock_logger,
            mock_virt_checks,
            mock_httpd_setup,
            mock_github_checker,
            mock_site_builder,
        )

        assert creator.agent == mock_agent
        assert creator.logger == mock_logger
        assert creator.virtualization_checks == mock_virt_checks
        assert creator.httpd_setup == mock_httpd_setup
        assert creator.github_checker == mock_github_checker
        assert creator.site_builder == mock_site_builder
        assert creator.disk_ops is not None
        assert creator.vmconf_manager is not None
        assert creator.launcher is not None


class TestValidateConfig:
    """Test cases for configuration validation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_httpd_setup = Mock()
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            self.mock_httpd_setup,
            self.mock_github_checker,
            self.mock_site_builder,
        )

    def _create_valid_config(self):
        """Create a valid VM configuration for testing."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=["pkg_add sysmanage-agent"],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
        )

    def test_validate_config_success(self):
        """Test successful configuration validation."""
        config = self._create_valid_config()
        result = self.creator._validate_config(config)

        assert result["success"] is True

    def test_validate_config_missing_distribution(self):
        """Test validation fails when distribution is missing."""
        config = self._create_valid_config()
        config.distribution = ""
        result = self.creator._validate_config(config)

        assert result["success"] is False
        assert "Distribution is required" in result["error"]

    def test_validate_config_missing_vm_name(self):
        """Test validation fails when vm_name is missing."""
        config = self._create_valid_config()
        config.vm_name = ""
        result = self.creator._validate_config(config)

        assert result["success"] is False
        assert "VM name is required" in result["error"]

    def test_validate_config_missing_hostname(self):
        """Test validation fails when hostname is missing."""
        config = self._create_valid_config()
        config.hostname = ""
        result = self.creator._validate_config(config)

        assert result["success"] is False
        assert "Hostname is required" in result["error"]

    def test_validate_config_missing_username(self):
        """Test validation fails when username is missing."""
        config = self._create_valid_config()
        config.username = ""
        result = self.creator._validate_config(config)

        assert result["success"] is False
        assert "Username is required" in result["error"]

    def test_validate_config_missing_password_hash(self):
        """Test validation fails when password_hash is missing."""
        config = self._create_valid_config()
        config.password_hash = ""
        result = self.creator._validate_config(config)

        assert result["success"] is False
        assert "Password hash is required" in result["error"]

    def test_validate_config_missing_server_url(self):
        """Test validation fails when server_url is missing."""
        config = self._create_valid_config()
        config.server_config.server_url = ""
        result = self.creator._validate_config(config)

        assert result["success"] is False
        assert "Server URL is required" in result["error"]


class TestRunSubprocess:
    """Test cases for async subprocess execution."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_run_subprocess_success(self, mock_to_thread):
        """Test successful subprocess execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_to_thread.return_value = mock_result

        result = await self.creator._run_subprocess(["echo", "hello"])

        assert result.returncode == 0
        mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_run_subprocess_with_custom_timeout(self, mock_to_thread):
        """Test subprocess execution with custom timeout."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_to_thread.return_value = mock_result

        await self.creator._run_subprocess(["echo", "hello"], timeout=120)

        # Verify timeout was passed
        call_args = mock_to_thread.call_args
        assert call_args.kwargs.get("timeout") == 120 or 120 in call_args.args


class TestCheckVmmReady:
    """Test cases for VMM readiness checking."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    async def test_check_vmm_ready_success(self):
        """Test successful VMM check."""
        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        result = await self.creator._check_vmm_ready()

        assert result["success"] is True
        self.mock_launcher.send_progress.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_vmm_not_available(self):
        """Test VMM not available."""
        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": False,
            "running": False,
        }

        result = await self.creator._check_vmm_ready()

        assert result["success"] is False
        assert "VMM is not available" in result["error"]

    @pytest.mark.asyncio
    async def test_check_vmm_not_running(self):
        """Test VMM available but not running."""
        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": False,
        }

        result = await self.creator._check_vmm_ready()

        assert result["success"] is False
        assert "vmd is not running" in result["error"]


class TestGetAgentVersion:
    """Test cases for agent version retrieval from GitHub."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_github_checker = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            self.mock_github_checker,
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    async def test_get_agent_version_success(self):
        """Test successful version retrieval."""
        self.mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }

        version, tag = await self.creator._get_agent_version()

        assert version == "1.2.3"
        assert tag == "v1.2.3"
        self.mock_launcher.send_progress.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_agent_version_failure(self):
        """Test version retrieval failure."""
        self.mock_github_checker.get_latest_version.return_value = {
            "success": False,
            "error": "Network error",
        }

        with pytest.raises(RuntimeError) as exc_info:
            await self.creator._get_agent_version()

        assert "Failed to check GitHub version" in str(exc_info.value)


class TestBuildSiteTarball:
    """Test cases for site tarball building."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            self.mock_github_checker,
            self.mock_site_builder,
        )
        self.creator.launcher = self.mock_launcher

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            auto_approve_token="test-token",
        )

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_build_site_tarball_success(self, mock_to_thread):
        """Test successful site tarball build."""
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://github.com/test/tarball.tar.gz"
        )
        mock_to_thread.return_value = {
            "success": True,
            "site_tgz_path": "/tmp/site.tgz",
        }

        config = self._create_valid_config()
        result = await self.creator._build_site_tarball("7.7", "1.2.3", config)

        assert result == "/tmp/site.tgz"
        self.mock_launcher.send_progress.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_build_site_tarball_failure(self, mock_to_thread):
        """Test site tarball build failure."""
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://github.com/test/tarball.tar.gz"
        )
        mock_to_thread.return_value = {
            "success": False,
            "error": "Build failed",
        }

        config = self._create_valid_config()
        with pytest.raises(RuntimeError) as exc_info:
            await self.creator._build_site_tarball("7.7", "1.2.3", config)

        assert "Failed to build site tarball" in str(exc_info.value)


class TestGetGatewayIp:
    """Test cases for gateway IP retrieval."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.subprocess.run")
    def test_get_gateway_ip_success(self, mock_run):
        """Test successful gateway IP retrieval."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="vether0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "        inet 100.64.0.1 netmask 0xffffff00 broadcast 100.64.0.255\n",
        )

        result = self.creator._get_gateway_ip()

        assert result == "100.64.0.1"

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.subprocess.run")
    def test_get_gateway_ip_no_inet(self, mock_run):
        """Test gateway IP when no inet line exists."""
        mock_run.return_value = Mock(
            returncode=0, stdout="vether0: flags=8843<UP> mtu 1500\n"
        )

        result = self.creator._get_gateway_ip()

        assert result is None

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.subprocess.run")
    def test_get_gateway_ip_exception(self, mock_run):
        """Test gateway IP retrieval with exception."""
        mock_run.side_effect = Exception("Network error")

        result = self.creator._get_gateway_ip()

        assert result is None
        self.mock_logger.error.assert_called()


class TestGetNextVmIp:
    """Test cases for VM IP allocation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.Path.exists",
        return_value=False,
    )
    @patch.object(VmmVmCreator, "_is_ip_in_use", return_value=False)
    def test_get_next_vm_ip_first_vm(self, _mock_in_use, _mock_exists):
        """Test first VM gets .100 IP."""
        result = self.creator._get_next_vm_ip("100.64.0.1")

        assert result == "100.64.0.100"

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.Path")
    @patch.object(VmmVmCreator, "_is_ip_in_use", return_value=False)
    def test_get_next_vm_ip_with_existing_vms(self, _mock_in_use, mock_path):
        """Test VM IP allocation with existing VMs."""
        # Mock metadata directory with existing VMs
        mock_metadata_dir = MagicMock()
        mock_metadata_dir.exists.return_value = True
        mock_path.return_value = mock_metadata_dir

        # Mock glob to return metadata files
        mock_file1 = MagicMock()
        mock_metadata_dir.glob.return_value = [mock_file1]

        # Mock file reading
        with patch(
            "builtins.open",
            mock_open(read_data='{"vm_ip": "100.64.0.100"}'),
        ):
            result = self.creator._get_next_vm_ip("100.64.0.1")

        assert result == "100.64.0.101"

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.Path")
    @patch.object(VmmVmCreator, "_is_ip_in_use")
    def test_get_next_vm_ip_skips_in_use(self, mock_in_use, mock_path):
        """Test VM IP allocation skips IPs in use."""
        mock_metadata_dir = MagicMock()
        mock_metadata_dir.exists.return_value = False
        mock_path.return_value = mock_metadata_dir

        # First IP is in use via ping, second is not
        mock_in_use.side_effect = [True, False]

        result = self.creator._get_next_vm_ip("100.64.0.1")

        assert result == "100.64.0.101"


class TestIsIpInUse:
    """Test cases for IP in-use checking."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.subprocess.run")
    def test_is_ip_in_use_true(self, mock_run):
        """Test IP in use detection when ARP entry exists."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="100.64.0.100 (100.64.0.100) at aa:bb:cc:dd:ee:ff on vether0",
        )

        result = self.creator._is_ip_in_use("100.64.0.100")

        assert result is True

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.subprocess.run")
    def test_is_ip_in_use_no_entry(self, mock_run):
        """Test IP not in use when no ARP entry."""
        mock_run.return_value = Mock(returncode=1, stdout="no entry")

        result = self.creator._is_ip_in_use("100.64.0.100")

        assert result is False

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.subprocess.run")
    def test_is_ip_in_use_exception(self, mock_run):
        """Test IP in use check with exception."""
        mock_run.side_effect = Exception("Network error")

        result = self.creator._is_ip_in_use("100.64.0.100")

        assert result is False


class TestSetupHttpAndDownloadSets:
    """Test cases for HTTP setup and set downloading."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_httpd_setup = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            Mock(),
            Mock(),
            self.mock_httpd_setup,
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_setup_http_and_download_success(self, mock_to_thread):
        """Test successful HTTP setup and download."""
        mock_to_thread.side_effect = [
            {"success": True},  # httpd setup
            {"success": True, "sets_dir": "/var/www/htdocs/pub/OpenBSD/7.7/amd64"},
        ]

        result = await self.creator._setup_http_and_download_sets("7.7", "100.64.0.1")

        assert result == Path("/var/www/htdocs/pub/OpenBSD/7.7/amd64")
        assert self.mock_launcher.send_progress.call_count == 2

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_setup_http_httpd_failure(self, mock_to_thread):
        """Test HTTP setup failure."""
        mock_to_thread.return_value = {"success": False, "error": "httpd config failed"}

        with pytest.raises(RuntimeError) as exc_info:
            await self.creator._setup_http_and_download_sets("7.7", "100.64.0.1")

        assert "Failed to setup httpd" in str(exc_info.value)

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_setup_http_download_failure(self, mock_to_thread):
        """Test sets download failure."""
        mock_to_thread.side_effect = [
            {"success": True},  # httpd setup
            {"success": False, "error": "Download failed"},  # sets download
        ]

        with pytest.raises(RuntimeError) as exc_info:
            await self.creator._setup_http_and_download_sets("7.7", "100.64.0.1")

        assert "Failed to download OpenBSD sets" in str(exc_info.value)


class TestCopySiteTarball:
    """Test cases for site tarball copying."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.aiofiles.open")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.shutil.copy2")
    async def test_copy_site_tarball_success(self, mock_copy, mock_aiofiles):
        """Test successful site tarball copy."""
        # Setup mocks
        mock_sets_dir = MagicMock()
        mock_site_dest = MagicMock()
        mock_site_dest.stat.return_value = MagicMock(
            st_size=1024, st_mtime=1234567890.0
        )

        # Mock index.txt not existing
        mock_index_path = MagicMock()
        mock_index_path.exists.return_value = False
        mock_sha_path = MagicMock()
        mock_sha_path.exists.return_value = False

        def mock_div(name):
            if name == "site77.tgz":
                return mock_site_dest
            if name == "index.txt":
                return mock_index_path
            return mock_sha_path

        mock_sets_dir.__truediv__ = Mock(side_effect=mock_div)

        # Mock async file handle for binary read (for SHA256 calculation)
        mock_binary_file_handle = AsyncMock()
        # Return bytes once, then empty bytes to end the read loop
        mock_binary_file_handle.read = AsyncMock(side_effect=[b"test content", b""])

        # Create context manager mock
        mock_binary_context = AsyncMock()
        mock_binary_context.__aenter__ = AsyncMock(return_value=mock_binary_file_handle)
        mock_binary_context.__aexit__ = AsyncMock(return_value=None)

        # aiofiles.open should return the binary context
        mock_aiofiles.return_value = mock_binary_context

        result = await self.creator._copy_site_tarball(
            "/tmp/site.tgz", mock_sets_dir, "7.7"
        )

        assert result == mock_site_dest
        mock_copy.assert_called_once()


class TestCreateAndEmbedInstallConf:
    """Test cases for install.conf creation and embedding."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_httpd_setup = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            Mock(),
            Mock(),
            self.mock_httpd_setup,
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
        )

    @pytest.mark.asyncio
    async def test_create_and_embed_success(self):
        """Test successful install.conf creation and embedding."""
        self.mock_httpd_setup.create_install_conf_content.return_value = (
            "install.conf content"
        )
        self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
            "success": True,
            "bsdrd_path": "/var/www/htdocs/pub/OpenBSD/7.7/amd64/bsd.rd.autoinstall",
        }

        config = self._create_valid_config()
        result = await self.creator._create_and_embed_install_conf(
            config,
            "testvm.example.com",
            "100.64.0.1",
            "7.7",
            Path("/var/www/htdocs/pub/OpenBSD/7.7/amd64"),
            "100.64.0.100",
        )

        assert result == "/var/www/htdocs/pub/OpenBSD/7.7/amd64/bsd.rd.autoinstall"
        self.mock_launcher.send_progress.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_and_embed_failure(self):
        """Test install.conf embedding failure."""
        self.mock_httpd_setup.create_install_conf_content.return_value = (
            "install.conf content"
        )
        self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
            "success": False,
            "error": "Embedding failed",
        }

        config = self._create_valid_config()
        with pytest.raises(RuntimeError) as exc_info:
            await self.creator._create_and_embed_install_conf(
                config,
                "testvm.example.com",
                "100.64.0.1",
                "7.7",
                Path("/var/www/htdocs/pub/OpenBSD/7.7/amd64"),
                "100.64.0.100",
            )

        assert "Failed to embed install.conf" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_and_embed_uses_root_password_hash(self):
        """Test that root_password_hash is used when provided."""
        self.mock_httpd_setup.create_install_conf_content.return_value = (
            "install.conf content"
        )
        self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
            "success": True,
            "bsdrd_path": "/path/to/bsd.rd",
        }

        config = self._create_valid_config()
        config.root_password_hash = "$2b$12$root..."

        await self.creator._create_and_embed_install_conf(
            config,
            "testvm.example.com",
            "100.64.0.1",
            "7.7",
            Path("/var/www/htdocs/pub/OpenBSD/7.7/amd64"),
            "100.64.0.100",
        )

        # Verify root_password_hash was used
        call_args = self.mock_httpd_setup.create_install_conf_content.call_args
        assert call_args.kwargs["root_password_hash"] == "$2b$12$root..."


class TestCreateVmDisk:
    """Test cases for VM disk creation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_disk_ops = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.disk_ops = self.mock_disk_ops
        self.creator.launcher = self.mock_launcher

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(disk_size="20G"),
        )

    @pytest.mark.asyncio
    async def test_create_vm_disk_success(self):
        """Test successful disk creation."""
        self.mock_disk_ops.create_disk_image.return_value = {"success": True}

        config = self._create_valid_config()
        result = await self.creator._create_vm_disk(config)

        assert result == "/var/vmm/testvm.qcow2"
        self.mock_launcher.send_progress.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_vm_disk_failure(self):
        """Test disk creation failure."""
        self.mock_disk_ops.create_disk_image.return_value = {
            "success": False,
            "error": "No space left",
        }

        config = self._create_valid_config()
        result = await self.creator._create_vm_disk(config)

        assert result is None
        self.mock_logger.error.assert_called()


class TestLaunchVmForInstall:
    """Test cases for VM launch during installation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.mock_launcher.launch_vm_with_bsdrd = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(memory="1G"),
        )

    @pytest.mark.asyncio
    async def test_launch_vm_for_install_success(self):
        """Test successful VM launch for installation."""
        self.mock_launcher.launch_vm_with_bsdrd.return_value = {"success": True}

        config = self._create_valid_config()
        result = await self.creator._launch_vm_for_install(
            config, "/var/vmm/testvm.qcow2", "/path/to/bsd.rd"
        )

        assert result["success"] is True
        self.mock_launcher.send_progress.assert_called_once()

    @pytest.mark.asyncio
    async def test_launch_vm_for_install_failure(self):
        """Test VM launch failure."""
        self.mock_launcher.launch_vm_with_bsdrd.return_value = {
            "success": False,
            "error": "VM failed to start",
        }

        config = self._create_valid_config()
        result = await self.creator._launch_vm_for_install(
            config, "/var/vmm/testvm.qcow2", "/path/to/bsd.rd"
        )

        assert result["success"] is False


class TestWaitForInstallationComplete:
    """Test cases for waiting for installation completion."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.mock_launcher.wait_for_vm_shutdown = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    async def test_wait_for_installation_success(self):
        """Test successful installation wait."""
        self.mock_launcher.wait_for_vm_shutdown.return_value = {"success": True}

        result = await self.creator._wait_for_installation_complete("testvm")

        assert result["success"] is True
        self.mock_launcher.send_progress.assert_called_once()
        self.mock_launcher.wait_for_vm_shutdown.assert_called_once_with(
            "testvm", timeout=1800
        )

    @pytest.mark.asyncio
    async def test_wait_for_installation_timeout(self):
        """Test installation wait timeout."""
        self.mock_launcher.wait_for_vm_shutdown.return_value = {
            "success": False,
            "error": "Timeout",
        }

        result = await self.creator._wait_for_installation_complete("testvm")

        assert result["success"] is False


class TestRestartVmFromDisk:
    """Test cases for VM restart from disk."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.mock_launcher.launch_vm_from_disk = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(memory="1G"),
        )

    @pytest.mark.asyncio
    async def test_restart_vm_from_disk_success(self):
        """Test successful VM restart from disk."""
        self.mock_launcher.launch_vm_from_disk.return_value = {"success": True}

        config = self._create_valid_config()
        result = await self.creator._restart_vm_from_disk(
            config, "/var/vmm/testvm.qcow2"
        )

        assert result["success"] is True
        self.mock_launcher.send_progress.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_vm_from_disk_failure(self):
        """Test VM restart failure."""
        self.mock_launcher.launch_vm_from_disk.return_value = {
            "success": False,
            "error": "Failed to start",
        }

        config = self._create_valid_config()
        result = await self.creator._restart_vm_from_disk(
            config, "/var/vmm/testvm.qcow2"
        )

        assert result["success"] is False


class TestCreateVmmVm:
    """Integration-style tests for the main create_vmm_vm method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_httpd_setup = Mock()
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            self.mock_httpd_setup,
            self.mock_github_checker,
            self.mock_site_builder,
        )

        # Mock the launcher
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.mock_launcher.launch_vm_with_bsdrd = AsyncMock()
        self.mock_launcher.wait_for_vm_shutdown = AsyncMock()
        self.mock_launcher.launch_vm_from_disk = AsyncMock()
        self.creator.launcher = self.mock_launcher

        # Mock disk ops
        self.mock_disk_ops = Mock()
        self.creator.disk_ops = self.mock_disk_ops

        # Mock vmconf manager
        self.mock_vmconf_manager = Mock()
        self.creator.vmconf_manager = self.mock_vmconf_manager

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=["pkg_add sysmanage-agent"],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(memory="1G", disk_size="20G"),
        )

    @pytest.mark.asyncio
    async def test_create_vmm_vm_validation_failure(self):
        """Test VM creation fails on validation."""
        config = self._create_valid_config()
        config.vm_name = ""  # Invalid

        result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "VM name is required" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    async def test_create_vmm_vm_version_extraction_failure(self, mock_extract):
        """Test VM creation fails when version extraction fails."""
        mock_extract.return_value = None

        config = self._create_valid_config()
        result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "Could not parse OpenBSD version" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    async def test_create_vmm_vm_already_exists(
        self, mock_exists, mock_fqdn, mock_extract
    ):
        """Test VM creation fails when VM already exists."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = True
        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        config = self._create_valid_config()
        result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.ensure_vmm_directories"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.save_vm_metadata")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_create_vmm_vm_success(
        self,
        mock_to_thread,
        _mock_save_metadata,
        _mock_ensure_dirs,
        mock_exists,
        mock_fqdn,
        mock_extract,
    ):
        """Test successful VM creation."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = False

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        self.mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://test.com/tarball.tgz"
        )

        # Mock asyncio.to_thread for various async operations
        mock_to_thread.side_effect = [
            {"success": True, "site_tgz_path": "/tmp/site.tgz"},  # site builder
            {"success": True},  # httpd setup
            {"success": True, "sets_dir": "/var/www/htdocs/pub/OpenBSD/7.7/amd64"},
        ]

        # Mock gateway IP
        with patch.object(self.creator, "_get_gateway_ip", return_value="100.64.0.1"):
            with patch.object(
                self.creator, "_get_next_vm_ip", return_value="100.64.0.100"
            ):
                with patch.object(
                    self.creator,
                    "_copy_site_tarball",
                    new_callable=AsyncMock,
                    return_value=Path("/var/www/htdocs/site77.tgz"),
                ):
                    self.mock_httpd_setup.create_install_conf_content.return_value = (
                        "install.conf"
                    )
                    self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
                        "success": True,
                        "bsdrd_path": "/path/to/bsd.rd",
                    }
                    self.mock_disk_ops.create_disk_image.return_value = {
                        "success": True
                    }
                    self.mock_launcher.launch_vm_with_bsdrd.return_value = {
                        "success": True
                    }
                    self.mock_launcher.wait_for_vm_shutdown.return_value = {
                        "success": True
                    }
                    self.mock_launcher.launch_vm_from_disk.return_value = {
                        "success": True
                    }
                    self.mock_vmconf_manager.persist_vm.return_value = True

                    config = self._create_valid_config()
                    result = await self.creator.create_vmm_vm(config)

        assert result["success"] is True
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        assert result["openbsd_version"] == "7.7"

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    async def test_create_vmm_vm_vmm_not_ready(
        self, mock_exists, mock_fqdn, mock_extract
    ):
        """Test VM creation fails when VMM is not ready."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = False

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": False,
        }

        config = self._create_valid_config()
        result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "vmd is not running" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.ensure_vmm_directories"
    )
    async def test_create_vmm_vm_no_gateway_ip(
        self, _mock_ensure_dirs, mock_exists, mock_fqdn, mock_extract
    ):
        """Test VM creation fails when gateway IP cannot be determined."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = False

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        self.mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://test.com/tarball.tgz"
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread"
        ) as mock_to_thread:
            mock_to_thread.return_value = {
                "success": True,
                "site_tgz_path": "/tmp/site.tgz",
            }
            with patch.object(self.creator, "_get_gateway_ip", return_value=None):
                config = self._create_valid_config()
                result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "gateway IP" in result["error"]

    @pytest.mark.asyncio
    async def test_create_vmm_vm_exception_handling(self):
        """Test VM creation handles exceptions properly."""
        with patch.object(
            self.creator, "_validate_config", side_effect=Exception("Unexpected error")
        ):
            config = self._create_valid_config()
            result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestCreateVmmVmDiskCreationFailure:
    """Test cases for disk creation failure scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_httpd_setup = Mock()
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            self.mock_httpd_setup,
            self.mock_github_checker,
            self.mock_site_builder,
        )

        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.creator.launcher = self.mock_launcher

        self.mock_disk_ops = Mock()
        self.creator.disk_ops = self.mock_disk_ops

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(memory="1G", disk_size="20G"),
        )

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.ensure_vmm_directories"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_create_vmm_vm_disk_failure(
        self, mock_to_thread, _mock_ensure_dirs, mock_exists, mock_fqdn, mock_extract
    ):
        """Test VM creation fails when disk creation fails."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = False

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        self.mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://test.com/tarball.tgz"
        )

        mock_to_thread.side_effect = [
            {"success": True, "site_tgz_path": "/tmp/site.tgz"},
            {"success": True},
            {"success": True, "sets_dir": "/var/www/htdocs/pub/OpenBSD/7.7/amd64"},
        ]

        with patch.object(self.creator, "_get_gateway_ip", return_value="100.64.0.1"):
            with patch.object(
                self.creator, "_get_next_vm_ip", return_value="100.64.0.100"
            ):
                with patch.object(
                    self.creator,
                    "_copy_site_tarball",
                    new_callable=AsyncMock,
                    return_value=Path("/var/www/htdocs/site77.tgz"),
                ):
                    self.mock_httpd_setup.create_install_conf_content.return_value = (
                        "install.conf"
                    )
                    self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
                        "success": True,
                        "bsdrd_path": "/path/to/bsd.rd",
                    }
                    # Disk creation fails
                    self.mock_disk_ops.create_disk_image.return_value = {
                        "success": False,
                        "error": "No space",
                    }

                    config = self._create_valid_config()
                    result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "Failed to create disk image" in result["error"]


class TestCreateVmmVmLaunchFailure:
    """Test cases for VM launch failure scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_httpd_setup = Mock()
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            self.mock_httpd_setup,
            self.mock_github_checker,
            self.mock_site_builder,
        )

        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.mock_launcher.launch_vm_with_bsdrd = AsyncMock()
        self.creator.launcher = self.mock_launcher

        self.mock_disk_ops = Mock()
        self.creator.disk_ops = self.mock_disk_ops

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(memory="1G", disk_size="20G"),
        )

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.ensure_vmm_directories"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_create_vmm_vm_launch_failure(
        self, mock_to_thread, _mock_ensure_dirs, mock_exists, mock_fqdn, mock_extract
    ):
        """Test VM creation fails when VM launch fails."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = False

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        self.mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://test.com/tarball.tgz"
        )

        mock_to_thread.side_effect = [
            {"success": True, "site_tgz_path": "/tmp/site.tgz"},
            {"success": True},
            {"success": True, "sets_dir": "/var/www/htdocs/pub/OpenBSD/7.7/amd64"},
        ]

        with patch.object(self.creator, "_get_gateway_ip", return_value="100.64.0.1"):
            with patch.object(
                self.creator, "_get_next_vm_ip", return_value="100.64.0.100"
            ):
                with patch.object(
                    self.creator,
                    "_copy_site_tarball",
                    new_callable=AsyncMock,
                    return_value=Path("/var/www/htdocs/site77.tgz"),
                ):
                    self.mock_httpd_setup.create_install_conf_content.return_value = (
                        "install.conf"
                    )
                    self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
                        "success": True,
                        "bsdrd_path": "/path/to/bsd.rd",
                    }
                    self.mock_disk_ops.create_disk_image.return_value = {
                        "success": True
                    }
                    # Launch fails
                    self.mock_launcher.launch_vm_with_bsdrd.return_value = {
                        "success": False,
                        "error": "VM failed to start",
                    }

                    config = self._create_valid_config()
                    result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "VM failed to start" in result["error"]


class TestCreateVmmVmInstallationFailure:
    """Test cases for installation failure scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_httpd_setup = Mock()
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            self.mock_httpd_setup,
            self.mock_github_checker,
            self.mock_site_builder,
        )

        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.mock_launcher.launch_vm_with_bsdrd = AsyncMock()
        self.mock_launcher.wait_for_vm_shutdown = AsyncMock()
        self.creator.launcher = self.mock_launcher

        self.mock_disk_ops = Mock()
        self.creator.disk_ops = self.mock_disk_ops

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(memory="1G", disk_size="20G"),
        )

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.ensure_vmm_directories"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_create_vmm_vm_installation_timeout(
        self, mock_to_thread, _mock_ensure_dirs, mock_exists, mock_fqdn, mock_extract
    ):
        """Test VM creation fails when installation times out."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = False

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        self.mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://test.com/tarball.tgz"
        )

        mock_to_thread.side_effect = [
            {"success": True, "site_tgz_path": "/tmp/site.tgz"},
            {"success": True},
            {"success": True, "sets_dir": "/var/www/htdocs/pub/OpenBSD/7.7/amd64"},
        ]

        with patch.object(self.creator, "_get_gateway_ip", return_value="100.64.0.1"):
            with patch.object(
                self.creator, "_get_next_vm_ip", return_value="100.64.0.100"
            ):
                with patch.object(
                    self.creator,
                    "_copy_site_tarball",
                    new_callable=AsyncMock,
                    return_value=Path("/var/www/htdocs/site77.tgz"),
                ):
                    self.mock_httpd_setup.create_install_conf_content.return_value = (
                        "install.conf"
                    )
                    self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
                        "success": True,
                        "bsdrd_path": "/path/to/bsd.rd",
                    }
                    self.mock_disk_ops.create_disk_image.return_value = {
                        "success": True
                    }
                    self.mock_launcher.launch_vm_with_bsdrd.return_value = {
                        "success": True
                    }
                    # Installation times out
                    self.mock_launcher.wait_for_vm_shutdown.return_value = {
                        "success": False,
                        "error": "Timeout waiting for VM to shutdown",
                    }

                    config = self._create_valid_config()
                    result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "Timeout" in result["error"]


class TestCreateVmmVmRestartFailure:
    """Test cases for VM restart failure scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_httpd_setup = Mock()
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            self.mock_httpd_setup,
            self.mock_github_checker,
            self.mock_site_builder,
        )

        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.mock_launcher.launch_vm_with_bsdrd = AsyncMock()
        self.mock_launcher.wait_for_vm_shutdown = AsyncMock()
        self.mock_launcher.launch_vm_from_disk = AsyncMock()
        self.creator.launcher = self.mock_launcher

        self.mock_disk_ops = Mock()
        self.creator.disk_ops = self.mock_disk_ops

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(memory="1G", disk_size="20G"),
        )

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.ensure_vmm_directories"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_create_vmm_vm_restart_failure(
        self, mock_to_thread, _mock_ensure_dirs, mock_exists, mock_fqdn, mock_extract
    ):
        """Test VM creation fails when VM restart fails."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = False

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        self.mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://test.com/tarball.tgz"
        )

        mock_to_thread.side_effect = [
            {"success": True, "site_tgz_path": "/tmp/site.tgz"},
            {"success": True},
            {"success": True, "sets_dir": "/var/www/htdocs/pub/OpenBSD/7.7/amd64"},
        ]

        with patch.object(self.creator, "_get_gateway_ip", return_value="100.64.0.1"):
            with patch.object(
                self.creator, "_get_next_vm_ip", return_value="100.64.0.100"
            ):
                with patch.object(
                    self.creator,
                    "_copy_site_tarball",
                    new_callable=AsyncMock,
                    return_value=Path("/var/www/htdocs/site77.tgz"),
                ):
                    self.mock_httpd_setup.create_install_conf_content.return_value = (
                        "install.conf"
                    )
                    self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
                        "success": True,
                        "bsdrd_path": "/path/to/bsd.rd",
                    }
                    self.mock_disk_ops.create_disk_image.return_value = {
                        "success": True
                    }
                    self.mock_launcher.launch_vm_with_bsdrd.return_value = {
                        "success": True
                    }
                    self.mock_launcher.wait_for_vm_shutdown.return_value = {
                        "success": True
                    }
                    # Restart fails
                    self.mock_launcher.launch_vm_from_disk.return_value = {
                        "success": False,
                        "error": "Failed to restart VM",
                    }

                    config = self._create_valid_config()
                    result = await self.creator.create_vmm_vm(config)

        assert result["success"] is False
        assert "Failed to restart VM" in result["error"]


class TestGetNextVmIpEdgeCases:
    """Edge case tests for VM IP allocation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.Path")
    @patch.object(VmmVmCreator, "_is_ip_in_use", return_value=False)
    def test_get_next_vm_ip_json_decode_error(self, _mock_in_use, mock_path):
        """Test VM IP allocation handles invalid JSON in metadata."""
        mock_metadata_dir = MagicMock()
        mock_metadata_dir.exists.return_value = True
        mock_path.return_value = mock_metadata_dir

        mock_file = MagicMock()
        mock_metadata_dir.glob.return_value = [mock_file]

        # Mock file reading with invalid JSON
        with patch("builtins.open", mock_open(read_data="invalid json")):
            result = self.creator._get_next_vm_ip("100.64.0.1")

        # Should still work, skipping the invalid file
        assert result == "100.64.0.100"

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.Path")
    @patch.object(VmmVmCreator, "_is_ip_in_use", return_value=False)
    def test_get_next_vm_ip_file_read_error(self, _mock_in_use, mock_path):
        """Test VM IP allocation handles file read errors."""
        mock_metadata_dir = MagicMock()
        mock_metadata_dir.exists.return_value = True
        mock_path.return_value = mock_metadata_dir

        mock_file = MagicMock()
        mock_metadata_dir.glob.return_value = [mock_file]

        # Mock file reading with OSError
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = self.creator._get_next_vm_ip("100.64.0.1")

        # Should still work, skipping the unreadable file
        assert result == "100.64.0.100"


class TestCopySiteTarballEdgeCases:
    """Edge case tests for site tarball copying."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.aiofiles.open")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.shutil.copy2")
    async def test_copy_site_tarball_site_already_in_index(
        self, _mock_copy, mock_aiofiles
    ):
        """Test site tarball not added to index if already present."""
        mock_sets_dir = MagicMock()
        mock_site_dest = MagicMock()
        mock_site_dest.stat.return_value = MagicMock(
            st_size=1024, st_mtime=1234567890.0
        )

        mock_index_path = MagicMock()
        mock_index_path.exists.return_value = True

        mock_sha_path = MagicMock()
        mock_sha_path.exists.return_value = False

        def mock_div(name):
            if name == "site77.tgz":
                return mock_site_dest
            if name == "index.txt":
                return mock_index_path
            return mock_sha_path

        mock_sets_dir.__truediv__ = Mock(side_effect=mock_div)

        # Track which mode was used for each open call
        call_count = [0]

        def aiofiles_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            mock_context = AsyncMock()
            mock_file_handle = AsyncMock()

            # First call is for reading index.txt (text mode)
            # Second call is for reading the binary site tarball for SHA256
            if call_count[0] == 1:
                # Text file read (index.txt)
                mock_file_handle.read = AsyncMock(
                    return_value="site77.tgz already in list"
                )
            else:
                # Binary file read (site tarball for SHA256)
                mock_file_handle.read = AsyncMock(side_effect=[b"test content", b""])

            mock_context.__aenter__ = AsyncMock(return_value=mock_file_handle)
            mock_context.__aexit__ = AsyncMock(return_value=None)
            return mock_context

        mock_aiofiles.side_effect = aiofiles_open_side_effect

        result = await self.creator._copy_site_tarball(
            "/tmp/site.tgz", mock_sets_dir, "7.7"
        )

        assert result == mock_site_dest


class TestVmConfManagerIntegration:
    """Tests for vmconf_manager integration in VM creation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_httpd_setup = Mock()
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            self.mock_httpd_setup,
            self.mock_github_checker,
            self.mock_site_builder,
        )

        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.mock_launcher.launch_vm_with_bsdrd = AsyncMock()
        self.mock_launcher.wait_for_vm_shutdown = AsyncMock()
        self.mock_launcher.launch_vm_from_disk = AsyncMock()
        self.creator.launcher = self.mock_launcher

        self.mock_disk_ops = Mock()
        self.creator.disk_ops = self.mock_disk_ops

        self.mock_vmconf_manager = Mock()
        self.creator.vmconf_manager = self.mock_vmconf_manager

    def _create_valid_config(self):
        """Create a valid VM configuration."""
        return VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm.example.com",
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
            resource_config=VmmResourceConfig(memory="1G", disk_size="20G"),
        )

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.vm_exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.ensure_vmm_directories"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.save_vm_metadata")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.asyncio.to_thread")
    async def test_vmconf_persist_failure_logs_warning(
        self,
        mock_to_thread,
        _mock_save_metadata,
        _mock_ensure_dirs,
        mock_exists,
        mock_fqdn,
        mock_extract,
    ):
        """Test that vmconf persist failure logs a warning but doesn't fail creation."""
        mock_extract.return_value = "7.7"
        mock_fqdn.return_value = "testvm.example.com"
        mock_exists.return_value = False

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": True,
        }

        self.mock_github_checker.get_latest_version.return_value = {
            "success": True,
            "version": "1.2.3",
            "tag_name": "v1.2.3",
        }
        self.mock_github_checker.get_port_tarball_url.return_value = (
            "https://test.com/tarball.tgz"
        )

        mock_to_thread.side_effect = [
            {"success": True, "site_tgz_path": "/tmp/site.tgz"},
            {"success": True},
            {"success": True, "sets_dir": "/var/www/htdocs/pub/OpenBSD/7.7/amd64"},
        ]

        with patch.object(self.creator, "_get_gateway_ip", return_value="100.64.0.1"):
            with patch.object(
                self.creator, "_get_next_vm_ip", return_value="100.64.0.100"
            ):
                with patch.object(
                    self.creator,
                    "_copy_site_tarball",
                    new_callable=AsyncMock,
                    return_value=Path("/var/www/htdocs/site77.tgz"),
                ):
                    self.mock_httpd_setup.create_install_conf_content.return_value = (
                        "install.conf"
                    )
                    self.mock_httpd_setup.embed_install_conf_in_bsdrd.return_value = {
                        "success": True,
                        "bsdrd_path": "/path/to/bsd.rd",
                    }
                    self.mock_disk_ops.create_disk_image.return_value = {
                        "success": True
                    }
                    self.mock_launcher.launch_vm_with_bsdrd.return_value = {
                        "success": True
                    }
                    self.mock_launcher.wait_for_vm_shutdown.return_value = {
                        "success": True
                    }
                    self.mock_launcher.launch_vm_from_disk.return_value = {
                        "success": True
                    }
                    # vmconf persist fails
                    self.mock_vmconf_manager.persist_vm.return_value = False

                    config = self._create_valid_config()
                    result = await self.creator.create_vmm_vm(config)

        # Creation should still succeed
        assert result["success"] is True
        # But a warning should be logged
        self.mock_logger.warning.assert_called()


class TestFqdnHostnameLogging:
    """Test cases for FQDN hostname logging."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.mock_virt_checks = Mock()
        self.mock_httpd_setup = Mock()
        self.mock_github_checker = Mock()
        self.mock_site_builder = Mock()

        self.creator = VmmVmCreator(
            self.mock_agent,
            self.mock_logger,
            self.mock_virt_checks,
            self.mock_httpd_setup,
            self.mock_github_checker,
            self.mock_site_builder,
        )

        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_vm_creator.extract_openbsd_version"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.get_fqdn_hostname")
    async def test_fqdn_different_from_hostname_logs(self, mock_fqdn, mock_extract):
        """Test that when FQDN differs from hostname, it is logged."""
        mock_extract.return_value = "7.7"
        # Return a different FQDN than what was provided
        mock_fqdn.return_value = "testvm.example.com"

        self.mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "running": False,  # Cause early exit for simpler test
        }

        # Config with short hostname that will be expanded to FQDN
        config = VmmVmConfig(
            distribution="OpenBSD 7.7",
            vm_name="testvm",
            hostname="testvm",  # Short hostname, will be expanded
            username="testuser",
            password_hash="$2b$12$...",
            agent_install_commands=[],
            server_config=VmmServerConfig(server_url="https://sysmanage.example.com"),
        )

        await self.creator.create_vmm_vm(config)

        # Verify that the FQDN difference was logged
        log_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("FQDN hostname" in str(call) for call in log_calls)


class TestGetNextVmIpFallback:
    """Test cases for VM IP allocation fallback."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )

    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.Path")
    @patch.object(VmmVmCreator, "_is_ip_in_use")
    def test_get_next_vm_ip_all_ips_in_use_fallback(self, mock_in_use, mock_path):
        """Test VM IP allocation fallback when all IPs are in use."""
        mock_metadata_dir = MagicMock()
        mock_metadata_dir.exists.return_value = False
        mock_path.return_value = mock_metadata_dir

        # All IPs are in use
        mock_in_use.return_value = True

        result = self.creator._get_next_vm_ip("100.64.0.1")

        # Should return fallback .100 even though it's in use
        assert result == "100.64.0.100"


class TestCopySiteTarballIndexUpdate:
    """Test cases for site tarball index.txt update."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.aiofiles.open")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.shutil.copy2")
    async def test_copy_site_tarball_updates_index_txt(self, _mock_copy, mock_aiofiles):
        """Test that index.txt is updated when site tarball is not in it."""
        mock_sets_dir = MagicMock()
        mock_site_dest = MagicMock()
        mock_site_dest.stat.return_value = MagicMock(
            st_size=1024, st_mtime=1234567890.0
        )

        mock_index_path = MagicMock()
        mock_index_path.exists.return_value = True

        mock_sha_path = MagicMock()
        mock_sha_path.exists.return_value = False

        def mock_div(name):
            if name == "site77.tgz":
                return mock_site_dest
            if name == "index.txt":
                return mock_index_path
            return mock_sha_path

        mock_sets_dir.__truediv__ = Mock(side_effect=mock_div)

        # Track calls to aiofiles.open
        call_count = [0]
        written_content = []

        def aiofiles_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            mock_context = AsyncMock()
            mock_file_handle = AsyncMock()

            if call_count[0] == 1:
                # First call - reading index.txt (site77.tgz NOT in content)
                mock_file_handle.read = AsyncMock(return_value="base77.tgz\ncomp77.tgz")
            elif call_count[0] == 2:
                # Second call - writing to index.txt

                async def capture_write(content):
                    written_content.append(content)

                mock_file_handle.write = capture_write
            else:
                # Binary read for SHA256
                mock_file_handle.read = AsyncMock(side_effect=[b"test content", b""])

            mock_context.__aenter__ = AsyncMock(return_value=mock_file_handle)
            mock_context.__aexit__ = AsyncMock(return_value=None)
            return mock_context

        mock_aiofiles.side_effect = aiofiles_open_side_effect

        result = await self.creator._copy_site_tarball(
            "/tmp/site.tgz", mock_sets_dir, "7.7"
        )

        assert result == mock_site_dest
        # Verify index.txt was updated
        assert len(written_content) > 0
        assert "site77.tgz" in written_content[0]


class TestCopySiteTarballSha256Update:
    """Test cases for site tarball SHA256 update."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_launcher = Mock()
        self.mock_launcher.send_progress = AsyncMock()

        self.creator = VmmVmCreator(
            Mock(),
            self.mock_logger,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        )
        self.creator.launcher = self.mock_launcher

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.aiofiles.open")
    @patch("src.sysmanage_agent.operations.child_host_vmm_vm_creator.shutil.copy2")
    async def test_copy_site_tarball_updates_sha256(self, _mock_copy, mock_aiofiles):
        """Test that SHA256 files are updated when site tarball is not in them."""
        mock_sets_dir = MagicMock()
        mock_site_dest = MagicMock()
        mock_site_dest.stat.return_value = MagicMock(
            st_size=1024, st_mtime=1234567890.0
        )

        mock_index_path = MagicMock()
        mock_index_path.exists.return_value = False

        mock_sha_path = MagicMock()
        mock_sha_path.exists.return_value = True

        def mock_div(name):
            if name == "site77.tgz":
                return mock_site_dest
            if name == "index.txt":
                return mock_index_path
            return mock_sha_path

        mock_sets_dir.__truediv__ = Mock(side_effect=mock_div)

        # Track calls to aiofiles.open
        call_count = [0]
        written_content = []

        def aiofiles_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            mock_context = AsyncMock()
            mock_file_handle = AsyncMock()

            if call_count[0] == 1:
                # First call - binary read for SHA256 calculation
                mock_file_handle.read = AsyncMock(side_effect=[b"test content", b""])
            elif call_count[0] in [2, 4]:
                # Reading SHA256 or SHA256.sig (site77.tgz NOT in content)
                mock_file_handle.read = AsyncMock(
                    return_value="SHA256 (base77.tgz) = abc123"
                )
            else:
                # Writing to SHA256 or SHA256.sig

                async def capture_write(content):
                    written_content.append(content)

                mock_file_handle.write = capture_write

            mock_context.__aenter__ = AsyncMock(return_value=mock_file_handle)
            mock_context.__aexit__ = AsyncMock(return_value=None)
            return mock_context

        mock_aiofiles.side_effect = aiofiles_open_side_effect

        result = await self.creator._copy_site_tarball(
            "/tmp/site.tgz", mock_sets_dir, "7.7"
        )

        assert result == mock_site_dest
        # Verify SHA256 was updated (written_content should have SHA256 entries)
        assert any("site77.tgz" in content for content in written_content)
