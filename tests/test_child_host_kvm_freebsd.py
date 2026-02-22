"""
Comprehensive unit tests for FreeBSD KVM provisioning operations.

Tests cover:
- FreeBSDProvisioner initialization
- SSH key pair generation
- FreeBSD distribution detection
- User-data generation
- Meta-data generation
- Bootstrap script generation
- Config disk creation
- Image provisioning
- SSH bootstrap execution
- PTY-based bootstrap
- sshpass installation
- Cleanup operations
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import asyncio
import logging
import subprocess
from unittest.mock import AsyncMock, Mock, patch, mock_open

import pytest

from src.sysmanage_agent.operations.child_host_kvm_freebsd import (
    FreeBSDProvisioner,
    _SSH_STRICT_HOST_KEY_CHECKING,
    _SSH_USER_KNOWN_HOSTS_FILE,
)
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_freebsd")


@pytest.fixture
def provisioner(logger):
    """Create a FreeBSDProvisioner instance for testing."""
    return FreeBSDProvisioner(logger)


@pytest.fixture
def sample_config():
    """Create a sample VM configuration for testing."""
    return KvmVmConfig(
        distribution="freebsd:14.0",
        vm_name="test-freebsd-vm",
        hostname="test-freebsd.example.com",
        username="testuser",
        password_hash="$6$rounds=4096$abc$xyz",
        server_url="https://server.example.com",
        agent_install_commands=[],
        server_port=8443,
        use_https=True,
        auto_approve_token="test-token-123",
    )


@pytest.fixture
def sample_config_no_token():
    """Create a sample VM configuration without auto-approve token."""
    return KvmVmConfig(
        distribution="freebsd:14.0",
        vm_name="test-freebsd-vm",
        hostname="test-freebsd.example.com",
        username="testuser",
        password_hash="$6$rounds=4096$abc$xyz",
        server_url="https://server.example.com",
        agent_install_commands=[],
        server_port=8443,
        use_https=False,
    )


class TestFreeBSDProvisionerInit:
    """Tests for FreeBSDProvisioner initialization."""

    def test_init_sets_logger(self, provisioner, logger):
        """Test that __init__ sets logger."""
        assert provisioner.logger == logger

    def test_init_config_disk_path_is_none(self, provisioner):
        """Test that config disk path is initially None."""
        assert provisioner._config_disk_path is None

    def test_init_ssh_private_key_path_is_none(self, provisioner):
        """Test that SSH private key path is initially None."""
        assert provisioner._ssh_private_key_path is None

    def test_init_ssh_public_key_is_none(self, provisioner):
        """Test that SSH public key is initially None."""
        assert provisioner._ssh_public_key is None

    def test_init_bootstrap_username_is_none(self, provisioner):
        """Test that bootstrap username is initially None."""
        assert provisioner._bootstrap_username is None

    def test_init_temp_root_password_is_none(self, provisioner):
        """Test that temp root password is initially None."""
        assert provisioner._temp_root_password is None


class TestIsFreeBSD:
    """Tests for is_freebsd method."""

    def test_is_freebsd_with_freebsd_distribution(self, provisioner, sample_config):
        """Test detection of FreeBSD distribution."""
        sample_config.distribution = "freebsd:14.0"
        assert provisioner.is_freebsd(sample_config) is True

    def test_is_freebsd_with_freebsd_uppercase(self, provisioner, sample_config):
        """Test detection of FreeBSD with uppercase."""
        sample_config.distribution = "FreeBSD:14.0"
        assert provisioner.is_freebsd(sample_config) is True

    def test_is_freebsd_with_bsd_suffix(self, provisioner, sample_config):
        """Test detection with BSD suffix."""
        sample_config.distribution = "openbsd:7.0"
        assert provisioner.is_freebsd(sample_config) is True

    def test_is_freebsd_with_linux(self, provisioner, sample_config):
        """Test that Linux is not detected as FreeBSD."""
        sample_config.distribution = "ubuntu:22.04"
        assert provisioner.is_freebsd(sample_config) is False

    def test_is_freebsd_with_windows(self, provisioner, sample_config):
        """Test that Windows is not detected as FreeBSD."""
        sample_config.distribution = "windows:11"
        assert provisioner.is_freebsd(sample_config) is False


class TestGenerateSshKeypair:
    """Tests for _generate_ssh_keypair method."""

    def test_generate_ssh_keypair_success(self, provisioner):
        """Test successful SSH key generation."""
        mock_pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 sysmanage-bootstrap-test-vm"

        with patch("tempfile.mkdtemp", return_value="/tmp/test_ssh_dir"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("builtins.open", mock_open(read_data=mock_pub_key)):
                    result = provisioner._generate_ssh_keypair("test-vm")

        assert result["success"] is True
        assert result["private_key_path"] == "/tmp/test_ssh_dir/bootstrap_key"
        assert result["public_key"] == mock_pub_key
        assert provisioner._ssh_private_key_path == "/tmp/test_ssh_dir/bootstrap_key"
        assert provisioner._ssh_public_key == mock_pub_key
        assert provisioner._temp_root_password is not None

    def test_generate_ssh_keypair_failure(self, provisioner):
        """Test SSH key generation failure."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_ssh_dir"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="", stderr="ssh-keygen: error"
                )
                result = provisioner._generate_ssh_keypair("test-vm")

        assert result["success"] is False
        assert "error" in result
        assert "ssh-keygen" in result["error"].lower()

    def test_generate_ssh_keypair_exception(self, provisioner):
        """Test SSH key generation with exception."""
        with patch("tempfile.mkdtemp", side_effect=OSError("Cannot create temp dir")):
            result = provisioner._generate_ssh_keypair("test-vm")

        assert result["success"] is False
        assert "error" in result


class TestGenerateUserData:
    """Tests for _generate_user_data method."""

    def test_generate_user_data_basic(self, provisioner, sample_config):
        """Test basic user-data generation."""
        user_data = provisioner._generate_user_data(sample_config)

        assert "#cloud-config" in user_data
        assert "hostname: test-freebsd" in user_data
        assert "fqdn: test-freebsd.example.com" in user_data
        assert "name: testuser" in user_data
        assert 'passwd: "$6$rounds=4096$abc$xyz"' in user_data
        assert "ssh_pwauth: true" in user_data
        assert "disable_root: false" in user_data

    def test_generate_user_data_with_ssh_key(self, provisioner, sample_config):
        """Test user-data generation with SSH key."""
        provisioner._ssh_public_key = "ssh-ed25519 AAAAC3NzaC1 test-key"
        user_data = provisioner._generate_user_data(sample_config)

        assert "ssh_authorized_keys:" in user_data
        assert "ssh-ed25519 AAAAC3NzaC1 test-key" in user_data

    def test_generate_user_data_with_root_password(self, provisioner, sample_config):
        """Test user-data generation with root password."""
        provisioner._temp_root_password = "temppassword123"
        user_data = provisioner._generate_user_data(sample_config)

        assert "chpasswd:" in user_data
        assert "root:temppassword123" in user_data
        assert "expire: false" in user_data

    def test_generate_user_data_without_ssh_key(self, provisioner, sample_config):
        """Test user-data generation without SSH key."""
        provisioner._ssh_public_key = None
        user_data = provisioner._generate_user_data(sample_config)

        assert "ssh_authorized_keys:" not in user_data


class TestGenerateBootstrapScript:
    """Tests for _generate_bootstrap_script method."""

    def test_generate_bootstrap_script_basic(self, provisioner, sample_config):
        """Test basic bootstrap script generation."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_freebsd.get_host_dns_servers",
            return_value=["8.8.8.8", "8.8.4.4"],
        ):
            script = provisioner._generate_bootstrap_script(sample_config)

        assert "#!/bin/sh" in script
        assert "FreeBSD sysmanage-agent Bootstrap" in script
        assert "pkg install -y sudo" in script
        assert "pkg install -y python311" in script
        assert 'server:\n  hostname: "https://server.example.com"' in script
        assert "port: 8443" in script
        assert "use_https: true" in script
        assert 'hostname: "test-freebsd.example.com"' in script

    def test_generate_bootstrap_script_with_auto_approve(
        self, provisioner, sample_config
    ):
        """Test bootstrap script with auto-approve token."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_freebsd.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            script = provisioner._generate_bootstrap_script(sample_config)

        assert "auto_approve:" in script
        assert 'token: "test-token-123"' in script

    def test_generate_bootstrap_script_without_auto_approve(
        self, provisioner, sample_config_no_token
    ):
        """Test bootstrap script without auto-approve token."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_freebsd.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            script = provisioner._generate_bootstrap_script(sample_config_no_token)

        assert "auto_approve:" not in script
        assert "use_https: false" in script

    def test_generate_bootstrap_script_dns_config(self, provisioner, sample_config):
        """Test bootstrap script includes DNS configuration."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_freebsd.get_host_dns_servers",
            return_value=["1.1.1.1", "9.9.9.9"],
        ):
            script = provisioner._generate_bootstrap_script(sample_config)

        assert 'echo "nameserver 1.1.1.1" >> /etc/resolv.conf' in script
        assert 'echo "nameserver 9.9.9.9" >> /etc/resolv.conf' in script


class TestGenerateMetaData:
    """Tests for _generate_meta_data method."""

    def test_generate_meta_data(self, provisioner, sample_config):
        """Test meta-data generation."""
        meta_data = provisioner._generate_meta_data(sample_config)

        assert "instance-id: test-freebsd-vm" in meta_data
        assert "local-hostname: test-freebsd" in meta_data

    def test_generate_meta_data_with_simple_hostname(self, provisioner, sample_config):
        """Test meta-data generation with simple hostname."""
        sample_config.hostname = "simplehost"
        sample_config.vm_name = "simple-vm"
        meta_data = provisioner._generate_meta_data(sample_config)

        assert "instance-id: simple-vm" in meta_data
        assert "local-hostname: simplehost" in meta_data


class TestCreateConfigDisk:
    """Tests for create_config_disk method."""

    def test_create_config_disk_success_genisoimage(self, provisioner, sample_config):
        """Test successful config disk creation with genisoimage."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_config"):
            with patch("builtins.open", mock_open()):
                with patch("os.chmod"):
                    with patch(
                        "shutil.which",
                        side_effect=lambda cmd: (
                            "/usr/bin/genisoimage" if cmd == "genisoimage" else None
                        ),
                    ):
                        with patch("subprocess.run") as mock_run:
                            mock_run.return_value = Mock(
                                returncode=0, stdout="", stderr=""
                            )
                            with patch("shutil.rmtree"):
                                with patch(
                                    "src.sysmanage_agent.operations.child_host_kvm_freebsd.get_host_dns_servers",
                                    return_value=["8.8.8.8"],
                                ):
                                    result = provisioner.create_config_disk(
                                        sample_config, "/var/lib/libvirt/images"
                                    )

        assert result["success"] is True
        assert "config_disk_path" in result
        assert "test-freebsd-vm-freebsd-config.iso" in result["config_disk_path"]

    def test_create_config_disk_success_mkisofs(self, provisioner, sample_config):
        """Test successful config disk creation with mkisofs."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_config"):
            with patch("builtins.open", mock_open()):
                with patch("os.chmod"):
                    with patch(
                        "shutil.which",
                        side_effect=lambda cmd: (
                            "/usr/bin/mkisofs" if cmd == "mkisofs" else None
                        ),
                    ):
                        with patch("subprocess.run") as mock_run:
                            mock_run.return_value = Mock(
                                returncode=0, stdout="", stderr=""
                            )
                            with patch("shutil.rmtree"):
                                with patch(
                                    "src.sysmanage_agent.operations.child_host_kvm_freebsd.get_host_dns_servers",
                                    return_value=["8.8.8.8"],
                                ):
                                    result = provisioner.create_config_disk(
                                        sample_config, "/var/lib/libvirt/images"
                                    )

        assert result["success"] is True

    def test_create_config_disk_no_iso_tool(self, provisioner, sample_config):
        """Test config disk creation when no ISO tool is available."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_config"):
            with patch("builtins.open", mock_open()):
                with patch("os.chmod"):
                    with patch("shutil.which", return_value=None):
                        with patch("shutil.rmtree"):
                            with patch(
                                "src.sysmanage_agent.operations.child_host_kvm_freebsd.get_host_dns_servers",
                                return_value=["8.8.8.8"],
                            ):
                                result = provisioner.create_config_disk(
                                    sample_config, "/var/lib/libvirt/images"
                                )

        assert result["success"] is False
        assert "ISO creation tool" in result["error"]

    def test_create_config_disk_iso_creation_failure(self, provisioner, sample_config):
        """Test config disk creation when ISO creation fails."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_config"):
            with patch("builtins.open", mock_open()):
                with patch("os.chmod"):
                    with patch(
                        "shutil.which",
                        side_effect=lambda cmd: (
                            "/usr/bin/genisoimage" if cmd == "genisoimage" else None
                        ),
                    ):
                        with patch("subprocess.run") as mock_run:
                            mock_run.return_value = Mock(
                                returncode=1,
                                stdout="",
                                stderr="genisoimage: permission denied",
                            )
                            with patch("shutil.rmtree"):
                                with patch(
                                    "src.sysmanage_agent.operations.child_host_kvm_freebsd.get_host_dns_servers",
                                    return_value=["8.8.8.8"],
                                ):
                                    result = provisioner.create_config_disk(
                                        sample_config, "/var/lib/libvirt/images"
                                    )

        assert result["success"] is False
        assert "permission denied" in result["error"]

    def test_create_config_disk_exception(self, provisioner, sample_config):
        """Test config disk creation with exception."""
        with patch("tempfile.mkdtemp", side_effect=OSError("Cannot create temp dir")):
            result = provisioner.create_config_disk(
                sample_config, "/var/lib/libvirt/images"
            )

        assert result["success"] is False
        assert "error" in result


class TestProvisionImage:
    """Tests for provision_image method."""

    def test_provision_image_success(self, provisioner, sample_config):
        """Test successful image provisioning."""

        def set_ssh_key_path(*_args, **_kwargs):
            provisioner._ssh_private_key_path = "/tmp/key"
            return {"success": True, "private_key_path": "/tmp/key"}

        with patch.object(
            provisioner, "_generate_ssh_keypair", side_effect=set_ssh_key_path
        ):
            with patch.object(provisioner, "create_config_disk") as mock_disk:
                mock_disk.return_value = {
                    "success": True,
                    "config_disk_path": "/tmp/config.iso",
                }
                result = provisioner.provision_image(
                    "/var/lib/libvirt/images/test.qcow2", sample_config
                )

        assert result["success"] is True
        assert result["config_disk_path"] == "/tmp/config.iso"
        assert result["ssh_key_available"] is True
        assert sample_config.freebsd_config_disk == "/tmp/config.iso"

    def test_provision_image_ssh_key_failure_continues(
        self, provisioner, sample_config
    ):
        """Test provisioning continues when SSH key generation fails."""
        with patch.object(provisioner, "_generate_ssh_keypair") as mock_ssh:
            mock_ssh.return_value = {"success": False, "error": "keygen failed"}
            with patch.object(provisioner, "create_config_disk") as mock_disk:
                mock_disk.return_value = {
                    "success": True,
                    "config_disk_path": "/tmp/config.iso",
                }
                result = provisioner.provision_image(
                    "/var/lib/libvirt/images/test.qcow2", sample_config
                )

        assert result["success"] is True
        assert result["ssh_key_available"] is False

    def test_provision_image_config_disk_failure(self, provisioner, sample_config):
        """Test provisioning when config disk creation fails."""
        with patch.object(provisioner, "_generate_ssh_keypair") as mock_ssh:
            mock_ssh.return_value = {"success": True, "private_key_path": "/tmp/key"}
            with patch.object(provisioner, "create_config_disk") as mock_disk:
                mock_disk.return_value = {
                    "success": False,
                    "error": "ISO creation failed",
                }
                result = provisioner.provision_image(
                    "/var/lib/libvirt/images/test.qcow2", sample_config
                )

        assert result["success"] is False
        assert "ISO creation failed" in result["error"]

    def test_provision_image_exception(self, provisioner, sample_config):
        """Test provisioning with exception."""
        with patch.object(
            provisioner, "_generate_ssh_keypair", side_effect=Exception("Unexpected")
        ):
            result = provisioner.provision_image(
                "/var/lib/libvirt/images/test.qcow2", sample_config
            )

        assert result["success"] is False
        assert "error" in result


class TestGetConfigDiskPath:
    """Tests for get_config_disk_path method."""

    def test_get_config_disk_path_none(self, provisioner):
        """Test getting config disk path when not set."""
        assert provisioner.get_config_disk_path() is None

    def test_get_config_disk_path_set(self, provisioner):
        """Test getting config disk path when set."""
        provisioner._config_disk_path = "/var/lib/libvirt/images/config.iso"
        assert (
            provisioner.get_config_disk_path() == "/var/lib/libvirt/images/config.iso"
        )


class TestHasSshKey:
    """Tests for has_ssh_key method."""

    def test_has_ssh_key_false(self, provisioner):
        """Test has_ssh_key when no key available."""
        assert provisioner.has_ssh_key() is False

    def test_has_ssh_key_true(self, provisioner):
        """Test has_ssh_key when key available."""
        provisioner._ssh_private_key_path = "/tmp/key"
        assert provisioner.has_ssh_key() is True


class TestInstallSshpass:
    """Tests for _install_sshpass method."""

    def test_install_sshpass_apt(self, provisioner):
        """Test installing sshpass via apt."""
        with patch(
            "shutil.which",
            side_effect=lambda cmd: "/usr/bin/apt-get" if cmd == "apt-get" else None,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = provisioner._install_sshpass()

        assert result["success"] is True
        mock_run.assert_called_once()
        assert "apt-get" in mock_run.call_args[0][0]

    def test_install_sshpass_dnf(self, provisioner):
        """Test installing sshpass via dnf."""
        with patch(
            "shutil.which",
            side_effect=lambda cmd: "/usr/bin/dnf" if cmd == "dnf" else None,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = provisioner._install_sshpass()

        assert result["success"] is True
        assert "dnf" in mock_run.call_args[0][0]

    def test_install_sshpass_yum(self, provisioner):
        """Test installing sshpass via yum."""
        with patch(
            "shutil.which",
            side_effect=lambda cmd: "/usr/bin/yum" if cmd == "yum" else None,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = provisioner._install_sshpass()

        assert result["success"] is True
        assert "yum" in mock_run.call_args[0][0]

    def test_install_sshpass_zypper(self, provisioner):
        """Test installing sshpass via zypper."""
        with patch(
            "shutil.which",
            side_effect=lambda cmd: "/usr/bin/zypper" if cmd == "zypper" else None,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = provisioner._install_sshpass()

        assert result["success"] is True
        assert "zypper" in mock_run.call_args[0][0]

    def test_install_sshpass_apk(self, provisioner):
        """Test installing sshpass via apk."""
        with patch(
            "shutil.which",
            side_effect=lambda cmd: "/sbin/apk" if cmd == "apk" else None,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = provisioner._install_sshpass()

        assert result["success"] is True
        assert "apk" in mock_run.call_args[0][0]

    def test_install_sshpass_no_package_manager(self, provisioner):
        """Test installing sshpass when no package manager found."""
        with patch("shutil.which", return_value=None):
            result = provisioner._install_sshpass()

        assert result["success"] is False
        assert "Could not detect package manager" in result["error"]

    def test_install_sshpass_failure(self, provisioner):
        """Test sshpass installation failure."""
        with patch(
            "shutil.which",
            side_effect=lambda cmd: "/usr/bin/apt-get" if cmd == "apt-get" else None,
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="", stderr="Package not found"
                )
                result = provisioner._install_sshpass()

        assert result["success"] is False
        assert "Package not found" in result["error"]

    def test_install_sshpass_timeout(self, provisioner):
        """Test sshpass installation timeout."""
        with patch(
            "shutil.which",
            side_effect=lambda cmd: "/usr/bin/apt-get" if cmd == "apt-get" else None,
        ):
            with patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("apt", 120)
            ):
                result = provisioner._install_sshpass()

        assert result["success"] is False
        assert "Timeout" in result["error"]

    def test_install_sshpass_exception(self, provisioner):
        """Test sshpass installation with exception."""
        with patch(
            "shutil.which",
            side_effect=lambda cmd: "/usr/bin/apt-get" if cmd == "apt-get" else None,
        ):
            with patch("subprocess.run", side_effect=Exception("Unexpected error")):
                result = provisioner._install_sshpass()

        assert result["success"] is False
        assert "error" in result


class TestRunBootstrapViaSsh:
    """Tests for run_bootstrap_via_ssh method."""

    @pytest.mark.asyncio
    async def test_run_bootstrap_no_ssh_key(self, provisioner):
        """Test bootstrap fails when no SSH key available."""
        provisioner._ssh_private_key_path = None
        result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is False
        assert "No SSH key available" in result["error"]

    @pytest.mark.asyncio
    async def test_run_bootstrap_no_username(self, provisioner):
        """Test bootstrap fails when no username set."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = None
        result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is False
        assert "username not set" in result["error"]

    @pytest.mark.asyncio
    async def test_run_bootstrap_no_root_password(self, provisioner):
        """Test bootstrap fails when no root password available."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = None
        result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is False
        assert "No temporary root password" in result["error"]

    @pytest.mark.asyncio
    async def test_run_bootstrap_ssh_auth_failure(self, provisioner):
        """Test bootstrap when SSH auth fails."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass"

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Permission denied"

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_freebsd.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is False
        assert "SSH key authentication failed" in result["error"]

    @pytest.mark.asyncio
    async def test_run_bootstrap_ssh_auth_retry_success(self, provisioner):
        """Test bootstrap succeeds on SSH auth retry."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass"

        # First call fails, second call succeeds
        mock_fail_result = Mock()
        mock_fail_result.returncode = 1
        mock_fail_result.stdout = ""
        mock_fail_result.stderr = "Permission denied"

        mock_success_result = Mock()
        mock_success_result.returncode = 0
        mock_success_result.stdout = "SSH key auth works"
        mock_success_result.stderr = ""

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_freebsd.run_command_async",
                new_callable=AsyncMock,
                side_effect=[mock_fail_result, mock_success_result],
            ):
                with patch.object(
                    provisioner,
                    "_run_su_bootstrap_via_pty",
                    return_value={"success": True, "stdout": "Bootstrap complete"},
                ):
                    result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_bootstrap_success(self, provisioner):
        """Test successful bootstrap."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass"

        mock_ssh_result = Mock()
        mock_ssh_result.returncode = 0
        mock_ssh_result.stdout = "SSH key auth works"
        mock_ssh_result.stderr = ""

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_freebsd.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_ssh_result,
            ):
                with patch.object(
                    provisioner,
                    "_run_su_bootstrap_via_pty",
                    return_value={"success": True, "stdout": "Bootstrap complete"},
                ):
                    result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_bootstrap_pty_failure(self, provisioner):
        """Test bootstrap when PTY execution fails."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass"

        mock_ssh_result = Mock()
        mock_ssh_result.returncode = 0
        mock_ssh_result.stdout = "SSH key auth works"
        mock_ssh_result.stderr = ""

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_freebsd.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_ssh_result,
            ):
                with patch.object(
                    provisioner,
                    "_run_su_bootstrap_via_pty",
                    return_value={
                        "success": False,
                        "error": "Bootstrap failed",
                        "stdout": "Error output",
                        "stderr": "",
                    },
                ):
                    result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is False
        assert "Bootstrap script failed" in result["error"]

    @pytest.mark.asyncio
    async def test_run_bootstrap_timeout(self, provisioner):
        """Test bootstrap timeout."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass"

        with patch("asyncio.sleep", side_effect=asyncio.TimeoutError()):
            result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is False
        assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_run_bootstrap_exception(self, provisioner):
        """Test bootstrap with exception."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass"

        with patch("asyncio.sleep", side_effect=Exception("Unexpected error")):
            result = await provisioner.run_bootstrap_via_ssh("192.168.122.100")

        assert result["success"] is False
        assert "error" in result


class TestReadPtyData:
    """Tests for _read_pty_data method."""

    def test_read_pty_data_success(self, provisioner):
        """Test successful PTY data read."""
        with patch("os.read", return_value=b"test output"):
            result = provisioner._read_pty_data(5)

        assert result == "test output"

    def test_read_pty_data_eof(self, provisioner):
        """Test PTY data read at EOF."""
        with patch("os.read", return_value=b""):
            result = provisioner._read_pty_data(5)

        assert result == ""

    def test_read_pty_data_error(self, provisioner):
        """Test PTY data read error."""
        with patch("os.read", side_effect=OSError("Read error")):
            result = provisioner._read_pty_data(5)

        assert result is None


class TestSendPasswordIfPrompted:
    """Tests for _send_password_if_prompted method."""

    def test_send_password_already_sent(self, provisioner):
        """Test that password is not sent if already sent."""
        result = provisioner._send_password_if_prompted(
            5, "Password:", "secret", password_sent=True
        )
        assert result is True

    def test_send_password_no_prompt(self, provisioner):
        """Test that password is not sent without prompt."""
        result = provisioner._send_password_if_prompted(
            5, "Some other text", "secret", password_sent=False
        )
        assert result is False

    def test_send_password_on_prompt(self, provisioner):
        """Test that password is sent on prompt."""
        with patch("time.sleep"):
            with patch("os.write"):
                result = provisioner._send_password_if_prompted(
                    5, "Password:", "secret", password_sent=False
                )
        assert result is True


class TestGetBootstrapRootCommands:
    """Tests for _get_bootstrap_root_commands method."""

    def test_get_bootstrap_root_commands(self, provisioner):
        """Test getting bootstrap root commands."""
        commands = provisioner._get_bootstrap_root_commands()

        assert "set -e" in commands
        assert "mkdir -p /mnt/cidata" in commands
        assert "mount -t cd9660" in commands
        assert "bootstrap.sh" in commands


class TestBuildSshCommand:
    """Tests for _build_ssh_command method."""

    def test_build_ssh_command(self, provisioner):
        """Test building SSH command."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"

        cmd = provisioner._build_ssh_command("192.168.122.100", "echo hello")

        assert "ssh" in cmd
        assert "-t" in cmd
        assert "-i" in cmd
        assert "/tmp/key" in cmd
        assert "-o" in cmd
        assert _SSH_STRICT_HOST_KEY_CHECKING in cmd
        assert _SSH_USER_KNOWN_HOSTS_FILE in cmd
        assert "testuser@192.168.122.100" in cmd
        assert "echo hello" in cmd[len(cmd) - 1]


class TestHandlePtyDataAvailable:
    """Tests for _handle_pty_data_available method."""

    def test_handle_pty_data_error(self, provisioner):
        """Test handling PTY data when error occurs."""
        with patch.object(provisioner, "_read_pty_data", return_value=None):
            should_break, _accumulated, _password_sent = (
                provisioner._handle_pty_data_available(5, [], "", "pass", False)
            )

        assert should_break is True

    def test_handle_pty_data_eof(self, provisioner):
        """Test handling PTY data at EOF."""
        with patch.object(provisioner, "_read_pty_data", return_value=""):
            should_break, _accumulated, _password_sent = (
                provisioner._handle_pty_data_available(5, [], "", "pass", False)
            )

        assert should_break is True

    def test_handle_pty_data_success(self, provisioner):
        """Test handling PTY data successfully."""
        output = []
        with patch.object(provisioner, "_read_pty_data", return_value="output data"):
            with patch.object(
                provisioner, "_send_password_if_prompted", return_value=False
            ):
                should_break, accumulated, _password_sent = (
                    provisioner._handle_pty_data_available(5, output, "", "pass", False)
                )

        assert should_break is False
        assert "output data" in output
        assert accumulated == "output data"


class TestHandleProcessExited:
    """Tests for _handle_process_exited method."""

    def test_handle_process_exited_with_data(self, provisioner):
        """Test handling process exit with remaining data."""
        output = []
        with patch.object(provisioner, "_read_pty_data", return_value="final data"):
            provisioner._handle_process_exited(5, output)

        assert "final data" in output

    def test_handle_process_exited_no_data(self, provisioner):
        """Test handling process exit with no data."""
        output = []
        with patch.object(provisioner, "_read_pty_data", return_value=None):
            provisioner._handle_process_exited(5, output)

        assert len(output) == 0


class TestRunSuBootstrapViaPty:
    """Tests for _run_su_bootstrap_via_pty method."""

    def test_run_su_bootstrap_success(self, provisioner):
        """Test successful su bootstrap via PTY."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"

        mock_process = Mock()
        mock_process.poll.side_effect = [None, None, 0]
        mock_process.wait.return_value = 0

        with patch("pty.openpty", return_value=(10, 11)):
            with patch("subprocess.Popen", return_value=mock_process):
                with patch("os.close"):
                    with patch("select.select", return_value=([10], [], [])):
                        with patch.object(
                            provisioner,
                            "_handle_pty_data_available",
                            return_value=(True, "", False),
                        ):
                            result = provisioner._run_su_bootstrap_via_pty(
                                "192.168.122.100", "temppass"
                            )

        assert result["exit_code"] == 0

    def test_run_su_bootstrap_timeout(self, provisioner):
        """Test su bootstrap timeout."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"

        mock_process = Mock()
        mock_process.poll.return_value = None
        mock_process.kill = Mock()
        mock_process.wait.return_value = -9

        with patch("pty.openpty", return_value=(10, 11)):
            with patch("subprocess.Popen", return_value=mock_process):
                with patch("os.close"):
                    with patch("select.select", return_value=([], [], [])):
                        with patch("time.time") as mock_time:
                            mock_time.side_effect = [0, 0, 700]  # Exceed timeout
                            result = provisioner._run_su_bootstrap_via_pty(
                                "192.168.122.100", "temppass", timeout=600
                            )

        assert result["success"] is False
        assert "Timeout" in result["error"]

    def test_run_su_bootstrap_exception(self, provisioner):
        """Test su bootstrap with exception."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"

        with patch("pty.openpty", side_effect=OSError("Cannot open pty")):
            result = provisioner._run_su_bootstrap_via_pty(
                "192.168.122.100", "temppass"
            )

        assert result["success"] is False
        assert "Cannot open pty" in result["error"]

    def test_run_su_bootstrap_nonzero_exit(self, provisioner):
        """Test su bootstrap with non-zero exit code."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"

        mock_process = Mock()
        mock_process.poll.side_effect = [None, 1]
        mock_process.wait.return_value = 1

        with patch("pty.openpty", return_value=(10, 11)):
            with patch("subprocess.Popen", return_value=mock_process):
                with patch("os.close"):
                    with patch("select.select", return_value=([], [], [])):
                        with patch.object(provisioner, "_handle_process_exited"):
                            result = provisioner._run_su_bootstrap_via_pty(
                                "192.168.122.100", "temppass"
                            )

        assert result["success"] is False
        assert result["exit_code"] == 1

    def test_run_su_bootstrap_finally_close_error(self, provisioner):
        """Test su bootstrap handles os.close error in finally block."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"

        # Simulate exception during PTY operations, and os.close fails in finally
        close_call_count = [0]

        def mock_close(_fd):
            close_call_count[0] += 1
            if close_call_count[0] == 1:
                # First close for slave_fd works
                return None
            # Subsequent closes raise OSError (simulates error in finally)
            raise OSError("Bad file descriptor")

        with patch("pty.openpty", return_value=(10, 11)):
            with patch(
                "subprocess.Popen", side_effect=OSError("Process creation failed")
            ):
                with patch("os.close", side_effect=mock_close):
                    result = provisioner._run_su_bootstrap_via_pty(
                        "192.168.122.100", "temppass"
                    )

        assert result["success"] is False
        assert "Process creation failed" in result["error"]

    def test_run_su_bootstrap_success_with_finally_close_error(self, provisioner):
        """Test su bootstrap succeeds even when finally os.close raises OSError."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"

        mock_process = Mock()
        mock_process.poll.side_effect = [None, 0]
        mock_process.wait.return_value = 0

        # Track close calls to raise error on the final close in finally
        close_calls = [0]

        def mock_close(_fd):
            close_calls[0] += 1
            if close_calls[0] <= 2:
                # First closes work (slave_fd close and normal master_fd close)
                return None
            # The close in finally block fails
            raise OSError("Bad file descriptor")

        with patch("pty.openpty", return_value=(10, 11)):
            with patch("subprocess.Popen", return_value=mock_process):
                with patch("os.close", side_effect=mock_close):
                    with patch("select.select", return_value=([], [], [])):
                        with patch.object(provisioner, "_handle_process_exited"):
                            result = provisioner._run_su_bootstrap_via_pty(
                                "192.168.122.100", "temppass"
                            )

        assert result["success"] is True
        assert result["exit_code"] == 0


class TestCleanup:
    """Tests for cleanup method."""

    def test_cleanup_with_config_disk(self, provisioner):
        """Test cleanup removes config disk."""
        provisioner._config_disk_path = "/tmp/config.iso"

        with patch("os.path.exists", return_value=True):
            with patch("os.remove") as mock_remove:
                with patch("shutil.rmtree"):
                    provisioner.cleanup()

        mock_remove.assert_called_once_with("/tmp/config.iso")
        assert provisioner._config_disk_path is None

    def test_cleanup_with_ssh_key(self, provisioner):
        """Test cleanup removes SSH key directory."""
        provisioner._ssh_private_key_path = "/tmp/ssh_dir/key"
        provisioner._ssh_public_key = "ssh-ed25519 test"

        with patch("os.path.exists", return_value=False):
            with patch("shutil.rmtree") as mock_rmtree:
                provisioner.cleanup()

        mock_rmtree.assert_called_once_with("/tmp/ssh_dir", ignore_errors=True)
        assert provisioner._ssh_private_key_path is None
        assert provisioner._ssh_public_key is None

    def test_cleanup_with_no_resources(self, provisioner):
        """Test cleanup with no resources to clean."""
        provisioner.cleanup()

        assert provisioner._config_disk_path is None
        assert provisioner._ssh_private_key_path is None
        assert provisioner._bootstrap_username is None
        assert provisioner._temp_root_password is None

    def test_cleanup_handles_os_errors(self, provisioner):
        """Test cleanup handles OS errors gracefully."""
        provisioner._config_disk_path = "/tmp/config.iso"
        provisioner._ssh_private_key_path = "/tmp/ssh_dir/key"

        with patch("os.path.exists", return_value=True):
            with patch("os.remove", side_effect=OSError("Permission denied")):
                with patch("shutil.rmtree", side_effect=OSError("Permission denied")):
                    # Should not raise exception
                    provisioner.cleanup()

        assert provisioner._config_disk_path is None
        assert provisioner._ssh_private_key_path is None


class TestSshConstants:
    """Tests for SSH constants."""

    def test_ssh_strict_host_key_checking_constant(self):
        """Test SSH strict host key checking constant."""
        assert _SSH_STRICT_HOST_KEY_CHECKING == "StrictHostKeyChecking=no"

    def test_ssh_user_known_hosts_file_constant(self):
        """Test SSH user known hosts file constant."""
        assert _SSH_USER_KNOWN_HOSTS_FILE == "UserKnownHostsFile=/dev/null"
