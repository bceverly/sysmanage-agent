"""
Unit tests for src.sysmanage_agent.operations.child_host_kvm_cloudinit module.
Tests KVM/libvirt cloud-init ISO generation for VM provisioning.
"""

# pylint: disable=protected-access,redefined-outer-name

import os
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_kvm_cloudinit import (
    KvmCloudInit,
    KVM_CLOUDINIT_DIR,
)
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig


@pytest.fixture
def mock_logger():
    """Create a mock logger instance."""
    logger = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.debug = Mock()
    return logger


@pytest.fixture
def cloudinit(mock_logger):
    """Create a KvmCloudInit instance for testing."""
    return KvmCloudInit(mock_logger)


@pytest.fixture
def base_vm_config():
    """Create a base VM configuration for testing."""
    return KvmVmConfig(
        distribution="ubuntu-22.04",
        vm_name="test-vm",
        hostname="test-vm.local",
        username="testuser",
        password_hash="$6$saltsalt$hashedpassword",
        server_url="sysmanage.example.com",
        agent_install_commands=[
            "curl -fsSL https://example.com/install.sh | bash",
            "apt-get install -y sysmanage-agent",
        ],
        server_port=8443,
        use_https=True,
        auto_approve_token="test-token-uuid-1234",
    )


@pytest.fixture
def freebsd_vm_config():
    """Create a FreeBSD VM configuration for testing."""
    return KvmVmConfig(
        distribution="freebsd-14.0",
        vm_name="freebsd-test",
        hostname="freebsd-test.local",
        username="fbsduser",
        password_hash="$2b$12$bcrypthash",
        server_url="sysmanage.example.com",
        agent_install_commands=[
            "pkg install -y sysmanage-agent",
        ],
        server_port=8443,
        use_https=True,
        auto_approve_token="freebsd-token-uuid",
    )


class TestKvmCloudInitInit:
    """Test cases for KvmCloudInit initialization."""

    def test_init_sets_logger(self, mock_logger):
        """Test that __init__ sets the logger."""
        cloudinit = KvmCloudInit(mock_logger)
        assert cloudinit.logger == mock_logger

    def test_init_with_different_logger(self):
        """Test initialization with a different logger type."""
        custom_logger = Mock()
        custom_logger.info = Mock()
        cloudinit = KvmCloudInit(custom_logger)
        assert cloudinit.logger == custom_logger


class TestIsFreeBSD:
    """Test cases for _is_freebsd method."""

    def test_is_freebsd_with_freebsd_distribution(self, cloudinit, base_vm_config):
        """Test detection of FreeBSD distribution."""
        base_vm_config.distribution = "freebsd-14.0"
        assert cloudinit._is_freebsd(base_vm_config) is True

    def test_is_freebsd_with_freebsd_uppercase(self, cloudinit, base_vm_config):
        """Test detection of FreeBSD distribution with uppercase."""
        base_vm_config.distribution = "FreeBSD-13.2"
        assert cloudinit._is_freebsd(base_vm_config) is True

    def test_is_freebsd_with_bsd_in_name(self, cloudinit, base_vm_config):
        """Test detection of BSD variant."""
        base_vm_config.distribution = "openbsd-7.4"
        assert cloudinit._is_freebsd(base_vm_config) is True

    def test_is_freebsd_with_netbsd(self, cloudinit, base_vm_config):
        """Test detection of NetBSD."""
        base_vm_config.distribution = "netbsd-9.3"
        assert cloudinit._is_freebsd(base_vm_config) is True

    def test_is_freebsd_with_linux(self, cloudinit, base_vm_config):
        """Test non-FreeBSD distribution (Ubuntu)."""
        base_vm_config.distribution = "ubuntu-22.04"
        assert cloudinit._is_freebsd(base_vm_config) is False

    def test_is_freebsd_with_debian(self, cloudinit, base_vm_config):
        """Test non-FreeBSD distribution (Debian)."""
        base_vm_config.distribution = "debian-12"
        assert cloudinit._is_freebsd(base_vm_config) is False

    def test_is_freebsd_with_alpine(self, cloudinit, base_vm_config):
        """Test non-FreeBSD distribution (Alpine)."""
        base_vm_config.distribution = "alpine-3.18"
        assert cloudinit._is_freebsd(base_vm_config) is False


class TestGenerateMetaData:
    """Test cases for generate_meta_data method."""

    def test_generate_meta_data_contains_instance_id(self, cloudinit, base_vm_config):
        """Test that meta-data contains instance-id."""
        meta_data = cloudinit.generate_meta_data(base_vm_config)
        assert "instance-id:" in meta_data
        assert base_vm_config.vm_name in meta_data

    def test_generate_meta_data_contains_hostname(self, cloudinit, base_vm_config):
        """Test that meta-data contains local-hostname."""
        meta_data = cloudinit.generate_meta_data(base_vm_config)
        assert f"local-hostname: {base_vm_config.hostname}" in meta_data

    def test_generate_meta_data_format(self, cloudinit, base_vm_config):
        """Test meta-data YAML format."""
        with patch("time.time", return_value=1234567890):
            meta_data = cloudinit.generate_meta_data(base_vm_config)

        assert "instance-id: test-vm-1234567890" in meta_data
        assert "local-hostname: test-vm.local" in meta_data

    def test_generate_meta_data_unique_instance_ids(self, cloudinit, base_vm_config):
        """Test that instance IDs include timestamp for uniqueness."""
        with patch("time.time", return_value=1000000000):
            meta_data1 = cloudinit.generate_meta_data(base_vm_config)

        with patch("time.time", return_value=2000000000):
            meta_data2 = cloudinit.generate_meta_data(base_vm_config)

        assert "1000000000" in meta_data1
        assert "2000000000" in meta_data2


class TestIndentContent:
    """Test cases for _indent_content method."""

    def test_indent_content_basic(self, cloudinit):
        """Test basic content indentation."""
        content = "line1\nline2\nline3"
        result = cloudinit._indent_content(content, 4)

        lines = result.split("\n")
        assert lines[0] == "    line1"
        assert lines[1] == "    line2"
        assert lines[2] == "    line3"

    def test_indent_content_with_empty_lines(self, cloudinit):
        """Test indentation preserves empty lines."""
        content = "line1\n\nline3"
        result = cloudinit._indent_content(content, 2)

        lines = result.split("\n")
        assert lines[0] == "  line1"
        assert lines[1] == ""  # Empty line not indented
        assert lines[2] == "  line3"

    def test_indent_content_with_different_spaces(self, cloudinit):
        """Test indentation with various space counts."""
        content = "test"

        result_2 = cloudinit._indent_content(content, 2)
        result_6 = cloudinit._indent_content(content, 6)
        result_8 = cloudinit._indent_content(content, 8)

        assert result_2 == "  test"
        assert result_6 == "      test"
        assert result_8 == "        test"

    def test_indent_content_with_whitespace_only_lines(self, cloudinit):
        """Test indentation with whitespace-only lines."""
        content = "line1\n   \nline3"
        result = cloudinit._indent_content(content, 4)

        lines = result.split("\n")
        assert lines[0] == "    line1"
        assert lines[1] == ""  # Whitespace-only becomes empty
        assert lines[2] == "    line3"

    def test_indent_content_strips_content(self, cloudinit):
        """Test that content is stripped before processing."""
        content = "\n\nline1\nline2\n\n"
        result = cloudinit._indent_content(content, 2)

        # Should strip leading/trailing newlines
        assert not result.startswith("\n")
        assert "  line1" in result


class TestGenerateFreeBSDUserData:
    """Test cases for _generate_freebsd_user_data method."""

    def test_generate_freebsd_user_data_cloud_config_header(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data starts with cloud-config header."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8", "8.8.4.4"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert user_data.startswith("#cloud-config")

    def test_generate_freebsd_user_data_contains_hostname(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data contains hostname configuration."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert f"hostname: {freebsd_vm_config.hostname}" in user_data
        assert f"fqdn: {freebsd_vm_config.hostname}" in user_data

    def test_generate_freebsd_user_data_contains_user(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data contains user configuration."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert f"name: {freebsd_vm_config.username}" in user_data
        assert "shell: /bin/sh" in user_data  # FreeBSD uses /bin/sh
        assert "wheel" in user_data  # FreeBSD uses wheel group

    def test_generate_freebsd_user_data_contains_dns(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data contains DNS configuration."""
        dns_servers = ["1.1.1.1", "8.8.8.8"]
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=dns_servers,
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        for dns in dns_servers:
            assert dns in user_data

    def test_generate_freebsd_user_data_contains_bootcmd(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data contains bootcmd for early DNS setup."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert "bootcmd:" in user_data
        assert "nameserver" in user_data
        assert "/etc/resolv.conf" in user_data

    def test_generate_freebsd_user_data_contains_pkg_bootstrap(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data contains pkg bootstrap command."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert "pkg bootstrap" in user_data
        assert "pkg update" in user_data

    def test_generate_freebsd_user_data_contains_agent_install_commands(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data contains agent install commands."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        for cmd in freebsd_vm_config.agent_install_commands:
            # Commands may have quotes escaped
            assert cmd in user_data or cmd.replace("'", "'\"'\"'") in user_data

    def test_generate_freebsd_user_data_contains_sysrc(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data uses sysrc for service configuration."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert "sysrc sysmanage_agent_enable=YES" in user_data
        assert "service sysmanage_agent" in user_data

    def test_generate_freebsd_user_data_contains_agent_config(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data contains agent configuration file."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert "write_files:" in user_data
        assert "/etc/sysmanage-agent.yaml" in user_data
        assert freebsd_vm_config.server_url in user_data

    def test_generate_freebsd_user_data_contains_freebsd_packages(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data includes FreeBSD-specific packages."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert "packages:" in user_data
        assert "curl" in user_data
        assert "ca_root_nss" in user_data

    def test_generate_freebsd_user_data_multiple_dns_servers(
        self, cloudinit, freebsd_vm_config
    ):
        """Test FreeBSD user-data with multiple DNS servers."""
        dns_servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=dns_servers,
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        # First DNS should use > (overwrite)
        assert "nameserver 1.1.1.1' > /etc/resolv.conf" in user_data
        # Subsequent DNS should use >> (append)
        assert "nameserver 8.8.8.8' >> /etc/resolv.conf" in user_data
        assert "nameserver 9.9.9.9' >> /etc/resolv.conf" in user_data


class TestGenerateUserData:
    """Test cases for generate_user_data method."""

    def test_generate_user_data_linux_cloud_config_header(
        self, cloudinit, base_vm_config
    ):
        """Test Linux user-data starts with cloud-config header."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert user_data.startswith("#cloud-config")

    def test_generate_user_data_linux_contains_hostname(
        self, cloudinit, base_vm_config
    ):
        """Test Linux user-data contains hostname configuration."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert f"hostname: {base_vm_config.hostname}" in user_data
        assert f"fqdn: {base_vm_config.hostname}" in user_data

    def test_generate_user_data_linux_contains_bash_shell(
        self, cloudinit, base_vm_config
    ):
        """Test Linux user-data uses bash shell."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert "shell: /bin/bash" in user_data

    def test_generate_user_data_linux_contains_systemctl(
        self, cloudinit, base_vm_config
    ):
        """Test Linux user-data uses systemctl for service management."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert "systemctl daemon-reload" in user_data
        assert "systemctl enable sysmanage-agent" in user_data
        assert "systemctl restart sysmanage-agent" in user_data

    def test_generate_user_data_linux_contains_directories(
        self, cloudinit, base_vm_config
    ):
        """Test Linux user-data creates required directories."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert "mkdir -p /var/lib/sysmanage-agent" in user_data
        assert "mkdir -p /var/log/sysmanage-agent" in user_data
        assert "chown -R sysmanage-agent:sysmanage-agent" in user_data

    def test_generate_user_data_linux_contains_packages(
        self, cloudinit, base_vm_config
    ):
        """Test Linux user-data contains Linux packages."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert "packages:" in user_data
        assert "curl" in user_data
        assert "gnupg" in user_data
        assert "ca-certificates" in user_data

    def test_generate_user_data_delegates_to_freebsd(
        self, cloudinit, freebsd_vm_config, mock_logger
    ):
        """Test that FreeBSD config delegates to FreeBSD-specific method."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(freebsd_vm_config)

        # Should have FreeBSD characteristics
        assert "shell: /bin/sh" in user_data
        assert "pkg bootstrap" in user_data
        mock_logger.info.assert_called()

    def test_generate_user_data_ubuntu_os_type(self, cloudinit, base_vm_config):
        """Test OS type detection for Ubuntu."""
        base_vm_config.distribution = "ubuntu-22.04"
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_cloudinit.generate_agent_config"
            ) as mock_gen:
                mock_gen.return_value = "# config"
                cloudinit.generate_user_data(base_vm_config)

                # Verify os_type was passed correctly
                call_kwargs = mock_gen.call_args[1]
                assert call_kwargs["os_type"] == "ubuntu"

    def test_generate_user_data_debian_os_type(self, cloudinit, base_vm_config):
        """Test OS type detection for Debian."""
        base_vm_config.distribution = "debian-12"
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_cloudinit.generate_agent_config"
            ) as mock_gen:
                mock_gen.return_value = "# config"
                cloudinit.generate_user_data(base_vm_config)

                call_kwargs = mock_gen.call_args[1]
                assert call_kwargs["os_type"] == "debian"

    def test_generate_user_data_alpine_os_type(self, cloudinit, base_vm_config):
        """Test OS type detection for Alpine."""
        base_vm_config.distribution = "alpine-3.18"
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_cloudinit.generate_agent_config"
            ) as mock_gen:
                mock_gen.return_value = "# config"
                cloudinit.generate_user_data(base_vm_config)

                call_kwargs = mock_gen.call_args[1]
                assert call_kwargs["os_type"] == "alpine"

    def test_generate_user_data_generic_linux_os_type(self, cloudinit, base_vm_config):
        """Test OS type detection for generic Linux."""
        base_vm_config.distribution = "centos-9"
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_cloudinit.generate_agent_config"
            ) as mock_gen:
                mock_gen.return_value = "# config"
                cloudinit.generate_user_data(base_vm_config)

                call_kwargs = mock_gen.call_args[1]
                assert call_kwargs["os_type"] == "linux"

    def test_generate_user_data_escapes_single_quotes(self, cloudinit, base_vm_config):
        """Test that single quotes in commands are escaped."""
        base_vm_config.agent_install_commands = [
            "echo 'hello world'",
        ]
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        # Single quotes should be escaped for shell
        assert "'\"'\"'" in user_data

    def test_generate_user_data_multiple_dns_servers(self, cloudinit, base_vm_config):
        """Test Linux user-data with multiple DNS servers."""
        dns_servers = ["1.1.1.1", "8.8.8.8"]
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=dns_servers,
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        # First DNS should use > (overwrite)
        assert "nameserver 1.1.1.1' > /etc/resolv.conf" in user_data
        # Second DNS should use >> (append)
        assert "nameserver 8.8.8.8' >> /etc/resolv.conf" in user_data


class TestCreateCloudInitIso:
    """Test cases for create_cloud_init_iso method."""

    def test_create_cloud_init_iso_success_genisoimage(self, cloudinit, base_vm_config):
        """Test successful ISO creation with genisoimage."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which") as mock_which:
                    mock_which.side_effect = lambda x: (
                        "/usr/bin/genisoimage" if x == "genisoimage" else None
                    )
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stderr="")
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                result = cloudinit.create_cloud_init_iso(base_vm_config)

        assert result["success"] is True
        assert "path" in result
        assert base_vm_config.vm_name in result["path"]

    def test_create_cloud_init_iso_success_mkisofs(self, cloudinit, base_vm_config):
        """Test successful ISO creation with mkisofs."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which") as mock_which:
                    # Return mkisofs but not genisoimage
                    def which_side_effect(cmd):
                        if cmd == "mkisofs":
                            return "/usr/bin/mkisofs"
                        return None

                    mock_which.side_effect = which_side_effect

                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stderr="")
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                result = cloudinit.create_cloud_init_iso(base_vm_config)

        assert result["success"] is True

    def test_create_cloud_init_iso_success_xorrisofs(self, cloudinit, base_vm_config):
        """Test successful ISO creation with xorrisofs."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which") as mock_which:
                    # Return xorrisofs but not others
                    def which_side_effect(cmd):
                        if cmd == "xorrisofs":
                            return "/usr/bin/xorrisofs"
                        return None

                    mock_which.side_effect = which_side_effect

                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stderr="")
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                result = cloudinit.create_cloud_init_iso(base_vm_config)

        assert result["success"] is True

    def test_create_cloud_init_iso_no_tool_available(self, cloudinit, base_vm_config):
        """Test ISO creation fails when no ISO tool is available."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which", return_value=None):
                    with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                        mock_tmpdir.return_value.__enter__ = Mock(
                            return_value="/tmp/test"
                        )
                        mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                        with patch("builtins.open", create=True) as mock_open:
                            mock_open.return_value.__enter__ = Mock()
                            mock_open.return_value.__exit__ = Mock(return_value=False)

                            result = cloudinit.create_cloud_init_iso(base_vm_config)

        assert result["success"] is False
        assert "No ISO creation tool found" in result["error"]

    def test_create_cloud_init_iso_command_failure(self, cloudinit, base_vm_config):
        """Test ISO creation fails when command returns non-zero."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which", return_value="/usr/bin/genisoimage"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(
                            returncode=1, stderr="Error creating ISO"
                        )
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                result = cloudinit.create_cloud_init_iso(base_vm_config)

        assert result["success"] is False
        assert "Error creating ISO" in result["error"]

    def test_create_cloud_init_iso_command_failure_empty_stderr(
        self, cloudinit, base_vm_config
    ):
        """Test ISO creation failure with empty stderr uses default message."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which", return_value="/usr/bin/genisoimage"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=1, stderr="")
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                result = cloudinit.create_cloud_init_iso(base_vm_config)

        assert result["success"] is False
        assert "Failed to create cloud-init ISO" in result["error"]

    def test_create_cloud_init_iso_exception(self, cloudinit, base_vm_config):
        """Test ISO creation handles exceptions gracefully."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs", side_effect=PermissionError("Permission denied")):
                result = cloudinit.create_cloud_init_iso(base_vm_config)

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    def test_create_cloud_init_iso_sets_config_path(self, cloudinit, base_vm_config):
        """Test that ISO path is set on config after successful creation."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which", return_value="/usr/bin/genisoimage"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stderr="")
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                result = cloudinit.create_cloud_init_iso(base_vm_config)

        assert result["success"] is True
        assert base_vm_config.cloud_init_iso_path != ""
        assert base_vm_config.vm_name in base_vm_config.cloud_init_iso_path

    def test_create_cloud_init_iso_uses_correct_directory(
        self, cloudinit, base_vm_config
    ):
        """Test that ISO is created in the correct directory."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs") as mock_makedirs:
                with patch("shutil.which", return_value="/usr/bin/genisoimage"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stderr="")
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                cloudinit.create_cloud_init_iso(base_vm_config)

        mock_makedirs.assert_called_with(KVM_CLOUDINIT_DIR, mode=0o755, exist_ok=True)

    def test_create_cloud_init_iso_calls_subprocess_with_sudo(
        self, cloudinit, base_vm_config
    ):
        """Test that subprocess is called with sudo."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which", return_value="/usr/bin/genisoimage"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stderr="")
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                cloudinit.create_cloud_init_iso(base_vm_config)

        # Verify subprocess was called with sudo
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "sudo"

    def test_create_cloud_init_iso_logs_info(
        self, cloudinit, base_vm_config, mock_logger
    ):
        """Test that ISO creation logs info message."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs"):
                with patch("shutil.which", return_value="/usr/bin/genisoimage"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stderr="")
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/test"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)
                            with patch("builtins.open", create=True) as mock_open:
                                mock_open.return_value.__enter__ = Mock()
                                mock_open.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                cloudinit.create_cloud_init_iso(base_vm_config)

        # Verify logger.info was called
        mock_logger.info.assert_called()

    def test_create_cloud_init_iso_logs_error_on_exception(
        self, cloudinit, base_vm_config, mock_logger
    ):
        """Test that exceptions are logged."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            with patch("os.makedirs", side_effect=Exception("Test error")):
                cloudinit.create_cloud_init_iso(base_vm_config)

        mock_logger.error.assert_called()


class TestKvmCloudInitDirConstant:
    """Test cases for the KVM_CLOUDINIT_DIR constant."""

    def test_cloudinit_dir_is_correct(self):
        """Test that the default cloud-init directory is correct."""
        assert KVM_CLOUDINIT_DIR == "/var/lib/libvirt/cloud-init"

    def test_cloudinit_dir_is_absolute(self):
        """Test that the cloud-init directory is an absolute path."""
        assert os.path.isabs(KVM_CLOUDINIT_DIR)


class TestGenerateUserDataWithAutoApproveToken:
    """Test cases for auto_approve_token handling in user data."""

    def test_generate_user_data_includes_auto_approve_token(
        self, cloudinit, base_vm_config
    ):
        """Test that auto_approve_token is included in agent config."""
        base_vm_config.auto_approve_token = "my-special-token"
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert "my-special-token" in user_data

    def test_generate_freebsd_user_data_includes_auto_approve_token(
        self, cloudinit, freebsd_vm_config
    ):
        """Test that auto_approve_token is included in FreeBSD agent config."""
        freebsd_vm_config.auto_approve_token = "freebsd-token-123"
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit._generate_freebsd_user_data(freebsd_vm_config)

        assert "freebsd-token-123" in user_data

    def test_generate_user_data_without_auto_approve_token(
        self, cloudinit, base_vm_config
    ):
        """Test user data generation when auto_approve_token is None."""
        base_vm_config.auto_approve_token = None
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        # Should still generate valid cloud-config
        assert "#cloud-config" in user_data
        assert base_vm_config.hostname in user_data


class TestGenerateUserDataServerConfiguration:
    """Test cases for server configuration in user data."""

    def test_generate_user_data_includes_server_url(self, cloudinit, base_vm_config):
        """Test that server URL is included in config."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert base_vm_config.server_url in user_data

    def test_generate_user_data_includes_server_port(self, cloudinit, base_vm_config):
        """Test that server port is included in config."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        assert str(base_vm_config.server_port) in user_data

    def test_generate_user_data_includes_use_https(self, cloudinit, base_vm_config):
        """Test that use_https setting is included in config."""
        base_vm_config.use_https = True
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_cloudinit.get_host_dns_servers",
            return_value=["8.8.8.8"],
        ):
            user_data = cloudinit.generate_user_data(base_vm_config)

        # The config should include use_https setting
        assert "use_https" in user_data
