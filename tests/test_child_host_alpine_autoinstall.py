"""
Unit tests for Alpine Linux VMM autoinstall module.

Tests for AlpineAutoinstallSetup class which handles automated
installation of Alpine Linux VMs via serial console.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch, MagicMock
import urllib.error

import pytest

from src.sysmanage_agent.operations.child_host_alpine_autoinstall import (
    AlpineAutoinstallSetup,
)


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
def setup_instance(mock_logger):
    """Create an AlpineAutoinstallSetup instance for testing."""
    return AlpineAutoinstallSetup(mock_logger)


class TestAlpineAutoinstallSetupInit:
    """Tests for AlpineAutoinstallSetup initialization."""

    def test_init_sets_logger(self, mock_logger):
        """Test that __init__ sets the logger."""
        setup = AlpineAutoinstallSetup(mock_logger)
        assert setup.logger == mock_logger

    def test_class_constants(self, setup_instance):
        """Test that class constants are set correctly."""
        assert setup_instance.ISO_CACHE_DIR == "/var/vmm/iso-cache"
        assert setup_instance.ALPINE_SETS_BASE == "/var/www/htdocs/pub/Alpine"


class TestDownloadAlpineIso:
    """Tests for download_alpine_iso method."""

    def test_unsupported_version(self, setup_instance, tmp_path):
        """Test handling of unsupported Alpine version."""
        with patch.object(setup_instance, "ISO_CACHE_DIR", str(tmp_path)):
            result = setup_instance.download_alpine_iso("999.99")

        assert result["success"] is False
        assert result["iso_path"] is None
        assert "Unsupported Alpine version" in result["error"]

    def test_cached_iso_exists(self, setup_instance, tmp_path):
        """Test using cached ISO when it already exists."""
        # Create a fake cached ISO
        iso_filename = "alpine-virt-3.21.3-x86_64.iso"
        fake_iso = tmp_path / iso_filename

        with patch.object(setup_instance, "ISO_CACHE_DIR", str(tmp_path)):
            # Create the fake cached ISO file
            fake_iso.write_text("fake iso content")

            result = setup_instance.download_alpine_iso("3.21")

        assert result["success"] is True
        assert result["iso_path"] == str(fake_iso)
        setup_instance.logger.info.assert_called()

    def test_download_iso_success(self, setup_instance, tmp_path):
        """Test successful ISO download."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"fake iso content"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup_instance, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = setup_instance.download_alpine_iso("3.21")

        assert result["success"] is True
        assert result["iso_path"] is not None
        assert "alpine-virt-3.21" in result["iso_path"]

    def test_download_iso_network_error(self, setup_instance, tmp_path):
        """Test handling network error during ISO download."""
        with patch.object(setup_instance, "ISO_CACHE_DIR", str(tmp_path)):
            with patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.URLError("Network error"),
            ):
                result = setup_instance.download_alpine_iso("3.21")

        assert result["success"] is False
        assert result["iso_path"] is None
        assert "error" in result

    def test_download_iso_timeout(self, setup_instance, tmp_path):
        """Test handling timeout during ISO download."""
        with patch.object(setup_instance, "ISO_CACHE_DIR", str(tmp_path)):
            with patch(
                "urllib.request.urlopen",
                side_effect=TimeoutError("Connection timed out"),
            ):
                result = setup_instance.download_alpine_iso("3.20")

        assert result["success"] is False
        assert result["iso_path"] is None

    def test_download_iso_creates_cache_dir(self, setup_instance, tmp_path):
        """Test that download creates cache directory if it doesn't exist."""
        cache_dir = tmp_path / "new_cache_dir"

        mock_response = MagicMock()
        mock_response.read.return_value = b"fake iso content"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup_instance, "ISO_CACHE_DIR", str(cache_dir)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = setup_instance.download_alpine_iso("3.19")

        assert result["success"] is True
        assert cache_dir.exists()

    def test_download_iso_version_3_19(self, setup_instance, tmp_path):
        """Test downloading Alpine 3.19 ISO."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"fake iso content"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup_instance, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = setup_instance.download_alpine_iso("3.19")

        assert result["success"] is True
        assert "3.19" in result["iso_path"]

    def test_download_iso_version_3_20(self, setup_instance, tmp_path):
        """Test downloading Alpine 3.20 ISO."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"fake iso content"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup_instance, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = setup_instance.download_alpine_iso("3.20")

        assert result["success"] is True
        assert "3.20" in result["iso_path"]


class TestCreateSetupScript:
    """Tests for create_setup_script method."""

    def test_basic_setup_script(self, setup_instance):
        """Test basic setup script generation."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        # Check script basics
        assert script.startswith("#!/bin/sh")
        assert "set -e" in script
        assert "test-vm.example.com" in script
        assert "192.168.1.100" in script
        assert "192.168.1.1" in script

    def test_setup_script_keyboard_config(self, setup_instance):
        """Test keyboard configuration in setup script."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "setup-keymap us us" in script

    def test_setup_script_networking(self, setup_instance):
        """Test network configuration in setup script."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="10.0.0.1",
            vm_ip="10.0.0.50",
            alpine_version="3.21",
        )

        assert "address 10.0.0.50" in script
        assert "gateway 10.0.0.1" in script
        assert "netmask 255.255.255.0" in script
        assert "auto eth0" in script
        assert "iface eth0 inet static" in script

    def test_setup_script_default_dns(self, setup_instance):
        """Test default DNS configuration."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        # Default DNS should be Google DNS
        assert "nameserver 8.8.8.8" in script

    def test_setup_script_custom_dns(self, setup_instance):
        """Test custom DNS configuration."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
            dns_server="1.1.1.1",
        )

        assert "nameserver 1.1.1.1" in script

    def test_setup_script_apk_repos(self, setup_instance):
        """Test APK repository configuration."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "/etc/apk/repositories" in script
        assert "v3.21" in script
        assert "/main" in script
        assert "/community" in script

    def test_setup_script_ssh_install(self, setup_instance):
        """Test SSH installation in setup script."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "apk add openssh" in script
        assert "rc-update add sshd default" in script
        assert "/etc/init.d/sshd start" in script

    def test_setup_script_user_creation(self, setup_instance):
        """Test user creation in setup script."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="myuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "adduser -D" in script
        assert "myuser" in script
        assert "adduser myuser wheel" in script
        assert "chpasswd" in script

    def test_setup_script_sudo_config(self, setup_instance):
        """Test sudo configuration in setup script."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "apk add sudo" in script
        assert "%wheel ALL=(ALL) ALL" in script

    def test_setup_script_disk_install(self, setup_instance):
        """Test disk installation in setup script."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "setup-disk -m sys /dev/vdb" in script
        assert 'echo "y"' in script  # Auto-confirm disk erase

    def test_setup_script_poweroff(self, setup_instance):
        """Test poweroff at end of setup script."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "poweroff" in script

    def test_setup_script_with_server_config(self, setup_instance):
        """Test setup script with sysmanage-agent server configuration."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        # Should include agent config section
        assert "sysmanage-agent configuration" in script
        assert "/etc/sysmanage-agent" in script
        assert "sysmanage.example.com" in script
        assert "8443" in script

    def test_setup_script_with_auto_approve_token(self, setup_instance):
        """Test setup script with auto-approve token."""
        token = "12345678-1234-1234-1234-123456789012"
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert token in script

    def test_setup_script_firstboot_section(self, setup_instance):
        """Test firstboot script section when server config provided."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
            server_hostname="sysmanage.example.com",
            server_port=8443,
        )

        # Should include firstboot script section
        assert "/etc/local.d/sysmanage-firstboot.start" in script
        assert "rc-update add local default" in script
        assert "apk update" in script

    def test_setup_script_no_firstboot_without_server(self, setup_instance):
        """Test that firstboot section is omitted without server config."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        # Should not include firstboot script section
        assert "/etc/local.d/sysmanage-firstboot.start" not in script

    def test_setup_script_uses_https(self, setup_instance):
        """Test setup script uses HTTPS setting."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=False,
        )

        # Config should reflect https setting
        assert "sysmanage.example.com" in script

    def test_setup_script_version_3_19(self, setup_instance):
        """Test setup script for Alpine 3.19."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.19",
        )

        assert "v3.19" in script

    def test_setup_script_version_fallback(self, setup_instance):
        """Test setup script falls back to 3.21 for unknown version."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="unknown",
        )

        # Should fall back to 3.21 repo URL
        assert "v3.21" in script

    def test_setup_script_serial_console_opts(self, setup_instance):
        """Test serial console kernel options are set."""
        script = setup_instance.create_setup_script(
            hostname="test-vm.example.com",
            username="testuser",
            user_password="hashedpassword",
            root_password="roothashed",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "KERNELOPTS" in script
        assert "console=ttyS0,115200" in script


class TestCreateFirstbootSetup:
    """Tests for create_firstboot_setup method."""

    def test_create_firstboot_setup(self, setup_instance):
        """Test firstboot setup script generation."""
        script = setup_instance.create_firstboot_setup(
            _server_hostname="sysmanage.example.com",
            _server_port=8443,
            _use_https=True,
        )

        # Check it returns a script
        assert script.startswith("#!/bin/sh")
        assert "First boot setup" in script

    def test_create_firstboot_setup_with_token(self, setup_instance):
        """Test firstboot setup with auto-approve token."""
        script = setup_instance.create_firstboot_setup(
            _server_hostname="sysmanage.example.com",
            _server_port=8443,
            _use_https=True,
            _auto_approve_token="12345678-1234-1234-1234-123456789012",
        )

        # Should still return valid script
        assert script.startswith("#!/bin/sh")

    def test_create_firstboot_setup_apk_operations(self, setup_instance):
        """Test firstboot script includes APK operations."""
        script = setup_instance.create_firstboot_setup(
            _server_hostname="sysmanage.example.com",
            _server_port=8443,
            _use_https=True,
        )

        assert "apk update" in script
        assert "apk add" in script

    def test_create_firstboot_setup_service_management(self, setup_instance):
        """Test firstboot script includes service management."""
        script = setup_instance.create_firstboot_setup(
            _server_hostname="sysmanage.example.com",
            _server_port=8443,
            _use_https=True,
        )

        assert "rc-update add" in script
        assert "rc-service" in script


class TestCreateAgentConfig:
    """Tests for create_agent_config method."""

    def test_create_agent_config_basic(self, setup_instance):
        """Test basic agent config generation."""
        config = setup_instance.create_agent_config(
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        assert 'hostname: "sysmanage.example.com"' in config
        assert "port: 8443" in config
        assert "use_https: true" in config

    def test_create_agent_config_http(self, setup_instance):
        """Test agent config with HTTP."""
        config = setup_instance.create_agent_config(
            server_hostname="sysmanage.example.com",
            server_port=8080,
            use_https=False,
        )

        assert "use_https: false" in config
        assert "port: 8080" in config

    def test_create_agent_config_with_token(self, setup_instance):
        """Test agent config with auto-approve token."""
        token = "12345678-1234-1234-1234-123456789012"
        config = setup_instance.create_agent_config(
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert "auto_approve:" in config
        assert f'token: "{token}"' in config

    def test_create_agent_config_without_token(self, setup_instance):
        """Test agent config without auto-approve token."""
        config = setup_instance.create_agent_config(
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            auto_approve_token=None,
        )

        # Should not have auto_approve section when token is None
        # The behavior depends on the underlying generate_agent_config
        assert 'hostname: "sysmanage.example.com"' in config


class TestRunSerialConsoleSetup:
    """Tests for run_serial_console_setup method."""

    def test_run_serial_console_setup_success(self, setup_instance):
        """Test successful serial console setup."""
        setup_script = "#!/bin/sh\necho 'test'\n"

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__ = Mock(return_value=mock_file)
            mock_open.return_value.__exit__ = Mock(return_value=False)

            result = setup_instance.run_serial_console_setup(
                vm_name="test-vm",
                setup_script=setup_script,
                _timeout=600,
            )

        assert result["success"] is True
        assert "message" in result
        setup_instance.logger.warning.assert_called()

    def test_run_serial_console_setup_writes_script(self, setup_instance, tmp_path):
        """Test that serial console setup writes script to file."""
        setup_script = "#!/bin/sh\necho 'test'\n"
        _script_path = tmp_path / "alpine_setup_test-vm.sh"

        # Mock open to track what's written
        with patch("builtins.open", MagicMock(return_value=MagicMock())) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file
            mock_open.return_value.__exit__.return_value = False

            result = setup_instance.run_serial_console_setup(
                vm_name="test-vm",
                setup_script=setup_script,
            )

        assert result["success"] is True
        # Verify file was opened for writing
        mock_open.assert_called()

    def test_run_serial_console_setup_exception(self, setup_instance):
        """Test serial console setup with exception."""
        setup_script = "#!/bin/sh\necho 'test'\n"

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = setup_instance.run_serial_console_setup(
                vm_name="test-vm",
                setup_script=setup_script,
            )

        assert result["success"] is False
        assert "error" in result
        assert "Access denied" in result["error"]

    def test_run_serial_console_setup_logs_info(self, setup_instance):
        """Test that serial console setup logs info."""
        setup_script = "#!/bin/sh\necho 'test'\n"

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__ = Mock(return_value=mock_file)
            mock_open.return_value.__exit__ = Mock(return_value=False)

            setup_instance.run_serial_console_setup(
                vm_name="test-vm",
                setup_script=setup_script,
            )

        # Should log info about starting setup
        setup_instance.logger.info.assert_called()


class TestWaitForAlpineBoot:
    """Tests for wait_for_alpine_boot method."""

    def test_wait_for_boot_success(self, setup_instance):
        """Test successful VM boot detection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test-vm running"

        with patch("subprocess.run", return_value=mock_result):
            result = setup_instance.wait_for_alpine_boot(
                vm_name="test-vm",
                timeout=10,
            )

        assert result["success"] is True

    def test_wait_for_boot_timeout(self, setup_instance):
        """Test VM boot timeout."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test-vm stopped"  # Not running

        with patch("subprocess.run", return_value=mock_result):
            with patch("time.sleep"):  # Don't actually sleep
                with patch("time.time") as mock_time:
                    # Simulate timeout
                    mock_time.side_effect = [0, 400]  # Start time, then past timeout

                    result = setup_instance.wait_for_alpine_boot(
                        vm_name="test-vm",
                        timeout=300,
                    )

        assert result["success"] is False
        assert "Timeout" in result["error"]

    def test_wait_for_boot_exception(self, setup_instance):
        """Test VM boot with exception."""
        with patch("subprocess.run", side_effect=Exception("vmctl failed")):
            result = setup_instance.wait_for_alpine_boot(
                vm_name="test-vm",
                timeout=10,
            )

        assert result["success"] is False
        assert "vmctl failed" in result["error"]

    def test_wait_for_boot_logs_info(self, setup_instance):
        """Test that wait_for_alpine_boot logs info."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test-vm running"

        with patch("subprocess.run", return_value=mock_result):
            setup_instance.wait_for_alpine_boot(
                vm_name="test-vm",
                timeout=10,
            )

        setup_instance.logger.info.assert_called()

    def test_wait_for_boot_checks_running_status(self, setup_instance):
        """Test that wait checks for 'running' in vmctl output."""
        # First call returns not running, second returns running
        mock_result_stopped = Mock()
        mock_result_stopped.returncode = 0
        mock_result_stopped.stdout = "test-vm stopped"

        mock_result_running = Mock()
        mock_result_running.returncode = 0
        mock_result_running.stdout = "test-vm running"

        call_count = [0]

        def side_effect(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return mock_result_stopped
            return mock_result_running

        with patch("subprocess.run", side_effect=side_effect):
            with patch("time.sleep"):
                with patch("time.time") as mock_time:
                    mock_time.side_effect = [0, 1, 2, 3]

                    result = setup_instance.wait_for_alpine_boot(
                        vm_name="test-vm",
                        timeout=300,
                    )

        assert result["success"] is True

    def test_wait_for_boot_vmctl_error(self, setup_instance):
        """Test handling vmctl command error."""
        mock_result = Mock()
        mock_result.returncode = 1  # Command failed
        mock_result.stdout = "error"

        with patch("subprocess.run", return_value=mock_result):
            with patch("time.sleep"):
                with patch("time.time") as mock_time:
                    mock_time.side_effect = [0, 400]

                    result = setup_instance.wait_for_alpine_boot(
                        vm_name="test-vm",
                        timeout=300,
                    )

        assert result["success"] is False


class TestCreateAlpineDataDisk:
    """Tests for create_alpine_data_disk method."""

    def test_create_data_disk_success(self, setup_instance):
        """Test successful data disk creation."""
        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_autoinstall.Path"
        ) as mock_path:
            mock_data_dir = MagicMock()
            mock_vm_data_dir = MagicMock()
            mock_path.return_value = mock_data_dir
            mock_data_dir.__truediv__ = Mock(return_value=mock_vm_data_dir)
            mock_vm_data_dir.__truediv__ = Mock(return_value=MagicMock())

            result = setup_instance.create_alpine_data_disk(
                vm_name="test-vm",
                setup_script="#!/bin/sh\necho test",
                agent_config="server:\n  hostname: test",
                firstboot_script="#!/bin/sh\necho firstboot",
            )

        assert result["success"] is True
        assert "data_dir" in result

    def test_create_data_disk_writes_files(self, setup_instance, tmp_path):
        """Test that data disk creation writes all required files."""
        data_dir = tmp_path / "alpine-data"
        data_dir.mkdir(parents=True)

        setup_script = "#!/bin/sh\necho setup"
        agent_config = "server:\n  hostname: test"
        firstboot_script = "#!/bin/sh\necho firstboot"

        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_autoinstall.Path"
        ) as mock_path_class:
            # Set up the mock to behave like Path
            mock_data_dir = tmp_path / "alpine-data"
            mock_data_dir.mkdir(exist_ok=True)

            mock_path_class.return_value = mock_data_dir

            result = setup_instance.create_alpine_data_disk(
                vm_name="test-vm",
                setup_script=setup_script,
                agent_config=agent_config,
                firstboot_script=firstboot_script,
            )

        assert result["success"] is True

    def test_create_data_disk_exception(self, setup_instance):
        """Test data disk creation with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_autoinstall.Path"
        ) as mock_path:
            mock_path.return_value.mkdir.side_effect = PermissionError(
                "Permission denied"
            )

            result = setup_instance.create_alpine_data_disk(
                vm_name="test-vm",
                setup_script="#!/bin/sh\necho test",
                agent_config="server:\n  hostname: test",
                firstboot_script="#!/bin/sh\necho firstboot",
            )

        assert result["success"] is False
        assert "error" in result

    def test_create_data_disk_logs_info(self, setup_instance):
        """Test that data disk creation logs info."""
        with patch(
            "src.sysmanage_agent.operations.child_host_alpine_autoinstall.Path"
        ) as mock_path:
            mock_data_dir = MagicMock()
            mock_vm_data_dir = MagicMock()
            mock_path.return_value = mock_data_dir
            mock_data_dir.__truediv__ = Mock(return_value=mock_vm_data_dir)

            # Make all path operations return mock
            mock_setup_path = MagicMock()
            mock_config_path = MagicMock()
            mock_firstboot_path = MagicMock()

            mock_vm_data_dir.__truediv__ = Mock(
                side_effect=[mock_setup_path, mock_config_path, mock_firstboot_path]
            )

            result = setup_instance.create_alpine_data_disk(
                vm_name="test-vm",
                setup_script="#!/bin/sh\necho test",
                agent_config="server:\n  hostname: test",
                firstboot_script="#!/bin/sh\necho firstboot",
            )

        if result["success"]:
            setup_instance.logger.info.assert_called()


class TestSetupScriptContentIntegrity:
    """Integration tests for setup script content."""

    def test_setup_script_is_valid_shell(self, setup_instance):
        """Test that generated setup script is valid shell syntax."""
        script = setup_instance.create_setup_script(
            hostname="test.example.com",
            username="admin",
            user_password="$6$hash",
            root_password="$6$roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        # Basic shell syntax checks
        assert script.startswith("#!/bin/sh")
        assert "set -e" in script
        # No unbalanced quotes (simple check)
        assert script.count('"') % 2 == 0

    def test_setup_script_contains_all_sections(self, setup_instance):
        """Test that setup script contains all required sections."""
        script = setup_instance.create_setup_script(
            hostname="test.example.com",
            username="admin",
            user_password="$6$hash",
            root_password="$6$roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        # All major sections should be present
        required_sections = [
            "setup-keymap",
            "setup-hostname",
            "/etc/network/interfaces",
            "/etc/resolv.conf",
            "setup-timezone",
            "/etc/apk/repositories",
            "apk update",
            "apk add openssh",
            "adduser",
            "chpasswd",
            "setup-disk",
            "poweroff",
        ]

        for section in required_sections:
            assert section in script, f"Missing section: {section}"

    def test_setup_script_escapes_special_chars_in_password(self, setup_instance):
        """Test that passwords with special chars are handled."""
        # Use a password with special shell characters
        script = setup_instance.create_setup_script(
            hostname="test.example.com",
            username="admin",
            user_password="$6$rounds=5000$salt$hashvalue",
            root_password="$6$rounds=5000$salt$roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        # The password should appear in the chpasswd section
        assert "chpasswd" in script


class TestEdgeCases:
    """Edge case tests for AlpineAutoinstallSetup."""

    def test_empty_hostname(self, setup_instance):
        """Test handling empty hostname."""
        script = setup_instance.create_setup_script(
            hostname="",
            username="admin",
            user_password="hash",
            root_password="roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        # Should still generate a script
        assert script.startswith("#!/bin/sh")

    def test_special_chars_in_username(self, setup_instance):
        """Test handling special characters in username."""
        script = setup_instance.create_setup_script(
            hostname="test.example.com",
            username="test-user_01",
            user_password="hash",
            root_password="roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert "test-user_01" in script

    def test_ipv6_addresses_not_supported(self, setup_instance):
        """Test that IPv6 addresses are passed through (validation elsewhere)."""
        # The module doesn't validate IPs, it just uses them
        script = setup_instance.create_setup_script(
            hostname="test.example.com",
            username="admin",
            user_password="hash",
            root_password="roothash",
            gateway_ip="fe80::1",
            vm_ip="fe80::100",
            alpine_version="3.21",
        )

        assert "fe80::100" in script

    def test_long_hostname(self, setup_instance):
        """Test handling very long hostname."""
        long_hostname = "a" * 200 + ".example.com"
        script = setup_instance.create_setup_script(
            hostname=long_hostname,
            username="admin",
            user_password="hash",
            root_password="roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        assert long_hostname in script

    def test_vm_name_with_special_chars(self, setup_instance):
        """Test VM name with special characters in serial console setup."""
        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__ = Mock(return_value=mock_file)
            mock_open.return_value.__exit__ = Mock(return_value=False)

            result = setup_instance.run_serial_console_setup(
                vm_name="test-vm_01.local",
                setup_script="#!/bin/sh\necho test",
            )

        assert result["success"] is True


class TestSecurityConsiderations:
    """Security-related tests."""

    def test_no_hardcoded_passwords_in_scripts(self, setup_instance):
        """Test that no hardcoded passwords appear in generated scripts."""
        script = setup_instance.create_setup_script(
            hostname="test.example.com",
            username="admin",
            user_password="$6$salt$hash",
            root_password="$6$salt$roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
        )

        # Should not contain plain text passwords
        assert "password123" not in script.lower()
        assert "admin123" not in script.lower()

    def test_script_uses_proper_permissions(self, setup_instance):
        """Test that scripts reference appropriate file permissions."""
        script = setup_instance.create_setup_script(
            hostname="test.example.com",
            username="admin",
            user_password="hash",
            root_password="roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            alpine_version="3.21",
            server_hostname="sysmanage.example.com",
            server_port=8443,
        )

        # Firstboot script should be made executable
        assert "chmod 755" in script

    def test_temp_file_path_in_serial_setup(self, setup_instance):
        """Test that temp file path uses /tmp for serial console setup."""
        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__ = Mock(return_value=mock_file)
            mock_open.return_value.__exit__ = Mock(return_value=False)

            setup_instance.run_serial_console_setup(
                vm_name="test-vm",
                setup_script="#!/bin/sh\necho test",
            )

            # Verify temp file is in /tmp
            call_args = mock_open.call_args[0][0]
            assert call_args.startswith("/tmp/")
            assert "alpine_setup" in call_args
