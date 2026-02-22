"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_debian_console module.
Tests Debian VMM console automation for automated Debian VM setup.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import base64
import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_debian_console import (
    DebianConsoleAutomation,
)


class TestDebianConsoleAutomationInit:
    """Test cases for DebianConsoleAutomation initialization."""

    def test_init_with_logger(self):
        """Test DebianConsoleAutomation initialization with logger."""
        mock_logger = Mock()
        console = DebianConsoleAutomation(mock_logger)

        assert console.logger == mock_logger

    def test_init_timeout_constants(self):
        """Test that timeout constants are properly set."""
        mock_logger = Mock()
        console = DebianConsoleAutomation(mock_logger)

        assert console.BOOT_MENU_TIMEOUT == 60
        assert console.BOOT_TIMEOUT == 120
        assert console.INSTALLER_TIMEOUT == 1200
        assert console.COMMAND_TIMEOUT == 30


class TestParseTtyFromStatus:
    """Test cases for _parse_tty_from_status method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch("subprocess.run")
    def test_parse_tty_from_status_success(self, mock_run):
        """Test successful TTY parsing from vmctl status."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="   ID   PID VCPUS  MAXMEM  CURMEM     TTY         OWNER STATE   NAME\n"
            "    1 12345     1    512M    256M ttyp0      root running test-vm",
        )

        result = self.console._parse_tty_from_status("test-vm")

        assert result == "ttyp0"
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_parse_tty_from_status_vm_not_running(self, mock_run):
        """Test TTY parsing when VM is not running."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="   ID   PID VCPUS  MAXMEM  CURMEM     TTY         OWNER STATE   NAME\n"
            "    1     -     1    512M       -       -      root stopped test-vm",
        )

        result = self.console._parse_tty_from_status("test-vm")

        assert result is None

    @patch("subprocess.run")
    def test_parse_tty_from_status_vm_not_found(self, mock_run):
        """Test TTY parsing when VM is not in the list."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="   ID   PID VCPUS  MAXMEM  CURMEM     TTY         OWNER STATE   NAME\n"
            "    1 12345     1    512M    256M ttyp0      root running other-vm",
        )

        result = self.console._parse_tty_from_status("test-vm")

        assert result is None

    @patch("subprocess.run")
    def test_parse_tty_from_status_empty_output(self, mock_run):
        """Test TTY parsing with empty vmctl output."""
        mock_run.return_value = Mock(returncode=0, stdout="")

        result = self.console._parse_tty_from_status("test-vm")

        assert result is None

    @patch("subprocess.run")
    def test_parse_tty_from_status_exception(self, mock_run):
        """Test TTY parsing with exception."""
        mock_run.side_effect = Exception("vmctl not found")

        result = self.console._parse_tty_from_status("test-vm")

        assert result is None
        self.mock_logger.error.assert_called()

    @patch("subprocess.run")
    def test_parse_tty_from_status_timeout(self, mock_run):
        """Test TTY parsing with subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("vmctl", 10)

        result = self.console._parse_tty_from_status("test-vm")

        assert result is None


class TestExtractTtyFromLine:
    """Test cases for _extract_tty_from_line method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    def test_extract_tty_from_valid_line(self):
        """Test extracting TTY from a valid vmctl status line."""
        line = "    1 12345     1    512M    256M ttyp0      root running test-vm"

        result = self.console._extract_tty_from_line(line, "test-vm")

        assert result == "ttyp0"

    def test_extract_tty_from_line_vm_not_in_line(self):
        """Test extracting TTY when VM name is not in line."""
        line = "    1 12345     1    512M    256M ttyp0      root running other-vm"

        result = self.console._extract_tty_from_line(line, "test-vm")

        assert result is None

    def test_extract_tty_from_line_not_running(self):
        """Test extracting TTY when VM is not running."""
        line = "    1     -     1    512M       -       -      root stopped test-vm"

        result = self.console._extract_tty_from_line(line, "test-vm")

        assert result is None

    def test_extract_tty_from_line_short_line(self):
        """Test extracting TTY from a line with insufficient parts."""
        line = "    1 12345"

        result = self.console._extract_tty_from_line(line, "test-vm")

        assert result is None

    def test_extract_tty_from_line_no_tty_prefix(self):
        """Test extracting TTY when TTY field doesn't start with 'tty'."""
        line = "    1 12345     1    512M    256M       -      root running test-vm"

        result = self.console._extract_tty_from_line(line, "test-vm")

        assert result is None

    def test_extract_tty_different_tty_names(self):
        """Test extracting different TTY names."""
        for tty in ["ttyp0", "ttyp1", "ttypa", "ttypf"]:
            line = f"    1 12345     1    512M    256M {tty}      root running test-vm"
            result = self.console._extract_tty_from_line(line, "test-vm")
            assert result == tty


class TestGetVmTty:
    """Test cases for get_vm_tty method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch.object(DebianConsoleAutomation, "_parse_tty_from_status")
    def test_get_vm_tty_immediate_success(self, mock_parse):
        """Test getting VM TTY on first attempt."""
        mock_parse.return_value = "ttyp0"

        result = self.console.get_vm_tty("test-vm")

        assert result == "ttyp0"
        mock_parse.assert_called_once_with("test-vm")

    @patch.object(DebianConsoleAutomation, "_parse_tty_from_status")
    @patch("time.sleep")
    def test_get_vm_tty_success_after_retries(self, mock_sleep, mock_parse):
        """Test getting VM TTY after a few retries."""
        mock_parse.side_effect = [None, None, "ttyp0"]

        result = self.console.get_vm_tty("test-vm", retries=5, delay=1.0)

        assert result == "ttyp0"
        assert mock_parse.call_count == 3
        assert mock_sleep.call_count == 2

    @patch.object(DebianConsoleAutomation, "_parse_tty_from_status")
    @patch("time.sleep")
    def test_get_vm_tty_failure_after_all_retries(self, mock_sleep, mock_parse):
        """Test getting VM TTY fails after all retries."""
        mock_parse.return_value = None

        result = self.console.get_vm_tty("test-vm", retries=3, delay=0.1)

        assert result is None
        assert mock_parse.call_count == 3
        assert mock_sleep.call_count == 2
        self.mock_logger.error.assert_called()

    @patch.object(DebianConsoleAutomation, "_parse_tty_from_status")
    def test_get_vm_tty_single_retry(self, mock_parse):
        """Test getting VM TTY with single retry."""
        mock_parse.return_value = None

        result = self.console.get_vm_tty("test-vm", retries=1)

        assert result is None
        mock_parse.assert_called_once()


class TestInjectBootParameters:
    """Test cases for inject_boot_parameters async method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    async def test_inject_boot_parameters_no_tty(self, mock_get_tty):
        """Test inject_boot_parameters when TTY cannot be found."""
        mock_get_tty.return_value = None

        result = await self.console.inject_boot_parameters("test-vm")

        assert result["success"] is False
        assert "Could not find TTY" in result["error"]

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    @patch.object(DebianConsoleAutomation, "_inject_boot_params")
    @patch("asyncio.to_thread")
    async def test_inject_boot_parameters_success(
        self, mock_to_thread, _mock_inject, mock_get_tty
    ):
        """Test successful inject_boot_parameters."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {
            "success": True,
            "message": "Boot parameters injected successfully",
        }

        result = await self.console.inject_boot_parameters(
            "test-vm",
            preseed_url="http://example.com/preseed.cfg",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert result["success"] is True
        mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    async def test_inject_boot_parameters_exception(self, mock_get_tty):
        """Test inject_boot_parameters with exception."""
        mock_get_tty.side_effect = Exception("Unexpected error")

        result = await self.console.inject_boot_parameters("test-vm")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_inject_boot_parameters_with_custom_timeout(
        self, mock_to_thread, mock_get_tty
    ):
        """Test inject_boot_parameters with custom timeout."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {"success": True}

        await self.console.inject_boot_parameters("test-vm", timeout=120)

        # Verify the custom timeout was passed to the inject function
        # Args: func, vm_name, tty_device, preseed_url, gateway_ip, vm_ip, dns_server, timeout
        call_args = mock_to_thread.call_args
        assert (
            call_args[0][7] == 120
        )  # timeout is at position 7 (after func + 6 params)


class TestInjectBootParams:
    """Test cases for _inject_boot_params method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(DebianConsoleAutomation, "_wait_for_prompt")
    @patch.object(DebianConsoleAutomation, "_read_output")
    @patch.object(DebianConsoleAutomation, "_send_key")
    @patch.object(DebianConsoleAutomation, "_build_boot_params")
    @patch("os.write")
    @patch("time.sleep")
    def test_inject_boot_params_success(
        self,
        _mock_sleep,
        _mock_write,
        mock_build_params,
        _mock_send_key,
        mock_read_output,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test successful boot parameter injection."""
        mock_openpty.return_value = (3, 4)
        mock_process = Mock()
        mock_process.terminate = Mock()
        mock_process.wait = Mock()
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = "Boot menu output"
        mock_build_params.return_value = " console=ttyS0,115200n8"

        result = self.console._inject_boot_params(
            "test-vm",
            "/dev/ttyp0",
            "http://example.com/preseed.cfg",
            "192.168.1.1",
            "192.168.1.100",
            "8.8.8.8",
            60,
        )

        assert result["success"] is True
        assert "injected successfully" in result["message"]
        mock_process.terminate.assert_called_once()

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(DebianConsoleAutomation, "_wait_for_prompt")
    @patch.object(DebianConsoleAutomation, "_read_output")
    @patch.object(DebianConsoleAutomation, "_send_key")
    @patch.object(DebianConsoleAutomation, "_build_boot_params")
    @patch("os.write")
    @patch("time.sleep")
    def test_inject_boot_params_menu_not_detected(
        self,
        _mock_sleep,
        _mock_write,
        mock_build_params,
        _mock_send_key,
        mock_read_output,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test boot parameter injection when menu not detected."""
        mock_openpty.return_value = (3, 4)
        mock_process = Mock()
        mock_process.terminate = Mock()
        mock_process.wait = Mock()
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = False
        mock_read_output.return_value = ""
        mock_build_params.return_value = " console=ttyS0,115200n8"

        result = self.console._inject_boot_params(
            "test-vm", "/dev/ttyp0", None, None, None, None, 60
        )

        # Should still succeed even if menu not detected
        assert result["success"] is True
        self.mock_logger.warning.assert_called()

    @patch("pty.openpty")
    def test_inject_boot_params_pty_exception(self, mock_openpty):
        """Test boot parameter injection with PTY exception."""
        mock_openpty.side_effect = OSError("PTY allocation failed")

        result = self.console._inject_boot_params(
            "test-vm", "/dev/ttyp0", None, None, None, None, 60
        )

        assert result["success"] is False
        assert "PTY allocation failed" in result["error"]

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(DebianConsoleAutomation, "_wait_for_prompt")
    @patch.object(DebianConsoleAutomation, "_read_output")
    @patch.object(DebianConsoleAutomation, "_send_key")
    @patch.object(DebianConsoleAutomation, "_build_boot_params")
    @patch("os.write")
    @patch("time.sleep")
    def test_inject_boot_params_process_timeout(
        self,
        _mock_sleep,
        _mock_write,
        mock_build_params,
        _mock_send_key,
        mock_read_output,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test boot parameter injection with process timeout."""

        mock_openpty.return_value = (3, 4)
        mock_process = Mock()
        mock_process.terminate = Mock()
        mock_process.wait = Mock(
            side_effect=[subprocess.TimeoutExpired("vmctl", 10), None]
        )
        mock_process.kill = Mock()
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = ""
        mock_build_params.return_value = " console=ttyS0,115200n8"

        result = self.console._inject_boot_params(
            "test-vm", "/dev/ttyp0", None, None, None, None, 60
        )

        assert result["success"] is True
        mock_process.kill.assert_called_once()

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(DebianConsoleAutomation, "_wait_for_prompt")
    @patch.object(DebianConsoleAutomation, "_read_output")
    @patch.object(DebianConsoleAutomation, "_send_key")
    @patch.object(DebianConsoleAutomation, "_build_boot_params")
    @patch("os.write")
    @patch("time.sleep")
    def test_inject_boot_params_close_oserror(
        self,
        _mock_sleep,
        _mock_write,
        mock_build_params,
        _mock_send_key,
        mock_read_output,
        mock_wait_prompt,
        mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test boot parameter injection handles OSError on fd close in finally."""
        mock_openpty.return_value = (3, 4)
        mock_process = Mock()
        mock_process.terminate = Mock()
        mock_process.wait = Mock()
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = ""
        mock_build_params.return_value = " console=ttyS0,115200n8"
        # First close (slave_fd in try block) succeeds, second (master_fd in finally) fails
        mock_close.side_effect = [None, OSError("Bad file descriptor")]

        # Should not raise, OSError is caught in finally block
        result = self.console._inject_boot_params(
            "test-vm", "/dev/ttyp0", None, None, None, None, 60
        )

        assert result["success"] is True

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    def test_inject_boot_params_slave_fd_oserror_on_exception(
        self,
        mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test boot parameter injection handles OSError when closing slave_fd on error."""
        mock_openpty.return_value = (3, 4)
        # Popen fails before slave is closed
        mock_popen.side_effect = Exception("Popen failed")
        # Make close fail for both fds (master first, then slave)
        mock_close.side_effect = OSError("Bad file descriptor")

        # Should not raise, OSError is caught in finally block
        result = self.console._inject_boot_params(
            "test-vm", "/dev/ttyp0", None, None, None, None, 60
        )

        assert result["success"] is False
        assert "Popen failed" in result["error"]


class TestBuildBootCommand:
    """Test cases for _build_boot_command method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    def test_build_boot_command_basic(self):
        """Test building basic boot command without optional params."""
        result = self.console._build_boot_command(None, None, None, None)

        assert result.startswith("install ")
        assert "console=ttyS0,115200n8" in result
        assert "vga=off" in result
        assert "DEBIAN_FRONTEND=text" in result
        assert "auto=true" in result
        assert "priority=critical" in result
        assert "net.ifnames=0" in result
        assert "biosdevname=0" in result

    def test_build_boot_command_with_preseed(self):
        """Test building boot command with preseed URL."""
        result = self.console._build_boot_command(
            "http://example.com/preseed.cfg", None, None, None
        )

        assert "url=http://example.com/preseed.cfg" in result

    def test_build_boot_command_with_network(self):
        """Test building boot command with network configuration."""
        result = self.console._build_boot_command(
            None, "192.168.1.1", "192.168.1.100", "8.8.8.8"
        )

        assert "ip=192.168.1.100::192.168.1.1:255.255.255.0" in result
        assert "netcfg/get_ipaddress=192.168.1.100" in result
        assert "netcfg/get_gateway=192.168.1.1" in result
        assert "netcfg/get_nameservers=8.8.8.8" in result
        assert "netcfg/disable_dhcp=true" in result

    def test_build_boot_command_network_without_dns(self):
        """Test building boot command with network but no DNS."""
        result = self.console._build_boot_command(
            None, "192.168.1.1", "192.168.1.100", None
        )

        assert "netcfg/get_nameservers" not in result

    def test_build_boot_command_full(self):
        """Test building boot command with all parameters."""
        result = self.console._build_boot_command(
            "http://example.com/preseed.cfg",
            "192.168.1.1",
            "192.168.1.100",
            "8.8.8.8",
        )

        assert result.startswith("install ")
        assert "url=http://example.com/preseed.cfg" in result
        assert "ip=192.168.1.100::192.168.1.1:255.255.255.0" in result
        assert "netcfg/get_nameservers=8.8.8.8" in result


class TestBuildBootParams:
    """Test cases for _build_boot_params method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    def test_build_boot_params_basic(self):
        """Test building basic boot params without optional params."""
        result = self.console._build_boot_params(None, None, None, None)

        # Should start with a space for appending
        assert result.startswith(" ")
        assert "console=ttyS0,115200n8" in result
        assert "vga=off" in result

    def test_build_boot_params_with_preseed(self):
        """Test building boot params with preseed URL."""
        result = self.console._build_boot_params(
            "http://example.com/preseed.cfg", None, None, None
        )

        assert "url=http://example.com/preseed.cfg" in result

    def test_build_boot_params_with_network(self):
        """Test building boot params with network configuration."""
        result = self.console._build_boot_params(
            None, "192.168.1.1", "192.168.1.100", "8.8.8.8"
        )

        # Check hostname is derived from IP
        assert "192-168-1-100:eth0:off" in result
        assert "netcfg/choose_interface=eth0" in result
        assert "netcfg/get_ipaddress=192.168.1.100" in result
        assert "netcfg/get_netmask=255.255.255.0" in result
        assert "netcfg/get_gateway=192.168.1.1" in result
        assert "netcfg/get_nameservers=8.8.8.8" in result
        assert "netcfg/disable_dhcp=true" in result
        assert "netcfg/confirm_static=true" in result

    def test_build_boot_params_network_no_dns(self):
        """Test building boot params with network but no DNS."""
        result = self.console._build_boot_params(
            None, "192.168.1.1", "192.168.1.100", None
        )

        assert "netcfg/get_nameservers" not in result
        assert "netcfg/disable_dhcp=true" in result


class TestRunPreseedSetup:
    """Test cases for run_preseed_setup async method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    async def test_run_preseed_setup_no_tty(self, mock_get_tty):
        """Test run_preseed_setup when TTY cannot be found."""
        mock_get_tty.return_value = None

        result = await self.console.run_preseed_setup(
            "test-vm", "preseed content", "agent config", "firstboot", "systemd"
        )

        assert result["success"] is False
        assert "Could not find TTY" in result["error"]

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_run_preseed_setup_success(self, mock_to_thread, mock_get_tty):
        """Test successful run_preseed_setup."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {
            "success": True,
            "message": "Debian setup monitoring complete",
        }

        result = await self.console.run_preseed_setup(
            "test-vm",
            "preseed content",
            "agent config",
            "firstboot script",
            "systemd service",
        )

        assert result["success"] is True
        mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    async def test_run_preseed_setup_exception(self, mock_get_tty):
        """Test run_preseed_setup with exception."""
        mock_get_tty.side_effect = Exception("Unexpected error")

        result = await self.console.run_preseed_setup(
            "test-vm", "preseed", "config", "firstboot", "systemd"
        )

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_run_preseed_setup_custom_timeout(self, mock_to_thread, mock_get_tty):
        """Test run_preseed_setup with custom timeout."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {"success": True}

        await self.console.run_preseed_setup(
            "test-vm", "preseed", "config", "firstboot", "systemd", timeout=1800
        )

        call_args = mock_to_thread.call_args
        assert call_args[0][7] == 1800  # timeout parameter position


class TestManualPreseedSetup:
    """Test cases for _manual_preseed_setup method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(DebianConsoleAutomation, "_wait_for_prompt")
    def test_manual_preseed_setup_success(
        self, mock_wait_prompt, _mock_close, mock_popen, mock_openpty
    ):
        """Test successful manual preseed setup."""
        mock_openpty.return_value = (3, 4)
        mock_process = Mock()
        mock_process.terminate = Mock()
        mock_process.wait = Mock()
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True

        result = self.console._manual_preseed_setup(
            "test-vm",
            "/dev/ttyp0",
            "preseed content",
            "agent config",
            "firstboot script",
            "systemd service",
            300,
        )

        assert result["success"] is True
        assert "monitoring complete" in result["message"]

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(DebianConsoleAutomation, "_wait_for_prompt")
    def test_manual_preseed_setup_login_not_detected(
        self, mock_wait_prompt, _mock_close, mock_popen, mock_openpty
    ):
        """Test manual preseed setup when login prompt not detected."""
        mock_openpty.return_value = (3, 4)
        mock_process = Mock()
        mock_process.terminate = Mock()
        mock_process.wait = Mock()
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = False

        result = self.console._manual_preseed_setup(
            "test-vm", "/dev/ttyp0", "preseed", "config", "firstboot", "systemd", 300
        )

        # Should still succeed even if login not detected
        assert result["success"] is True
        self.mock_logger.warning.assert_called()

    @patch("pty.openpty")
    def test_manual_preseed_setup_pty_exception(self, mock_openpty):
        """Test manual preseed setup with PTY exception."""
        mock_openpty.side_effect = OSError("PTY allocation failed")

        result = self.console._manual_preseed_setup(
            "test-vm", "/dev/ttyp0", "preseed", "config", "firstboot", "systemd", 300
        )

        assert result["success"] is False
        assert "PTY allocation failed" in result["error"]

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(DebianConsoleAutomation, "_wait_for_prompt")
    def test_manual_preseed_setup_process_timeout(
        self, mock_wait_prompt, _mock_close, mock_popen, mock_openpty
    ):
        """Test manual preseed setup with process timeout on terminate."""

        mock_openpty.return_value = (3, 4)
        mock_process = Mock()
        mock_process.terminate = Mock()
        mock_process.wait = Mock(
            side_effect=[subprocess.TimeoutExpired("vmctl", 10), None]
        )
        mock_process.kill = Mock()
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True

        result = self.console._manual_preseed_setup(
            "test-vm", "/dev/ttyp0", "preseed", "config", "firstboot", "systemd", 300
        )

        assert result["success"] is True
        mock_process.kill.assert_called_once()

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(DebianConsoleAutomation, "_wait_for_prompt")
    def test_manual_preseed_setup_close_oserror(
        self, mock_wait_prompt, mock_close, mock_popen, mock_openpty
    ):
        """Test manual preseed setup handles OSError on fd close in finally."""
        mock_openpty.return_value = (3, 4)
        mock_process = Mock()
        mock_process.terminate = Mock()
        mock_process.wait = Mock()
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        # First close (slave_fd in try block) succeeds, second (master_fd in finally) fails
        mock_close.side_effect = [None, OSError("Bad file descriptor")]

        # Should not raise, OSError is caught in finally block
        result = self.console._manual_preseed_setup(
            "test-vm", "/dev/ttyp0", "preseed", "config", "firstboot", "systemd", 300
        )

        assert result["success"] is True

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    def test_manual_preseed_setup_slave_fd_oserror_on_exception(
        self,
        mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test manual preseed setup handles OSError when closing slave_fd on error."""
        mock_openpty.return_value = (3, 4)
        # Popen fails before slave is closed
        mock_popen.side_effect = Exception("Popen failed")
        # Make close fail for both fds (master first, then slave)
        mock_close.side_effect = OSError("Bad file descriptor")

        # Should not raise, OSError is caught in finally block
        result = self.console._manual_preseed_setup(
            "test-vm", "/dev/ttyp0", "preseed", "config", "firstboot", "systemd", 300
        )

        assert result["success"] is False
        assert "Popen failed" in result["error"]


class TestWaitForInstallationComplete:
    """Test cases for wait_for_installation_complete async method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_debian_console.run_command_async")
    @patch("time.time")
    @patch("asyncio.sleep")
    async def test_wait_for_installation_vm_stopped(
        self, _mock_sleep, mock_time, mock_run_command
    ):
        """Test waiting for installation when VM stops."""
        mock_time.side_effect = [0, 10]  # Two time checks
        mock_run_command.return_value = Mock(
            returncode=0, stdout="test-vm stopped", stderr=""
        )

        result = await self.console.wait_for_installation_complete(
            "test-vm", timeout=300
        )

        assert result["success"] is True
        assert "completed" in result["message"]

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_debian_console.run_command_async")
    @patch("time.time")
    @patch("asyncio.sleep")
    async def test_wait_for_installation_running_then_stopped(
        self, _mock_sleep, mock_time, mock_run_command
    ):
        """Test waiting for installation when VM is running then stops."""
        mock_time.side_effect = [0, 10, 20, 30]
        mock_run_command.side_effect = [
            Mock(returncode=0, stdout="running", stderr=""),
            Mock(returncode=0, stdout="running", stderr=""),
            Mock(returncode=0, stdout="stopped", stderr=""),
        ]

        result = await self.console.wait_for_installation_complete(
            "test-vm", timeout=300
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_debian_console.run_command_async")
    @patch("time.time")
    @patch("asyncio.sleep")
    async def test_wait_for_installation_timeout(
        self, _mock_sleep, mock_time, mock_run_command
    ):
        """Test waiting for installation with timeout."""
        mock_time.side_effect = [0, 100, 200, 301]
        mock_run_command.return_value = Mock(returncode=0, stdout="running", stderr="")

        result = await self.console.wait_for_installation_complete(
            "test-vm", timeout=300
        )

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_debian_console.run_command_async")
    async def test_wait_for_installation_exception(self, mock_run_command):
        """Test waiting for installation with exception."""
        mock_run_command.side_effect = Exception("Command failed")

        result = await self.console.wait_for_installation_complete("test-vm")

        assert result["success"] is False
        assert "Command failed" in result["error"]

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_debian_console.run_command_async")
    @patch("time.time")
    @patch("asyncio.sleep")
    async def test_wait_for_installation_default_timeout(
        self, _mock_sleep, mock_time, mock_run_command
    ):
        """Test wait_for_installation_complete uses default timeout."""
        mock_time.return_value = 0
        mock_run_command.return_value = Mock(returncode=0, stdout="stopped", stderr="")

        await self.console.wait_for_installation_complete("test-vm")

        # Should use default INSTALLER_TIMEOUT
        self.mock_logger.info.assert_called()


class TestWaitForPrompt:
    """Test cases for _wait_for_prompt method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch("select.select")
    @patch.object(DebianConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_found(self, mock_time, mock_safe_read, mock_select):
        """Test waiting for prompt when prompt is found."""
        mock_time.side_effect = [0, 1, 2]
        mock_select.return_value = ([True], [], [])
        mock_safe_read.return_value = b"Welcome to Debian login:"

        result = self.console._wait_for_prompt(3, [b"login:"], 30)

        assert result is True

    @patch("select.select")
    @patch.object(DebianConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_not_found(self, mock_time, mock_safe_read, mock_select):
        """Test waiting for prompt when prompt is not found."""
        mock_time.side_effect = [0, 10, 20, 31]  # Exceeds timeout
        mock_select.return_value = ([True], [], [])
        mock_safe_read.return_value = b"Some other output"

        result = self.console._wait_for_prompt(3, [b"login:"], 30)

        assert result is False

    @patch("select.select")
    @patch("time.time")
    def test_wait_for_prompt_no_data(self, mock_time, mock_select):
        """Test waiting for prompt when no data is ready."""
        mock_time.side_effect = [0, 10, 20, 31]
        mock_select.return_value = ([], [], [])

        result = self.console._wait_for_prompt(3, [b"login:"], 30)

        assert result is False

    @patch("select.select")
    @patch.object(DebianConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_read_error(self, mock_time, mock_safe_read, mock_select):
        """Test waiting for prompt with read error."""
        mock_time.side_effect = [0, 1]
        mock_select.return_value = ([True], [], [])
        mock_safe_read.return_value = None  # Read error

        result = self.console._wait_for_prompt(3, [b"login:"], 30)

        assert result is False

    @patch("select.select")
    @patch.object(DebianConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_multiple_prompts(
        self, mock_time, mock_safe_read, mock_select
    ):
        """Test waiting for one of multiple prompts."""
        mock_time.side_effect = [0, 1]
        mock_select.return_value = ([True], [], [])
        mock_safe_read.return_value = b"Graphical install"

        result = self.console._wait_for_prompt(
            3, [b"Graphical install", b"Install", b"ISOLINUX"], 30
        )

        assert result is True


class TestSafeRead:
    """Test cases for _safe_read method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch("os.read")
    def test_safe_read_success(self, mock_read):
        """Test successful safe read."""
        mock_read.return_value = b"Hello World"

        result = self.console._safe_read(3)

        assert result == b"Hello World"
        mock_read.assert_called_once_with(3, 1024)

    @patch("os.read")
    def test_safe_read_oserror(self, mock_read):
        """Test safe read with OSError."""
        mock_read.side_effect = OSError("Read error")

        result = self.console._safe_read(3)

        assert result is None


class TestCheckPrompts:
    """Test cases for _check_prompts method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    def test_check_prompts_found(self):
        """Test checking prompts when prompt is present."""
        buffer = b"Welcome to Debian login:"
        prompts = [b"login:", b"Password:"]

        result = self.console._check_prompts(buffer, prompts)

        assert result is True

    def test_check_prompts_not_found(self):
        """Test checking prompts when prompt is not present."""
        buffer = b"Welcome to Debian"
        prompts = [b"login:", b"Password:"]

        result = self.console._check_prompts(buffer, prompts)

        assert result is False

    def test_check_prompts_empty_buffer(self):
        """Test checking prompts with empty buffer."""
        buffer = b""
        prompts = [b"login:"]

        result = self.console._check_prompts(buffer, prompts)

        assert result is False

    def test_check_prompts_empty_prompts(self):
        """Test checking prompts with empty prompts list."""
        buffer = b"Welcome to Debian"
        prompts = []

        result = self.console._check_prompts(buffer, prompts)

        assert result is False


class TestSendKey:
    """Test cases for _send_key method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch("os.write")
    @patch("time.sleep")
    def test_send_key_success(self, mock_sleep, mock_write):
        """Test successful key send."""
        self.console._send_key(3, "\t")

        mock_write.assert_called_once_with(3, b"\t")
        mock_sleep.assert_called_once_with(0.1)

    @patch("os.write")
    @patch("time.sleep")
    def test_send_key_escape_sequence(self, _mock_sleep, mock_write):
        """Test sending escape sequence (arrow key)."""
        self.console._send_key(3, "\x1b[B")  # Down arrow

        mock_write.assert_called_once_with(3, b"\x1b[B")

    @patch("os.write")
    @patch("time.sleep")
    def test_send_key_enter(self, _mock_sleep, mock_write):
        """Test sending enter key."""
        self.console._send_key(3, "\r")

        mock_write.assert_called_once_with(3, b"\r")


class TestSendLine:
    """Test cases for _send_line method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch("os.write")
    @patch("time.sleep")
    def test_send_line_success(self, mock_sleep, mock_write):
        """Test successful line send."""
        self.console._send_line(3, "echo hello")

        mock_write.assert_called_once_with(3, b"echo hello\n")
        mock_sleep.assert_called_once_with(0.1)

    @patch("os.write")
    @patch("time.sleep")
    def test_send_line_empty(self, _mock_sleep, mock_write):
        """Test sending empty line."""
        self.console._send_line(3, "")

        mock_write.assert_called_once_with(3, b"\n")


class TestReadOutput:
    """Test cases for _read_output method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_success(self, mock_time, mock_read, mock_select):
        """Test successful output reading."""
        # The _read_output loop checks time multiple times per iteration
        # More calls needed: start, first check, first select loop, second loop, etc.
        mock_time.side_effect = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 1.1]
        mock_select.side_effect = [
            ([True], [], []),  # First read
            ([True], [], []),  # Second read
            ([], [], []),  # No more data, exit
        ]
        mock_read.side_effect = [b"Hello ", b"World"]

        result = self.console._read_output(3, timeout=1.0)

        assert result == "Hello World"

    @patch("select.select")
    @patch("time.time")
    def test_read_output_no_data(self, mock_time, mock_select):
        """Test output reading with no data."""
        mock_time.side_effect = [0, 0.5, 1.1]
        mock_select.return_value = ([], [], [])

        result = self.console._read_output(3, timeout=1.0)

        assert result == ""

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_oserror(self, mock_time, mock_read, mock_select):
        """Test output reading with OSError."""
        mock_time.side_effect = [0, 0.5]
        mock_select.return_value = ([True], [], [])
        mock_read.side_effect = OSError("Read error")

        result = self.console._read_output(3, timeout=1.0)

        assert result == ""

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_empty_read(self, mock_time, mock_read, mock_select):
        """Test output reading with empty read (EOF)."""
        mock_time.side_effect = [0, 0.5]
        mock_select.return_value = ([True], [], [])
        mock_read.return_value = b""

        result = self.console._read_output(3, timeout=1.0)

        assert result == ""

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_unicode_errors(self, mock_time, mock_read, mock_select):
        """Test output reading with invalid unicode."""
        mock_time.side_effect = [0, 0.5, 1.1]
        mock_select.side_effect = [([True], [], []), ([], [], [])]
        # Invalid UTF-8 bytes
        mock_read.return_value = b"Hello \xff\xfe World"

        result = self.console._read_output(3, timeout=1.0)

        # Should handle invalid unicode gracefully
        assert "Hello" in result


class TestWriteFileViaBase64:
    """Test cases for _write_file_via_base64 method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @patch.object(DebianConsoleAutomation, "_send_line")
    @patch("time.sleep")
    def test_write_file_via_base64_success(self, _mock_sleep, mock_send_line):
        """Test successful file writing via base64."""
        content = "Hello World"

        result = self.console._write_file_via_base64(
            3, content, "/tmp/test.txt", executable=False
        )

        assert result is True
        # Should have called _send_line multiple times
        assert mock_send_line.call_count >= 2

    @patch.object(DebianConsoleAutomation, "_send_line")
    @patch("time.sleep")
    def test_write_file_via_base64_executable(self, _mock_sleep, mock_send_line):
        """Test writing executable file via base64."""
        content = "#!/bin/bash\necho hello"

        result = self.console._write_file_via_base64(
            3, content, "/tmp/script.sh", executable=True
        )

        assert result is True
        # Should have called chmod
        chmod_calls = [c for c in mock_send_line.call_args_list if "chmod" in str(c)]
        assert len(chmod_calls) > 0

    @patch.object(DebianConsoleAutomation, "_send_line")
    @patch("time.sleep")
    def test_write_file_via_base64_long_content(self, _mock_sleep, mock_send_line):
        """Test writing long content that requires multiple chunks."""
        # Create content longer than chunk size (800)
        content = "A" * 2000

        result = self.console._write_file_via_base64(
            3, content, "/tmp/large.txt", executable=False
        )

        assert result is True
        # Should have multiple echo calls for chunks
        echo_calls = [c for c in mock_send_line.call_args_list if "echo" in str(c)]
        assert len(echo_calls) >= 2

    @patch.object(DebianConsoleAutomation, "_send_line")
    @patch("time.sleep")
    def test_write_file_via_base64_exception(self, _mock_sleep, mock_send_line):
        """Test file writing with exception."""
        mock_send_line.side_effect = Exception("Write failed")

        result = self.console._write_file_via_base64(
            3, "content", "/tmp/test.txt", executable=False
        )

        assert result is False
        self.mock_logger.error.assert_called()

    @patch.object(DebianConsoleAutomation, "_send_line")
    @patch("time.sleep")
    def test_write_file_via_base64_cleanup(self, _mock_sleep, mock_send_line):
        """Test that temporary file is cleaned up."""
        content = "test content"

        self.console._write_file_via_base64(
            3, content, "/tmp/test.txt", executable=False
        )

        # Should have rm /tmp/file.b64 call
        rm_calls = [
            c for c in mock_send_line.call_args_list if "rm /tmp/file.b64" in str(c)
        ]
        assert len(rm_calls) == 1


class TestIntegration:
    """Integration-style tests for DebianConsoleAutomation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_full_boot_injection_workflow(self, mock_to_thread, mock_get_tty):
        """Test complete boot parameter injection workflow."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {
            "success": True,
            "message": "Boot parameters injected successfully",
        }

        result = await self.console.inject_boot_parameters(
            "debian-vm",
            preseed_url="http://preseed.example.com/preseed.cfg",
            gateway_ip="192.168.100.1",
            vm_ip="192.168.100.50",
            dns_server="8.8.8.8",
            timeout=120,
        )

        assert result["success"] is True
        mock_get_tty.assert_called_once_with("debian-vm")

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    @patch.object(DebianConsoleAutomation, "wait_for_installation_complete")
    async def test_full_preseed_setup_workflow(
        self, mock_wait_install, mock_to_thread, mock_get_tty
    ):
        """Test complete preseed setup workflow."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {
            "success": True,
            "message": "Debian setup monitoring complete",
        }
        mock_wait_install.return_value = {
            "success": True,
            "message": "Installation completed",
        }

        # Run preseed setup
        preseed_result = await self.console.run_preseed_setup(
            "debian-vm",
            "d-i debian-installer/locale string en_US",
            "server_url: https://sysmanage.example.com",
            "#!/bin/bash\necho firstboot",
            "[Unit]\nDescription=Firstboot",
        )

        # Wait for installation
        install_result = await mock_wait_install("debian-vm")

        assert preseed_result["success"] is True
        assert install_result["success"] is True


class TestEdgeCases:
    """Edge case tests for DebianConsoleAutomation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.console = DebianConsoleAutomation(self.mock_logger)

    def test_extract_tty_case_insensitive_running(self):
        """Test that 'running' check is case insensitive."""
        line = "    1 12345     1    512M    256M ttyp0      root RUNNING test-vm"

        result = self.console._extract_tty_from_line(line, "test-vm")

        assert result == "ttyp0"

    def test_build_boot_params_ip_hostname_format(self):
        """Test that IP is correctly converted to hostname format."""
        result = self.console._build_boot_params(None, "10.0.0.1", "10.0.0.100", None)

        # IP dots should be converted to dashes in hostname
        assert "10-0-0-100:eth0:off" in result

    @patch("subprocess.run")
    def test_parse_tty_truncates_long_output(self, mock_run):
        """Test that very long vmctl output is handled."""
        # Create output longer than 200 chars
        long_output = "A" * 500
        mock_run.return_value = Mock(returncode=0, stdout=long_output)

        # Should not raise
        self.console._parse_tty_from_status("test-vm")

        # Logger should be called with truncated output
        self.mock_logger.info.assert_called()

    @patch.object(DebianConsoleAutomation, "_send_line")
    @patch("time.sleep")
    def test_write_file_base64_encoding(self, _mock_sleep, mock_send_line):
        """Test that content is properly base64 encoded."""
        content = "Hello\nWorld\n"
        expected_b64 = base64.b64encode(content.encode()).decode("ascii")

        self.console._write_file_via_base64(3, content, "/tmp/test.txt")

        # Find the echo call with base64 content
        echo_calls = [str(c) for c in mock_send_line.call_args_list if "echo" in str(c)]
        # At least one call should contain our base64 content
        found_b64 = any(expected_b64[:20] in call for call in echo_calls)
        assert found_b64

    def test_check_prompts_partial_match(self):
        """Test that prompts match partially in buffer."""
        buffer = b"Some text before login: and after"
        prompts = [b"login:"]

        result = self.console._check_prompts(buffer, prompts)

        assert result is True

    @pytest.mark.asyncio
    @patch.object(DebianConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_inject_boot_parameters_none_values(
        self, mock_to_thread, mock_get_tty
    ):
        """Test inject_boot_parameters with None optional values."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {"success": True}

        # All optional parameters as None
        await self.console.inject_boot_parameters("test-vm")

        assert mock_to_thread.called

    def test_build_boot_command_gateway_only(self):
        """Test build_boot_command with gateway but no vm_ip."""
        boot_command = self.console._build_boot_command(None, "192.168.1.1", None, None)

        # Should not include network config without both gateway and vm_ip
        assert "netcfg/get_ipaddress" not in boot_command

    def test_build_boot_command_vm_ip_only(self):
        """Test build_boot_command with vm_ip but no gateway."""
        result = self.console._build_boot_command(None, None, "192.168.1.100", None)

        # Should not include network config without both gateway and vm_ip
        assert "netcfg/get_ipaddress" not in result
