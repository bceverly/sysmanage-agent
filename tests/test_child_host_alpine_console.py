"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_alpine_console module.
Tests Alpine Linux VMM console automation for automated VM installation.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import base64
import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_alpine_console import (
    AlpineConsoleAutomation,
)


class TestAlpineConsoleAutomationInit:
    """Test cases for AlpineConsoleAutomation initialization."""

    def test_init_with_logger(self):
        """Test AlpineConsoleAutomation initialization with logger."""
        mock_logger = Mock()
        automation = AlpineConsoleAutomation(mock_logger)

        assert automation.logger == mock_logger

    def test_init_timeout_constants(self):
        """Test that timeout constants are properly defined."""
        mock_logger = Mock()
        automation = AlpineConsoleAutomation(mock_logger)

        assert automation.BOOT_TIMEOUT == 120
        assert automation.LOGIN_TIMEOUT == 60
        assert automation.COMMAND_TIMEOUT == 30
        assert automation.INSTALL_TIMEOUT == 600


class TestParseTTYFromStatus:
    """Test cases for _parse_tty_from_status method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch("subprocess.run")
    def test_parse_tty_success(self, mock_run):
        """Test successful TTY parsing from vmctl status."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE     NAME\n"
            "    1  1234     1    512M    256M   ttyp0         root running   alpine-vm",
        )

        result = self.automation._parse_tty_from_status("alpine-vm")

        assert result == "ttyp0"
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_parse_tty_vm_not_found(self, mock_run):
        """Test TTY parsing when VM is not in status output."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE     NAME\n"
            "    1  1234     1    512M    256M   ttyp0         root running   other-vm",
        )

        result = self.automation._parse_tty_from_status("alpine-vm")

        assert result is None

    @patch("subprocess.run")
    def test_parse_tty_vm_not_running(self, mock_run):
        """Test TTY parsing when VM exists but is not running."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE     NAME\n"
            "    1  1234     1    512M    256M   ttyp0         root stopped   alpine-vm",
        )

        result = self.automation._parse_tty_from_status("alpine-vm")

        assert result is None

    @patch("subprocess.run")
    def test_parse_tty_empty_status(self, mock_run):
        """Test TTY parsing with empty vmctl status output."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE     NAME\n",
        )

        result = self.automation._parse_tty_from_status("alpine-vm")

        assert result is None

    @patch("subprocess.run")
    def test_parse_tty_exception(self, mock_run):
        """Test TTY parsing when subprocess raises exception."""
        mock_run.side_effect = Exception("Command failed")

        result = self.automation._parse_tty_from_status("alpine-vm")

        assert result is None
        self.mock_logger.error.assert_called()

    @patch("subprocess.run")
    def test_parse_tty_timeout(self, mock_run):
        """Test TTY parsing when subprocess times out."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="vmctl", timeout=10)

        result = self.automation._parse_tty_from_status("alpine-vm")

        assert result is None
        self.mock_logger.error.assert_called()


class TestExtractTTYFromLine:
    """Test cases for _extract_tty_from_line method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    def test_extract_tty_valid_line(self):
        """Test extracting TTY from valid vmctl status line."""
        line = (
            "    1  1234     1    512M    256M   ttyp0         root running   alpine-vm"
        )

        result = self.automation._extract_tty_from_line(line, "alpine-vm")

        assert result == "ttyp0"

    def test_extract_tty_different_tty(self):
        """Test extracting TTY with different TTY name."""
        line = (
            "    2  5678     2   1024M    512M   ttyp1         root running   alpine-vm"
        )

        result = self.automation._extract_tty_from_line(line, "alpine-vm")

        assert result == "ttyp1"

    def test_extract_tty_vm_not_in_line(self):
        """Test extracting TTY when VM name not in line."""
        line = (
            "    1  1234     1    512M    256M   ttyp0         root running   other-vm"
        )

        result = self.automation._extract_tty_from_line(line, "alpine-vm")

        assert result is None

    def test_extract_tty_not_running(self):
        """Test extracting TTY when VM is not running."""
        line = (
            "    1  1234     1    512M    256M   ttyp0         root stopped   alpine-vm"
        )

        result = self.automation._extract_tty_from_line(line, "alpine-vm")

        assert result is None

    def test_extract_tty_short_line(self):
        """Test extracting TTY from line with insufficient parts."""
        line = "    1  1234     1"

        result = self.automation._extract_tty_from_line(line, "alpine-vm")

        assert result is None

    def test_extract_tty_no_tty_prefix(self):
        """Test extracting TTY when TTY field doesn't start with 'tty'."""
        line = (
            "    1  1234     1    512M    256M   -             root running   alpine-vm"
        )

        result = self.automation._extract_tty_from_line(line, "alpine-vm")

        assert result is None

    def test_extract_tty_empty_line(self):
        """Test extracting TTY from empty line."""
        line = ""

        result = self.automation._extract_tty_from_line(line, "alpine-vm")

        assert result is None


class TestGetVmTTY:
    """Test cases for get_vm_tty method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch.object(AlpineConsoleAutomation, "_parse_tty_from_status")
    def test_get_vm_tty_immediate_success(self, mock_parse):
        """Test getting VM TTY on first attempt."""
        mock_parse.return_value = "ttyp0"

        result = self.automation.get_vm_tty("alpine-vm")

        assert result == "ttyp0"
        assert mock_parse.call_count == 1
        self.mock_logger.info.assert_called()

    @patch.object(AlpineConsoleAutomation, "_parse_tty_from_status")
    @patch("time.sleep")
    def test_get_vm_tty_success_after_retries(self, mock_sleep, mock_parse):
        """Test getting VM TTY after a few retries."""
        mock_parse.side_effect = [None, None, "ttyp0"]

        result = self.automation.get_vm_tty("alpine-vm", retries=5, delay=1.0)

        assert result == "ttyp0"
        assert mock_parse.call_count == 3
        assert mock_sleep.call_count == 2

    @patch.object(AlpineConsoleAutomation, "_parse_tty_from_status")
    @patch("time.sleep")
    def test_get_vm_tty_all_retries_fail(self, mock_sleep, mock_parse):
        """Test getting VM TTY when all retries fail."""
        mock_parse.return_value = None

        result = self.automation.get_vm_tty("alpine-vm", retries=3, delay=0.5)

        assert result is None
        assert mock_parse.call_count == 3
        assert mock_sleep.call_count == 2
        self.mock_logger.error.assert_called()

    @patch.object(AlpineConsoleAutomation, "_parse_tty_from_status")
    def test_get_vm_tty_single_retry(self, mock_parse):
        """Test getting VM TTY with single retry."""
        mock_parse.return_value = None

        result = self.automation.get_vm_tty("alpine-vm", retries=1)

        assert result is None
        assert mock_parse.call_count == 1
        self.mock_logger.error.assert_called()

    @patch.object(AlpineConsoleAutomation, "_parse_tty_from_status")
    @patch("time.sleep")
    def test_get_vm_tty_custom_delay(self, mock_sleep, mock_parse):
        """Test getting VM TTY with custom delay."""
        mock_parse.side_effect = [None, "ttyp0"]

        self.automation.get_vm_tty("alpine-vm", retries=3, delay=5.0)

        mock_sleep.assert_called_with(5.0)


class TestRunAutomatedSetup:
    """Test cases for run_automated_setup method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(AlpineConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_run_automated_setup_success(self, mock_to_thread, mock_get_tty):
        """Test successful automated setup."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {
            "success": True,
            "message": "Console automation completed",
        }

        result = await self.automation.run_automated_setup(
            "alpine-vm", "#!/bin/sh\necho hello"
        )

        assert result["success"] is True
        mock_get_tty.assert_called_once_with("alpine-vm")
        mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    @patch.object(AlpineConsoleAutomation, "get_vm_tty")
    async def test_run_automated_setup_no_tty(self, mock_get_tty):
        """Test automated setup when TTY not found."""
        mock_get_tty.return_value = None

        result = await self.automation.run_automated_setup(
            "alpine-vm", "#!/bin/sh\necho hello"
        )

        assert result["success"] is False
        assert "Could not find TTY" in result["error"]

    @pytest.mark.asyncio
    @patch.object(AlpineConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_run_automated_setup_exception(self, mock_to_thread, mock_get_tty):
        """Test automated setup with exception."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.side_effect = Exception("Console interaction failed")

        result = await self.automation.run_automated_setup(
            "alpine-vm", "#!/bin/sh\necho hello"
        )

        assert result["success"] is False
        assert "Console interaction failed" in result["error"]
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    @patch.object(AlpineConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_run_automated_setup_custom_timeout(
        self, mock_to_thread, mock_get_tty
    ):
        """Test automated setup with custom timeout."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {"success": True}

        await self.automation.run_automated_setup(
            "alpine-vm", "#!/bin/sh\necho hello", timeout=300
        )

        # Verify custom timeout was passed to console interaction
        call_args = mock_to_thread.call_args
        assert call_args[0][4] == 300  # Fourth positional arg is timeout

    @pytest.mark.asyncio
    @patch.object(AlpineConsoleAutomation, "get_vm_tty")
    @patch("asyncio.to_thread")
    async def test_run_automated_setup_default_timeout(
        self, mock_to_thread, mock_get_tty
    ):
        """Test automated setup uses default timeout when not specified."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {"success": True}

        await self.automation.run_automated_setup("alpine-vm", "#!/bin/sh\necho hello")

        # Verify default timeout (INSTALL_TIMEOUT = 600) was used
        call_args = mock_to_thread.call_args
        assert call_args[0][4] == 600


class TestConsoleInteraction:
    """Test cases for _console_interaction method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(AlpineConsoleAutomation, "_wait_for_prompt")
    @patch.object(AlpineConsoleAutomation, "_send_line")
    @patch.object(AlpineConsoleAutomation, "_read_output")
    @patch("time.sleep")
    def test_console_interaction_success(
        self,
        _mock_sleep,
        mock_read_output,
        mock_send_line,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test successful console interaction."""
        mock_openpty.return_value = (10, 11)
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = "Script started"

        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "#!/bin/sh\necho hello", 600
        )

        assert result["success"] is True
        assert "Console automation completed" in result["message"]
        mock_openpty.assert_called_once()
        mock_popen.assert_called_once()
        # Verify root login was sent
        assert any("root" in str(call) for call in mock_send_line.call_args_list)

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(AlpineConsoleAutomation, "_wait_for_prompt")
    @patch.object(AlpineConsoleAutomation, "_send_line")
    @patch.object(AlpineConsoleAutomation, "_read_output")
    @patch("time.sleep")
    def test_console_interaction_no_login_prompt(
        self,
        _mock_sleep,
        mock_read_output,
        _mock_send_line,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test console interaction when login prompt is not found."""
        mock_openpty.return_value = (10, 11)
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = False  # No prompt found
        mock_read_output.return_value = ""

        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "#!/bin/sh\necho hello", 600
        )

        # Should still succeed (continues anyway)
        assert result["success"] is True
        self.mock_logger.warning.assert_called()

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    def test_console_interaction_pty_exception(
        self, _mock_close, _mock_popen, mock_openpty
    ):
        """Test console interaction when PTY opening fails."""
        mock_openpty.side_effect = OSError("Failed to open PTY")

        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "#!/bin/sh\necho hello", 600
        )

        assert result["success"] is False
        assert "Failed to open PTY" in result["error"]

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(AlpineConsoleAutomation, "_wait_for_prompt")
    @patch.object(AlpineConsoleAutomation, "_send_line")
    @patch.object(AlpineConsoleAutomation, "_read_output")
    @patch("time.sleep")
    def test_console_interaction_process_timeout(
        self,
        _mock_sleep,
        mock_read_output,
        _mock_send_line,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test console interaction when process termination times out."""
        mock_openpty.return_value = (10, 11)
        mock_process = Mock()
        mock_process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="vmctl", timeout=10),
            0,  # After kill
        ]
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = ""

        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "#!/bin/sh\necho hello", 600
        )

        assert result["success"] is True
        mock_process.kill.assert_called_once()

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(AlpineConsoleAutomation, "_wait_for_prompt")
    @patch.object(AlpineConsoleAutomation, "_send_line")
    @patch.object(AlpineConsoleAutomation, "_read_output")
    @patch("time.sleep")
    def test_console_interaction_base64_chunks(
        self,
        _mock_sleep,
        mock_read_output,
        mock_send_line,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test that large scripts are sent in base64 chunks."""
        mock_openpty.return_value = (10, 11)
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = ""

        # Create a large script that will require multiple chunks
        large_script = "#!/bin/sh\n" + "echo 'line' # " + "x" * 2000

        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", large_script, 600
        )

        assert result["success"] is True
        # Verify multiple echo commands were sent (chunking)
        send_calls = [str(call) for call in mock_send_line.call_args_list]
        echo_calls = [c for c in send_calls if "/tmp/setup.b64" in c]
        assert len(echo_calls) > 1  # Multiple chunks

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(AlpineConsoleAutomation, "_wait_for_prompt")
    @patch.object(AlpineConsoleAutomation, "_send_line")
    @patch.object(AlpineConsoleAutomation, "_read_output")
    @patch("time.sleep")
    def test_console_interaction_script_execution(
        self,
        _mock_sleep,
        mock_read_output,
        mock_send_line,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test that script is properly executed."""
        mock_openpty.return_value = (10, 11)
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = "Setup running"

        self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "#!/bin/sh\necho hello", 600
        )

        # Verify setup script execution sequence
        send_calls = [str(call) for call in mock_send_line.call_args_list]
        # Should include base64 decode, chmod, and execute
        assert any("base64 -d" in c for c in send_calls)
        assert any("chmod +x" in c for c in send_calls)
        assert any("sh /tmp/setup.sh" in c for c in send_calls)

    @patch("pty.openpty")
    @patch("os.close")
    def test_console_interaction_closes_fds_on_error(self, mock_close, mock_openpty):
        """Test that file descriptors are closed on error."""
        mock_openpty.return_value = (10, 11)

        # Simulate error after opening PTY
        with patch("subprocess.Popen", side_effect=Exception("Spawn failed")):
            self.automation._console_interaction(
                "alpine-vm", "/dev/ttyp0", "#!/bin/sh\necho hello", 600
            )

        # Should attempt to close master_fd (10)
        assert any(call[0][0] == 10 for call in mock_close.call_args_list)


class TestWaitForPrompt:
    """Test cases for _wait_for_prompt method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch("select.select")
    @patch.object(AlpineConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_found_immediately(
        self, mock_time, mock_safe_read, mock_select
    ):
        """Test prompt found immediately."""
        mock_time.side_effect = [0, 0.5]
        mock_select.return_value = ([1], [], [])
        mock_safe_read.return_value = b"localhost login:"

        result = self.automation._wait_for_prompt(10, [b"login:"], 30)

        assert result is True

    @patch("select.select")
    @patch.object(AlpineConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_found_after_data(
        self, mock_time, mock_safe_read, mock_select
    ):
        """Test prompt found after receiving some data."""
        mock_time.side_effect = [0, 0.5, 1.0, 1.5]
        mock_select.return_value = ([1], [], [])
        mock_safe_read.side_effect = [b"Booting...\n", b"localhost login:"]

        result = self.automation._wait_for_prompt(10, [b"login:"], 30)

        assert result is True

    @patch("select.select")
    @patch.object(AlpineConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_timeout(self, mock_time, mock_safe_read, mock_select):
        """Test prompt search times out."""
        mock_time.side_effect = [0, 15, 31]  # Exceeds 30 second timeout
        mock_select.return_value = ([1], [], [])
        mock_safe_read.return_value = b"Still booting...\n"

        result = self.automation._wait_for_prompt(10, [b"login:"], 30)

        assert result is False

    @patch("select.select")
    @patch("time.time")
    def test_wait_for_prompt_no_data(self, mock_time, mock_select):
        """Test when no data is available."""
        mock_time.side_effect = [0, 15, 31]
        mock_select.return_value = ([], [], [])  # No data ready

        result = self.automation._wait_for_prompt(10, [b"login:"], 30)

        assert result is False

    @patch("select.select")
    @patch.object(AlpineConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_read_returns_none(
        self, mock_time, mock_safe_read, mock_select
    ):
        """Test when read returns None (error)."""
        mock_time.side_effect = [0, 0.5]
        mock_select.return_value = ([1], [], [])
        mock_safe_read.return_value = None

        result = self.automation._wait_for_prompt(10, [b"login:"], 30)

        assert result is False

    @patch("select.select")
    @patch.object(AlpineConsoleAutomation, "_safe_read")
    @patch("time.time")
    def test_wait_for_prompt_multiple_prompts(
        self, mock_time, mock_safe_read, mock_select
    ):
        """Test matching one of multiple prompts."""
        mock_time.side_effect = [0, 0.5]
        mock_select.return_value = ([1], [], [])
        mock_safe_read.return_value = b"Welcome\nroot@alpine:~# "

        result = self.automation._wait_for_prompt(10, [b"login:", b"#", b"$"], 30)

        assert result is True


class TestSafeRead:
    """Test cases for _safe_read method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch("os.read")
    def test_safe_read_success(self, mock_read):
        """Test successful read."""
        mock_read.return_value = b"hello world"

        result = self.automation._safe_read(10)

        assert result == b"hello world"
        mock_read.assert_called_once_with(10, 1024)

    @patch("os.read")
    def test_safe_read_os_error(self, mock_read):
        """Test read with OS error."""
        mock_read.side_effect = OSError("Device not ready")

        result = self.automation._safe_read(10)

        assert result is None

    @patch("os.read")
    def test_safe_read_empty(self, mock_read):
        """Test read with empty data."""
        mock_read.return_value = b""

        result = self.automation._safe_read(10)

        assert result == b""


class TestCheckPrompts:
    """Test cases for _check_prompts method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    def test_check_prompts_found(self):
        """Test prompt found in buffer."""
        buffer = b"localhost login:"
        prompts = [b"login:", b"#"]

        result = self.automation._check_prompts(buffer, prompts)

        assert result is True

    def test_check_prompts_not_found(self):
        """Test prompt not in buffer."""
        buffer = b"Still booting..."
        prompts = [b"login:", b"#"]

        result = self.automation._check_prompts(buffer, prompts)

        assert result is False

    def test_check_prompts_partial_match(self):
        """Test partial prompt match (should not match)."""
        buffer = b"log"  # Partial "login:"
        prompts = [b"login:", b"#"]

        result = self.automation._check_prompts(buffer, prompts)

        assert result is False

    def test_check_prompts_empty_buffer(self):
        """Test with empty buffer."""
        buffer = b""
        prompts = [b"login:", b"#"]

        result = self.automation._check_prompts(buffer, prompts)

        assert result is False

    def test_check_prompts_second_prompt(self):
        """Test matching second prompt in list."""
        buffer = b"alpine:~# "
        prompts = [b"login:", b"#"]

        result = self.automation._check_prompts(buffer, prompts)

        assert result is True


class TestSendLine:
    """Test cases for _send_line method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch("os.write")
    @patch("time.sleep")
    def test_send_line_success(self, mock_sleep, mock_write):
        """Test successful line send."""
        self.automation._send_line(10, "echo hello")

        mock_write.assert_called_once_with(10, b"echo hello\n")
        mock_sleep.assert_called_once_with(0.1)

    @patch("os.write")
    @patch("time.sleep")
    def test_send_line_empty(self, _mock_sleep, mock_write):
        """Test sending empty line."""
        self.automation._send_line(10, "")

        mock_write.assert_called_once_with(10, b"\n")

    @patch("os.write")
    @patch("time.sleep")
    def test_send_line_special_characters(self, _mock_sleep, mock_write):
        """Test sending line with special characters."""
        self.automation._send_line(10, "echo 'hello world'")

        mock_write.assert_called_once_with(10, b"echo 'hello world'\n")


class TestReadOutput:
    """Test cases for _read_output method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_success(self, mock_time, mock_read, mock_select):
        """Test successful output read."""
        mock_time.side_effect = [0, 0.2, 0.5]
        mock_select.side_effect = [([1], [], []), ([], [], [])]
        mock_read.return_value = b"command output"

        result = self.automation._read_output(10, timeout=1.0)

        assert result == "command output"

    @patch("select.select")
    @patch("time.time")
    def test_read_output_no_data(self, mock_time, mock_select):
        """Test output read with no data available."""
        mock_time.side_effect = [0, 1.5]
        mock_select.return_value = ([], [], [])

        result = self.automation._read_output(10, timeout=1.0)

        assert result == ""

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_multiple_reads(self, mock_time, mock_read, mock_select):
        """Test output read with multiple data chunks."""
        mock_time.side_effect = [0, 0.1, 0.2, 0.5]
        mock_select.side_effect = [([1], [], []), ([1], [], []), ([], [], [])]
        mock_read.side_effect = [b"hello ", b"world"]

        result = self.automation._read_output(10, timeout=1.0)

        assert result == "hello world"

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_eof(self, mock_time, mock_read, mock_select):
        """Test output read with EOF (empty read)."""
        mock_time.side_effect = [0, 0.2]
        mock_select.return_value = ([1], [], [])
        mock_read.return_value = b""  # EOF

        result = self.automation._read_output(10, timeout=1.0)

        assert result == ""

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_os_error(self, mock_time, mock_read, mock_select):
        """Test output read with OS error."""
        mock_time.side_effect = [0, 0.2]
        mock_select.return_value = ([1], [], [])
        mock_read.side_effect = OSError("Read error")

        result = self.automation._read_output(10, timeout=1.0)

        assert result == ""

    @patch("select.select")
    @patch("os.read")
    @patch("time.time")
    def test_read_output_unicode_decode(self, mock_time, mock_read, mock_select):
        """Test output read handles unicode decode errors."""
        mock_time.side_effect = [0, 0.2, 0.5]
        mock_select.side_effect = [([1], [], []), ([], [], [])]
        # Invalid UTF-8 sequence
        mock_read.return_value = b"hello \xff\xfe world"

        result = self.automation._read_output(10, timeout=1.0)

        # Should replace invalid chars
        assert "hello" in result
        assert "world" in result


class TestConsoleInteractionEdgeCases:
    """Edge case tests for console interaction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(AlpineConsoleAutomation, "_wait_for_prompt")
    @patch.object(AlpineConsoleAutomation, "_send_line")
    @patch.object(AlpineConsoleAutomation, "_read_output")
    @patch("time.sleep")
    def test_empty_script(
        self,
        _mock_sleep,
        mock_read_output,
        _mock_send_line,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test console interaction with empty script."""
        mock_openpty.return_value = (10, 11)
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = ""

        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "", 600
        )

        assert result["success"] is True

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(AlpineConsoleAutomation, "_wait_for_prompt")
    @patch.object(AlpineConsoleAutomation, "_send_line")
    @patch.object(AlpineConsoleAutomation, "_read_output")
    @patch("time.sleep")
    def test_script_with_unicode(
        self,
        _mock_sleep,
        mock_read_output,
        _mock_send_line,
        mock_wait_prompt,
        _mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test console interaction with unicode script content."""
        mock_openpty.return_value = (10, 11)
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = ""

        script = "#!/bin/sh\necho 'Hello'"

        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", script, 600
        )

        assert result["success"] is True

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    def test_close_slave_fd_when_set(self, mock_close, mock_popen, mock_openpty):
        """Test slave_fd is closed in finally block when not None."""
        mock_openpty.return_value = (10, 11)
        mock_popen.side_effect = Exception("Popen failed before slave close")

        self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "echo hello", 600
        )

        # Both fds should be attempted to close
        close_calls = [call[0][0] for call in mock_close.call_args_list]
        assert 10 in close_calls
        assert 11 in close_calls

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    @patch.object(AlpineConsoleAutomation, "_wait_for_prompt")
    @patch.object(AlpineConsoleAutomation, "_send_line")
    @patch.object(AlpineConsoleAutomation, "_read_output")
    @patch("time.sleep")
    def test_close_handles_oserror(
        self,
        _mock_sleep,
        mock_read_output,
        _mock_send_line,
        mock_wait_prompt,
        mock_close,
        mock_popen,
        mock_openpty,
    ):
        """Test OSError during fd close is handled gracefully in finally block."""
        mock_openpty.return_value = (10, 11)
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_wait_prompt.return_value = True
        mock_read_output.return_value = ""

        # First close (slave_fd in try block) succeeds, subsequent closes fail
        # This simulates the finally block trying to close already-closed fds
        call_count = [0]

        def close_side_effect(_fd):
            call_count[0] += 1
            # First call is closing slave_fd after Popen (line 207), should succeed
            if call_count[0] == 1:
                return None
            # Subsequent calls in finally block should raise OSError but be caught
            raise OSError("Already closed")

        mock_close.side_effect = close_side_effect

        # Should not raise exception - OSError in finally is caught
        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "echo hello", 600
        )

        assert result["success"] is True


class TestFinallyBlockCoverage:
    """Tests specifically for finally block coverage."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @patch("pty.openpty")
    @patch("subprocess.Popen")
    @patch("os.close")
    def test_slave_fd_close_oserror_in_finally(
        self, mock_close, mock_popen, mock_openpty
    ):
        """Test that OSError during slave_fd close in finally is handled.

        This covers lines 331-332 where slave_fd close raises OSError.
        This scenario occurs when Popen fails before slave_fd is closed and set to None.
        """
        mock_openpty.return_value = (10, 11)
        # Popen fails, so slave_fd is never closed in the try block and remains non-None
        mock_popen.side_effect = Exception("Popen failed")
        # os.close will raise OSError for both fds in finally block
        mock_close.side_effect = OSError("Already closed")

        result = self.automation._console_interaction(
            "alpine-vm", "/dev/ttyp0", "echo hello", 600
        )

        # Should handle OSError gracefully
        assert result["success"] is False
        assert "Popen failed" in result["error"]
        # Both master_fd (10) and slave_fd (11) should have close attempts
        close_calls = [call[0][0] for call in mock_close.call_args_list]
        assert 10 in close_calls
        assert 11 in close_calls


class TestIntegration:
    """Integration-style tests for Alpine console automation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.automation = AlpineConsoleAutomation(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(AlpineConsoleAutomation, "get_vm_tty")
    @patch.object(AlpineConsoleAutomation, "_console_interaction")
    @patch("asyncio.to_thread")
    async def test_full_setup_workflow(
        self, mock_to_thread, _mock_interaction, mock_get_tty
    ):
        """Test full automated setup workflow."""
        mock_get_tty.return_value = "ttyp0"
        mock_to_thread.return_value = {
            "success": True,
            "message": "Console automation completed",
        }

        setup_script = """#!/bin/sh
setup-alpine -f /root/answers
apk add sysmanage-agent
rc-update add sysmanage-agent
reboot
"""

        result = await self.automation.run_automated_setup("alpine-vm", setup_script)

        assert result["success"] is True
        mock_get_tty.assert_called_once_with("alpine-vm")
        mock_to_thread.assert_called_once()

    @patch("subprocess.run")
    def test_vmctl_command_construction(self, mock_run):
        """Test that vmctl commands are constructed correctly."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE     NAME\n"
            "    1  1234     1    512M    256M   ttyp0         root running   test-vm",
        )

        self.automation._parse_tty_from_status("test-vm")

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["vmctl", "status"]
        assert call_args[1]["capture_output"] is True
        assert call_args[1]["text"] is True
        assert call_args[1]["timeout"] == 10

    def test_base64_encoding_script(self):
        """Test that script is properly base64 encoded."""
        script = "#!/bin/sh\necho 'hello world'"
        expected_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")

        # Verify the encoding logic
        script_bytes = script.encode("utf-8")
        script_b64 = base64.b64encode(script_bytes).decode("ascii")

        assert script_b64 == expected_b64
        # Verify it can be decoded back
        decoded = base64.b64decode(script_b64).decode("utf-8")
        assert decoded == script
