"""
Unit tests for WSL child host operations.

Tests cover:
- WslOperations initialization
- Creation flags
- Output decoding
- WSL enabling (internal and public)
- WSL status checking
- Control operations (start, stop, restart, delete)
"""

# pylint: disable=redefined-outer-name,protected-access

import asyncio
import logging
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_wsl import WslOperations


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_wsl")


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock_checks = Mock()
    mock_checks.check_wsl_support = Mock(
        return_value={
            "available": True,
            "needs_enable": False,
        }
    )
    return mock_checks


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    mock = Mock()
    mock.send_message = AsyncMock()
    mock.create_message = Mock(return_value={"type": "test"})
    return mock


@pytest.fixture
def wsl_ops(mock_agent, logger, mock_virtualization_checks):
    """Create a WslOperations instance for testing."""
    return WslOperations(mock_agent, logger, mock_virtualization_checks)


class TestWslOperationsInit:
    """Tests for WslOperations initialization."""

    def test_init_sets_agent(self, wsl_ops, mock_agent):
        """Test that __init__ sets agent."""
        assert wsl_ops.agent == mock_agent

    def test_init_sets_logger(self, wsl_ops, logger):
        """Test that __init__ sets logger."""
        assert wsl_ops.logger == logger

    def test_init_sets_virtualization_checks(self, wsl_ops, mock_virtualization_checks):
        """Test that __init__ sets virtualization_checks."""
        assert wsl_ops.virtualization_checks == mock_virtualization_checks

    def test_init_creates_control_ops(self, wsl_ops):
        """Test that __init__ creates control operations."""
        assert wsl_ops._control_ops is not None


class TestGetCreationFlags:
    """Tests for _get_creationflags method."""

    def test_get_creationflags_with_create_no_window(self, wsl_ops):
        """Test getting creation flags when CREATE_NO_WINDOW is available."""
        with patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True):
            result = wsl_ops._get_creationflags()
        assert result == 0x08000000

    def test_get_creationflags_without_create_no_window(self, wsl_ops):
        """Test getting creation flags when CREATE_NO_WINDOW is not available."""
        # On Linux, CREATE_NO_WINDOW doesn't exist
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            delattr(subprocess, "CREATE_NO_WINDOW")
        result = wsl_ops._get_creationflags()
        assert result == 0


class TestDecodeWslOutput:
    """Tests for _decode_wsl_output method."""

    def test_decode_empty_output(self, wsl_ops):
        """Test decoding empty output."""
        result = wsl_ops._decode_wsl_output(b"", b"")
        assert result == ""

    def test_decode_utf16le_with_bom(self, wsl_ops):
        """Test decoding UTF-16LE output with BOM."""
        # UTF-16LE BOM + "Hello" encoded as UTF-16LE
        stdout = b"\xff\xfeH\x00e\x00l\x00l\x00o\x00"
        result = wsl_ops._decode_wsl_output(stdout, b"")
        assert "Hello" in result

    def test_decode_utf16le_without_bom(self, wsl_ops):
        """Test decoding UTF-16LE output without BOM."""
        # "Test" encoded as UTF-16LE without BOM
        stdout = b"T\x00e\x00s\x00t\x00"
        result = wsl_ops._decode_wsl_output(stdout, b"")
        assert "Test" in result

    def test_decode_utf8_fallback(self, wsl_ops):
        """Test decoding falls back to UTF-8."""
        stdout = b"Hello UTF-8"
        result = wsl_ops._decode_wsl_output(stdout, b"")
        assert result == "Hello UTF-8"

    def test_decode_latin1_fallback(self, wsl_ops):
        """Test decoding falls back to Latin-1 for invalid UTF-8."""
        # Invalid UTF-8 sequence
        stdout = b"\xff\xfe\xfd"
        result = wsl_ops._decode_wsl_output(stdout, b"")
        # Should not raise, should return something
        assert isinstance(result, str)

    def test_decode_combined_stdout_stderr(self, wsl_ops):
        """Test decoding combines stdout and stderr."""
        stdout = b"stdout "
        stderr = b"stderr"
        result = wsl_ops._decode_wsl_output(stdout, stderr)
        assert "stdout" in result or "stderr" in result


class TestEnableWslInternal:
    """Tests for enable_wsl_internal method."""

    @pytest.mark.asyncio
    async def test_enable_wsl_timeout(self, wsl_ops):
        """Test WSL enable with timeout."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_proc.kill = Mock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is False
        assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_wsl_reboot_required_exit_code(self, wsl_ops):
        """Test WSL enable with reboot required exit code."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 3010

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is True
        assert result["reboot_required"] is True

    @pytest.mark.asyncio
    async def test_enable_wsl_reboot_in_output(self, wsl_ops):
        """Test WSL enable with reboot indicator in output."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"Please reboot your system", b"")
        )
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch.object(
                wsl_ops, "_decode_wsl_output", return_value="please reboot your system"
            ):
                result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is True
        assert result["reboot_required"] is True

    @pytest.mark.asyncio
    async def test_enable_wsl_failure(self, wsl_ops):
        """Test WSL enable failure."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"Error message"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch.object(
                wsl_ops, "_decode_wsl_output", return_value="error message"
            ):
                result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_enable_wsl_success_verified(self, wsl_ops):
        """Test WSL enable success with verification."""
        mock_install_proc = Mock()
        mock_install_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_install_proc.returncode = 0

        mock_status_proc = Mock()
        mock_status_proc.communicate = AsyncMock(return_value=(b"WSL version: 2", b""))
        mock_status_proc.returncode = 0

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_install_proc, mock_status_proc],
        ):
            with patch.object(
                wsl_ops, "_decode_wsl_output", side_effect=["", "wsl version: 2"]
            ):
                result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_wsl_exception(self, wsl_ops):
        """Test WSL enable with exception."""
        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestCheckWslStatusOutput:
    """Tests for _check_wsl_status_output method."""

    def test_status_requires_bios_virtualization(self, wsl_ops):
        """Test status output requiring BIOS virtualization."""
        status_output = "please enable virtualization in bios"
        result = wsl_ops._check_wsl_status_output(status_output, b"", b"")

        assert result["success"] is False
        assert result["requires_bios_change"] is True

    def test_status_requires_additional_setup(self, wsl_ops):
        """Test status output requiring additional setup."""
        status_output = "please enable virtual machine platform"
        result = wsl_ops._check_wsl_status_output(status_output, b"", b"")

        assert result["success"] is True
        assert result["reboot_required"] is True

    def test_status_not_supported(self, wsl_ops):
        """Test status output when not supported."""
        status_output = "wsl 2 is not supported on this version"
        result = wsl_ops._check_wsl_status_output(status_output, b"", b"")

        assert result["success"] is True
        assert result["reboot_required"] is True

    def test_status_success(self, wsl_ops):
        """Test successful status check."""
        status_output = "default distribution: ubuntu"
        result = wsl_ops._check_wsl_status_output(status_output, b"", b"")

        assert result["success"] is True
        assert result["reboot_required"] is False


class TestEnableWsl:
    """Tests for enable_wsl method."""

    @pytest.mark.asyncio
    async def test_enable_wsl_success(self, wsl_ops, mock_agent):
        """Test successful WSL enabling."""
        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": False}

            result = await wsl_ops.enable_wsl({})

        assert result["success"] is True
        mock_agent.send_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_enable_wsl_reboot_required(self, wsl_ops, mock_agent):
        """Test WSL enabling with reboot required."""
        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": True}

            result = await wsl_ops.enable_wsl({})

        assert result["success"] is True
        assert result["reboot_required"] is True
        mock_agent.create_message.assert_called_once_with(
            "reboot_status_update",
            {
                "reboot_required": True,
                "reboot_required_reason": "WSL feature enablement pending",
            },
        )
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_wsl_reboot_send_fails(self, wsl_ops, mock_agent):
        """Test WSL enabling when reboot message send fails."""
        mock_agent.send_message.side_effect = Exception("Send failed")

        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": True}

            result = await wsl_ops.enable_wsl({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_wsl_no_send_method(self, wsl_ops):
        """Test WSL enabling when agent has no send_message."""
        wsl_ops.agent = Mock(spec=[])

        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": True}

            result = await wsl_ops.enable_wsl({})

        assert result["success"] is True


class TestControlOperationsDelegation:
    """Tests for control operation delegation methods."""

    @pytest.mark.asyncio
    async def test_start_child_host_delegated(self, wsl_ops):
        """Test that start_child_host delegates to control_ops."""
        with patch.object(
            wsl_ops._control_ops, "start_child_host", new_callable=AsyncMock
        ) as mock_start:
            mock_start.return_value = {"success": True}

            result = await wsl_ops.start_child_host({"child_name": "Ubuntu"})

        mock_start.assert_called_once_with({"child_name": "Ubuntu"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_child_host_delegated(self, wsl_ops):
        """Test that stop_child_host delegates to control_ops."""
        with patch.object(
            wsl_ops._control_ops, "stop_child_host", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}

            result = await wsl_ops.stop_child_host({"child_name": "Ubuntu"})

        mock_stop.assert_called_once_with({"child_name": "Ubuntu"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_child_host_delegated(self, wsl_ops):
        """Test that restart_child_host delegates to control_ops."""
        with patch.object(
            wsl_ops._control_ops, "restart_child_host", new_callable=AsyncMock
        ) as mock_restart:
            mock_restart.return_value = {"success": True}

            result = await wsl_ops.restart_child_host({"child_name": "Ubuntu"})

        mock_restart.assert_called_once_with({"child_name": "Ubuntu"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_child_host_delegated(self, wsl_ops):
        """Test that delete_child_host delegates to control_ops."""
        with patch.object(
            wsl_ops._control_ops, "delete_child_host", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True}

            result = await wsl_ops.delete_child_host({"child_name": "Ubuntu"})

        mock_delete.assert_called_once_with({"child_name": "Ubuntu"})
        assert result["success"] is True


class TestEnableWslInternalEdgeCases:
    """Additional tests for enable_wsl_internal edge cases."""

    @pytest.mark.asyncio
    async def test_enable_wsl_status_check_timeout(self, wsl_ops):
        """Test when WSL status check times out."""
        mock_install_proc = Mock()
        mock_install_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_install_proc.returncode = 0

        mock_status_proc = Mock()
        mock_status_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_status_proc.kill = Mock()

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_install_proc, mock_status_proc],
        ):
            with patch.object(wsl_ops, "_decode_wsl_output", return_value=""):
                result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is False
        assert "timed out" in result["error"]
