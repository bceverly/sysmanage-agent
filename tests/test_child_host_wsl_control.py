"""
Comprehensive unit tests for WSL child host control operations.

Tests cover:
- WslControlOperations initialization
- WSL lifecycle operations (start, stop, restart, delete)
- GUID verification for safe delete operations
- Timeout handling
- Error handling
- Edge cases
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import asyncio
import logging
import subprocess
from unittest.mock import AsyncMock, Mock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.child_host_wsl_control import WslControlOperations


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_wsl_control")


@pytest.fixture
def mock_decode_func():
    """Create a mock decode function for WSL output."""

    def decode_wsl_output(stdout, stderr):
        """Decode WSL output, handling UTF-16LE encoding."""
        output = ""
        if stdout:
            try:
                output = stdout.decode("utf-16le")
            except (UnicodeDecodeError, AttributeError):
                output = stdout.decode("utf-8", errors="replace")
        if stderr:
            try:
                output += stderr.decode("utf-16le")
            except (UnicodeDecodeError, AttributeError):
                output += stderr.decode("utf-8", errors="replace")
        return output.strip()

    return decode_wsl_output


@pytest.fixture
def wsl_control_ops(logger, mock_decode_func):
    """Create a WslControlOperations instance for testing."""
    return WslControlOperations(logger, mock_decode_func)


class TestWslControlOperationsInit:
    """Tests for WslControlOperations initialization."""

    def test_init_sets_logger(self, logger, mock_decode_func):
        """Test that __init__ sets logger."""
        ops = WslControlOperations(logger, mock_decode_func)
        assert ops.logger == logger

    def test_init_sets_decode_function(self, logger, mock_decode_func):
        """Test that __init__ sets decode function."""
        ops = WslControlOperations(logger, mock_decode_func)
        assert ops._decode_wsl_output == mock_decode_func


class TestGetCreationFlags:
    """Tests for _get_creationflags method."""

    def test_get_creationflags_returns_create_no_window_on_windows(
        self, wsl_control_ops
    ):
        """Test that CREATE_NO_WINDOW is returned when available."""
        with patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True):
            result = wsl_control_ops._get_creationflags()
            assert result == 0x08000000

    def test_get_creationflags_returns_zero_when_not_available(self, wsl_control_ops):
        """Test that 0 is returned when CREATE_NO_WINDOW is not available."""
        # Remove CREATE_NO_WINDOW attribute if it exists
        original = getattr(subprocess, "CREATE_NO_WINDOW", None)
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            delattr(subprocess, "CREATE_NO_WINDOW")

        try:
            result = wsl_control_ops._get_creationflags()
            assert result == 0
        finally:
            # Restore original state
            if original is not None:
                subprocess.CREATE_NO_WINDOW = original


class TestGetWslGuid:
    """Tests for _get_wsl_guid method."""

    def test_get_wsl_guid_returns_none_when_winreg_not_available(self, wsl_control_ops):
        """Test that None is returned when winreg is not available."""
        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_control.winreg", None
        ):
            result = wsl_control_ops._get_wsl_guid("Ubuntu-24.04")
            assert result is None

    def test_get_wsl_guid_success(self, wsl_control_ops):
        """Test successful GUID retrieval from registry."""
        mock_winreg = MagicMock()
        mock_lxss_key = MagicMock()
        mock_dist_key = MagicMock()

        # Set up mock registry structure
        mock_winreg.HKEY_CURRENT_USER = 1
        mock_winreg.OpenKey.return_value.__enter__.return_value = mock_lxss_key
        mock_winreg.EnumKey.side_effect = [
            "{0283592d-be56-40d4-b935-3dc18c3aa007}",
            OSError("No more keys"),
        ]

        # Set up nested context manager for distribution key
        mock_lxss_key.__enter__ = Mock(return_value=mock_lxss_key)
        mock_lxss_key.__exit__ = Mock(return_value=False)

        def mock_open_key(_parent, subkey):
            if subkey == "{0283592d-be56-40d4-b935-3dc18c3aa007}":
                return mock_dist_key
            return mock_lxss_key

        mock_winreg.OpenKey.side_effect = mock_open_key
        mock_dist_key.__enter__ = Mock(return_value=mock_dist_key)
        mock_dist_key.__exit__ = Mock(return_value=False)
        mock_winreg.QueryValueEx.return_value = ("Ubuntu-24.04", 1)

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_control.winreg",
            mock_winreg,
        ):
            result = wsl_control_ops._get_wsl_guid("Ubuntu-24.04")
            assert result == "0283592d-be56-40d4-b935-3dc18c3aa007"

    def test_get_wsl_guid_distribution_not_found(self, wsl_control_ops):
        """Test when distribution is not found in registry."""
        mock_winreg = MagicMock()
        mock_lxss_key = MagicMock()
        mock_dist_key = MagicMock()

        mock_winreg.HKEY_CURRENT_USER = 1
        mock_winreg.OpenKey.return_value.__enter__.return_value = mock_lxss_key
        mock_winreg.EnumKey.side_effect = [
            "{guid-for-other-distro}",
            OSError("No more keys"),
        ]

        def mock_open_key(_parent, subkey):
            if subkey == "{guid-for-other-distro}":
                return mock_dist_key
            return mock_lxss_key

        mock_winreg.OpenKey.side_effect = mock_open_key
        mock_dist_key.__enter__ = Mock(return_value=mock_dist_key)
        mock_dist_key.__exit__ = Mock(return_value=False)
        mock_winreg.QueryValueEx.return_value = ("Other-Distro", 1)

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_control.winreg",
            mock_winreg,
        ):
            result = wsl_control_ops._get_wsl_guid("Ubuntu-24.04")
            assert result is None

    def test_get_wsl_guid_registry_key_not_found(self, wsl_control_ops):
        """Test when WSL registry key doesn't exist."""
        mock_winreg = MagicMock()
        mock_winreg.HKEY_CURRENT_USER = 1
        mock_winreg.OpenKey.side_effect = FileNotFoundError("Registry key not found")

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_control.winreg",
            mock_winreg,
        ):
            result = wsl_control_ops._get_wsl_guid("Ubuntu-24.04")
            assert result is None

    def test_get_wsl_guid_handles_generic_exception(self, wsl_control_ops):
        """Test handling of generic exceptions during registry access."""
        mock_winreg = MagicMock()
        mock_winreg.HKEY_CURRENT_USER = 1
        mock_winreg.OpenKey.side_effect = Exception("Unexpected error")

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_control.winreg",
            mock_winreg,
        ):
            result = wsl_control_ops._get_wsl_guid("Ubuntu-24.04")
            assert result is None

    def test_get_wsl_guid_handles_dist_name_file_not_found(self, wsl_control_ops):
        """Test when DistributionName value is not found in registry key."""
        mock_winreg = MagicMock()
        mock_lxss_key = MagicMock()
        mock_dist_key = MagicMock()

        mock_winreg.HKEY_CURRENT_USER = 1
        mock_winreg.OpenKey.return_value.__enter__.return_value = mock_lxss_key
        mock_winreg.EnumKey.side_effect = [
            "{some-guid}",
            OSError("No more keys"),
        ]

        def mock_open_key(_parent, subkey):
            if subkey == "{some-guid}":
                return mock_dist_key
            return mock_lxss_key

        mock_winreg.OpenKey.side_effect = mock_open_key
        mock_dist_key.__enter__ = Mock(return_value=mock_dist_key)
        mock_dist_key.__exit__ = Mock(return_value=False)
        mock_winreg.QueryValueEx.side_effect = FileNotFoundError("Value not found")

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_control.winreg",
            mock_winreg,
        ):
            result = wsl_control_ops._get_wsl_guid("Ubuntu-24.04")
            assert result is None


class TestStartChildHost:
    """Tests for start_child_host method."""

    @pytest.mark.asyncio
    async def test_start_child_host_no_child_name(self, wsl_control_ops):
        """Test start with missing child_name."""
        result = await wsl_control_ops.start_child_host({})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_child_host_empty_child_name(self, wsl_control_ops):
        """Test start with empty child_name."""
        result = await wsl_control_ops.start_child_host({"child_name": ""})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_child_host_success(self, wsl_control_ops):
        """Test successful WSL instance start."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"Started\n", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.start_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is True
        assert result["child_name"] == "Ubuntu-24.04"
        assert result["child_type"] == "wsl"
        assert result["status"] == "running"
        assert "started successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_start_child_host_failure(self, wsl_control_ops):
        """Test WSL instance start failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"Distribution not found")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.start_child_host(
                {"child_name": "NonExistent"}
            )

        assert result["success"] is False
        assert "failed to start" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_child_host_timeout(self, wsl_control_ops):
        """Test WSL instance start with timeout."""
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_process.kill = Mock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                result = await wsl_control_ops.start_child_host(
                    {"child_name": "Ubuntu-24.04"}
                )

        assert result["success"] is False
        assert "timed out" in result["error"].lower()
        mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_child_host_exception(self, wsl_control_ops):
        """Test WSL instance start with unexpected exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Unexpected error"),
        ):
            result = await wsl_control_ops.start_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestStopChildHost:
    """Tests for stop_child_host method."""

    @pytest.mark.asyncio
    async def test_stop_child_host_no_child_name(self, wsl_control_ops):
        """Test stop with missing child_name."""
        result = await wsl_control_ops.stop_child_host({})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_stop_child_host_empty_child_name(self, wsl_control_ops):
        """Test stop with empty child_name."""
        result = await wsl_control_ops.stop_child_host({"child_name": ""})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_stop_child_host_success(self, wsl_control_ops):
        """Test successful WSL instance stop."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.stop_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is True
        assert result["child_name"] == "Ubuntu-24.04"
        assert result["child_type"] == "wsl"
        assert result["status"] == "stopped"
        assert "stopped successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_stop_child_host_already_stopped(self, wsl_control_ops):
        """Test stopping already stopped WSL instance."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"The distribution is not running")
        )

        # Mock decode to return lowercase for matching
        def decode_mock(_stdout, _stderr):
            return "the distribution is not running"

        wsl_control_ops._decode_wsl_output = decode_mock

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.stop_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is True
        assert result["status"] == "stopped"
        assert "already stopped" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_stop_child_host_failure(self, wsl_control_ops):
        """Test WSL instance stop failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Access denied"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.stop_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is False
        assert "failed to stop" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_stop_child_host_timeout(self, wsl_control_ops):
        """Test WSL instance stop with timeout."""
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_process.kill = Mock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                result = await wsl_control_ops.stop_child_host(
                    {"child_name": "Ubuntu-24.04"}
                )

        assert result["success"] is False
        assert "timed out" in result["error"].lower()
        mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_child_host_exception(self, wsl_control_ops):
        """Test WSL instance stop with unexpected exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Unexpected error"),
        ):
            result = await wsl_control_ops.stop_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestRestartChildHost:
    """Tests for restart_child_host method."""

    @pytest.mark.asyncio
    async def test_restart_child_host_no_child_name(self, wsl_control_ops):
        """Test restart with missing child_name."""
        result = await wsl_control_ops.restart_child_host({})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_restart_child_host_success(self, wsl_control_ops):
        """Test successful WSL instance restart."""
        with patch.object(
            wsl_control_ops,
            "stop_child_host",
            new_callable=AsyncMock,
            return_value={
                "success": True,
                "child_name": "Ubuntu-24.04",
                "status": "stopped",
                "message": "WSL instance stopped successfully",
            },
        ) as mock_stop:
            with patch.object(
                wsl_control_ops,
                "start_child_host",
                new_callable=AsyncMock,
                return_value={
                    "success": True,
                    "child_name": "Ubuntu-24.04",
                    "status": "running",
                    "message": "WSL instance started successfully",
                },
            ) as mock_start:
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await wsl_control_ops.restart_child_host(
                        {"child_name": "Ubuntu-24.04"}
                    )

        assert result["success"] is True
        assert result["child_name"] == "Ubuntu-24.04"
        assert result["child_type"] == "wsl"
        assert result["status"] == "running"
        assert "restarted successfully" in result["message"].lower()
        mock_stop.assert_called_once()
        mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_child_host_stop_failed(self, wsl_control_ops):
        """Test restart when stop fails."""
        with patch.object(
            wsl_control_ops,
            "stop_child_host",
            new_callable=AsyncMock,
            return_value={
                "success": False,
                "error": "Permission denied",
            },
        ):
            result = await wsl_control_ops.restart_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_child_host_already_stopped(self, wsl_control_ops):
        """Test restart when instance was already stopped."""
        with patch.object(
            wsl_control_ops,
            "stop_child_host",
            new_callable=AsyncMock,
            return_value={
                "success": True,
                "child_name": "Ubuntu-24.04",
                "status": "stopped",
                "message": "WSL instance 'Ubuntu-24.04' was already stopped",
            },
        ):
            with patch.object(
                wsl_control_ops,
                "start_child_host",
                new_callable=AsyncMock,
                return_value={
                    "success": True,
                    "child_name": "Ubuntu-24.04",
                    "status": "running",
                    "message": "WSL instance started successfully",
                },
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await wsl_control_ops.restart_child_host(
                        {"child_name": "Ubuntu-24.04"}
                    )

        assert result["success"] is True
        assert result["status"] == "running"

    @pytest.mark.asyncio
    async def test_restart_child_host_start_failed(self, wsl_control_ops):
        """Test restart when start fails after stop."""
        with patch.object(
            wsl_control_ops,
            "stop_child_host",
            new_callable=AsyncMock,
            return_value={
                "success": True,
                "child_name": "Ubuntu-24.04",
                "status": "stopped",
                "message": "WSL instance stopped successfully",
            },
        ):
            with patch.object(
                wsl_control_ops,
                "start_child_host",
                new_callable=AsyncMock,
                return_value={
                    "success": False,
                    "error": "Failed to start WSL instance",
                },
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await wsl_control_ops.restart_child_host(
                        {"child_name": "Ubuntu-24.04"}
                    )

        assert result["success"] is False
        assert "failed to start" in result["error"].lower()


class TestDeleteChildHost:
    """Tests for delete_child_host method."""

    @pytest.mark.asyncio
    async def test_delete_child_host_no_child_name(self, wsl_control_ops):
        """Test delete with missing child_name."""
        result = await wsl_control_ops.delete_child_host({})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_child_host_empty_child_name(self, wsl_control_ops):
        """Test delete with empty child_name."""
        result = await wsl_control_ops.delete_child_host({"child_name": ""})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_child_host_success(self, wsl_control_ops):
        """Test successful WSL instance deletion."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.delete_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is True
        assert result["child_name"] == "Ubuntu-24.04"
        assert result["child_type"] == "wsl"
        assert "deleted successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_child_host_already_deleted(self, wsl_control_ops):
        """Test deleting already deleted WSL instance."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"The distribution is not registered")
        )

        # Mock decode to return lowercase for matching
        def decode_mock(_stdout, _stderr):
            return "the distribution is not registered"

        wsl_control_ops._decode_wsl_output = decode_mock

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.delete_child_host(
                {"child_name": "NonExistent"}
            )

        assert result["success"] is True
        assert "already deleted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_child_host_not_found(self, wsl_control_ops):
        """Test deleting WSL instance that was not found."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"The distribution was not found")
        )

        # Mock decode to return lowercase for matching
        def decode_mock(_stdout, _stderr):
            return "the distribution was not found"

        wsl_control_ops._decode_wsl_output = decode_mock

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.delete_child_host(
                {"child_name": "NonExistent"}
            )

        assert result["success"] is True
        assert "already deleted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_child_host_failure(self, wsl_control_ops):
        """Test WSL instance delete failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Access denied"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.delete_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is False
        assert "failed to delete" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_child_host_timeout(self, wsl_control_ops):
        """Test WSL instance delete with timeout."""
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_process.kill = Mock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                result = await wsl_control_ops.delete_child_host(
                    {"child_name": "Ubuntu-24.04"}
                )

        assert result["success"] is False
        assert "timed out" in result["error"].lower()
        mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_child_host_exception(self, wsl_control_ops):
        """Test WSL instance delete with unexpected exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Unexpected error"),
        ):
            result = await wsl_control_ops.delete_child_host(
                {"child_name": "Ubuntu-24.04"}
            )

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestDeleteChildHostWithGuidVerification:
    """Tests for delete_child_host with GUID verification."""

    @pytest.mark.asyncio
    async def test_delete_with_matching_guid(self, wsl_control_ops):
        """Test delete with matching GUID proceeds."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch.object(
            wsl_control_ops,
            "_get_wsl_guid",
            return_value="0283592d-be56-40d4-b935-3dc18c3aa007",
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await wsl_control_ops.delete_child_host(
                    {
                        "child_name": "Ubuntu-24.04",
                        "wsl_guid": "0283592d-be56-40d4-b935-3dc18c3aa007",
                    }
                )

        assert result["success"] is True
        assert "deleted successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_with_matching_guid_case_insensitive(self, wsl_control_ops):
        """Test delete with GUID matching is case insensitive."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch.object(
            wsl_control_ops,
            "_get_wsl_guid",
            return_value="0283592D-BE56-40D4-B935-3DC18C3AA007",
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await wsl_control_ops.delete_child_host(
                    {
                        "child_name": "Ubuntu-24.04",
                        "wsl_guid": "0283592d-be56-40d4-b935-3dc18c3aa007",
                    }
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_with_mismatched_guid(self, wsl_control_ops):
        """Test delete refuses when GUID doesn't match."""
        with patch.object(
            wsl_control_ops,
            "_get_wsl_guid",
            return_value="different-guid-1234-5678",
        ):
            result = await wsl_control_ops.delete_child_host(
                {
                    "child_name": "Ubuntu-24.04",
                    "wsl_guid": "0283592d-be56-40d4-b935-3dc18c3aa007",
                }
            )

        assert result["success"] is False
        assert "different GUID" in result["error"]
        assert result["expected_guid"] == "0283592d-be56-40d4-b935-3dc18c3aa007"
        assert result["current_guid"] == "different-guid-1234-5678"

    @pytest.mark.asyncio
    async def test_delete_with_guid_instance_not_found(self, wsl_control_ops):
        """Test delete when GUID provided but instance not found."""
        with patch.object(wsl_control_ops, "_get_wsl_guid", return_value=None):
            result = await wsl_control_ops.delete_child_host(
                {
                    "child_name": "Ubuntu-24.04",
                    "wsl_guid": "0283592d-be56-40d4-b935-3dc18c3aa007",
                }
            )

        assert result["success"] is True
        assert "already deleted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_without_guid_skips_verification(self, wsl_control_ops):
        """Test delete without GUID skips verification."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch.object(wsl_control_ops, "_get_wsl_guid") as mock_get_guid:
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await wsl_control_ops.delete_child_host(
                    {"child_name": "Ubuntu-24.04"}
                )

        # _get_wsl_guid should not be called when no wsl_guid parameter
        mock_get_guid.assert_not_called()
        assert result["success"] is True


class TestVerifyWslGuid:
    """Tests for _verify_wsl_guid method."""

    def test_verify_wsl_guid_match_returns_none(self, wsl_control_ops):
        """Test that matching GUID returns None (proceed with delete)."""
        with patch.object(
            wsl_control_ops,
            "_get_wsl_guid",
            return_value="0283592d-be56-40d4-b935-3dc18c3aa007",
        ):
            result = wsl_control_ops._verify_wsl_guid(
                "Ubuntu-24.04", "0283592d-be56-40d4-b935-3dc18c3aa007"
            )
            assert result is None

    def test_verify_wsl_guid_mismatch_returns_error(self, wsl_control_ops):
        """Test that mismatched GUID returns error dict."""
        with patch.object(
            wsl_control_ops,
            "_get_wsl_guid",
            return_value="different-guid",
        ):
            result = wsl_control_ops._verify_wsl_guid(
                "Ubuntu-24.04", "0283592d-be56-40d4-b935-3dc18c3aa007"
            )

        assert result is not None
        assert result["success"] is False
        assert "different GUID" in result["error"]

    def test_verify_wsl_guid_not_found_returns_already_deleted(self, wsl_control_ops):
        """Test that missing GUID returns already deleted response."""
        with patch.object(wsl_control_ops, "_get_wsl_guid", return_value=None):
            result = wsl_control_ops._verify_wsl_guid(
                "Ubuntu-24.04", "0283592d-be56-40d4-b935-3dc18c3aa007"
            )

        assert result is not None
        assert result["success"] is True
        assert "already deleted" in result["message"].lower()

    def test_verify_wsl_guid_case_insensitive_match(self, wsl_control_ops):
        """Test that GUID comparison is case insensitive."""
        with patch.object(
            wsl_control_ops,
            "_get_wsl_guid",
            return_value="ABCD1234-EF56-7890-GHIJ-KLMNOPQRSTUV",
        ):
            result = wsl_control_ops._verify_wsl_guid(
                "Ubuntu-24.04", "abcd1234-ef56-7890-ghij-klmnopqrstuv"
            )
            assert result is None


class TestEdgeCases:
    """Edge case tests for WSL control operations."""

    @pytest.mark.asyncio
    async def test_start_with_none_child_name(self, wsl_control_ops):
        """Test start with None child_name."""
        result = await wsl_control_ops.start_child_host({"child_name": None})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_stop_with_whitespace_child_name(self, wsl_control_ops):
        """Test stop with whitespace-only child_name."""
        _result = await wsl_control_ops.stop_child_host({"child_name": "   "})
        # Whitespace is truthy, so the operation will proceed
        # but will likely fail at the WSL level
        # This tests that the code handles edge cases properly

    @pytest.mark.asyncio
    async def test_delete_with_special_characters(self, wsl_control_ops):
        """Test delete with special characters in name."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wsl_control_ops.delete_child_host(
                {"child_name": "Ubuntu-24.04-Custom"}
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_preserves_parameters(self, wsl_control_ops):
        """Test that restart passes parameters to stop and start."""
        params = {"child_name": "Ubuntu-24.04", "extra_param": "value"}

        with patch.object(
            wsl_control_ops,
            "stop_child_host",
            new_callable=AsyncMock,
            return_value={"success": True, "message": "stopped"},
        ) as mock_stop:
            with patch.object(
                wsl_control_ops,
                "start_child_host",
                new_callable=AsyncMock,
                return_value={"success": True, "status": "running"},
            ) as mock_start:
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    await wsl_control_ops.restart_child_host(params)

        # Verify parameters were passed through
        mock_stop.assert_called_once_with(params)
        mock_start.assert_called_once_with(params)


class TestLogging:
    """Tests for logging behavior in WSL control operations."""

    @pytest.mark.asyncio
    async def test_start_logs_info_on_success(self, wsl_control_ops, logger):
        """Test that successful start logs info messages."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"Started\n", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch.object(logger, "info") as mock_logger:
                wsl_control_ops.logger = logger
                await wsl_control_ops.start_child_host({"child_name": "Ubuntu-24.04"})

        # Verify logging occurred
        assert mock_logger.called

    @pytest.mark.asyncio
    async def test_stop_logs_error_on_exception(self, wsl_control_ops, logger):
        """Test that exceptions log error messages."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Test error"),
        ):
            with patch.object(logger, "error") as mock_logger:
                wsl_control_ops.logger = logger
                await wsl_control_ops.stop_child_host({"child_name": "Ubuntu-24.04"})

        # Verify error logging occurred
        assert mock_logger.called

    @pytest.mark.asyncio
    async def test_delete_logs_info_on_success(self, wsl_control_ops, logger):
        """Test that successful delete logs info messages."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch.object(logger, "info") as mock_logger:
                wsl_control_ops.logger = logger
                await wsl_control_ops.delete_child_host({"child_name": "Ubuntu-24.04"})

        assert mock_logger.called

    def test_guid_mismatch_logs_warning(self, wsl_control_ops, logger):
        """Test that GUID mismatch logs warning."""
        with patch.object(
            wsl_control_ops,
            "_get_wsl_guid",
            return_value="different-guid",
        ):
            with patch.object(logger, "warning") as mock_logger:
                wsl_control_ops.logger = logger
                wsl_control_ops._verify_wsl_guid(
                    "Ubuntu-24.04", "0283592d-be56-40d4-b935-3dc18c3aa007"
                )

        assert mock_logger.called


class TestDecodeOutput:
    """Tests for decode output handling."""

    @pytest.mark.asyncio
    async def test_start_decodes_utf16le_output(self, logger):
        """Test that UTF-16LE output is properly decoded."""
        decode_called = False
        decoded_output = ""

        def mock_decode(stdout, _stderr):
            nonlocal decode_called, decoded_output
            decode_called = True
            if stdout:
                decoded_output = stdout.decode("utf-8", errors="replace")
            return decoded_output

        ops = WslControlOperations(logger, mock_decode)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"Started\n", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            await ops.start_child_host({"child_name": "Ubuntu-24.04"})

        assert decode_called

    @pytest.mark.asyncio
    async def test_stop_uses_decode_function(self, logger):
        """Test that stop operation uses the decode function."""
        decode_called = False

        def mock_decode(_stdout, _stderr):
            nonlocal decode_called
            decode_called = True
            return "not running"

        ops = WslControlOperations(logger, mock_decode)

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"not running"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await ops.stop_child_host({"child_name": "Ubuntu-24.04"})

        assert decode_called
        assert result["success"] is True  # "not running" triggers already stopped
