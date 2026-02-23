"""
Comprehensive unit tests for LXD container operations.

Tests cover:
- LXD initialization
- Container lifecycle operations (start, stop, restart, delete)
- Container creation
- Status checks
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import asyncio
import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_lxd import LxdOperations


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock_checks = Mock()
    mock_checks.check_lxd_support = Mock(
        return_value={
            "available": True,
            "installed": True,
            "initialized": True,
            "user_in_group": True,
            "needs_install": False,
            "needs_init": False,
            "snap_available": True,
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
def lxd_ops(mock_agent, logger, mock_virtualization_checks):
    """Create an LxdOperations instance for testing."""
    return LxdOperations(mock_agent, logger, mock_virtualization_checks)


class TestLxdOperationsInit:
    """Tests for LxdOperations initialization."""

    def test_init_sets_agent(self, lxd_ops, mock_agent):
        """Test that __init__ sets agent."""
        assert lxd_ops.agent == mock_agent

    def test_init_sets_logger(self, lxd_ops, logger):
        """Test that __init__ sets logger."""
        assert lxd_ops.logger == logger

    def test_init_sets_virtualization_checks(self, lxd_ops, mock_virtualization_checks):
        """Test that __init__ sets virtualization_checks."""
        assert lxd_ops.virtualization_checks == mock_virtualization_checks


class TestLxdOperationsInitializeLxd:
    """Tests for initialize_lxd method."""

    @pytest.mark.asyncio
    async def test_initialize_lxd_not_available(
        self, lxd_ops, mock_virtualization_checks
    ):
        """Test initialize_lxd when LXD is not available."""
        mock_virtualization_checks.check_lxd_support.return_value = {
            "available": False,
            "installed": False,
            "initialized": False,
        }

        result = await lxd_ops.initialize_lxd({})

        assert result["success"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_initialize_lxd_already_initialized(
        self, lxd_ops, mock_virtualization_checks
    ):
        """Test initialize_lxd when already initialized."""
        mock_virtualization_checks.check_lxd_support.return_value = {
            "available": True,
            "installed": True,
            "initialized": True,
            "user_in_group": True,
            "snap_available": True,
        }

        with patch.object(lxd_ops, "_configure_lxd_firewall") as mock_firewall:
            mock_firewall.return_value = {"success": True}
            result = await lxd_ops.initialize_lxd({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_initialize_lxd_install_via_snap(
        self, lxd_ops, mock_virtualization_checks
    ):
        """Test initialize_lxd installing LXD via snap."""
        mock_virtualization_checks.check_lxd_support.side_effect = [
            {
                "available": True,
                "installed": False,
                "initialized": False,
                "user_in_group": False,
                "snap_available": True,
            },
            {
                "available": True,
                "installed": True,
                "initialized": True,
                "user_in_group": True,
                "snap_available": True,
            },
        ]

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            with patch.object(lxd_ops, "_configure_lxd_firewall") as mock_firewall:
                mock_firewall.return_value = {"success": True}
                result = await lxd_ops.initialize_lxd({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_initialize_lxd_snap_not_available(
        self, lxd_ops, mock_virtualization_checks
    ):
        """Test initialize_lxd when snap is not available."""
        mock_virtualization_checks.check_lxd_support.return_value = {
            "available": True,
            "installed": False,
            "initialized": False,
            "user_in_group": False,
            "snap_available": False,
        }

        result = await lxd_ops.initialize_lxd({})

        assert result["success"] is False
        assert "snap" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_initialize_lxd_timeout(self, lxd_ops, mock_virtualization_checks):
        """Test initialize_lxd with timeout."""
        mock_virtualization_checks.check_lxd_support.return_value = {
            "available": True,
            "installed": False,
            "initialized": False,
            "snap_available": True,
        }

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await lxd_ops.initialize_lxd({})

        assert result["success"] is False
        assert "timed out" in result["error"].lower()


class TestLxdOperationsStartChildHost:
    """Tests for start_child_host method."""

    @pytest.mark.asyncio
    async def test_start_container_no_name(self, lxd_ops):
        """Test starting container without name."""
        result = await lxd_ops.start_child_host({})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_container_success(self, lxd_ops):
        """Test starting container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.start_child_host({"child_name": "test-container"})

        assert result["success"] is True
        assert result["child_name"] == "test-container"
        assert result["child_type"] == "lxd"

    @pytest.mark.asyncio
    async def test_start_container_failure(self, lxd_ops):
        """Test starting container when it fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: Container 'test-container' is already running"

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.start_child_host({"child_name": "test-container"})

        assert result["success"] is False
        assert "already running" in result["error"]

    @pytest.mark.asyncio
    async def test_start_container_timeout(self, lxd_ops):
        """Test starting container with timeout."""
        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await lxd_ops.start_child_host({"child_name": "test-container"})

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_container_exception(self, lxd_ops):
        """Test starting container with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            side_effect=Exception("Unexpected error"),
        ):
            result = await lxd_ops.start_child_host({"child_name": "test-container"})

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestLxdOperationsStopChildHost:
    """Tests for stop_child_host method."""

    @pytest.mark.asyncio
    async def test_stop_container_no_name(self, lxd_ops):
        """Test stopping container without name."""
        result = await lxd_ops.stop_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_stop_container_success(self, lxd_ops):
        """Test stopping container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.stop_child_host({"child_name": "test-container"})

        assert result["success"] is True
        assert result["child_name"] == "test-container"
        assert result["child_type"] == "lxd"

    @pytest.mark.asyncio
    async def test_stop_container_failure(self, lxd_ops):
        """Test stopping container when it fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: Container 'test-container' is not running"

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.stop_child_host({"child_name": "test-container"})

        assert result["success"] is False


class TestLxdOperationsRestartChildHost:
    """Tests for restart_child_host method."""

    @pytest.mark.asyncio
    async def test_restart_container_no_name(self, lxd_ops):
        """Test restarting container without name."""
        result = await lxd_ops.restart_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_restart_container_success(self, lxd_ops):
        """Test restarting container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.restart_child_host({"child_name": "test-container"})

        assert result["success"] is True
        assert result["child_name"] == "test-container"

    @pytest.mark.asyncio
    async def test_restart_container_exception(self, lxd_ops):
        """Test restarting container with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            side_effect=Exception("Connection failed"),
        ):
            result = await lxd_ops.restart_child_host({"child_name": "test-container"})

        assert result["success"] is False


class TestLxdOperationsDeleteChildHost:
    """Tests for delete_child_host method."""

    @pytest.mark.asyncio
    async def test_delete_container_no_name(self, lxd_ops):
        """Test deleting container without name."""
        result = await lxd_ops.delete_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_container_success(self, lxd_ops):
        """Test deleting container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.delete_child_host({"child_name": "test-container"})

        assert result["success"] is True
        assert result["child_name"] == "test-container"

    @pytest.mark.asyncio
    async def test_delete_container_force_used(self, lxd_ops):
        """Test that delete uses --force flag."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ) as mock_cmd:
            await lxd_ops.delete_child_host({"child_name": "test-container"})

        # Verify --force was passed
        call_args = mock_cmd.call_args[0][0]
        assert "--force" in call_args


class TestLxdOperationsConfigureFirewall:
    """Tests for LxdOperations._configure_lxd_firewall method."""

    def test_configure_firewall_not_linux(self, lxd_ops):
        """Test configuring firewall on non-Linux."""
        with patch("platform.system", return_value="Darwin"):
            result = lxd_ops._configure_lxd_firewall()

        assert result["success"] is True
        assert "not needed" in result["message"].lower()

    def test_configure_firewall_success(self, lxd_ops):
        """Test configuring firewall successfully."""
        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.LinuxFirewallOperations"
            ) as mock_firewall:
                mock_instance = Mock()
                mock_instance.configure_lxd_firewall.return_value = {"success": True}
                mock_firewall.return_value = mock_instance
                result = lxd_ops._configure_lxd_firewall()

        assert result["success"] is True

    def test_configure_firewall_exception(self, lxd_ops):
        """Test configuring firewall with exception."""
        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.LinuxFirewallOperations",
                side_effect=Exception("Firewall error"),
            ):
                result = lxd_ops._configure_lxd_firewall()

        assert result["success"] is False
