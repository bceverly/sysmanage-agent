"""
Unit tests for src.sysmanage_agent.operations.firewall_operations module.
Tests the main FirewallOperations orchestrator class.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_operations import FirewallOperations


class TestFirewallOperationsInit:
    """Test cases for FirewallOperations initialization."""

    def test_init_with_logger(self):
        """Test FirewallOperations initialization with custom logger."""
        mock_agent = Mock()
        mock_logger = Mock()
        ops = FirewallOperations(mock_agent, logger=mock_logger)
        assert ops.agent == mock_agent
        assert ops.logger == mock_logger
        assert ops._os_handler is None

    def test_init_without_logger(self):
        """Test FirewallOperations initialization without logger."""
        mock_agent = Mock()
        ops = FirewallOperations(mock_agent)
        assert ops.agent == mock_agent
        assert ops.logger is not None


class TestGetOsHandler:
    """Test cases for getting OS-specific handler."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = FirewallOperations(self.mock_agent)

    def test_get_os_handler_linux(self):
        """Test getting Linux firewall handler."""
        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.firewall_operations.FirewallOperations._get_os_handler"
            ) as mock_method:
                mock_linux_handler = Mock()
                mock_method.return_value = mock_linux_handler
                self.ops._os_handler = None
                handler = self.ops._get_os_handler()
                assert handler is not None

    def test_get_os_handler_windows(self):
        """Test getting Windows firewall handler."""
        self.ops._os_handler = None
        self.ops.system = "Windows"

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.LinuxFirewallOperations"
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_windows.WindowsFirewallOperations"
            ) as mock_class:
                mock_handler = Mock()
                mock_class.return_value = mock_handler
                handler = self.ops._get_os_handler()
                assert handler == mock_handler

    def test_get_os_handler_macos(self):
        """Test getting macOS firewall handler."""
        self.ops._os_handler = None
        self.ops.system = "Darwin"

        with patch(
            "src.sysmanage_agent.operations.firewall_macos.MacOSFirewallOperations"
        ) as mock_class:
            mock_handler = Mock()
            mock_class.return_value = mock_handler
            handler = self.ops._get_os_handler()
            assert handler == mock_handler

    def test_get_os_handler_bsd(self):
        """Test getting BSD firewall handler."""
        for bsd_system in ["FreeBSD", "OpenBSD", "NetBSD"]:
            self.ops._os_handler = None
            self.ops.system = bsd_system

            with patch(
                "src.sysmanage_agent.operations.firewall_bsd.BSDFirewallOperations"
            ) as mock_class:
                mock_handler = Mock()
                mock_class.return_value = mock_handler
                handler = self.ops._get_os_handler()
                assert handler == mock_handler

    def test_get_os_handler_unsupported(self):
        """Test getting handler for unsupported OS."""
        self.ops._os_handler = None
        self.ops.system = "SomeOtherOS"

        with pytest.raises(ValueError) as excinfo:
            self.ops._get_os_handler()

        assert "Unsupported" in str(excinfo.value)

    def test_get_os_handler_caches_handler(self):
        """Test that handler is cached."""
        mock_handler = Mock()
        self.ops._os_handler = mock_handler

        handler = self.ops._get_os_handler()
        assert handler == mock_handler


class TestEnableFirewall:
    """Test cases for enabling firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = FirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_firewall_success(self):
        """Test enabling firewall successfully."""
        mock_handler = Mock()
        mock_handler._get_agent_communication_ports.return_value = ([8080], "tcp")
        mock_handler._get_local_server_ports.return_value = []
        mock_handler.enable_firewall = AsyncMock(
            return_value={"success": True, "message": "Firewall enabled"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.enable_firewall({})

        assert result["success"] is True
        mock_handler.enable_firewall.assert_called_once_with([8080], "tcp")

    @pytest.mark.asyncio
    async def test_enable_firewall_with_server_ports(self):
        """Test enabling firewall with local server ports."""
        mock_handler = Mock()
        mock_handler._get_agent_communication_ports.return_value = ([8080], "tcp")
        mock_handler._get_local_server_ports.return_value = [3000]
        mock_handler.enable_firewall = AsyncMock(
            return_value={"success": True, "message": "Firewall enabled"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.enable_firewall({})

        assert result["success"] is True
        # Should include both agent and server ports
        call_args = mock_handler.enable_firewall.call_args[0]
        assert 8080 in call_args[0]
        assert 3000 in call_args[0]

    @pytest.mark.asyncio
    async def test_enable_firewall_failure(self):
        """Test enabling firewall with failure."""
        mock_handler = Mock()
        mock_handler._get_agent_communication_ports.return_value = ([8080], "tcp")
        mock_handler._get_local_server_ports.return_value = []
        mock_handler.enable_firewall = AsyncMock(
            return_value={"success": False, "error": "Failed"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.enable_firewall({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_enable_firewall_value_error(self):
        """Test enabling firewall with ValueError."""
        self.ops._os_handler = None
        self.ops.system = "UnsupportedOS"

        result = await self.ops.enable_firewall({})

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_enable_firewall_exception(self):
        """Test enabling firewall with exception."""
        mock_handler = Mock()
        mock_handler._get_agent_communication_ports.side_effect = Exception(
            "Test error"
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.enable_firewall({})

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestDisableFirewall:
    """Test cases for disabling firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = FirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_disable_firewall_success(self):
        """Test disabling firewall successfully."""
        mock_handler = Mock()
        mock_handler.disable_firewall = AsyncMock(
            return_value={"success": True, "message": "Firewall disabled"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.disable_firewall({})

        assert result["success"] is True
        mock_handler.disable_firewall.assert_called_once()

    @pytest.mark.asyncio
    async def test_disable_firewall_failure(self):
        """Test disabling firewall with failure."""
        mock_handler = Mock()
        mock_handler.disable_firewall = AsyncMock(
            return_value={"success": False, "error": "Failed"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.disable_firewall({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_disable_firewall_value_error(self):
        """Test disabling firewall with ValueError."""
        self.ops._os_handler = None
        self.ops.system = "UnsupportedOS"

        result = await self.ops.disable_firewall({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_disable_firewall_exception(self):
        """Test disabling firewall with exception."""
        mock_handler = Mock()
        mock_handler.disable_firewall = AsyncMock(side_effect=Exception("Test error"))
        self.ops._os_handler = mock_handler

        result = await self.ops.disable_firewall({})

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestRestartFirewall:
    """Test cases for restarting firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = FirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_restart_firewall_success(self):
        """Test restarting firewall successfully."""
        mock_handler = Mock()
        mock_handler.restart_firewall = AsyncMock(
            return_value={"success": True, "message": "Firewall restarted"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.restart_firewall({})

        assert result["success"] is True
        mock_handler.restart_firewall.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_firewall_failure(self):
        """Test restarting firewall with failure."""
        mock_handler = Mock()
        mock_handler.restart_firewall = AsyncMock(
            return_value={"success": False, "error": "Failed"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.restart_firewall({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_restart_firewall_value_error(self):
        """Test restarting firewall with ValueError."""
        self.ops._os_handler = None
        self.ops.system = "UnsupportedOS"

        result = await self.ops.restart_firewall({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_restart_firewall_exception(self):
        """Test restarting firewall with exception."""
        mock_handler = Mock()
        mock_handler.restart_firewall = AsyncMock(side_effect=Exception("Test error"))
        self.ops._os_handler = mock_handler

        result = await self.ops.restart_firewall({})

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestDeployFirewall:
    """Test cases for deploying firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = FirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_deploy_firewall_success(self):
        """Test deploying firewall successfully."""
        mock_handler = Mock()
        mock_handler.deploy_firewall = AsyncMock(
            return_value={"success": True, "message": "Firewall deployed"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.deploy_firewall({})

        assert result["success"] is True
        mock_handler.deploy_firewall.assert_called_once()

    @pytest.mark.asyncio
    async def test_deploy_firewall_failure(self):
        """Test deploying firewall with failure."""
        mock_handler = Mock()
        mock_handler.deploy_firewall = AsyncMock(
            return_value={"success": False, "error": "Failed"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.deploy_firewall({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_firewall_value_error(self):
        """Test deploying firewall with ValueError."""
        self.ops._os_handler = None
        self.ops.system = "UnsupportedOS"

        result = await self.ops.deploy_firewall({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_firewall_exception(self):
        """Test deploying firewall with exception."""
        mock_handler = Mock()
        mock_handler.deploy_firewall = AsyncMock(side_effect=Exception("Test error"))
        self.ops._os_handler = mock_handler

        result = await self.ops.deploy_firewall({})

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestApplyFirewallRoles:
    """Test cases for applying firewall roles."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = FirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_success(self):
        """Test applying firewall roles successfully."""
        mock_handler = Mock()
        mock_handler.apply_firewall_roles = AsyncMock(
            return_value={"success": True, "message": "Roles applied"}
        )
        self.ops._os_handler = mock_handler

        parameters = {
            "ipv4_ports": [{"port": 80, "tcp": True, "udp": False}],
            "ipv6_ports": [],
        }

        result = await self.ops.apply_firewall_roles(parameters)

        assert result["success"] is True
        mock_handler.apply_firewall_roles.assert_called_once_with(
            [{"port": 80, "tcp": True, "udp": False}], []
        )

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_empty(self):
        """Test applying empty firewall roles."""
        mock_handler = Mock()
        mock_handler.apply_firewall_roles = AsyncMock(
            return_value={"success": True, "message": "Roles applied"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.apply_firewall_roles({})

        assert result["success"] is True
        mock_handler.apply_firewall_roles.assert_called_once_with([], [])

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_failure(self):
        """Test applying firewall roles with failure."""
        mock_handler = Mock()
        mock_handler.apply_firewall_roles = AsyncMock(
            return_value={"success": False, "error": "Failed"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.apply_firewall_roles({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_value_error(self):
        """Test applying firewall roles with ValueError."""
        self.ops._os_handler = None
        self.ops.system = "UnsupportedOS"

        result = await self.ops.apply_firewall_roles({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_exception(self):
        """Test applying firewall roles with exception."""
        mock_handler = Mock()
        mock_handler.apply_firewall_roles = AsyncMock(
            side_effect=Exception("Test error")
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.apply_firewall_roles({})

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestRemoveFirewallPorts:
    """Test cases for removing firewall ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = FirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_success(self):
        """Test removing firewall ports successfully."""
        mock_handler = Mock()
        mock_handler.remove_firewall_ports = AsyncMock(
            return_value={"success": True, "message": "Ports removed"}
        )
        self.ops._os_handler = mock_handler

        parameters = {
            "ipv4_ports": [{"port": 9000, "tcp": True, "udp": False}],
            "ipv6_ports": [],
        }

        result = await self.ops.remove_firewall_ports(parameters)

        assert result["success"] is True
        mock_handler.remove_firewall_ports.assert_called_once_with(
            [{"port": 9000, "tcp": True, "udp": False}], []
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_empty(self):
        """Test removing empty port list."""
        mock_handler = Mock()
        mock_handler.remove_firewall_ports = AsyncMock(
            return_value={"success": True, "message": "Ports removed"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.remove_firewall_ports({})

        assert result["success"] is True
        mock_handler.remove_firewall_ports.assert_called_once_with([], [])

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_failure(self):
        """Test removing firewall ports with failure."""
        mock_handler = Mock()
        mock_handler.remove_firewall_ports = AsyncMock(
            return_value={"success": False, "error": "Failed"}
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.remove_firewall_ports({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_value_error(self):
        """Test removing firewall ports with ValueError."""
        self.ops._os_handler = None
        self.ops.system = "UnsupportedOS"

        result = await self.ops.remove_firewall_ports({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_exception(self):
        """Test removing firewall ports with exception."""
        mock_handler = Mock()
        mock_handler.remove_firewall_ports = AsyncMock(
            side_effect=Exception("Test error")
        )
        self.ops._os_handler = mock_handler

        result = await self.ops.remove_firewall_ports({})

        assert result["success"] is False
        assert "Test error" in result["error"]
