"""
Unit tests for src.sysmanage_agent.operations.firewall_linux module.
Tests Linux firewall operations that delegate to UFW or firewalld.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_linux import LinuxFirewallOperations


class TestLinuxFirewallOperationsInit:
    """Test cases for LinuxFirewallOperations initialization."""

    def test_init(self):
        """Test LinuxFirewallOperations initialization."""
        mock_agent = Mock()
        mock_logger = Mock()
        ops = LinuxFirewallOperations(mock_agent, logger=mock_logger)

        assert ops.agent == mock_agent
        assert ops.logger == mock_logger
        assert ops._ufw is None
        assert ops._firewalld is None

    def test_init_without_logger(self):
        """Test LinuxFirewallOperations initialization without logger."""
        mock_agent = Mock()
        ops = LinuxFirewallOperations(mock_agent)

        assert ops.agent == mock_agent
        assert ops.logger is not None


class TestGetUfw:
    """Test cases for getting UFW operations handler."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    def test_get_ufw_creates_handler(self):
        """Test that _get_ufw creates a new handler."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations"
        ) as mock_class:
            mock_handler = Mock()
            mock_class.return_value = mock_handler

            result = self.ops._get_ufw()

            assert result == mock_handler
            mock_class.assert_called_once()

    def test_get_ufw_returns_cached(self):
        """Test that _get_ufw returns cached handler."""
        mock_handler = Mock()
        self.ops._ufw = mock_handler

        result = self.ops._get_ufw()

        assert result == mock_handler


class TestGetFirewalld:
    """Test cases for getting firewalld operations handler."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    def test_get_firewalld_creates_handler(self):
        """Test that _get_firewalld creates a new handler."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations"
        ) as mock_class:
            mock_handler = Mock()
            mock_class.return_value = mock_handler

            result = self.ops._get_firewalld()

            assert result == mock_handler
            mock_class.assert_called_once()

    def test_get_firewalld_returns_cached(self):
        """Test that _get_firewalld returns cached handler."""
        mock_handler = Mock()
        self.ops._firewalld = mock_handler

        result = self.ops._get_firewalld()

        assert result == mock_handler


class TestEnableFirewall:
    """Test cases for enabling firewall on Linux."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_firewall_ufw(self):
        """Test enabling firewall with UFW available."""
        mock_ufw = Mock()
        mock_ufw.enable_firewall = AsyncMock(
            return_value={"success": True, "message": "UFW enabled"}
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is True
        mock_ufw.enable_firewall.assert_called_once_with([8080], "tcp")

    @pytest.mark.asyncio
    async def test_enable_firewall_firewalld(self):
        """Test enabling firewall with firewalld when UFW not available."""
        mock_firewalld = Mock()
        mock_firewalld.enable_firewall = AsyncMock(
            return_value={"success": True, "message": "Firewalld enabled"}
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=True,
            ):
                with patch.object(
                    self.ops, "_get_firewalld", return_value=mock_firewalld
                ):
                    result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is True
        mock_firewalld.enable_firewall.assert_called_once_with([8080], "tcp")

    @pytest.mark.asyncio
    async def test_enable_firewall_no_firewall(self):
        """Test enabling firewall when no firewall is available."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=False,
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "No supported firewall" in result["error"]


class TestDisableFirewall:
    """Test cases for disabling firewall on Linux."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_disable_firewall_ufw(self):
        """Test disabling firewall with UFW available."""
        mock_ufw = Mock()
        mock_ufw.disable_firewall = AsyncMock(
            return_value={"success": True, "message": "UFW disabled"}
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                result = await self.ops.disable_firewall()

        assert result["success"] is True
        mock_ufw.disable_firewall.assert_called_once()

    @pytest.mark.asyncio
    async def test_disable_firewall_firewalld(self):
        """Test disabling firewall with firewalld when UFW not available."""
        mock_firewalld = Mock()
        mock_firewalld.disable_firewall = AsyncMock(
            return_value={"success": True, "message": "Firewalld disabled"}
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=True,
            ):
                with patch.object(
                    self.ops, "_get_firewalld", return_value=mock_firewalld
                ):
                    result = await self.ops.disable_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_firewall_no_firewall(self):
        """Test disabling firewall when no firewall is available."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=False,
            ):
                result = await self.ops.disable_firewall()

        assert result["success"] is False
        assert "No supported firewall" in result["error"]


class TestRestartFirewall:
    """Test cases for restarting firewall on Linux."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_restart_firewall_ufw(self):
        """Test restarting firewall with UFW available."""
        mock_ufw = Mock()
        mock_ufw.restart_firewall = AsyncMock(
            return_value={"success": True, "message": "UFW restarted"}
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                result = await self.ops.restart_firewall()

        assert result["success"] is True
        mock_ufw.restart_firewall.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_firewall_firewalld(self):
        """Test restarting firewall with firewalld when UFW not available."""
        mock_firewalld = Mock()
        mock_firewalld.restart_firewall = AsyncMock(
            return_value={"success": True, "message": "Firewalld restarted"}
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=True,
            ):
                with patch.object(
                    self.ops, "_get_firewalld", return_value=mock_firewalld
                ):
                    result = await self.ops.restart_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_firewall_no_firewall(self):
        """Test restarting firewall when no firewall is available."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=False,
            ):
                result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "No supported firewall" in result["error"]


class TestDeployFirewall:
    """Test cases for deploying firewall on Linux."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_deploy_firewall_success(self):
        """Test deploying firewall successfully."""
        mock_ufw = Mock()
        mock_ufw.enable_firewall = AsyncMock(
            return_value={"success": True, "message": "UFW enabled"}
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                with patch.object(
                    self.ops,
                    "_get_agent_communication_ports",
                    return_value=([8080], "tcp"),
                ):
                    with patch.object(
                        self.ops, "_get_local_server_ports", return_value=[]
                    ):
                        result = await self.ops.deploy_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_firewall_with_server_ports(self):
        """Test deploying firewall with local server ports."""
        mock_ufw = Mock()
        mock_ufw.enable_firewall = AsyncMock(
            return_value={"success": True, "message": "UFW enabled"}
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                with patch.object(
                    self.ops,
                    "_get_agent_communication_ports",
                    return_value=([8080], "tcp"),
                ):
                    with patch.object(
                        self.ops, "_get_local_server_ports", return_value=[3000]
                    ):
                        result = await self.ops.deploy_firewall()

        assert result["success"] is True
        # Verify both ports are included
        call_args = mock_ufw.enable_firewall.call_args[0]
        assert 8080 in call_args[0]
        assert 3000 in call_args[0]

    @pytest.mark.asyncio
    async def test_deploy_firewall_exception(self):
        """Test deploying firewall with exception."""
        with patch.object(
            self.ops,
            "_get_agent_communication_ports",
            side_effect=Exception("Test error"),
        ):
            result = await self.ops.deploy_firewall()

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestApplyFirewallRoles:
    """Test cases for applying firewall roles on Linux."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_ufw(self):
        """Test applying firewall roles with UFW."""
        mock_ufw = Mock()
        mock_ufw.apply_firewall_roles = AsyncMock(
            return_value={"success": True, "message": "Roles applied"}
        )

        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        mock_ufw.apply_firewall_roles.assert_called_once_with(ipv4_ports, ipv6_ports)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_firewalld(self):
        """Test applying firewall roles with firewalld."""
        mock_firewalld = Mock()
        mock_firewalld.apply_firewall_roles = AsyncMock(
            return_value={"success": True, "message": "Roles applied"}
        )

        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=True,
            ):
                with patch.object(
                    self.ops, "_get_firewalld", return_value=mock_firewalld
                ):
                    result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_no_firewall(self):
        """Test applying firewall roles when no firewall is available."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=False,
            ):
                result = await self.ops.apply_firewall_roles([], [])

        assert result["success"] is False
        assert "No supported firewall" in result["error"]


class TestRemoveFirewallPorts:
    """Test cases for removing firewall ports on Linux."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_ufw(self):
        """Test removing firewall ports with UFW."""
        mock_ufw = Mock()
        mock_ufw.remove_firewall_ports = AsyncMock(
            return_value={"success": True, "message": "Ports removed"}
        )

        ipv4_ports = [{"port": 9000, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        mock_ufw.remove_firewall_ports.assert_called_once_with(ipv4_ports, ipv6_ports)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_firewalld(self):
        """Test removing firewall ports with firewalld."""
        mock_firewalld = Mock()
        mock_firewalld.remove_firewall_ports = AsyncMock(
            return_value={"success": True, "message": "Ports removed"}
        )

        ipv4_ports = [{"port": 9000, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=True,
            ):
                with patch.object(
                    self.ops, "_get_firewalld", return_value=mock_firewalld
                ):
                    result = await self.ops.remove_firewall_ports(
                        ipv4_ports, ipv6_ports
                    )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_no_firewall(self):
        """Test removing firewall ports when no firewall is available."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=False,
            ):
                result = await self.ops.remove_firewall_ports([], [])

        assert result["success"] is False
        assert "No supported firewall" in result["error"]


class TestConfigureLxdFirewall:
    """Test cases for configuring LXD firewall on Linux."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = LinuxFirewallOperations(self.mock_agent)

    def test_configure_lxd_firewall_ufw(self):
        """Test configuring LXD firewall with UFW."""
        mock_ufw = Mock()
        mock_ufw.configure_lxd_firewall.return_value = {
            "success": True,
            "message": "LXD configured",
        }

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                result = self.ops.configure_lxd_firewall("lxdbr0")

        assert result["success"] is True
        mock_ufw.configure_lxd_firewall.assert_called_once_with("lxdbr0")

    def test_configure_lxd_firewall_firewalld(self):
        """Test configuring LXD firewall with firewalld (automatic)."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=True,
            ):
                result = self.ops.configure_lxd_firewall("lxdbr0")

        assert result["success"] is True
        assert "automatically" in result["message"]

    def test_configure_lxd_firewall_default_bridge(self):
        """Test configuring LXD firewall with default bridge name."""
        mock_ufw = Mock()
        mock_ufw.configure_lxd_firewall.return_value = {
            "success": True,
            "message": "LXD configured",
        }

        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=True,
        ):
            with patch.object(self.ops, "_get_ufw", return_value=mock_ufw):
                _result = self.ops.configure_lxd_firewall()

        mock_ufw.configure_lxd_firewall.assert_called_once_with("lxdbr0")

    def test_configure_lxd_firewall_no_firewall(self):
        """Test configuring LXD firewall when no firewall is available."""
        with patch(
            "src.sysmanage_agent.operations.firewall_linux.UfwOperations.is_available",
            return_value=False,
        ):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.FirewalldOperations.is_available",
                return_value=False,
            ):
                result = self.ops.configure_lxd_firewall()

        assert result["success"] is False
        assert "No supported firewall" in result["error"]
