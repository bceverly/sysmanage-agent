"""
Unit tests for src.sysmanage_agent.operations.firewall_macos module.
Tests macOS firewall operations using socketfilterfw.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_macos import (
    SOCKETFILTERFW_PATH,
    MacOSFirewallOperations,
)


class TestMacOSFirewallOperationsInit:
    """Test cases for MacOSFirewallOperations initialization."""

    def test_init_with_logger(self):
        """Test MacOSFirewallOperations initialization with custom logger."""
        mock_agent = Mock()
        mock_logger = Mock()
        ops = MacOSFirewallOperations(mock_agent, logger=mock_logger)

        assert ops.agent == mock_agent
        assert ops.logger == mock_logger

    def test_init_without_logger(self):
        """Test MacOSFirewallOperations initialization without logger."""
        mock_agent = Mock()
        ops = MacOSFirewallOperations(mock_agent)

        assert ops.agent == mock_agent
        assert ops.logger is not None

    def test_socketfilterfw_path(self):
        """Test that SOCKETFILTERFW_PATH is correctly defined."""
        assert SOCKETFILTERFW_PATH == "/usr/libexec/ApplicationFirewall/socketfilterfw"


class TestEnableFirewall:
    """Test cases for enabling firewall on macOS."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.mock_logger = Mock()
        self.ops = MacOSFirewallOperations(self.mock_agent, logger=self.mock_logger)

    @pytest.mark.asyncio
    async def test_enable_firewall_success(self):
        """Test enabling macOS firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall is on"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ) as mock_status:
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is True
        assert "enabled successfully" in result["message"]
        mock_run.assert_called_once_with(
            ["sudo", SOCKETFILTERFW_PATH, "--setglobalstate", "on"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        mock_status.assert_called_once()
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_failure(self):
        """Test enabling macOS firewall with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Permission denied"

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_firewall_exception(self):
        """Test enabling macOS firewall with exception."""
        with patch("subprocess.run", side_effect=Exception("Test error")):
            result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "Test error" in result["error"]
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_timeout_exception(self):
        """Test enabling macOS firewall with timeout."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="cmd", timeout=10),
        ):
            result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_ports_ignored(self):
        """Test that ports parameter is accepted but not used (macOS is app-based)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall is on"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                # Pass various ports - they should be ignored
                result = await self.ops.enable_firewall([80, 443, 8080], "tcp")

        assert result["success"] is True
        # Verify the command doesn't include any port-specific arguments
        call_args = mock_run.call_args[0][0]
        assert "80" not in call_args
        assert "443" not in call_args
        assert "8080" not in call_args


class TestDisableFirewall:
    """Test cases for disabling firewall on macOS."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.mock_logger = Mock()
        self.ops = MacOSFirewallOperations(self.mock_agent, logger=self.mock_logger)

    @pytest.mark.asyncio
    async def test_disable_firewall_success(self):
        """Test disabling macOS firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall is off"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ) as mock_status:
                result = await self.ops.disable_firewall()

        assert result["success"] is True
        assert "disabled successfully" in result["message"]
        mock_run.assert_called_once_with(
            ["sudo", SOCKETFILTERFW_PATH, "--setglobalstate", "off"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        mock_status.assert_called_once()
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_disable_firewall_failure(self):
        """Test disabling macOS firewall with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Permission denied"

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.disable_firewall()

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_firewall_exception(self):
        """Test disabling macOS firewall with exception."""
        with patch("subprocess.run", side_effect=Exception("Test error")):
            result = await self.ops.disable_firewall()

        assert result["success"] is False
        assert "Test error" in result["error"]
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_disable_firewall_timeout_exception(self):
        """Test disabling macOS firewall with timeout."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="cmd", timeout=10),
        ):
            result = await self.ops.disable_firewall()

        assert result["success"] is False
        self.mock_logger.error.assert_called()


class TestRestartFirewall:
    """Test cases for restarting firewall on macOS."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.mock_logger = Mock()
        self.ops = MacOSFirewallOperations(self.mock_agent, logger=self.mock_logger)

    @pytest.mark.asyncio
    async def test_restart_firewall_success(self):
        """Test restarting macOS firewall successfully (off then on)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall toggled"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ) as mock_status:
                result = await self.ops.restart_firewall()

        assert result["success"] is True
        assert "restarted successfully" in result["message"]
        # Should be called twice: off then on
        assert mock_run.call_count == 2
        calls = mock_run.call_args_list
        # First call should be to turn off
        assert calls[0][0][0] == [
            "sudo",
            SOCKETFILTERFW_PATH,
            "--setglobalstate",
            "off",
        ]
        # Second call should be to turn on
        assert calls[1][0][0] == [
            "sudo",
            SOCKETFILTERFW_PATH,
            "--setglobalstate",
            "on",
        ]
        mock_status.assert_called_once()
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_restart_firewall_first_command_fails(self):
        """Test restarting macOS firewall when first command (off) fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Failed to turn off"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "Failed to turn off" in result["error"]
        # Should only be called once since first command failed
        assert mock_run.call_count == 1

    @pytest.mark.asyncio
    async def test_restart_firewall_second_command_fails(self):
        """Test restarting macOS firewall when second command (on) fails."""
        mock_result_off = Mock()
        mock_result_off.returncode = 0
        mock_result_off.stdout = "Off"
        mock_result_off.stderr = ""

        mock_result_on = Mock()
        mock_result_on.returncode = 1
        mock_result_on.stdout = ""
        mock_result_on.stderr = "Failed to turn on"

        with patch(
            "subprocess.run", side_effect=[mock_result_off, mock_result_on]
        ) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "Failed to turn on" in result["error"]
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_restart_firewall_exception(self):
        """Test restarting macOS firewall with exception."""
        with patch("subprocess.run", side_effect=Exception("Test error")):
            result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "Test error" in result["error"]
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_restart_firewall_timeout_on_first_command(self):
        """Test restarting macOS firewall with timeout on first command."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="cmd", timeout=10),
        ):
            result = await self.ops.restart_firewall()

        assert result["success"] is False
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_restart_firewall_timeout_on_second_command(self):
        """Test restarting macOS firewall with timeout on second command."""
        mock_result_off = Mock()
        mock_result_off.returncode = 0
        mock_result_off.stdout = "Off"
        mock_result_off.stderr = ""

        with patch(
            "subprocess.run",
            side_effect=[
                mock_result_off,
                subprocess.TimeoutExpired(cmd="cmd", timeout=10),
            ],
        ):
            result = await self.ops.restart_firewall()

        assert result["success"] is False
        self.mock_logger.error.assert_called()


class TestDeployFirewall:
    """Test cases for deploying firewall on macOS."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.mock_logger = Mock()
        self.ops = MacOSFirewallOperations(self.mock_agent, logger=self.mock_logger)

    @pytest.mark.asyncio
    async def test_deploy_firewall_success(self):
        """Test deploying firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall is on"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
            ):
                with patch.object(self.ops, "_get_local_server_ports", return_value=[]):
                    with patch.object(
                        self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                    ):
                        result = await self.ops.deploy_firewall()

        assert result["success"] is True
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_deploy_firewall_with_server_ports(self):
        """Test deploying firewall with local server ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall is on"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
            ):
                with patch.object(
                    self.ops, "_get_local_server_ports", return_value=[3000]
                ):
                    with patch.object(
                        self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                    ):
                        result = await self.ops.deploy_firewall()

        assert result["success"] is True

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
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_deploy_firewall_enable_fails(self):
        """Test deploying firewall when enable fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Permission denied"

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
            ):
                with patch.object(self.ops, "_get_local_server_ports", return_value=[]):
                    with patch.object(
                        self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                    ):
                        result = await self.ops.deploy_firewall()

        assert result["success"] is False
        assert "Permission denied" in result["error"]


class TestApplyFirewallRoles:
    """Test cases for applying firewall roles on macOS."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.mock_logger = Mock()
        self.ops = MacOSFirewallOperations(self.mock_agent, logger=self.mock_logger)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_with_ports(self):
        """Test applying firewall roles with ports."""
        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 443, "tcp": True, "udp": False},
        ]
        ipv6_ports = [{"port": 8080, "tcp": True, "udp": True}]

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ) as mock_status:
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        assert "application-based" in result["message"]
        mock_status.assert_called_once()
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_empty_ports(self):
        """Test applying firewall roles with empty port lists."""
        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ) as mock_status:
            result = await self.ops.apply_firewall_roles([], [])

        assert result["success"] is True
        mock_status.assert_called_once()
        # Should log that no ports are configured
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_deduplicates_ports(self):
        """Test that duplicate ports across IPv4 and IPv6 are deduplicated."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = [{"port": 80, "tcp": False, "udp": True}]

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        # Verify logging was called (port 80 appears in both lists but is deduplicated)
        self.mock_logger.info.assert_called()
        # Verify there was a call with the format string and argument 1 for unique ports
        calls = self.mock_logger.info.call_args_list
        port_count_calls = [c for c in calls if len(c[0]) > 1 and c[0][1] == 1]
        assert len(port_count_calls) > 0, "Expected a log call with 1 unique port"

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_merges_protocols(self):
        """Test that protocols are merged when same port appears multiple times."""
        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 80, "tcp": False, "udp": True},
        ]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_tcp_only(self):
        """Test applying firewall roles with TCP-only ports."""
        ipv4_ports = [{"port": 22, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        self.mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_udp_only(self):
        """Test applying firewall roles with UDP-only ports."""
        ipv4_ports = [{"port": 53, "tcp": False, "udp": True}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        self.mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_both_protocols(self):
        """Test applying firewall roles with both TCP and UDP."""
        ipv4_ports = [{"port": 53, "tcp": True, "udp": True}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        self.mock_logger.debug.assert_called()


class TestRemoveFirewallPorts:
    """Test cases for removing firewall ports on macOS."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.mock_logger = Mock()
        self.ops = MacOSFirewallOperations(self.mock_agent, logger=self.mock_logger)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_with_ports(self):
        """Test removing firewall ports with ports."""
        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 443, "tcp": True, "udp": False},
        ]
        ipv6_ports = [{"port": 8080, "tcp": True, "udp": True}]

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ) as mock_status:
            result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        assert "application-based" in result["message"]
        mock_status.assert_called_once()
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_empty_ports(self):
        """Test removing firewall ports with empty port lists."""
        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ) as mock_status:
            result = await self.ops.remove_firewall_ports([], [])

        assert result["success"] is True
        mock_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_deduplicates_ports(self):
        """Test that duplicate ports across IPv4 and IPv6 are deduplicated."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = [{"port": 80, "tcp": False, "udp": True}]

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        # Verify logging was called (port 80 appears in both lists but is deduplicated)
        self.mock_logger.info.assert_called()
        # Verify there was a call with the format string and argument 1 for unique ports
        calls = self.mock_logger.info.call_args_list
        port_count_calls = [c for c in calls if len(c[0]) > 1 and c[0][1] == 1]
        assert len(port_count_calls) > 0, "Expected a log call with 1 unique port"

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_merges_protocols(self):
        """Test that protocols are merged when same port appears multiple times."""
        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 80, "tcp": False, "udp": True},
        ]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_tcp_only(self):
        """Test removing firewall ports with TCP-only ports."""
        ipv4_ports = [{"port": 22, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        self.mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_udp_only(self):
        """Test removing firewall ports with UDP-only ports."""
        ipv4_ports = [{"port": 53, "tcp": False, "udp": True}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        self.mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_both_protocols(self):
        """Test removing firewall ports with both TCP and UDP."""
        ipv4_ports = [{"port": 53, "tcp": True, "udp": True}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        self.mock_logger.debug.assert_called()


class TestMacOSFirewallIntegration:
    """Integration-like tests for macOS firewall operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.mock_logger = Mock()
        self.ops = MacOSFirewallOperations(self.mock_agent, logger=self.mock_logger)

    @pytest.mark.asyncio
    async def test_deploy_then_apply_roles(self):
        """Test deploying firewall then applying roles."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall is on"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
            ):
                with patch.object(self.ops, "_get_local_server_ports", return_value=[]):
                    with patch.object(
                        self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                    ):
                        deploy_result = await self.ops.deploy_firewall()
                        roles_result = await self.ops.apply_firewall_roles(
                            [{"port": 80, "tcp": True, "udp": False}], []
                        )

        assert deploy_result["success"] is True
        assert roles_result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_disable_cycle(self):
        """Test enabling then disabling firewall."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Success"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                enable_result = await self.ops.enable_firewall([8080], "tcp")
                disable_result = await self.ops.disable_firewall()

        assert enable_result["success"] is True
        assert disable_result["success"] is True


class TestMacOSFirewallEdgeCases:
    """Edge case tests for macOS firewall operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.mock_logger = Mock()
        self.ops = MacOSFirewallOperations(self.mock_agent, logger=self.mock_logger)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_missing_port_key(self):
        """Test applying firewall roles when port key is missing."""
        ipv4_ports = [{"tcp": True, "udp": False}]  # Missing 'port' key
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        # Should handle gracefully - port will be None
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_missing_protocol_keys(self):
        """Test applying firewall roles when tcp/udp keys are missing."""
        ipv4_ports = [{"port": 80}]  # Missing 'tcp' and 'udp' keys
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        # Should handle gracefully - defaults to False for both
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_missing_port_key(self):
        """Test removing firewall ports when port key is missing."""
        ipv4_ports = [{"tcp": True, "udp": False}]  # Missing 'port' key
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        # Should handle gracefully
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_missing_protocol_keys(self):
        """Test removing firewall ports when tcp/udp keys are missing."""
        ipv4_ports = [{"port": 80}]  # Missing 'tcp' and 'udp' keys
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        # Should handle gracefully
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_large_port_list(self):
        """Test applying firewall roles with many ports."""
        ipv4_ports = [{"port": i, "tcp": True, "udp": False} for i in range(1, 101)]
        ipv6_ports = []

        with patch.object(
            self.ops, "_send_firewall_status_update", new_callable=AsyncMock
        ):
            result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        # Verify logging was called with 100 unique ports
        self.mock_logger.info.assert_called()
        # Verify there was a call with the format string and argument 100 for unique ports
        calls = self.mock_logger.info.call_args_list
        port_count_calls = [c for c in calls if len(c[0]) > 1 and c[0][1] == 100]
        assert len(port_count_calls) > 0, "Expected a log call with 100 unique ports"

    @pytest.mark.asyncio
    async def test_enable_firewall_empty_stderr(self):
        """Test enabling firewall with empty stderr on failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_disable_firewall_empty_stderr(self):
        """Test disabling firewall with empty stderr on failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.disable_firewall()

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_restart_firewall_empty_stderr_on_first_fail(self):
        """Test restarting firewall with empty stderr on first command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_restart_firewall_empty_stderr_on_second_fail(self):
        """Test restarting firewall with empty stderr on second command failure."""
        mock_result_off = Mock()
        mock_result_off.returncode = 0
        mock_result_off.stdout = "Off"
        mock_result_off.stderr = ""

        mock_result_on = Mock()
        mock_result_on.returncode = 1
        mock_result_on.stdout = ""
        mock_result_on.stderr = ""

        with patch("subprocess.run", side_effect=[mock_result_off, mock_result_on]):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "error" in result
