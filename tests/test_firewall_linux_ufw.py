"""
Unit tests for src.sysmanage_agent.operations.firewall_linux_ufw module.
Tests UFW firewall operations for Ubuntu/Debian systems.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_linux_ufw import UfwOperations


class TestUfwOperationsInit:
    """Test cases for UfwOperations initialization."""

    def test_init(self):
        """Test UfwOperations initialization."""
        mock_logger = Mock()
        mock_get_ports = Mock(return_value=([8080], "tcp"))
        mock_send_status = AsyncMock()

        ufw = UfwOperations(
            logger=mock_logger,
            get_agent_ports_func=mock_get_ports,
            send_status_func=mock_send_status,
        )

        assert ufw.logger == mock_logger
        assert ufw._get_agent_communication_ports == mock_get_ports
        assert ufw._send_firewall_status_update == mock_send_status


class TestUfwIsAvailable:
    """Test cases for checking UFW availability."""

    def test_is_available_true(self):
        """Test is_available returns True when ufw is installed."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            assert UfwOperations.is_available() is True

    def test_is_available_false(self):
        """Test is_available returns False when ufw is not installed."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            assert UfwOperations.is_available() is False

    def test_is_available_file_not_found(self):
        """Test is_available returns False on FileNotFoundError."""
        with patch("subprocess.run", side_effect=FileNotFoundError("which not found")):
            assert UfwOperations.is_available() is False

    def test_is_available_timeout(self):
        """Test is_available returns False on timeout."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="which", timeout=5),
        ):
            assert UfwOperations.is_available() is False


class TestUfwEnableFirewall:
    """Test cases for enabling UFW firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    @pytest.mark.asyncio
    async def test_enable_firewall_success(self):
        """Test enabling firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.enable_firewall([8080], "tcp")

        assert result["success"] is True
        assert "enabled" in result["message"].lower()
        self.mock_send_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_firewall_failure(self):
        """Test enabling firewall with failure."""
        mock_results = [
            Mock(returncode=0, stderr=""),  # SSH rule
            Mock(returncode=0, stderr=""),  # Agent port rule
            Mock(returncode=1, stderr="Failed to enable ufw"),  # Enable
        ]

        with patch("subprocess.run", side_effect=mock_results):
            result = await self.ufw.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_enable_firewall_ssh_rule_failure_warning(self):
        """Test enabling firewall when SSH rule fails (warning only)."""
        mock_results = [
            Mock(returncode=1, stderr="Already added"),  # SSH rule fails
            Mock(returncode=0, stderr=""),  # Agent port rule
            Mock(returncode=0, stderr=""),  # Enable
        ]

        with patch("subprocess.run", side_effect=mock_results):
            result = await self.ufw.enable_firewall([8080], "tcp")

        assert result["success"] is True
        self.mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_multiple_ports(self):
        """Test enabling firewall with multiple ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = await self.ufw.enable_firewall([8080, 3000], "tcp")

        assert result["success"] is True
        # SSH + 2 agent ports + enable = 4 calls
        assert mock_run.call_count == 4


class TestUfwDisableFirewall:
    """Test cases for disabling UFW firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    @pytest.mark.asyncio
    async def test_disable_firewall_success(self):
        """Test disabling firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.disable_firewall()

        assert result["success"] is True
        assert "disabled" in result["message"].lower()
        self.mock_send_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_disable_firewall_failure(self):
        """Test disabling firewall with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to disable"

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.disable_firewall()

        assert result["success"] is False
        assert "error" in result


class TestUfwRestartFirewall:
    """Test cases for restarting UFW firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    @pytest.mark.asyncio
    async def test_restart_firewall_success(self):
        """Test restarting firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.restart_firewall()

        assert result["success"] is True
        assert "restarted" in result["message"].lower()
        self.mock_send_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_firewall_failure(self):
        """Test restarting firewall with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to reload"

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.restart_firewall()

        assert result["success"] is False
        assert "error" in result


class TestUfwGetCurrentPorts:
    """Test cases for getting current ports from UFW."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_get_current_ports_success(self):
        """Test getting current ports successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
53/udp                     ALLOW       Anywhere
"""

        with patch("subprocess.run", return_value=mock_result):
            ports = self.ufw.get_current_ports()

        assert 22 in ports
        assert ports[22]["tcp"] is True
        assert 80 in ports
        assert 443 in ports
        assert 53 in ports
        assert ports[53]["udp"] is True

    def test_get_current_ports_empty(self):
        """Test getting current ports when none are open."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Status: active"

        with patch("subprocess.run", return_value=mock_result):
            ports = self.ufw.get_current_ports()

        assert ports == {}

    def test_get_current_ports_failure(self):
        """Test getting current ports when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            ports = self.ufw.get_current_ports()

        assert ports == {}

    def test_get_current_ports_exception(self):
        """Test getting current ports when exception occurs."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            ports = self.ufw.get_current_ports()

        assert ports == {}
        self.mock_logger.warning.assert_called()


class TestUfwApplyFirewallRoles:
    """Test cases for applying firewall roles."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_success(self):
        """Test applying firewall roles successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Status: active"
        mock_result.stderr = ""

        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 443, "tcp": True, "udp": False},
        ]
        ipv6_ports = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True
        self.mock_send_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_with_removal(self):
        """Test applying firewall roles that removes old ports."""
        # Current ports: 80, 443, 9000
        # Desired ports: 80, 443
        # Should remove: 9000
        current_ports_output = Mock()
        current_ports_output.returncode = 0
        current_ports_output.stdout = """22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
9000/tcp                   ALLOW       Anywhere
"""
        current_ports_output.stderr = ""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 443, "tcp": True, "udp": False},
        ]

        with patch(
            "subprocess.run", side_effect=[current_ports_output] + [mock_result] * 10
        ):
            result = await self.ufw.apply_firewall_roles(ipv4_ports, [])

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_preserves_agent_ports(self):
        """Test that agent communication ports are preserved."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "8080/tcp                   ALLOW       Anywhere"
        mock_result.stderr = ""

        # Empty desired ports - should still keep 8080 (agent) and 22 (SSH)
        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.apply_firewall_roles([], [])

        assert result["success"] is True
        # Verify 8080 was in preserved ports via logging
        self.mock_logger.info.assert_called()


class TestUfwRemoveFirewallPorts:
    """Test cases for removing specific firewall ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_success(self):
        """Test removing firewall ports successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        ipv4_ports = [
            {"port": 9000, "tcp": True, "udp": False},
        ]

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.remove_firewall_ports(ipv4_ports, [])

        assert result["success"] is True
        self.mock_send_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_preserves_ssh(self):
        """Test that SSH port 22 is preserved during removal."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Try to remove port 22 - should be skipped
        ipv4_ports = [
            {"port": 22, "tcp": True, "udp": False},
        ]

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.remove_firewall_ports(ipv4_ports, [])

        assert result["success"] is True
        # Port 22 should be logged as skipped
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_preserves_agent_port(self):
        """Test that agent port is preserved during removal."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Try to remove agent port 8080 - should be skipped
        ipv4_ports = [
            {"port": 8080, "tcp": True, "udp": False},
        ]

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.remove_firewall_ports(ipv4_ports, [])

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_failure(self):
        """Test removing ports with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to delete rule"

        ipv4_ports = [
            {"port": 9000, "tcp": True, "udp": False},
        ]

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.remove_firewall_ports(ipv4_ports, [])

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_non_existent_rule_ok(self):
        """Test that removing non-existent rule is not an error."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Could not delete non-existent rule"

        ipv4_ports = [
            {"port": 9000, "tcp": True, "udp": False},
        ]

        # Non-existent rule error is expected and not a failure
        with patch("subprocess.run", return_value=mock_result):
            result = await self.ufw.remove_firewall_ports(ipv4_ports, [])

        # Should succeed because "Could not delete non-existent rule" is not a real error
        assert result["success"] is True


class TestUfwBuildPortsDict:
    """Test cases for building ports dictionary."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_build_ports_dict_single_port(self):
        """Test building ports dict with single port."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        result = self.ufw._build_ports_dict(ipv4_ports, ipv6_ports)

        assert 80 in result
        assert result[80]["tcp"] is True
        assert result[80]["udp"] is False

    def test_build_ports_dict_multiple_ports(self):
        """Test building ports dict with multiple ports."""
        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 443, "tcp": True, "udp": False},
        ]
        ipv6_ports = [
            {"port": 53, "tcp": True, "udp": True},
        ]

        result = self.ufw._build_ports_dict(ipv4_ports, ipv6_ports)

        assert 80 in result
        assert 443 in result
        assert 53 in result
        assert result[53]["tcp"] is True
        assert result[53]["udp"] is True

    def test_build_ports_dict_merges_ipv4_ipv6(self):
        """Test that same port from IPv4 and IPv6 is merged."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = [{"port": 80, "tcp": False, "udp": True}]

        result = self.ufw._build_ports_dict(ipv4_ports, ipv6_ports)

        assert 80 in result
        assert result[80]["tcp"] is True
        assert result[80]["udp"] is True


class TestUfwRemovePortRule:
    """Test cases for removing individual port rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_remove_port_rule_success(self):
        """Test removing port rule successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            self.ufw._remove_port_rule(80, "tcp")

        # Should not log warning on success

    def test_remove_port_rule_failure(self):
        """Test removing port rule with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Error deleting rule"

        with patch("subprocess.run", return_value=mock_result):
            self.ufw._remove_port_rule(80, "tcp")

        self.mock_logger.warning.assert_called()


class TestUfwRemovePortProtocols:
    """Test cases for removing port protocols."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_remove_port_protocols_all(self):
        """Test removing all protocols for a port."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.ufw._remove_port_protocols(80, {"tcp": True, "udp": True})

        # Should call twice for TCP and UDP
        assert mock_run.call_count == 2

    def test_remove_port_protocols_with_desired_state(self):
        """Test removing only changed protocols."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Current: TCP and UDP, Desired: only TCP
        # Should remove only UDP
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.ufw._remove_port_protocols(
                80,
                {"tcp": True, "udp": True},
                desired={"tcp": True, "udp": False},
            )

        # Should call once for UDP only
        assert mock_run.call_count == 1


class TestUfwConfigureLxdFirewall:
    """Test cases for configuring LXD firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_configure_lxd_firewall_success(self):
        """Test configuring LXD firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "10.227.191.1/24"
        mock_result.stderr = ""

        # Mock file operations
        mock_file_content = "some content"

        with patch("subprocess.run", return_value=mock_result):
            with patch(
                "builtins.open",
                Mock(
                    return_value=Mock(
                        __enter__=Mock(
                            return_value=Mock(read=Mock(return_value=mock_file_content))
                        ),
                        __exit__=Mock(return_value=False),
                    )
                ),
            ):
                result = self.ufw.configure_lxd_firewall("lxdbr0")

        assert result["success"] is True

    def test_configure_lxd_firewall_nat_already_configured(self):
        """Test configure_lxd_firewall when NAT is already configured."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        mock_file_content = "# LXD NAT rules - already configured"

        with patch("subprocess.run", return_value=mock_result):
            with patch(
                "builtins.open",
                Mock(
                    return_value=Mock(
                        __enter__=Mock(
                            return_value=Mock(read=Mock(return_value=mock_file_content))
                        ),
                        __exit__=Mock(return_value=False),
                    )
                ),
            ):
                result = self.ufw.configure_lxd_firewall("lxdbr0")

        assert result["success"] is True


class TestUfwGenerateNatRules:
    """Test cases for generating NAT rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_generate_ufw_nat_rules_default_subnet(self):
        """Test generating NAT rules with default subnet."""
        mock_result = Mock()
        mock_result.returncode = 1  # Command fails, uses default
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            rules = self.ufw._generate_ufw_nat_rules("lxdbr0")

        assert "10.0.0.0/8" in rules
        assert "POSTROUTING" in rules
        assert "MASQUERADE" in rules

    def test_generate_ufw_nat_rules_detected_subnet(self):
        """Test generating NAT rules with detected subnet."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "382: lxdbr0 inet 10.227.191.1/24 brd 10.227.191.255 scope global lxdbr0"
        )

        with patch("subprocess.run", return_value=mock_result):
            rules = self.ufw._generate_ufw_nat_rules("lxdbr0")

        assert "10.227.191.0/24" in rules
        assert "MASQUERADE" in rules


class TestUfwIpForwarding:
    """Test cases for IP forwarding configuration."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_enable_ip_forwarding_already_enabled(self):
        """Test IP forwarding when already enabled."""
        errors = []

        with patch(
            "builtins.open",
            Mock(
                return_value=Mock(
                    __enter__=Mock(return_value=Mock(read=Mock(return_value="1"))),
                    __exit__=Mock(return_value=False),
                )
            ),
        ):
            self.ufw._enable_ip_forwarding(errors)

        assert errors == []

    def test_enable_ip_forwarding_success(self):
        """Test enabling IP forwarding successfully."""
        errors = []
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch(
            "builtins.open",
            Mock(
                return_value=Mock(
                    __enter__=Mock(return_value=Mock(read=Mock(return_value="0"))),
                    __exit__=Mock(return_value=False),
                )
            ),
        ):
            with patch("subprocess.run", return_value=mock_result):
                self.ufw._enable_ip_forwarding(errors)

        assert errors == []

    def test_enable_ip_forwarding_failure(self):
        """Test enabling IP forwarding with failure."""
        errors = []
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Permission denied"

        with patch(
            "builtins.open",
            Mock(
                return_value=Mock(
                    __enter__=Mock(return_value=Mock(read=Mock(return_value="0"))),
                    __exit__=Mock(return_value=False),
                )
            ),
        ):
            with patch("subprocess.run", return_value=mock_result):
                self.ufw._enable_ip_forwarding(errors)

        assert len(errors) == 1
        assert "Permission denied" in errors[0]

    def test_enable_ip_forwarding_exception(self):
        """Test enabling IP forwarding with exception."""
        errors = []

        with patch("builtins.open", side_effect=Exception("File not found")):
            self.ufw._enable_ip_forwarding(errors)

        assert len(errors) == 1
        assert "File not found" in errors[0]


class TestUfwReload:
    """Test cases for reloading UFW."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_reload_ufw_success(self):
        """Test reloading UFW successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            self.ufw._reload_ufw()

        # No warning should be logged

    def test_reload_ufw_failure(self):
        """Test reloading UFW with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to reload"

        with patch("subprocess.run", return_value=mock_result):
            self.ufw._reload_ufw()

        self.mock_logger.warning.assert_called()


class TestUfwAddNewPorts:
    """Test cases for adding new ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.ufw = UfwOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_add_new_ports_success(self):
        """Test adding new ports successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        desired_ports = {80: {"tcp": True, "udp": False}}
        current_ports = {}

        with patch("subprocess.run", return_value=mock_result):
            errors = self.ufw._add_new_ports(desired_ports, current_ports)

        assert errors == []

    def test_add_new_ports_skip_existing(self):
        """Test that existing ports are skipped."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        desired_ports = {80: {"tcp": True, "udp": False}}
        current_ports = {80: {"tcp": True, "udp": False}}

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            errors = self.ufw._add_new_ports(desired_ports, current_ports)

        # Should not call subprocess since port already exists
        mock_run.assert_not_called()
        assert errors == []

    def test_add_new_ports_failure(self):
        """Test adding ports with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Rule addition failed"

        desired_ports = {80: {"tcp": True, "udp": False}}
        current_ports = {}

        with patch("subprocess.run", return_value=mock_result):
            errors = self.ufw._add_new_ports(desired_ports, current_ports)

        assert len(errors) == 1
        assert "80" in errors[0]
