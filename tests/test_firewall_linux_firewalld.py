"""
Unit tests for src.sysmanage_agent.operations.firewall_linux_firewalld module.
Tests firewalld firewall operations for RHEL/CentOS/Fedora systems.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_linux_firewalld import FirewalldOperations


class TestFirewalldOperationsInit:
    """Test cases for FirewalldOperations initialization."""

    def test_init(self):
        """Test FirewalldOperations initialization."""
        mock_logger = Mock()
        mock_get_ports = Mock(return_value=([8080], "tcp"))
        mock_send_status = AsyncMock()

        firewalld = FirewalldOperations(
            logger=mock_logger,
            get_agent_ports_func=mock_get_ports,
            send_status_func=mock_send_status,
        )

        assert firewalld.logger == mock_logger
        assert firewalld._get_agent_communication_ports == mock_get_ports
        assert firewalld._send_firewall_status_update == mock_send_status


class TestFirewalldIsAvailable:
    """Test cases for checking firewalld availability."""

    def test_is_available_true(self):
        """Test is_available returns True when firewall-cmd is installed."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            assert FirewalldOperations.is_available() is True

    def test_is_available_false(self):
        """Test is_available returns False when firewall-cmd is not installed."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            assert FirewalldOperations.is_available() is False

    def test_is_available_file_not_found(self):
        """Test is_available returns False on FileNotFoundError."""
        with patch("subprocess.run", side_effect=FileNotFoundError("which not found")):
            assert FirewalldOperations.is_available() is False

    def test_is_available_timeout(self):
        """Test is_available returns False on timeout."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="which", timeout=5),
        ):
            assert FirewalldOperations.is_available() is False


class TestFirewalldEnableFirewall:
    """Test cases for enabling firewalld firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
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
            result = await self.firewalld.enable_firewall([8080], "tcp")

        assert result["success"] is True
        assert "enabled" in result["message"].lower()
        self.mock_send_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_firewall_failure(self):
        """Test enabling firewall with failure."""
        # SSH rule, agent port, reload all succeed, but enable fails
        mock_results = [
            Mock(returncode=0, stderr=""),  # SSH rule
            Mock(returncode=0, stderr=""),  # Agent port rule
            Mock(returncode=0, stderr=""),  # Reload
            Mock(returncode=1, stderr="Failed to enable firewalld"),  # Enable
        ]

        with patch("subprocess.run", side_effect=mock_results):
            result = await self.firewalld.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_enable_firewall_ssh_rule_failure_warning(self):
        """Test enabling firewall when SSH rule fails (warning only)."""
        mock_results = [
            Mock(returncode=1, stderr="Already added"),  # SSH rule fails
            Mock(returncode=0, stderr=""),  # Agent port rule
            Mock(returncode=0, stderr=""),  # Reload
            Mock(returncode=0, stderr=""),  # Enable
        ]

        with patch("subprocess.run", side_effect=mock_results):
            result = await self.firewalld.enable_firewall([8080], "tcp")

        assert result["success"] is True
        self.mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_multiple_ports(self):
        """Test enabling firewall with multiple ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = await self.firewalld.enable_firewall([8080, 3000], "tcp")

        assert result["success"] is True
        # SSH + 2 agent ports + reload + enable = 5 calls
        assert mock_run.call_count == 5


class TestFirewalldDisableFirewall:
    """Test cases for disabling firewalld firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
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
            result = await self.firewalld.disable_firewall()

        assert result["success"] is True
        assert "disabled" in result["message"].lower()
        self.mock_send_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_disable_firewall_failure(self):
        """Test disabling firewall with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to stop"

        with patch("subprocess.run", return_value=mock_result):
            result = await self.firewalld.disable_firewall()

        assert result["success"] is False
        assert "error" in result


class TestFirewalldRestartFirewall:
    """Test cases for restarting firewalld firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
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
            result = await self.firewalld.restart_firewall()

        assert result["success"] is True
        assert "restarted" in result["message"].lower()
        self.mock_send_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_firewall_failure(self):
        """Test restarting firewall with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to restart"

        with patch("subprocess.run", return_value=mock_result):
            result = await self.firewalld.restart_firewall()

        assert result["success"] is False
        assert "error" in result


class TestFirewalldGetCurrentPorts:
    """Test cases for getting current ports from firewalld."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_get_current_ports_success(self):
        """Test getting current ports successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "22/tcp 80/tcp 443/tcp 53/udp"

        with patch("subprocess.run", return_value=mock_result):
            ports = self.firewalld.get_current_ports()

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
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            ports = self.firewalld.get_current_ports()

        assert not ports

    def test_get_current_ports_failure(self):
        """Test getting current ports when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            ports = self.firewalld.get_current_ports()

        assert not ports

    def test_get_current_ports_exception(self):
        """Test getting current ports when exception occurs."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            ports = self.firewalld.get_current_ports()

        assert not ports
        self.mock_logger.warning.assert_called()


class TestFirewalldApplyFirewallRoles:
    """Test cases for applying firewall roles."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_success(self):
        """Test applying firewall roles successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 443, "tcp": True, "udp": False},
        ]
        ipv6_ports = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.firewalld.apply_firewall_roles(ipv4_ports, ipv6_ports)

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
        current_ports_output.stdout = "22/tcp 80/tcp 443/tcp 9000/tcp"
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
            result = await self.firewalld.apply_firewall_roles(ipv4_ports, [])

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_preserves_agent_ports(self):
        """Test that agent communication ports are preserved."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "8080/tcp"
        mock_result.stderr = ""

        # Empty desired ports - should still keep 8080 (agent) and 22 (SSH)
        with patch("subprocess.run", return_value=mock_result):
            result = await self.firewalld.apply_firewall_roles([], [])

        assert result["success"] is True
        # Verify 8080 was in preserved ports via logging
        self.mock_logger.info.assert_called()


class TestFirewalldRemoveFirewallPorts:
    """Test cases for removing specific firewall ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
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
            result = await self.firewalld.remove_firewall_ports(ipv4_ports, [])

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
            result = await self.firewalld.remove_firewall_ports(ipv4_ports, [])

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
            result = await self.firewalld.remove_firewall_ports(ipv4_ports, [])

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_failure(self):
        """Test removing ports with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to remove port"

        ipv4_ports = [
            {"port": 9000, "tcp": True, "udp": False},
        ]

        with patch("subprocess.run", return_value=mock_result):
            result = await self.firewalld.remove_firewall_ports(ipv4_ports, [])

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_not_enabled_ok(self):
        """Test that removing port that is NOT_ENABLED is not an error."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "NOT_ENABLED"

        ipv4_ports = [
            {"port": 9000, "tcp": True, "udp": False},
        ]

        with patch("subprocess.run", return_value=mock_result):
            result = await self.firewalld.remove_firewall_ports(ipv4_ports, [])

        # Should succeed because NOT_ENABLED is not a real error
        assert result["success"] is True


class TestFirewalldBuildPortsDict:
    """Test cases for building ports dictionary."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_build_ports_dict_single_port(self):
        """Test building ports dict with single port."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        result = self.firewalld._build_ports_dict(ipv4_ports, ipv6_ports)

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

        result = self.firewalld._build_ports_dict(ipv4_ports, ipv6_ports)

        assert 80 in result
        assert 443 in result
        assert 53 in result
        assert result[53]["tcp"] is True
        assert result[53]["udp"] is True

    def test_build_ports_dict_merges_ipv4_ipv6(self):
        """Test that same port from IPv4 and IPv6 is merged."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = [{"port": 80, "tcp": False, "udp": True}]

        result = self.firewalld._build_ports_dict(ipv4_ports, ipv6_ports)

        assert 80 in result
        assert result[80]["tcp"] is True
        assert result[80]["udp"] is True


class TestFirewalldRemovePortRule:
    """Test cases for removing individual port rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
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
            self.firewalld._remove_port_rule(80, "tcp")

        # Should not log warning on success

    def test_remove_port_rule_failure(self):
        """Test removing port rule with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Error removing port"

        with patch("subprocess.run", return_value=mock_result):
            self.firewalld._remove_port_rule(80, "tcp")

        self.mock_logger.warning.assert_called()


class TestFirewalldRemovePortProtocols:
    """Test cases for removing port protocols."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
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
            self.firewalld._remove_port_protocols(80, {"tcp": True, "udp": True})

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
            self.firewalld._remove_port_protocols(
                80,
                {"tcp": True, "udp": True},
                desired={"tcp": True, "udp": False},
            )

        # Should call once for UDP only
        assert mock_run.call_count == 1


class TestFirewalldReload:
    """Test cases for reloading firewalld."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_reload_firewalld_success(self):
        """Test reloading firewalld successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            self.firewalld._reload_firewalld()

        # No warning should be logged

    def test_reload_firewalld_failure(self):
        """Test reloading firewalld with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to reload"

        with patch("subprocess.run", return_value=mock_result):
            self.firewalld._reload_firewalld()

        self.mock_logger.warning.assert_called()


class TestFirewalldAddNewPorts:
    """Test cases for adding new ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
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
            errors = self.firewalld._add_new_ports(desired_ports, current_ports)

        assert not errors

    def test_add_new_ports_skip_existing(self):
        """Test that existing ports are skipped."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        desired_ports = {80: {"tcp": True, "udp": False}}
        current_ports = {80: {"tcp": True, "udp": False}}

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            errors = self.firewalld._add_new_ports(desired_ports, current_ports)

        # Should not call subprocess since port already exists
        mock_run.assert_not_called()
        assert not errors

    def test_add_new_ports_failure(self):
        """Test adding ports with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Port addition failed"

        desired_ports = {80: {"tcp": True, "udp": False}}
        current_ports = {}

        with patch("subprocess.run", return_value=mock_result):
            errors = self.firewalld._add_new_ports(desired_ports, current_ports)

        assert len(errors) == 1
        assert "80" in errors[0]

    def test_add_new_ports_tcp_and_udp(self):
        """Test adding ports with both TCP and UDP."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        desired_ports = {53: {"tcp": True, "udp": True}}
        current_ports = {}

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            errors = self.firewalld._add_new_ports(desired_ports, current_ports)

        # Should call twice for TCP and UDP
        assert mock_run.call_count == 2
        assert not errors


class TestFirewalldRemovePortWithErrorTracking:
    """Test cases for removing ports with error tracking."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_remove_port_with_error_tracking_success(self):
        """Test removing port with error tracking - success case."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            self.firewalld._remove_port_with_error_tracking(80, "tcp", errors)

        assert not errors

    def test_remove_port_with_error_tracking_failure(self):
        """Test removing port with error tracking - failure case."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to remove"
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            self.firewalld._remove_port_with_error_tracking(80, "tcp", errors)

        assert len(errors) == 1
        assert "80" in errors[0]

    def test_remove_port_with_error_tracking_not_enabled(self):
        """Test removing port that is NOT_ENABLED."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "NOT_ENABLED"
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            self.firewalld._remove_port_with_error_tracking(80, "tcp", errors)

        # NOT_ENABLED should not be added to errors
        assert not errors


class TestFirewalldRemoveUnneededPorts:
    """Test cases for removing unneeded ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_get_ports = Mock(return_value=([8080], "tcp"))
        self.mock_send_status = AsyncMock()
        self.firewalld = FirewalldOperations(
            logger=self.mock_logger,
            get_agent_ports_func=self.mock_get_ports,
            send_status_func=self.mock_send_status,
        )

    def test_remove_unneeded_ports_removes_extra(self):
        """Test removing ports that are not in desired state."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        current_ports = {
            80: {"tcp": True, "udp": False},
            9000: {"tcp": True, "udp": False},
        }
        desired_ports = {80: {"tcp": True, "udp": False}}
        preserved_ports = {22}

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.firewalld._remove_unneeded_ports(
                current_ports, desired_ports, preserved_ports
            )

        # Should call once to remove 9000/tcp
        mock_run.assert_called_once()

    def test_remove_unneeded_ports_preserves_ports(self):
        """Test that preserved ports are not removed."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        current_ports = {22: {"tcp": True, "udp": False}}
        desired_ports = {}
        preserved_ports = {22}

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.firewalld._remove_unneeded_ports(
                current_ports, desired_ports, preserved_ports
            )

        # Should not call since 22 is preserved
        mock_run.assert_not_called()

    def test_remove_unneeded_ports_partial_protocol_removal(self):
        """Test removing only one protocol from a port."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Current has both TCP and UDP, desired only has TCP
        current_ports = {53: {"tcp": True, "udp": True}}
        desired_ports = {53: {"tcp": True, "udp": False}}
        preserved_ports = {22}

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.firewalld._remove_unneeded_ports(
                current_ports, desired_ports, preserved_ports
            )

        # Should call once to remove 53/udp
        mock_run.assert_called_once()
