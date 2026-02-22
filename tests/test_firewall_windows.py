"""
Unit tests for src.sysmanage_agent.operations.firewall_windows module.
Tests Windows firewall operations using netsh advfirewall.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_windows import WindowsFirewallOperations


class TestWindowsFirewallOperationsInit:
    """Test cases for WindowsFirewallOperations initialization."""

    def test_init_with_logger(self):
        """Test WindowsFirewallOperations initialization with custom logger."""
        mock_agent = Mock()
        mock_logger = Mock()
        ops = WindowsFirewallOperations(mock_agent, logger=mock_logger)

        assert ops.agent == mock_agent
        assert ops.logger == mock_logger

    def test_init_without_logger(self):
        """Test WindowsFirewallOperations initialization without logger."""
        mock_agent = Mock()
        ops = WindowsFirewallOperations(mock_agent)

        assert ops.agent == mock_agent
        assert ops.logger is not None


class TestEnableFirewall:
    """Test cases for enabling Windows Firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_firewall_success(self):
        """Test enabling Windows Firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is True
        assert "enabled successfully" in result["message"]
        # Should be called for RDP rule, port rule, and enable command
        assert mock_run.call_count == 3

    @pytest.mark.asyncio
    async def test_enable_firewall_multiple_ports(self):
        """Test enabling Windows Firewall with multiple ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.enable_firewall([8080, 443, 80], "tcp")

        assert result["success"] is True
        # RDP + 3 ports + enable = 5 calls
        assert mock_run.call_count == 5

    @pytest.mark.asyncio
    async def test_enable_firewall_udp_protocol(self):
        """Test enabling Windows Firewall with UDP protocol."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.enable_firewall([53], "udp")

        assert result["success"] is True
        # Verify UDP protocol was used in the command
        port_rule_call = mock_run.call_args_list[1]
        assert "protocol=UDP" in port_rule_call[0][0]

    @pytest.mark.asyncio
    async def test_enable_firewall_rdp_rule_failure(self):
        """Test enabling Windows Firewall when RDP rule fails (should continue)."""
        call_count = 0

        def side_effect(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            mock = Mock()
            if call_count == 1:  # RDP rule fails
                mock.returncode = 1
                mock.stderr = "RDP rule error"
            else:
                mock.returncode = 0
                mock.stderr = ""
            return mock

        with patch("subprocess.run", side_effect=side_effect):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        # Should still succeed even if RDP rule fails
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_firewall_port_rule_failure(self):
        """Test enabling Windows Firewall when port rule fails (should continue)."""
        call_count = 0

        def side_effect(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            mock = Mock()
            if call_count == 2:  # Port rule fails
                mock.returncode = 1
                mock.stderr = "Port rule error"
            else:
                mock.returncode = 0
                mock.stderr = ""
            return mock

        with patch("subprocess.run", side_effect=side_effect):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        # Should still succeed if final enable command succeeds
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_firewall_enable_command_failure(self):
        """Test enabling Windows Firewall when final enable command fails."""
        call_count = 0

        def side_effect(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            mock = Mock()
            if call_count == 3:  # Enable command fails
                mock.returncode = 1
                mock.stderr = "Enable command failed"
            else:
                mock.returncode = 0
                mock.stderr = ""
            return mock

        with patch("subprocess.run", side_effect=side_effect):
            result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "Enable command failed" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_firewall_exception(self):
        """Test enabling Windows Firewall with exception."""
        with patch("subprocess.run", side_effect=Exception("Subprocess error")):
            result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "Subprocess error" in result["error"]


class TestDisableFirewall:
    """Test cases for disabling Windows Firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_disable_firewall_success(self):
        """Test disabling Windows Firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.disable_firewall()

        assert result["success"] is True
        assert "disabled successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_disable_firewall_failure(self):
        """Test disabling Windows Firewall with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Disable failed"

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ops.disable_firewall()

        assert result["success"] is False
        assert "Disable failed" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_firewall_exception(self):
        """Test disabling Windows Firewall with exception."""
        with patch("subprocess.run", side_effect=Exception("Subprocess error")):
            result = await self.ops.disable_firewall()

        assert result["success"] is False
        assert "Subprocess error" in result["error"]


class TestRestartFirewall:
    """Test cases for restarting Windows Firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_restart_firewall_success(self):
        """Test restarting Windows Firewall successfully (toggle off then on)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                result = await self.ops.restart_firewall()

        assert result["success"] is True
        assert "restarted successfully" in result["message"]
        # Should call subprocess twice: off then on
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_restart_firewall_disable_failure(self):
        """Test restarting Windows Firewall when disable step fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Disable failed"

        with patch("subprocess.run", return_value=mock_result):
            result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "Disable failed" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_firewall_enable_failure(self):
        """Test restarting Windows Firewall when enable step fails."""
        call_count = 0

        def side_effect(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            mock = Mock()
            if call_count == 1:  # Disable succeeds
                mock.returncode = 0
                mock.stderr = ""
            else:  # Enable fails
                mock.returncode = 1
                mock.stderr = "Enable failed"
            return mock

        with patch("subprocess.run", side_effect=side_effect):
            result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "Enable failed" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_firewall_exception(self):
        """Test restarting Windows Firewall with exception."""
        with patch("subprocess.run", side_effect=Exception("Subprocess error")):
            result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "Subprocess error" in result["error"]


class TestDeployFirewall:
    """Test cases for deploying Windows Firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_deploy_firewall_success(self):
        """Test deploying Windows Firewall successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
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

    @pytest.mark.asyncio
    async def test_deploy_firewall_with_server_ports(self):
        """Test deploying Windows Firewall with local server ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
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
        # Should include both agent and server ports
        # RDP + port 8080 + port 3000 + enable = 4 calls
        assert mock_run.call_count == 4

    @pytest.mark.asyncio
    async def test_deploy_firewall_exception(self):
        """Test deploying Windows Firewall with exception."""
        with patch.object(
            self.ops,
            "_get_agent_communication_ports",
            side_effect=Exception("Config error"),
        ):
            result = await self.ops.deploy_firewall()

        assert result["success"] is False
        assert "Config error" in result["error"]


class TestGetWindowsSysmanageRoleRules:
    """Test cases for getting SysManage Role firewall rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_get_windows_sysmanage_role_rules_success(self):
        """Test getting Windows SysManage Role rules successfully."""
        mock_output = """
Rule Name:                            SysManage Role Port 80/TCP
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            80
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            SysManage Role Port 443/TCP
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Protocol:                             TCP
LocalPort:                            443
Action:                               Allow

Rule Name:                            Other Rule
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Protocol:                             TCP
LocalPort:                            22
Action:                               Allow
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_output

        with patch("subprocess.run", return_value=mock_result):
            result = self.ops._get_windows_sysmanage_role_rules()

        assert 80 in result
        assert result[80]["tcp"] is True
        assert 443 in result
        assert result[443]["tcp"] is True
        # Port 22 should not be included (not a SysManage Role rule)
        assert 22 not in result

    def test_get_windows_sysmanage_role_rules_with_udp(self):
        """Test getting Windows SysManage Role rules with UDP."""
        mock_output = """
Rule Name:                            SysManage Role Port 53/UDP
----------------------------------------------------------------------
Protocol:                             UDP
LocalPort:                            53
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_output

        with patch("subprocess.run", return_value=mock_result):
            result = self.ops._get_windows_sysmanage_role_rules()

        assert 53 in result
        assert result[53]["udp"] is True
        assert result[53]["tcp"] is False

    def test_get_windows_sysmanage_role_rules_command_failure(self):
        """Test getting rules when netsh command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = self.ops._get_windows_sysmanage_role_rules()

        assert not result

    def test_get_windows_sysmanage_role_rules_exception(self):
        """Test getting rules with exception."""
        with patch("subprocess.run", side_effect=Exception("Subprocess error")):
            result = self.ops._get_windows_sysmanage_role_rules()

        assert not result


class TestParseWindowsFirewallRules:
    """Test cases for parsing netsh output."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_parse_windows_firewall_rules_empty(self):
        """Test parsing empty output."""
        result = self.ops._parse_windows_firewall_rules("")
        assert not result

    def test_parse_windows_firewall_rules_no_sysmanage_rules(self):
        """Test parsing output with no SysManage Role rules."""
        output = """
Rule Name:                            Remote Desktop (RDP)
Protocol:                             TCP
LocalPort:                            3389
"""
        result = self.ops._parse_windows_firewall_rules(output)
        assert not result

    def test_parse_windows_firewall_rules_mixed_rules(self):
        """Test parsing output with mixed rules."""
        output = """
Rule Name:                            SysManage Role Port 8080/TCP
Protocol:                             TCP
LocalPort:                            8080

Rule Name:                            Some Other Rule
Protocol:                             TCP
LocalPort:                            22

Rule Name:                            SysManage Role Port 443/TCP
Protocol:                             TCP
LocalPort:                            443
"""
        result = self.ops._parse_windows_firewall_rules(output)
        assert 8080 in result
        assert 443 in result
        assert 22 not in result

    def test_parse_windows_firewall_rules_both_protocols(self):
        """Test parsing rules with both TCP and UDP for same port."""
        output = """
Rule Name:                            SysManage Role Port 53/TCP
Protocol:                             TCP
LocalPort:                            53

Rule Name:                            SysManage Role Port 53/UDP
Protocol:                             UDP
LocalPort:                            53
"""
        result = self.ops._parse_windows_firewall_rules(output)
        assert 53 in result
        assert result[53]["tcp"] is True
        assert result[53]["udp"] is True


class TestProcessLocalportLine:
    """Test cases for processing LocalPort lines."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_process_localport_line_valid(self):
        """Test processing valid LocalPort line."""
        current_ports = {}
        self.ops._process_localport_line(
            "LocalPort:                            80",
            "SysManage Role Port 80/TCP",
            "tcp",
            current_ports,
        )
        assert 80 in current_ports
        assert current_ports[80]["tcp"] is True

    def test_process_localport_line_no_rule_name(self):
        """Test processing line with no rule name."""
        current_ports = {}
        self.ops._process_localport_line(
            "LocalPort:                            80", None, "tcp", current_ports
        )
        assert not current_ports

    def test_process_localport_line_non_sysmanage_rule(self):
        """Test processing line for non-SysManage rule."""
        current_ports = {}
        self.ops._process_localport_line(
            "LocalPort:                            80",
            "Remote Desktop",
            "tcp",
            current_ports,
        )
        assert not current_ports

    def test_process_localport_line_no_port_number(self):
        """Test processing line without port number."""
        current_ports = {}
        self.ops._process_localport_line(
            "LocalPort:                            Any",
            "SysManage Role Port Any",
            "tcp",
            current_ports,
        )
        assert not current_ports

    def test_process_localport_line_udp(self):
        """Test processing UDP LocalPort line."""
        current_ports = {}
        self.ops._process_localport_line(
            "LocalPort:                            53",
            "SysManage Role Port 53/UDP",
            "udp",
            current_ports,
        )
        assert 53 in current_ports
        assert current_ports[53]["udp"] is True
        assert current_ports[53]["tcp"] is False

    def test_process_localport_line_existing_port(self):
        """Test processing line for existing port (add UDP to existing TCP)."""
        current_ports = {80: {"tcp": True, "udp": False}}
        self.ops._process_localport_line(
            "LocalPort:                            80",
            "SysManage Role Port 80/UDP",
            "udp",
            current_ports,
        )
        assert current_ports[80]["tcp"] is True
        assert current_ports[80]["udp"] is True


class TestRemovePortRule:
    """Test cases for removing port rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_remove_port_rule_success(self):
        """Test removing port rule successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.ops._remove_port_rule(80, "tcp")

        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "delete" in call_args
        assert "name=SysManage Role Port 80/TCP" in call_args

    def test_remove_port_rule_failure(self):
        """Test removing port rule with failure (logs warning)."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Rule not found"

        with patch("subprocess.run", return_value=mock_result):
            # Should not raise, just log warning
            self.ops._remove_port_rule(80, "tcp")

    def test_remove_port_rule_udp(self):
        """Test removing UDP port rule."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.ops._remove_port_rule(53, "udp")

        call_args = mock_run.call_args[0][0]
        assert "name=SysManage Role Port 53/UDP" in call_args


class TestRemovePortProtocols:
    """Test cases for removing port protocols."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_remove_port_protocols_all(self):
        """Test removing all protocols for a port (no desired state)."""
        with patch.object(self.ops, "_remove_port_rule") as mock_remove:
            self.ops._remove_port_protocols(80, {"tcp": True, "udp": True})

        assert mock_remove.call_count == 2
        mock_remove.assert_any_call(80, "tcp")
        mock_remove.assert_any_call(80, "udp")

    def test_remove_port_protocols_tcp_only(self):
        """Test removing only TCP protocol."""
        with patch.object(self.ops, "_remove_port_rule") as mock_remove:
            self.ops._remove_port_protocols(80, {"tcp": True, "udp": False})

        mock_remove.assert_called_once_with(80, "tcp")

    def test_remove_port_protocols_with_desired_state(self):
        """Test removing protocols based on desired state."""
        with patch.object(self.ops, "_remove_port_rule") as mock_remove:
            self.ops._remove_port_protocols(
                80, {"tcp": True, "udp": True}, {"tcp": True, "udp": False}
            )

        # Should only remove UDP since TCP is desired
        mock_remove.assert_called_once_with(80, "udp")

    def test_remove_port_protocols_keep_all(self):
        """Test keeping all protocols when all are desired."""
        with patch.object(self.ops, "_remove_port_rule") as mock_remove:
            self.ops._remove_port_protocols(
                80, {"tcp": True, "udp": True}, {"tcp": True, "udp": True}
            )

        mock_remove.assert_not_called()

    def test_remove_port_protocols_remove_tcp_keep_udp(self):
        """Test removing TCP but keeping UDP based on desired state."""
        with patch.object(self.ops, "_remove_port_rule") as mock_remove:
            self.ops._remove_port_protocols(
                80, {"tcp": True, "udp": True}, {"tcp": False, "udp": True}
            )

        # Should only remove TCP since UDP is desired
        mock_remove.assert_called_once_with(80, "tcp")


class TestRemoveUnneededPorts:
    """Test cases for removing unneeded ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_remove_unneeded_ports_all_removed(self):
        """Test removing all ports that are not desired."""
        current = {80: {"tcp": True, "udp": False}, 443: {"tcp": True, "udp": False}}
        desired = {}
        preserved = set()

        with patch.object(self.ops, "_remove_port_protocols") as mock_remove:
            self.ops._remove_unneeded_ports(current, desired, preserved)

        assert mock_remove.call_count == 2

    def test_remove_unneeded_ports_preserved(self):
        """Test that preserved ports are not removed."""
        current = {80: {"tcp": True, "udp": False}, 3389: {"tcp": True, "udp": False}}
        desired = {}
        preserved = {3389}

        with patch.object(self.ops, "_remove_port_protocols") as mock_remove:
            self.ops._remove_unneeded_ports(current, desired, preserved)

        # Only port 80 should be removed
        mock_remove.assert_called_once()
        assert mock_remove.call_args[0][0] == 80

    def test_remove_unneeded_ports_partial_removal(self):
        """Test removing only some protocols from a port."""
        current = {80: {"tcp": True, "udp": True}}
        desired = {80: {"tcp": True, "udp": False}}
        preserved = set()

        with patch.object(self.ops, "_remove_port_protocols") as mock_remove:
            self.ops._remove_unneeded_ports(current, desired, preserved)

        mock_remove.assert_called_once_with(
            80, {"tcp": True, "udp": True}, {"tcp": True, "udp": False}
        )


class TestAddPortRule:
    """Test cases for adding port rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_add_port_rule_success(self):
        """Test adding port rule successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        errors = []
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.ops._add_port_rule(80, "tcp", errors)

        assert len(errors) == 0
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "add" in call_args
        assert "name=SysManage Role Port 80/TCP" in call_args
        assert "protocol=TCP" in call_args
        assert "localport=80" in call_args

    def test_add_port_rule_failure(self):
        """Test adding port rule with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Rule already exists"

        errors = []
        with patch("subprocess.run", return_value=mock_result):
            self.ops._add_port_rule(80, "tcp", errors)

        assert len(errors) == 1
        assert "Failed to add TCP port 80" in errors[0]

    def test_add_port_rule_udp(self):
        """Test adding UDP port rule."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        errors = []
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.ops._add_port_rule(53, "udp", errors)

        call_args = mock_run.call_args[0][0]
        assert "protocol=UDP" in call_args


class TestAddNewPorts:
    """Test cases for adding new ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_add_new_ports_success(self):
        """Test adding new ports successfully."""
        desired = {80: {"tcp": True, "udp": False}}
        current = {}
        agent_ports = [8080]

        with patch.object(self.ops, "_add_port_rule") as mock_add:
            errors = self.ops._add_new_ports(desired, current, agent_ports)

        assert len(errors) == 0
        mock_add.assert_called_once_with(80, "tcp", [])

    def test_add_new_ports_skip_agent_ports(self):
        """Test that agent ports are skipped."""
        desired = {8080: {"tcp": True, "udp": False}}
        current = {}
        agent_ports = [8080]

        with patch.object(self.ops, "_add_port_rule") as mock_add:
            _errors = self.ops._add_new_ports(desired, current, agent_ports)

        mock_add.assert_not_called()

    def test_add_new_ports_skip_existing(self):
        """Test that existing ports are skipped."""
        desired = {80: {"tcp": True, "udp": False}}
        current = {80: {"tcp": True, "udp": False}}
        agent_ports = []

        with patch.object(self.ops, "_add_port_rule") as mock_add:
            _errors = self.ops._add_new_ports(desired, current, agent_ports)

        mock_add.assert_not_called()

    def test_add_new_ports_add_missing_protocol(self):
        """Test adding missing protocol to existing port."""
        desired = {80: {"tcp": True, "udp": True}}
        current = {80: {"tcp": True, "udp": False}}
        agent_ports = []

        with patch.object(self.ops, "_add_port_rule") as mock_add:
            _errors = self.ops._add_new_ports(desired, current, agent_ports)

        # Should only add UDP since TCP already exists
        mock_add.assert_called_once_with(80, "udp", [])


class TestBuildPortsDict:
    """Test cases for building ports dictionary."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_build_ports_dict_empty(self):
        """Test building empty ports dict."""
        result = self.ops._build_ports_dict([], [])
        assert not result

    def test_build_ports_dict_ipv4_only(self):
        """Test building ports dict with IPv4 only."""
        ipv4 = [{"port": 80, "tcp": True, "udp": False}]
        result = self.ops._build_ports_dict(ipv4, [])
        assert 80 in result
        assert result[80]["tcp"] is True
        assert result[80]["udp"] is False

    def test_build_ports_dict_ipv6_only(self):
        """Test building ports dict with IPv6 only."""
        ipv6 = [{"port": 443, "tcp": True, "udp": False}]
        result = self.ops._build_ports_dict([], ipv6)
        assert 443 in result
        assert result[443]["tcp"] is True

    def test_build_ports_dict_merged(self):
        """Test building ports dict merging IPv4 and IPv6."""
        ipv4 = [{"port": 80, "tcp": True, "udp": False}]
        ipv6 = [{"port": 80, "tcp": False, "udp": True}]
        result = self.ops._build_ports_dict(ipv4, ipv6)
        assert 80 in result
        assert result[80]["tcp"] is True
        assert result[80]["udp"] is True

    def test_build_ports_dict_multiple_ports(self):
        """Test building ports dict with multiple ports."""
        ipv4 = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 443, "tcp": True, "udp": False},
        ]
        result = self.ops._build_ports_dict(ipv4, [])
        assert 80 in result
        assert 443 in result


class TestApplyFirewallRoles:
    """Test cases for applying firewall roles."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_success(self):
        """Test applying firewall roles successfully."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_get_windows_sysmanage_role_rules", return_value={}
            ):
                with patch.object(self.ops, "_remove_unneeded_ports"):
                    with patch.object(self.ops, "_add_new_ports", return_value=[]):
                        with patch.object(
                            self.ops,
                            "_send_firewall_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await self.ops.apply_firewall_roles(
                                ipv4_ports, ipv6_ports
                            )

        assert result["success"] is True
        assert "synchronized successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_with_errors(self):
        """Test applying firewall roles with some errors."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_get_windows_sysmanage_role_rules", return_value={}
            ):
                with patch.object(self.ops, "_remove_unneeded_ports"):
                    with patch.object(
                        self.ops,
                        "_add_new_ports",
                        return_value=["Failed to add TCP port 80: error"],
                    ):
                        with patch.object(
                            self.ops,
                            "_send_firewall_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await self.ops.apply_firewall_roles(
                                ipv4_ports, ipv6_ports
                            )

        assert result["success"] is False
        assert "Failed to add TCP port 80" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_empty(self):
        """Test applying empty firewall roles."""
        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_get_windows_sysmanage_role_rules", return_value={}
            ):
                with patch.object(self.ops, "_remove_unneeded_ports") as mock_remove:
                    with patch.object(
                        self.ops, "_add_new_ports", return_value=[]
                    ) as mock_add:
                        with patch.object(
                            self.ops,
                            "_send_firewall_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await self.ops.apply_firewall_roles([], [])

        assert result["success"] is True
        mock_remove.assert_called_once()
        mock_add.assert_called_once()


class TestRemovePortWithErrorTracking:
    """Test cases for removing port with error tracking."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = WindowsFirewallOperations(self.mock_agent)

    def test_remove_port_with_error_tracking_success(self):
        """Test removing port successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        errors = []
        with patch("subprocess.run", return_value=mock_result):
            self.ops._remove_port_with_error_tracking(80, "tcp", errors)

        assert len(errors) == 0

    def test_remove_port_with_error_tracking_failure(self):
        """Test removing port with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Access denied"

        errors = []
        with patch("subprocess.run", return_value=mock_result):
            self.ops._remove_port_with_error_tracking(80, "tcp", errors)

        assert len(errors) == 1
        assert "Failed to remove TCP port 80" in errors[0]

    def test_remove_port_with_error_tracking_no_match(self):
        """Test removing port when no rules match (not an error)."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "No rules match the specified criteria"

        errors = []
        with patch("subprocess.run", return_value=mock_result):
            self.ops._remove_port_with_error_tracking(80, "tcp", errors)

        # "No rules match" should not be considered an error
        assert len(errors) == 0


class TestRemoveFirewallPorts:
    """Test cases for removing firewall ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_success(self):
        """Test removing firewall ports successfully."""
        ipv4_ports = [{"port": 9000, "tcp": True, "udp": False}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_remove_port_with_error_tracking"
            ) as mock_remove:
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops.remove_firewall_ports(
                        ipv4_ports, ipv6_ports
                    )

        assert result["success"] is True
        assert "removed successfully" in result["message"]
        mock_remove.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_preserved(self):
        """Test that preserved ports (agent/RDP) are not removed."""
        ipv4_ports = [
            {"port": 8080, "tcp": True, "udp": False},  # Agent port
            {"port": 3389, "tcp": True, "udp": False},  # RDP port
            {"port": 9000, "tcp": True, "udp": False},  # Regular port
        ]
        ipv6_ports = []

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_remove_port_with_error_tracking"
            ) as mock_remove:
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops.remove_firewall_ports(
                        ipv4_ports, ipv6_ports
                    )

        assert result["success"] is True
        # Should only remove port 9000, not 8080 or 3389
        mock_remove.assert_called_once()
        call_args = mock_remove.call_args[0]
        assert call_args[0] == 9000

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_with_errors(self):
        """Test removing firewall ports with some errors."""
        ipv4_ports = [{"port": 9000, "tcp": True, "udp": False}]
        ipv6_ports = []

        def add_error(port, protocol, errors):
            errors.append(f"Failed to remove {protocol.upper()} port {port}")

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_remove_port_with_error_tracking", side_effect=add_error
            ):
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops.remove_firewall_ports(
                        ipv4_ports, ipv6_ports
                    )

        assert result["success"] is False
        assert "Failed to remove" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_empty(self):
        """Test removing empty port list."""
        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_remove_port_with_error_tracking"
            ) as mock_remove:
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops.remove_firewall_ports([], [])

        assert result["success"] is True
        mock_remove.assert_not_called()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_both_protocols(self):
        """Test removing ports with both TCP and UDP."""
        ipv4_ports = [{"port": 53, "tcp": True, "udp": True}]
        ipv6_ports = []

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_remove_port_with_error_tracking"
            ) as mock_remove:
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops.remove_firewall_ports(
                        ipv4_ports, ipv6_ports
                    )

        assert result["success"] is True
        assert mock_remove.call_count == 2
        mock_remove.assert_any_call(53, "tcp", [])
        mock_remove.assert_any_call(53, "udp", [])


class TestNetshCommandParameters:
    """Test cases verifying netsh command parameters are correct."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_firewall_command_format(self):
        """Test that enable firewall uses correct netsh command format."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                await self.ops.enable_firewall([8080], "tcp")

        # Check the final enable command
        enable_call = mock_run.call_args_list[-1]
        cmd = enable_call[0][0]
        assert cmd[0] == "netsh"
        assert cmd[1] == "advfirewall"
        assert cmd[2] == "set"
        assert cmd[3] == "allprofiles"
        assert cmd[4] == "state"
        assert cmd[5] == "on"

    @pytest.mark.asyncio
    async def test_disable_firewall_command_format(self):
        """Test that disable firewall uses correct netsh command format."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(
                self.ops, "_send_firewall_status_update", new_callable=AsyncMock
            ):
                await self.ops.disable_firewall()

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "netsh"
        assert cmd[1] == "advfirewall"
        assert cmd[2] == "set"
        assert cmd[3] == "allprofiles"
        assert cmd[4] == "state"
        assert cmd[5] == "off"

    def test_add_port_rule_command_format(self):
        """Test that add rule uses correct netsh command format."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.ops._add_port_rule(443, "tcp", [])

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "netsh"
        assert cmd[1] == "advfirewall"
        assert cmd[2] == "firewall"
        assert cmd[3] == "add"
        assert cmd[4] == "rule"
        assert "name=SysManage Role Port 443/TCP" in cmd
        assert "dir=in" in cmd
        assert "action=allow" in cmd
        assert "protocol=TCP" in cmd
        assert "localport=443" in cmd

    def test_delete_port_rule_command_format(self):
        """Test that delete rule uses correct netsh command format."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            self.ops._remove_port_rule(443, "tcp")

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "netsh"
        assert cmd[1] == "advfirewall"
        assert cmd[2] == "firewall"
        assert cmd[3] == "delete"
        assert cmd[4] == "rule"
        assert "name=SysManage Role Port 443/TCP" in cmd


class TestSubprocessTimeouts:
    """Test cases verifying subprocess timeout handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = WindowsFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_firewall_timeout(self):
        """Test that enable firewall handles subprocess timeout."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("netsh", 10)
        ):
            result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_disable_firewall_timeout(self):
        """Test that disable firewall handles subprocess timeout."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("netsh", 10)
        ):
            result = await self.ops.disable_firewall()

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_restart_firewall_timeout(self):
        """Test that restart firewall handles subprocess timeout."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("netsh", 10)
        ):
            result = await self.ops.restart_firewall()

        assert result["success"] is False
