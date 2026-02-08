"""
Unit tests for src.sysmanage_agent.operations.firewall_port_helpers module.
Tests port collection and formatting helper functions.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_port_helpers import (
    FirewallPortHelpers,
    _add_port_to_list,
    _categorize_port,
    _empty_port_lists,
    _extract_port_from_address,
    _is_ipv6_address,
)


class TestModuleLevelHelpers:
    """Test cases for module-level helper functions."""

    def test_empty_port_lists(self):
        """Test _empty_port_lists returns four empty lists."""
        result = _empty_port_lists()
        assert result == ([], [], [], [])

    def test_add_port_to_list_new_port(self):
        """Test adding new port to list."""
        port_list = []
        _add_port_to_list("22", port_list)
        assert port_list == ["22"]

    def test_add_port_to_list_duplicate(self):
        """Test adding duplicate port to list."""
        port_list = ["22"]
        _add_port_to_list("22", port_list)
        assert port_list == ["22"]  # No duplicate

    def test_extract_port_from_address_colon_separator(self):
        """Test extracting port with colon separator."""
        assert _extract_port_from_address("0.0.0.0:22") == "22"
        assert _extract_port_from_address("*:80") == "80"
        assert _extract_port_from_address("[::]:443") == "443"

    def test_extract_port_from_address_dot_separator(self):
        """Test extracting port with dot separator (BSD style)."""
        assert _extract_port_from_address("*.22", use_dot_separator=True) == "22"
        assert (
            _extract_port_from_address("192.168.1.1.80", use_dot_separator=True) == "80"
        )

    def test_extract_port_from_address_no_separator(self):
        """Test extracting port with no separator."""
        assert _extract_port_from_address("invalid") == ""

    def test_extract_port_from_address_non_numeric(self):
        """Test extracting non-numeric port."""
        assert _extract_port_from_address("*:ssh") == ""

    def test_is_ipv6_address_by_protocol(self):
        """Test detecting IPv6 by protocol indicator."""
        assert _is_ipv6_address("0.0.0.0:22", proto="tcp6") is True
        assert _is_ipv6_address("0.0.0.0:22", proto="udp6") is True
        assert _is_ipv6_address("0.0.0.0:22", proto="tcp") is False

    def test_is_ipv6_address_by_brackets(self):
        """Test detecting IPv6 by brackets."""
        assert _is_ipv6_address("[::]:22") is True
        assert _is_ipv6_address("[::1]:80") is True
        assert _is_ipv6_address("0.0.0.0:22") is False

    def test_is_ipv6_address_by_prefix(self):
        """Test detecting IPv6 by :: prefix."""
        assert _is_ipv6_address("::22") is True
        assert _is_ipv6_address("0.0.0.0:22") is False

    def test_categorize_port_tcp_ipv4(self):
        """Test categorizing TCP IPv4 port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        _categorize_port("22", "tcp", False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv4_tcp == ["22"]
        assert ipv4_udp == []

    def test_categorize_port_udp_ipv4(self):
        """Test categorizing UDP IPv4 port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        _categorize_port("53", "udp", False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv4_udp == ["53"]
        assert ipv4_tcp == []

    def test_categorize_port_tcp_ipv6(self):
        """Test categorizing TCP IPv6 port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        _categorize_port("22", "tcp6", True, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv6_tcp == ["22"]
        assert ipv4_tcp == []

    def test_categorize_port_udp_ipv6(self):
        """Test categorizing UDP IPv6 port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        _categorize_port("53", "udp6", True, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv6_udp == ["53"]
        assert ipv4_udp == []

    def test_categorize_port_unknown_protocol(self):
        """Test categorizing with unknown protocol."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        _categorize_port("22", "sctp", False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        # Should not add to any list
        assert ipv4_tcp == []
        assert ipv4_udp == []


class TestFirewallPortHelpersInit:
    """Test cases for FirewallPortHelpers initialization."""

    def test_init(self):
        """Test FirewallPortHelpers initialization."""
        mock_logger = Mock()
        helpers = FirewallPortHelpers(mock_logger)
        assert helpers.logger == mock_logger


class TestMergePortsWithProtocols:
    """Test cases for merging ports with protocols."""

    def setup_method(self):
        """Set up test fixtures."""
        self.helpers = FirewallPortHelpers(Mock())

    def test_merge_ports_tcp_only(self):
        """Test merging TCP-only ports."""
        result = self.helpers.merge_ports_with_protocols(["22", "80"], [])
        assert len(result) == 2
        assert {"port": "22", "protocols": ["tcp"]} in result
        assert {"port": "80", "protocols": ["tcp"]} in result

    def test_merge_ports_udp_only(self):
        """Test merging UDP-only ports."""
        result = self.helpers.merge_ports_with_protocols([], ["53", "67"])
        assert len(result) == 2
        assert {"port": "53", "protocols": ["udp"]} in result
        assert {"port": "67", "protocols": ["udp"]} in result

    def test_merge_ports_both_protocols(self):
        """Test merging ports with both protocols."""
        result = self.helpers.merge_ports_with_protocols(["53"], ["53"])
        assert len(result) == 1
        assert {"port": "53", "protocols": ["tcp", "udp"]} in result

    def test_merge_ports_sorted_numerically(self):
        """Test that ports are sorted numerically."""
        result = self.helpers.merge_ports_with_protocols(["443", "22", "80"], [])
        ports = [p["port"] for p in result]
        assert ports == ["22", "80", "443"]

    def test_merge_ports_with_ranges(self):
        """Test merging ports with port ranges."""
        result = self.helpers.merge_ports_with_protocols(["22", "33434-33600"], [])
        assert len(result) == 2
        # Port range should sort by first port number
        ports = [p["port"] for p in result]
        assert "22" in ports
        assert "33434-33600" in ports

    def test_merge_ports_empty(self):
        """Test merging empty port lists."""
        result = self.helpers.merge_ports_with_protocols([], [])
        assert result == []

    def test_merge_ports_no_duplicates(self):
        """Test that duplicate ports are merged."""
        result = self.helpers.merge_ports_with_protocols(["22", "22"], ["22"])
        assert len(result) == 1
        assert result[0]["protocols"] == ["tcp", "udp"]


class TestWindowsFirewallPorts:
    """Test cases for Windows firewall port collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.helpers = FirewallPortHelpers(Mock())

    def test_parse_windows_protocol_line_tcp(self):
        """Test parsing Windows TCP protocol line."""
        assert (
            self.helpers._parse_windows_protocol_line(
                "Protocol:                             TCP"
            )
            == "tcp"
        )

    def test_parse_windows_protocol_line_udp(self):
        """Test parsing Windows UDP protocol line."""
        assert (
            self.helpers._parse_windows_protocol_line(
                "Protocol:                             UDP"
            )
            == "udp"
        )

    def test_parse_windows_protocol_line_other(self):
        """Test parsing Windows non-TCP/UDP protocol line."""
        assert (
            self.helpers._parse_windows_protocol_line(
                "Protocol:                             ICMP"
            )
            == ""
        )

    def test_extract_windows_port_valid(self):
        """Test extracting valid Windows port."""
        assert (
            self.helpers._extract_windows_port(
                "LocalPort:                            3389"
            )
            == "3389"
        )

    def test_extract_windows_port_any(self):
        """Test extracting 'Any' Windows port."""
        assert (
            self.helpers._extract_windows_port(
                "LocalPort:                            Any"
            )
            == ""
        )

    def test_extract_windows_port_empty(self):
        """Test extracting empty Windows port."""
        assert self.helpers._extract_windows_port("LocalPort:") == ""

    def test_add_windows_port_tcp(self):
        """Test adding Windows TCP port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        self.helpers._add_windows_port(
            "3389", "tcp", ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert ipv4_tcp == ["3389"]
        assert ipv6_tcp == ["3389"]

    def test_add_windows_port_udp(self):
        """Test adding Windows UDP port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        self.helpers._add_windows_port(
            "53", "udp", ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert ipv4_udp == ["53"]
        assert ipv6_udp == ["53"]

    def test_get_windows_firewall_ports_success(self):
        """Test getting Windows firewall ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Rule Name:                            Remote Desktop
Protocol:                             TCP
LocalPort:                            3389

Rule Name:                            DNS
Protocol:                             UDP
LocalPort:                            53
"""

        with patch.object(self.helpers, "_run_netsh_command", return_value=mock_result):
            ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = (
                self.helpers.get_windows_firewall_ports()
            )

        assert "3389" in ipv4_tcp
        assert "53" in ipv4_udp

    def test_get_windows_firewall_ports_failure(self):
        """Test getting Windows firewall ports when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch.object(self.helpers, "_run_netsh_command", return_value=mock_result):
            ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = (
                self.helpers.get_windows_firewall_ports()
            )

        assert ipv4_tcp == []
        assert ipv4_udp == []

    def test_get_windows_firewall_ports_timeout(self):
        """Test getting Windows firewall ports with timeout."""
        with patch.object(
            self.helpers,
            "_run_netsh_command",
            side_effect=subprocess.TimeoutExpired(cmd="netsh", timeout=10),
        ):
            ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = (
                self.helpers.get_windows_firewall_ports()
            )

        assert ipv4_tcp == []


class TestListeningPorts:
    """Test cases for listening port detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.helpers = FirewallPortHelpers(Mock())

    def test_is_ss_listening_line_listen(self):
        """Test detecting LISTEN state in ss output."""
        assert (
            self.helpers._is_ss_listening_line(
                "tcp   LISTEN 0      128         0.0.0.0:22"
            )
            is True
        )

    def test_is_ss_listening_line_unconn(self):
        """Test detecting UNCONN state in ss output (UDP)."""
        assert (
            self.helpers._is_ss_listening_line(
                "udp   UNCONN 0      0           0.0.0.0:53"
            )
            is True
        )

    def test_is_ss_listening_line_established(self):
        """Test detecting non-listening state in ss output."""
        assert (
            self.helpers._is_ss_listening_line(
                "tcp   ESTAB  0      0     192.168.1.1:22"
            )
            is False
        )

    def test_parse_ss_line_valid(self):
        """Test parsing valid ss line."""
        line = "tcp   LISTEN 0      128         0.0.0.0:22       0.0.0.0:*"
        proto, local_addr = self.helpers._parse_ss_line(line)
        assert proto == "tcp"
        assert local_addr == "0.0.0.0:22"

    def test_parse_ss_line_invalid(self):
        """Test parsing invalid ss line."""
        line = "invalid"
        proto, local_addr = self.helpers._parse_ss_line(line)
        assert proto is None
        assert local_addr is None

    def test_parse_netstat_line_valid(self):
        """Test parsing valid netstat line."""
        line = (
            "tcp4       0      0  *.22                   *.*                    LISTEN"
        )
        proto, local_addr = self.helpers._parse_netstat_line(line)
        assert proto == "tcp4"
        assert local_addr == "*.22"

    def test_parse_netstat_line_invalid(self):
        """Test parsing invalid netstat line."""
        line = "invalid"
        proto, local_addr = self.helpers._parse_netstat_line(line)
        assert proto is None
        assert local_addr is None

    def test_extract_port_from_ss_addr_colon(self):
        """Test extracting port from ss address format."""
        assert self.helpers._extract_port_from_ss_addr("0.0.0.0:22") == "22"
        assert self.helpers._extract_port_from_ss_addr("[::]:80") == "80"
        assert self.helpers._extract_port_from_ss_addr("*:443") == "443"

    def test_extract_port_from_ss_addr_no_port(self):
        """Test extracting port when no colon."""
        assert self.helpers._extract_port_from_ss_addr("invalid") == ""

    def test_extract_port_from_ss_addr_non_numeric(self):
        """Test extracting non-numeric port."""
        assert self.helpers._extract_port_from_ss_addr("*:ssh") == ""

    def test_process_ss_output(self):
        """Test processing ss command output."""
        # ss -tuln format: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
        output = """Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port
tcp    LISTEN  0       128      0.0.0.0:22            0.0.0.0:*
tcp    LISTEN  0       128      [::]:22               [::]:*
udp    UNCONN  0       0        0.0.0.0:53            0.0.0.0:*
tcp    ESTAB   0       0        192.168.1.1:22        192.168.1.2:54321
"""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        self.helpers._process_ss_output(output, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)

        assert "22" in ipv4_tcp
        assert "22" in ipv6_tcp
        assert "53" in ipv4_udp

    def test_process_netstat_output(self):
        """Test processing netstat command output."""
        output = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
udp        0      0 0.0.0.0:68              0.0.0.0:*
"""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        self.helpers._process_netstat_output(
            output, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )

        assert "22" in ipv4_tcp
        # Note: UDP doesn't have LISTEN state so won't be caught

    def test_sort_port_lists(self):
        """Test sorting port lists."""
        result = self.helpers._sort_port_lists(
            ["80", "22", "443"], ["53", "67"], ["22"], ["53"]
        )

        assert result[0] == ["22", "443", "80"]
        assert result[1] == ["53", "67"]
        assert result[2] == ["22"]
        assert result[3] == ["53"]

    def test_try_ss_ports_success(self):
        """Test trying ss to get ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "tcp   LISTEN 0      128         0.0.0.0:22       0.0.0.0:*"
        )

        with patch.object(self.helpers, "_run_ss_command", return_value=mock_result):
            result = self.helpers._try_ss_ports()

        assert result is not None
        assert "22" in result[0]

    def test_try_ss_ports_failure(self):
        """Test trying ss when it fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch.object(self.helpers, "_run_ss_command", return_value=mock_result):
            result = self.helpers._try_ss_ports()

        assert result is None

    def test_try_ss_ports_not_found(self):
        """Test trying ss when command not found."""
        with patch.object(
            self.helpers, "_run_ss_command", side_effect=FileNotFoundError()
        ):
            result = self.helpers._try_ss_ports()

        assert result is None

    def test_try_netstat_ports_success(self):
        """Test trying netstat to get ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN"
        )

        with patch.object(
            self.helpers, "_run_netstat_command", return_value=mock_result
        ):
            result = self.helpers._try_netstat_ports()

        assert result is not None
        assert "22" in result[0]

    def test_try_netstat_ports_failure(self):
        """Test trying netstat when it fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch.object(
            self.helpers, "_run_netstat_command", return_value=mock_result
        ):
            result = self.helpers._try_netstat_ports()

        assert result is None

    def test_get_listening_ports_ss_success(self):
        """Test getting listening ports with ss success."""
        with patch.object(
            self.helpers, "_try_ss_ports", return_value=(["22"], [], ["22"], [])
        ):
            result = self.helpers.get_listening_ports()

        assert result == (["22"], [], ["22"], [])

    def test_get_listening_ports_fallback_to_netstat(self):
        """Test getting listening ports falling back to netstat."""
        with patch.object(self.helpers, "_try_ss_ports", return_value=None):
            with patch.object(
                self.helpers, "_try_netstat_ports", return_value=(["22"], [], [], [])
            ):
                result = self.helpers.get_listening_ports()

        assert result == (["22"], [], [], [])

    def test_get_listening_ports_both_fail(self):
        """Test getting listening ports when both fail."""
        with patch.object(self.helpers, "_try_ss_ports", return_value=None):
            with patch.object(self.helpers, "_try_netstat_ports", return_value=None):
                result = self.helpers.get_listening_ports()

        assert result == ([], [], [], [])


class TestSubprocessCommands:
    """Test cases for subprocess command execution."""

    def setup_method(self):
        """Set up test fixtures."""
        self.helpers = FirewallPortHelpers(Mock())

    def test_run_netsh_command(self):
        """Test running netsh command."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = self.helpers._run_netsh_command()

        assert result == mock_result

    def test_run_ss_command(self):
        """Test running ss command."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = self.helpers._run_ss_command()

        assert result == mock_result

    def test_run_netstat_command(self):
        """Test running netstat command."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = self.helpers._run_netstat_command()

        assert result == mock_result
