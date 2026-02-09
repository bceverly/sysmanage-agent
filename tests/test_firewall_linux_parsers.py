"""
Unit tests for src.sysmanage_agent.operations.firewall_linux_parsers module.
Tests parsing logic for UFW, firewalld, iptables, and nftables.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import subprocess
from unittest.mock import Mock, patch

from src.sysmanage_agent.operations.firewall_linux_parsers import LinuxFirewallParsers


class TestLinuxFirewallParsersInit:
    """Test cases for LinuxFirewallParsers initialization."""

    def test_init(self):
        """Test LinuxFirewallParsers initialization."""
        mock_logger = Mock()
        parsers = LinuxFirewallParsers(mock_logger)
        assert parsers.logger == mock_logger


class TestAddPortToList:
    """Test cases for _add_port_to_list helper."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parsers = LinuxFirewallParsers(Mock())

    def test_add_port_ipv4(self):
        """Test adding port to IPv4 list."""
        tcp_v4 = []
        tcp_v6 = []
        self.parsers._add_port_to_list(
            "22", is_ipv6=False, tcp_v4=tcp_v4, tcp_v6=tcp_v6
        )
        assert tcp_v4 == ["22"]
        assert not tcp_v6

    def test_add_port_ipv6(self):
        """Test adding port to IPv6 list."""
        tcp_v4 = []
        tcp_v6 = []
        self.parsers._add_port_to_list("22", is_ipv6=True, tcp_v4=tcp_v4, tcp_v6=tcp_v6)
        assert not tcp_v4
        assert tcp_v6 == ["22"]


class TestParseUfwRules:
    """Test cases for parsing UFW rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parsers = LinuxFirewallParsers(Mock())

    def test_parse_ufw_empty_output(self):
        """Test parsing empty UFW output."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = self.parsers.parse_ufw_rules("")
        assert not ipv4_tcp
        assert not ipv4_udp
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_parse_ufw_single_tcp_port(self):
        """Test parsing single TCP port."""
        output = "22/tcp                     ALLOW       Anywhere"
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert ipv4_tcp == ["22"]
        assert not ipv4_udp
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_parse_ufw_single_udp_port(self):
        """Test parsing single UDP port."""
        output = "53/udp                     ALLOW       Anywhere"
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert not ipv4_tcp
        assert ipv4_udp == ["53"]
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_parse_ufw_ipv6_port(self):
        """Test parsing IPv6 port with (v6) marker."""
        output = "22/tcp (v6)                ALLOW       Anywhere (v6)"
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert not ipv4_tcp
        assert not ipv4_udp
        assert ipv6_tcp == ["22"]
        assert not ipv6_udp

    def test_parse_ufw_multiple_ports(self):
        """Test parsing multiple ports and protocols."""
        output = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
53/udp                     ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
80/tcp (v6)                ALLOW       Anywhere (v6)
"""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert ipv4_tcp == ["22", "80", "443"]
        assert ipv4_udp == ["53"]
        assert ipv6_tcp == ["22", "80"]
        assert not ipv6_udp

    def test_parse_ufw_port_without_protocol(self):
        """Test parsing port without protocol (applies to both TCP and UDP)."""
        output = "8080                       ALLOW       Anywhere"
        ipv4_tcp, ipv4_udp, _ipv6_tcp, _ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert ipv4_tcp == ["8080"]
        assert ipv4_udp == ["8080"]

    def test_parse_ufw_deny_rule_ignored(self):
        """Test that DENY rules are ignored."""
        output = "22/tcp                     DENY        Anywhere"
        ipv4_tcp, ipv4_udp, _ipv6_tcp, _ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert not ipv4_tcp
        assert not ipv4_udp

    def test_parse_ufw_line_no_allow(self):
        """Test parsing line without ALLOW keyword."""
        output = "Status: active"
        ipv4_tcp, ipv4_udp, _ipv6_tcp, _ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert not ipv4_tcp
        assert not ipv4_udp

    def test_parse_ufw_line_empty_parts(self):
        """Test parsing line with insufficient parts."""
        output = ""
        ipv4_tcp, _ipv4_udp, _ipv6_tcp, _ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert not ipv4_tcp

    def test_parse_ufw_port_with_protocol_lower_case(self):
        """Test parsing port with lowercase protocol."""
        output = "22/TCP                     ALLOW       Anywhere"
        ipv4_tcp, _ipv4_udp, _ipv6_tcp, _ipv6_udp = self.parsers.parse_ufw_rules(output)
        assert ipv4_tcp == ["22"]


class TestGetFirewalldPorts:
    """Test cases for getting firewalld ports."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parsers = LinuxFirewallParsers(Mock())

    def test_get_firewalld_ports_success(self):
        """Test getting ports from firewalld successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "22/tcp 80/tcp 443/tcp 53/udp"

        with patch("subprocess.run", return_value=mock_result):
            ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = self.parsers.get_firewalld_ports()

        assert ipv4_tcp == ["22", "80", "443"]
        assert ipv4_udp == ["53"]
        # Firewalld ports apply to both IPv4 and IPv6
        assert ipv6_tcp == ["22", "80", "443"]
        assert ipv6_udp == ["53"]

    def test_get_firewalld_ports_empty(self):
        """Test getting empty ports from firewalld."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            ipv4_tcp, ipv4_udp, _ipv6_tcp, _ipv6_udp = (
                self.parsers.get_firewalld_ports()
            )

        assert not ipv4_tcp
        assert not ipv4_udp

    def test_get_firewalld_ports_command_failure(self):
        """Test handling firewalld command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            ipv4_tcp, ipv4_udp, _ipv6_tcp, _ipv6_udp = (
                self.parsers.get_firewalld_ports()
            )

        assert not ipv4_tcp
        assert not ipv4_udp

    def test_get_firewalld_ports_file_not_found(self):
        """Test handling FileNotFoundError."""
        with patch(
            "subprocess.run", side_effect=FileNotFoundError("firewall-cmd not found")
        ):
            ipv4_tcp, ipv4_udp, _ipv6_tcp, _ipv6_udp = (
                self.parsers.get_firewalld_ports()
            )

        assert not ipv4_tcp
        assert not ipv4_udp

    def test_get_firewalld_ports_timeout(self):
        """Test handling subprocess timeout."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="firewall-cmd", timeout=5),
        ):
            ipv4_tcp, ipv4_udp, _ipv6_tcp, _ipv6_udp = (
                self.parsers.get_firewalld_ports()
            )

        assert not ipv4_tcp
        assert not ipv4_udp


class TestParseIptablesRules:
    """Test cases for parsing iptables rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parsers = LinuxFirewallParsers(Mock())

    def test_run_iptables_command_success(self):
        """Test running iptables command successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test output"

        with patch("subprocess.run", return_value=mock_result):
            result = self.parsers._run_iptables_command(["iptables", "-L"])

        assert result == "test output"

    def test_run_iptables_command_failure(self):
        """Test running iptables command with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = self.parsers._run_iptables_command(["iptables", "-L"])

        assert result is None

    def test_run_iptables_command_file_not_found(self):
        """Test running iptables when command not found."""
        with patch(
            "subprocess.run", side_effect=FileNotFoundError("iptables not found")
        ):
            result = self.parsers._run_iptables_command(["iptables", "-L"])

        assert result is None

    def test_run_iptables_command_timeout(self):
        """Test running iptables with timeout."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="iptables", timeout=5),
        ):
            result = self.parsers._run_iptables_command(["iptables", "-L"])

        assert result is None

    def test_parse_iptables_line_accept_tcp(self):
        """Test parsing iptables ACCEPT rule for TCP."""
        tcp_ports = []
        udp_ports = []
        line = (
            "ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:22"
        )
        self.parsers._parse_iptables_line(line, tcp_ports, udp_ports)
        assert tcp_ports == ["22"]
        assert not udp_ports

    def test_parse_iptables_line_accept_udp(self):
        """Test parsing iptables ACCEPT rule for UDP."""
        tcp_ports = []
        udp_ports = []
        line = (
            "ACCEPT     udp  --  anywhere             anywhere             udp dpt:53"
        )
        self.parsers._parse_iptables_line(line, tcp_ports, udp_ports)
        assert not tcp_ports
        assert udp_ports == ["53"]

    def test_parse_iptables_line_no_accept(self):
        """Test parsing iptables line without ACCEPT."""
        tcp_ports = []
        udp_ports = []
        line = (
            "DROP       tcp  --  anywhere             anywhere             tcp dpt:22"
        )
        self.parsers._parse_iptables_line(line, tcp_ports, udp_ports)
        assert not tcp_ports
        assert not udp_ports

    def test_parse_iptables_line_no_dpt(self):
        """Test parsing iptables line without dpt."""
        tcp_ports = []
        udp_ports = []
        line = "ACCEPT     all  --  anywhere             anywhere"
        self.parsers._parse_iptables_line(line, tcp_ports, udp_ports)
        assert not tcp_ports
        assert not udp_ports

    def test_parse_iptables_output(self):
        """Test parsing full iptables output."""
        tcp_ports = []
        udp_ports = []
        output = """Chain INPUT (policy ACCEPT)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
2        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80
3        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53
"""
        self.parsers._parse_iptables_output(output, tcp_ports, udp_ports)
        assert tcp_ports == ["22", "80"]
        assert udp_ports == ["53"]

    def test_parse_iptables_rules(self):
        """Test parsing both iptables and ip6tables rules."""
        ipv4_output = (
            "ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:22"
        )
        ipv6_output = (
            "ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:443"
        )

        with patch.object(self.parsers, "_run_iptables_command") as mock_run:
            mock_run.side_effect = [ipv4_output, ipv6_output]
            ipv4_tcp, _ipv4_udp, ipv6_tcp, _ipv6_udp = (
                self.parsers.parse_iptables_rules()
            )

        assert ipv4_tcp == ["22"]
        assert ipv6_tcp == ["443"]

    def test_parse_iptables_rules_no_ipv4(self):
        """Test parsing when iptables fails but ip6tables works."""
        with patch.object(self.parsers, "_run_iptables_command") as mock_run:
            mock_run.side_effect = [None, "ACCEPT     tcp  dpt:443"]
            ipv4_tcp, _ipv4_udp, ipv6_tcp, _ipv6_udp = (
                self.parsers.parse_iptables_rules()
            )

        assert not ipv4_tcp
        assert ipv6_tcp == ["443"]


class TestParseNftablesRules:
    """Test cases for parsing nftables rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parsers = LinuxFirewallParsers(Mock())

    def test_extract_nftables_table_family_ip(self):
        """Test extracting IP table family."""
        family = self.parsers._extract_nftables_table_family("table ip filter {")
        assert family == "ip"

    def test_extract_nftables_table_family_ip6(self):
        """Test extracting IPv6 table family."""
        family = self.parsers._extract_nftables_table_family("table ip6 filter {")
        assert family == "ip6"

    def test_extract_nftables_table_family_inet(self):
        """Test extracting inet table family."""
        family = self.parsers._extract_nftables_table_family("table inet filter {")
        assert family == "inet"

    def test_extract_nftables_table_family_not_table(self):
        """Test extracting family from non-table line."""
        family = self.parsers._extract_nftables_table_family("chain input {")
        assert family is None

    def test_is_nftables_accept_rule_true(self):
        """Test identifying accept rule with dport."""
        result = self.parsers._is_nftables_accept_rule("tcp dport 22 accept")
        assert result is True

    def test_is_nftables_accept_rule_no_accept(self):
        """Test identifying rule without accept."""
        result = self.parsers._is_nftables_accept_rule("tcp dport 22 drop")
        assert result is False

    def test_is_nftables_accept_rule_no_dport(self):
        """Test identifying rule without dport."""
        result = self.parsers._is_nftables_accept_rule("accept")
        assert result is False

    def test_get_nftables_protocol_tcp(self):
        """Test getting TCP protocol from rule."""
        is_tcp, is_udp = self.parsers._get_nftables_protocol("tcp dport 22 accept")
        assert is_tcp is True
        assert is_udp is False

    def test_get_nftables_protocol_udp(self):
        """Test getting UDP protocol from rule."""
        is_tcp, is_udp = self.parsers._get_nftables_protocol("udp dport 53 accept")
        assert is_tcp is False
        assert is_udp is True

    def test_get_nftables_protocol_both(self):
        """Test getting both protocols from rule."""
        is_tcp, is_udp = self.parsers._get_nftables_protocol("tcp udp dport 80 accept")
        assert is_tcp is True
        assert is_udp is True

    def test_extract_nftables_ports_single(self):
        """Test extracting single port from nftables rule."""
        ports = self.parsers._extract_nftables_ports("tcp dport 22 accept")
        assert ports == ["22"]

    def test_extract_nftables_ports_set(self):
        """Test extracting port set from nftables rule."""
        ports = self.parsers._extract_nftables_ports("tcp dport { 22, 80, 443 } accept")
        assert ports == ["22", "80", "443"]

    def test_extract_nftables_ports_no_dport(self):
        """Test extracting ports when no dport keyword."""
        ports = self.parsers._extract_nftables_ports("accept")
        assert ports is None

    def test_add_nftables_port_by_family_ip(self):
        """Test adding port for IP family."""
        port_lists = {"ipv4_tcp": [], "ipv4_udp": [], "ipv6_tcp": [], "ipv6_udp": []}
        self.parsers._add_nftables_port_by_family("22", "ip", True, False, port_lists)
        assert port_lists["ipv4_tcp"] == ["22"]
        assert not port_lists["ipv6_tcp"]

    def test_add_nftables_port_by_family_ip6(self):
        """Test adding port for IPv6 family."""
        port_lists = {"ipv4_tcp": [], "ipv4_udp": [], "ipv6_tcp": [], "ipv6_udp": []}
        self.parsers._add_nftables_port_by_family("22", "ip6", True, False, port_lists)
        assert not port_lists["ipv4_tcp"]
        assert port_lists["ipv6_tcp"] == ["22"]

    def test_add_nftables_port_by_family_inet(self):
        """Test adding port for inet family (both IPv4 and IPv6)."""
        port_lists = {"ipv4_tcp": [], "ipv4_udp": [], "ipv6_tcp": [], "ipv6_udp": []}
        self.parsers._add_nftables_port_by_family("22", "inet", True, False, port_lists)
        assert port_lists["ipv4_tcp"] == ["22"]
        assert port_lists["ipv6_tcp"] == ["22"]

    def test_add_port_by_protocol_tcp(self):
        """Test adding port by TCP protocol."""
        tcp_list = []
        udp_list = []
        self.parsers._add_port_by_protocol("22", True, False, tcp_list, udp_list)
        assert tcp_list == ["22"]
        assert not udp_list

    def test_add_port_by_protocol_udp(self):
        """Test adding port by UDP protocol."""
        tcp_list = []
        udp_list = []
        self.parsers._add_port_by_protocol("53", False, True, tcp_list, udp_list)
        assert not tcp_list
        assert udp_list == ["53"]

    def test_parse_nftables_line_accept(self):
        """Test parsing nftables accept rule line."""
        port_lists = {"ipv4_tcp": [], "ipv4_udp": [], "ipv6_tcp": [], "ipv6_udp": []}
        self.parsers._parse_nftables_line("tcp dport 22 accept", "ip", port_lists)
        assert port_lists["ipv4_tcp"] == ["22"]

    def test_parse_nftables_line_not_accept(self):
        """Test parsing nftables non-accept rule."""
        port_lists = {"ipv4_tcp": [], "ipv4_udp": [], "ipv6_tcp": [], "ipv6_udp": []}
        self.parsers._parse_nftables_line("tcp dport 22 drop", "ip", port_lists)
        assert not port_lists["ipv4_tcp"]

    def test_parse_nftables_line_no_family(self):
        """Test parsing nftables rule without family context."""
        port_lists = {"ipv4_tcp": [], "ipv4_udp": [], "ipv6_tcp": [], "ipv6_udp": []}
        self.parsers._parse_nftables_line("tcp dport 22 accept", None, port_lists)
        assert not port_lists["ipv4_tcp"]

    def test_parse_nftables_rules_full(self):
        """Test parsing full nftables ruleset."""
        output = """table ip filter {
    chain input {
        type filter hook input priority 0;
        tcp dport 22 accept
        tcp dport { 80, 443 } accept
        udp dport 53 accept
    }
}
table ip6 filter {
    chain input {
        tcp dport 22 accept
    }
}
table inet myfilter {
    chain input {
        tcp dport 8080 accept
    }
}
"""
        ipv4_tcp, ipv4_udp, ipv6_tcp, _ipv6_udp = self.parsers.parse_nftables_rules(
            output
        )

        assert "22" in ipv4_tcp
        assert "80" in ipv4_tcp
        assert "443" in ipv4_tcp
        assert "53" in ipv4_udp
        assert "22" in ipv6_tcp
        # inet table adds to both
        assert "8080" in ipv4_tcp
        assert "8080" in ipv6_tcp

    def test_parse_nftables_rules_empty(self):
        """Test parsing empty nftables output."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = self.parsers.parse_nftables_rules("")
        assert not ipv4_tcp
        assert not ipv4_udp
        assert not ipv6_tcp
        assert not ipv6_udp
