"""
Unit tests for src.sysmanage_agent.operations.firewall_bsd_parsers module.
Tests BSD firewall parsing for pf, ipfw, and npf firewall systems.
"""

# pylint: disable=protected-access,redefined-outer-name

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_bsd_parsers import BsdFirewallParsers


@pytest.fixture
def parser():
    """Create a BSD firewall parser for testing."""
    mock_logger = Mock()
    return BsdFirewallParsers(mock_logger)


class TestBsdFirewallParsersInit:
    """Tests for BsdFirewallParsers initialization."""

    def test_init_with_logger(self):
        """Test initialization with a logger."""
        mock_logger = Mock()
        parsers = BsdFirewallParsers(mock_logger)
        assert parsers.logger == mock_logger


class TestAddPortToList:
    """Tests for _add_port_to_list method."""

    def test_add_tcp_ipv4_port(self, parser):
        """Test adding a TCP IPv4 port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        parser._add_port_to_list(
            "80", False, True, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert ipv4_tcp == ["80"]
        assert not ipv4_udp
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_add_tcp_ipv6_port(self, parser):
        """Test adding a TCP IPv6 port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        parser._add_port_to_list(
            "443", True, True, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert not ipv4_tcp
        assert not ipv4_udp
        assert ipv6_tcp == ["443"]
        assert not ipv6_udp

    def test_add_udp_ipv4_port(self, parser):
        """Test adding a UDP IPv4 port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        parser._add_port_to_list(
            "53", False, False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert not ipv4_tcp
        assert ipv4_udp == ["53"]
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_add_udp_ipv6_port(self, parser):
        """Test adding a UDP IPv6 port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        parser._add_port_to_list(
            "123", True, False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert not ipv4_tcp
        assert not ipv4_udp
        assert not ipv6_tcp
        assert ipv6_udp == ["123"]


class TestAddPortToBothProtocols:
    """Tests for _add_port_to_both_protocols method."""

    def test_add_to_both_protocols_ipv4(self, parser):
        """Test adding a port to both TCP and UDP for IPv4."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        parser._add_port_to_both_protocols(
            "8080", False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert ipv4_tcp == ["8080"]
        assert ipv4_udp == ["8080"]
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_add_to_both_protocols_ipv6(self, parser):
        """Test adding a port to both TCP and UDP for IPv6."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        parser._add_port_to_both_protocols(
            "9000", True, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert not ipv4_tcp
        assert not ipv4_udp
        assert ipv6_tcp == ["9000"]
        assert ipv6_udp == ["9000"]


class TestExtendPortsToList:
    """Tests for _extend_ports_to_list method."""

    def test_extend_tcp_ipv4_ports(self, parser):
        """Test extending TCP IPv4 ports."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = ["22"], [], [], []
        parser._extend_ports_to_list(
            ["80", "443"], False, True, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert ipv4_tcp == ["22", "80", "443"]
        assert not ipv4_udp
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_extend_tcp_ipv6_ports(self, parser):
        """Test extending TCP IPv6 ports."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], ["22"], []
        parser._extend_ports_to_list(
            ["80", "443"], True, True, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert not ipv4_tcp
        assert not ipv4_udp
        assert ipv6_tcp == ["22", "80", "443"]
        assert not ipv6_udp

    def test_extend_udp_ipv4_ports(self, parser):
        """Test extending UDP IPv4 ports."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], ["53"], [], []
        parser._extend_ports_to_list(
            ["67", "68"], False, False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert not ipv4_tcp
        assert ipv4_udp == ["53", "67", "68"]
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_extend_udp_ipv6_ports(self, parser):
        """Test extending UDP IPv6 ports."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], ["123"]
        parser._extend_ports_to_list(
            ["546", "547"], True, False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert not ipv4_tcp
        assert not ipv4_udp
        assert not ipv6_tcp
        assert ipv6_udp == ["123", "546", "547"]


class TestExtendPortsToBothProtocols:
    """Tests for _extend_ports_to_both_protocols method."""

    def test_extend_both_protocols_ipv4(self, parser):
        """Test extending ports to both protocols for IPv4."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = ["22"], ["53"], [], []
        parser._extend_ports_to_both_protocols(
            ["80", "443"], False, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert ipv4_tcp == ["22", "80", "443"]
        assert ipv4_udp == ["53", "80", "443"]
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_extend_both_protocols_ipv6(self, parser):
        """Test extending ports to both protocols for IPv6."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], ["22"], ["53"]
        parser._extend_ports_to_both_protocols(
            ["80", "443"], True, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
        )
        assert not ipv4_tcp
        assert not ipv4_udp
        assert ipv6_tcp == ["22", "80", "443"]
        assert ipv6_udp == ["53", "80", "443"]


class TestIsPfIpv6Rule:
    """Tests for _is_pf_ipv6_rule method."""

    def test_ipv6_rule_with_inet6(self, parser):
        """Test detection of IPv6 rule with inet6 keyword."""
        line = "pass in on em0 inet6 proto tcp from any to any port 22"
        assert parser._is_pf_ipv6_rule(line) is True

    def test_ipv4_rule_without_inet6(self, parser):
        """Test IPv4 rule without inet6 keyword."""
        line = "pass in on em0 inet proto tcp from any to any port 22"
        assert parser._is_pf_ipv6_rule(line) is False

    def test_rule_without_inet_family(self, parser):
        """Test rule without inet family specified."""
        line = "pass in on em0 proto tcp from any to any port 80"
        assert parser._is_pf_ipv6_rule(line) is False


class TestExtractPfPort:
    """Tests for _extract_pf_port method."""

    def test_extract_simple_port(self, parser):
        """Test extracting simple port number."""
        line = "pass in on em0 proto tcp from any to any port 80"
        assert parser._extract_pf_port(line) == "80"

    def test_extract_port_with_equals(self, parser):
        """Test extracting port with equals sign."""
        line = "pass in on em0 proto tcp from any to any port =443"
        assert parser._extract_pf_port(line) == "443"

    def test_no_port_in_line(self, parser):
        """Test line without port keyword."""
        line = "pass in on em0 proto tcp from any to any"
        assert parser._extract_pf_port(line) is None

    def test_extract_port_with_trailing_content(self, parser):
        """Test extracting port with additional content after."""
        line = "pass in on em0 proto tcp from any to any port 8080 keep state"
        assert parser._extract_pf_port(line) == "8080"


class TestGetPfProtocol:
    """Tests for _get_pf_protocol method."""

    def test_proto_tcp(self, parser):
        """Test detection of proto tcp."""
        line = "pass in on em0 proto tcp from any to any port 80"
        assert parser._get_pf_protocol(line) == "tcp"

    def test_proto_udp(self, parser):
        """Test detection of proto udp."""
        line = "pass in on em0 proto udp from any to any port 53"
        assert parser._get_pf_protocol(line) == "udp"

    def test_space_tcp(self, parser):
        """Test detection of tcp with spaces."""
        line = "pass in on em0 tcp from any to any port 80"
        assert parser._get_pf_protocol(line) == "tcp"

    def test_space_udp(self, parser):
        """Test detection of udp with spaces."""
        line = "pass in on em0 udp from any to any port 53"
        assert parser._get_pf_protocol(line) == "udp"

    def test_no_protocol_specified(self, parser):
        """Test rule without protocol specified returns both."""
        line = "pass in on em0 from any to any port 80"
        assert parser._get_pf_protocol(line) == "both"

    def test_other_protocol(self, parser):
        """Test rule with other protocol (e.g., icmp)."""
        line = "pass in on em0 proto icmp from any to any"
        assert parser._get_pf_protocol(line) is None


class TestProcessPfRule:
    """Tests for _process_pf_rule method."""

    def test_skip_non_pass_rule(self, parser):
        """Test that non-pass rules are skipped."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "block in on em0 proto tcp from any to any port 22"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp
        assert not ipv4_udp
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_skip_rule_without_port(self, parser):
        """Test that rules without port are skipped."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in on em0 proto tcp from any to any"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp
        assert not ipv4_udp
        assert not ipv6_tcp
        assert not ipv6_udp

    def test_process_tcp_ipv4_rule(self, parser):
        """Test processing TCP IPv4 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in on em0 proto tcp from any to any port 80"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv4_tcp == ["80"]
        assert not ipv4_udp

    def test_process_udp_ipv4_rule(self, parser):
        """Test processing UDP IPv4 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in on em0 proto udp from any to any port 53"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp
        assert ipv4_udp == ["53"]

    def test_process_tcp_ipv6_rule(self, parser):
        """Test processing TCP IPv6 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in on em0 inet6 proto tcp from any to any port 443"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp
        assert ipv6_tcp == ["443"]

    def test_process_udp_ipv6_rule(self, parser):
        """Test processing UDP IPv6 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in on em0 inet6 proto udp from any to any port 123"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_udp
        assert ipv6_udp == ["123"]

    def test_process_both_protocols_ipv4(self, parser):
        """Test processing rule without protocol (both TCP and UDP) for IPv4."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in on em0 from any to any port 8080"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv4_tcp == ["8080"]
        assert ipv4_udp == ["8080"]

    def test_process_both_protocols_ipv6(self, parser):
        """Test processing rule without protocol (both TCP and UDP) for IPv6."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in on em0 inet6 from any to any port 9000"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv6_tcp == ["9000"]
        assert ipv6_udp == ["9000"]

    def test_skip_rule_with_other_protocol(self, parser):
        """Test that rules with non-tcp/udp protocols are skipped."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in on em0 proto icmp from any to any port 80"
        parser._process_pf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp
        assert not ipv4_udp


class TestGetPfPorts:
    """Tests for get_pf_ports method."""

    def test_get_pf_ports_success(self, parser):
        """Test successful retrieval of pf ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
pass in on em0 proto tcp from any to any port 22
pass in on em0 proto tcp from any to any port 80
pass in on em0 proto udp from any to any port 53
pass in on em0 inet6 proto tcp from any to any port 443
"""
        with patch("subprocess.run", return_value=mock_result):
            result = parser.get_pf_ports()

        ipv4_tcp, ipv4_udp, ipv6_tcp, _ipv6_udp = result
        assert "22" in ipv4_tcp
        assert "80" in ipv4_tcp
        assert "53" in ipv4_udp
        assert "443" in ipv6_tcp

    def test_get_pf_ports_command_failed(self, parser):
        """Test when pfctl command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = parser.get_pf_ports()

        assert result == ([], [], [], [])

    def test_get_pf_ports_file_not_found(self, parser):
        """Test when pfctl is not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = parser.get_pf_ports()

        assert result == ([], [], [], [])

    def test_get_pf_ports_timeout(self, parser):
        """Test when pfctl command times out."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pfctl", 5)):
            result = parser.get_pf_ports()

        assert result == ([], [], [], [])

    def test_get_pf_ports_permission_error(self, parser):
        """Test when pfctl lacks permissions."""
        with patch("subprocess.run", side_effect=PermissionError()):
            result = parser.get_pf_ports()

        assert result == ([], [], [], [])

    def test_get_pf_ports_empty_output(self, parser):
        """Test with empty pfctl output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = parser.get_pf_ports()

        assert result == ([], [], [], [])


class TestIsIpfwIpv6Rule:
    """Tests for _is_ipfw_ipv6_rule method."""

    def test_ipv6_rule_with_ip6(self, parser):
        """Test detection of IPv6 rule with ip6 keyword."""
        line = "00100 allow ip6 tcp from any to any 22"
        assert parser._is_ipfw_ipv6_rule(line) is True

    def test_ipv6_rule_with_ipv6(self, parser):
        """Test detection of IPv6 rule with ipv6 keyword."""
        line = "00100 allow ipv6 tcp from any to any 22"
        assert parser._is_ipfw_ipv6_rule(line) is True

    def test_ipv4_rule(self, parser):
        """Test IPv4 rule detection."""
        line = "00100 allow tcp from any to any 22"
        assert parser._is_ipfw_ipv6_rule(line) is False

    def test_ipv6_case_insensitive(self, parser):
        """Test case insensitive detection of IPv6."""
        line = "00100 allow IP6 tcp from any to any 22"
        assert parser._is_ipfw_ipv6_rule(line) is True


class TestExtractIpfwPortDstPort:
    """Tests for _extract_ipfw_port_dst_port method."""

    def test_extract_dst_port(self, parser):
        """Test extracting port from dst-port format."""
        line = "00100 allow tcp from any to any dst-port 80"
        assert parser._extract_ipfw_port_dst_port(line) == "80"

    def test_extract_dst_port_with_comma(self, parser):
        """Test extracting port from dst-port with trailing comma."""
        line = "00100 allow tcp from any to any dst-port 443,"
        assert parser._extract_ipfw_port_dst_port(line) == "443"

    def test_no_dst_port(self, parser):
        """Test line without dst-port."""
        line = "00100 allow tcp from any to any 80"
        assert parser._extract_ipfw_port_dst_port(line) is None

    def test_dst_port_case_mismatch(self, parser):
        """Test dst-port with different casing (covers line 221).

        The check uses lowercase but the split uses exact case.
        When casing differs (e.g., DST-PORT), the split won't find it.
        """
        line = "00100 allow tcp from any to any DST-PORT 80"
        # The lowercase check passes, but split("dst-port") returns only 1 part
        result = parser._extract_ipfw_port_dst_port(line)
        assert result is None

    def test_dst_port_no_value(self, parser):
        """Test dst-port at end of line without value raises IndexError.

        Note: This documents current behavior - the method raises IndexError
        when dst-port has no following value. This is an edge case that
        would need to be handled if encountered in practice.
        """
        line = "00100 allow tcp from any to any dst-port"
        # The split results in parts with len > 1 but part[1] is empty
        # When strip().split() is called on empty string, it returns []
        # which causes IndexError on [0] access
        with pytest.raises(IndexError):
            parser._extract_ipfw_port_dst_port(line)


class TestExtractIpfwPortToAny:
    """Tests for _extract_ipfw_port_to_any method."""

    def test_extract_to_any_port(self, parser):
        """Test extracting port from 'to any <port>' format."""
        line = "00100 allow tcp from any to any 22"
        assert parser._extract_ipfw_port_to_any(line) == "22"

    def test_no_to_any_pattern(self, parser):
        """Test line without 'to any' pattern."""
        line = "00100 allow tcp from any dst-port 80"
        assert parser._extract_ipfw_port_to_any(line) is None

    def test_to_any_without_port(self, parser):
        """Test 'to any' without following port number."""
        line = "00100 allow tcp from any to any"
        assert parser._extract_ipfw_port_to_any(line) is None

    def test_to_any_with_non_digit(self, parser):
        """Test 'to any' followed by non-digit word."""
        line = "00100 allow tcp from any to any setup"
        assert parser._extract_ipfw_port_to_any(line) is None


class TestExtractIpfwPort:
    """Tests for _extract_ipfw_port method."""

    def test_extract_from_dst_port(self, parser):
        """Test extracting port from dst-port format."""
        line = "00100 allow tcp from any to any dst-port 8080"
        assert parser._extract_ipfw_port(line) == "8080"

    def test_extract_from_to_any(self, parser):
        """Test extracting port from 'to any' format."""
        line = "00100 allow tcp from any to any 443"
        assert parser._extract_ipfw_port(line) == "443"

    def test_dst_port_takes_precedence(self, parser):
        """Test that dst-port extraction is tried first."""
        line = "00100 allow tcp from any to any 22 dst-port 80"
        assert parser._extract_ipfw_port(line) == "80"


class TestShouldSkipIpfwLine:
    """Tests for _should_skip_ipfw_line method."""

    def test_skip_deny_rule(self, parser):
        """Test that deny rules are skipped."""
        line = "00100 deny tcp from any to any dst-port 22"
        assert parser._should_skip_ipfw_line(line) is True

    def test_skip_generic_allow(self, parser):
        """Test that generic allow without protocol is skipped."""
        line = "00100 allow ip from any to any"
        assert parser._should_skip_ipfw_line(line) is True

    def test_allow_tcp_not_skipped(self, parser):
        """Test that allow tcp rule is not skipped."""
        line = "00100 allow tcp from any to any dst-port 80"
        assert parser._should_skip_ipfw_line(line) is False

    def test_allow_udp_not_skipped(self, parser):
        """Test that allow udp rule is not skipped."""
        line = "00100 allow udp from any to any dst-port 53"
        assert parser._should_skip_ipfw_line(line) is False

    def test_skip_line_without_allow(self, parser):
        """Test that lines without allow are skipped."""
        line = "00100 count tcp from any to any"
        assert parser._should_skip_ipfw_line(line) is True


class TestProcessIpfwRule:
    """Tests for _process_ipfw_rule method."""

    def test_skip_deny_rule(self, parser):
        """Test that deny rules are skipped."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "00100 deny tcp from any to any dst-port 22"
        parser._process_ipfw_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp

    def test_process_tcp_ipv4_rule(self, parser):
        """Test processing TCP IPv4 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "00100 allow tcp from any to any dst-port 80"
        parser._process_ipfw_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv4_tcp == ["80"]
        assert not ipv4_udp

    def test_process_udp_ipv4_rule(self, parser):
        """Test processing UDP IPv4 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "00100 allow udp from any to any dst-port 53"
        parser._process_ipfw_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp
        assert ipv4_udp == ["53"]

    def test_process_tcp_ipv6_rule(self, parser):
        """Test processing TCP IPv6 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "00100 allow ip6 tcp from any to any dst-port 443"
        parser._process_ipfw_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp
        assert ipv6_tcp == ["443"]

    def test_process_udp_ipv6_rule(self, parser):
        """Test processing UDP IPv6 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "00100 allow ip6 udp from any to any dst-port 123"
        parser._process_ipfw_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv6_udp == ["123"]

    def test_tcp_rule_without_port(self, parser):
        """Test TCP rule without extractable port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "00100 allow tcp from any to me"
        parser._process_ipfw_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp

    def test_udp_rule_without_port(self, parser):
        """Test UDP rule without extractable port."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "00100 allow udp from any to me"
        parser._process_ipfw_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_udp


class TestParseIpfwRules:
    """Tests for parse_ipfw_rules method."""

    def test_parse_multiple_rules(self, parser):
        """Test parsing multiple ipfw rules."""
        output = """00100 allow tcp from any to any dst-port 22
00200 allow tcp from any to any dst-port 80
00300 allow udp from any to any dst-port 53
00400 allow ip6 tcp from any to any dst-port 443
00500 deny tcp from any to any"""

        result = parser.parse_ipfw_rules(output)

        ipv4_tcp, ipv4_udp, ipv6_tcp, _ipv6_udp = result
        assert "22" in ipv4_tcp
        assert "80" in ipv4_tcp
        assert "53" in ipv4_udp
        assert "443" in ipv6_tcp

    def test_parse_empty_output(self, parser):
        """Test parsing empty output."""
        result = parser.parse_ipfw_rules("")
        assert result == ([], [], [], [])

    def test_parse_rules_with_to_any_format(self, parser):
        """Test parsing rules with 'to any <port>' format."""
        output = "00100 allow tcp from any to any 8080"
        result = parser.parse_ipfw_rules(output)
        ipv4_tcp, _, _, _ = result
        assert "8080" in ipv4_tcp


class TestIsNpfIpv6Rule:
    """Tests for _is_npf_ipv6_rule method."""

    def test_ipv6_with_family_inet6(self, parser):
        """Test detection with 'family inet6'."""
        line = "pass in family inet6 proto tcp from any to any port 22"
        assert parser._is_npf_ipv6_rule(line) is True

    def test_ipv6_with_inet6(self, parser):
        """Test detection with 'inet6'."""
        line = "pass in inet6 proto tcp from any to any port 22"
        assert parser._is_npf_ipv6_rule(line) is True

    def test_ipv4_rule(self, parser):
        """Test IPv4 rule detection."""
        line = "pass in family inet proto tcp from any to any port 22"
        assert parser._is_npf_ipv6_rule(line) is False


class TestExtractNpfPortList:
    """Tests for _extract_npf_port_list method."""

    def test_extract_port_list(self, parser):
        """Test extracting port list."""
        port_part = "{ 80, 443, 8080 }"
        result = parser._extract_npf_port_list(port_part)
        assert result == ["80", "443", "8080"]

    def test_no_port_list(self, parser):
        """Test when no port list format."""
        port_part = "80"
        result = parser._extract_npf_port_list(port_part)
        assert result is None

    def test_unclosed_brace(self, parser):
        """Test port list with unclosed brace."""
        port_part = "{ 80, 443"
        result = parser._extract_npf_port_list(port_part)
        assert result is None


class TestExtractNpfPortRange:
    """Tests for _extract_npf_port_range method."""

    def test_extract_port_range(self, parser):
        """Test extracting port range."""
        port_part = "33434-33600"
        result = parser._extract_npf_port_range(port_part)
        assert result == ["33434-33600"]

    def test_no_port_range(self, parser):
        """Test when no port range format."""
        port_part = "80"
        result = parser._extract_npf_port_range(port_part)
        assert result is None


class TestExtractNpfSinglePort:
    """Tests for _extract_npf_single_port method."""

    def test_extract_single_port(self, parser):
        """Test extracting single port."""
        port_part = "80"
        result = parser._extract_npf_single_port(port_part)
        assert result == ["80"]

    def test_extract_port_with_comma(self, parser):
        """Test extracting port with trailing comma."""
        port_part = "443,"
        result = parser._extract_npf_single_port(port_part)
        assert result == ["443"]


class TestExtractNpfPorts:
    """Tests for _extract_npf_ports method."""

    def test_extract_single_port(self, parser):
        """Test extracting single port from rule."""
        line = "pass in proto tcp from any to any port 80"
        result = parser._extract_npf_ports(line)
        assert result == ["80"]

    def test_extract_port_list(self, parser):
        """Test extracting port list from rule."""
        line = "pass in proto tcp from any to any port { 80, 443, 8080 }"
        result = parser._extract_npf_ports(line)
        assert result == ["80", "443", "8080"]

    def test_extract_port_range(self, parser):
        """Test extracting port range from rule."""
        line = "pass in proto udp from any to any port 33434-33600"
        result = parser._extract_npf_ports(line)
        assert result == ["33434-33600"]

    def test_no_port_keyword(self, parser):
        """Test rule without port keyword."""
        line = "pass in proto tcp from any to any"
        result = parser._extract_npf_ports(line)
        assert result is None


class TestGetNpfProtocol:
    """Tests for _get_npf_protocol method."""

    def test_proto_tcp(self, parser):
        """Test detection of proto tcp."""
        line = "pass in proto tcp from any to any port 80"
        assert parser._get_npf_protocol(line) == "tcp"

    def test_proto_udp(self, parser):
        """Test detection of proto udp."""
        line = "pass in proto udp from any to any port 53"
        assert parser._get_npf_protocol(line) == "udp"

    def test_space_tcp(self, parser):
        """Test detection of tcp with spaces."""
        line = "pass in tcp from any to any port 80"
        assert parser._get_npf_protocol(line) == "tcp"

    def test_space_udp(self, parser):
        """Test detection of udp with spaces."""
        line = "pass in udp from any to any port 53"
        assert parser._get_npf_protocol(line) == "udp"

    def test_no_protocol(self, parser):
        """Test rule without protocol specified."""
        line = "pass in from any to any port 80"
        assert parser._get_npf_protocol(line) == "both"

    def test_other_protocol(self, parser):
        """Test rule with other protocol."""
        line = "pass in proto icmp from any to any"
        assert parser._get_npf_protocol(line) is None


class TestProcessNpfRule:
    """Tests for _process_npf_rule method."""

    def test_skip_non_pass_rule(self, parser):
        """Test that non-pass rules are skipped."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "block in proto tcp from any to any port 22"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp

    def test_skip_rule_without_port(self, parser):
        """Test that rules without port are skipped."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in proto tcp from any to any"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp

    def test_process_tcp_ipv4_rule(self, parser):
        """Test processing TCP IPv4 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in proto tcp from any to any port 80"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv4_tcp == ["80"]

    def test_process_udp_ipv4_rule(self, parser):
        """Test processing UDP IPv4 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in proto udp from any to any port 53"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv4_udp == ["53"]

    def test_process_tcp_ipv6_rule(self, parser):
        """Test processing TCP IPv6 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in family inet6 proto tcp from any to any port 443"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv6_tcp == ["443"]

    def test_process_udp_ipv6_rule(self, parser):
        """Test processing UDP IPv6 rule."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in inet6 proto udp from any to any port 123"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv6_udp == ["123"]

    def test_process_both_protocols_ipv4(self, parser):
        """Test processing rule without protocol (both) for IPv4."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in from any to any port 8080"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv4_tcp == ["8080"]
        assert ipv4_udp == ["8080"]

    def test_process_both_protocols_ipv6(self, parser):
        """Test processing rule without protocol (both) for IPv6."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in inet6 from any to any port 9000"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert ipv6_tcp == ["9000"]
        assert ipv6_udp == ["9000"]

    def test_process_port_list(self, parser):
        """Test processing rule with port list."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in proto tcp from any to any port { 80, 443, 8080 }"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert "80" in ipv4_tcp
        assert "443" in ipv4_tcp
        assert "8080" in ipv4_tcp

    def test_skip_rule_with_other_protocol(self, parser):
        """Test that rules with non-tcp/udp protocols are skipped."""
        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
        line = "pass in proto icmp from any to any port 80"
        parser._process_npf_rule(line, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        assert not ipv4_tcp


class TestParseNpfRules:
    """Tests for parse_npf_rules method."""

    def test_parse_multiple_rules(self, parser):
        """Test parsing multiple npf rules."""
        output = """pass in proto tcp from any to any port 22
pass in proto tcp from any to any port { 80, 443 }
pass in proto udp from any to any port 53
pass in family inet6 proto tcp from any to any port 8080
block in proto tcp from any to any port 25"""

        result = parser.parse_npf_rules(output)

        ipv4_tcp, ipv4_udp, ipv6_tcp, _ipv6_udp = result
        assert "22" in ipv4_tcp
        assert "80" in ipv4_tcp
        assert "443" in ipv4_tcp
        assert "53" in ipv4_udp
        assert "8080" in ipv6_tcp
        # Port 25 should not be included (block rule)
        assert "25" not in ipv4_tcp

    def test_parse_empty_output(self, parser):
        """Test parsing empty output."""
        result = parser.parse_npf_rules("")
        assert result == ([], [], [], [])

    def test_parse_rules_with_port_ranges(self, parser):
        """Test parsing rules with port ranges."""
        output = "pass in proto udp from any to any port 33434-33600"
        result = parser.parse_npf_rules(output)
        _, ipv4_udp, _, _ = result
        assert "33434-33600" in ipv4_udp


class TestIntegration:
    """Integration tests for the BSD firewall parsers."""

    def test_mixed_pf_rules(self, parser):
        """Test parsing a mix of pf rules."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
# SSH access
pass in on em0 proto tcp from any to any port 22
# Web server
pass in on em0 proto tcp from any to any port 80
pass in on em0 proto tcp from any to any port 443
# DNS
pass in on em0 proto udp from any to any port 53
# Block everything else
block in on em0 all
# IPv6 services
pass in on em0 inet6 proto tcp from any to any port 22
pass in on em0 inet6 proto tcp from any to any port 80
"""
        with patch("subprocess.run", return_value=mock_result):
            result = parser.get_pf_ports()

        ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = result
        assert len(ipv4_tcp) == 3  # 22, 80, 443
        assert len(ipv4_udp) == 1  # 53
        assert len(ipv6_tcp) == 2  # 22, 80
        assert len(ipv6_udp) == 0

    def test_complex_ipfw_rules(self, parser):
        """Test parsing complex ipfw rules."""
        output = """00010 allow ip from any to any via lo0
00020 deny ip from 127.0.0.0/8 to any in
00100 allow tcp from any to any dst-port 22 in via em0 setup keep-state
00200 allow tcp from any to any dst-port 80,443 in via em0 setup keep-state
00300 allow udp from any to any dst-port 53 in via em0 keep-state
00400 allow ip6 tcp from any to any dst-port 22 in via em0 setup keep-state
65535 deny ip from any to any"""

        result = parser.parse_ipfw_rules(output)

        ipv4_tcp, ipv4_udp, ipv6_tcp, _ = result
        assert "22" in ipv4_tcp
        assert "80,443" in ipv4_tcp  # This is extracted as a single string
        assert "53" in ipv4_udp
        assert "22" in ipv6_tcp

    def test_complex_npf_rules(self, parser):
        """Test parsing complex npf rules."""
        output = """group default {
    pass in proto tcp from any to any port 22
    pass in proto tcp from any to any port { 80, 443 }
    pass in proto udp from any to any port 53
    pass in proto udp from any to any port 33434-33600
    pass in family inet6 proto tcp from any to any port { 22, 80, 443 }
    block all
}"""

        result = parser.parse_npf_rules(output)

        ipv4_tcp, ipv4_udp, ipv6_tcp, _ = result
        assert "22" in ipv4_tcp
        assert "80" in ipv4_tcp
        assert "443" in ipv4_tcp
        assert "53" in ipv4_udp
        assert "33434-33600" in ipv4_udp
        assert "22" in ipv6_tcp
        assert "80" in ipv6_tcp
        assert "443" in ipv6_tcp
