"""
Unit tests for src.sysmanage_agent.operations.firewall_collector module.
Tests firewall status collection across different operating systems.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import json
from unittest.mock import Mock, patch

from src.sysmanage_agent.operations.firewall_collector import FirewallCollector


class TestFirewallCollectorInit:
    """Test cases for FirewallCollector initialization."""

    def test_init_with_logger(self):
        """Test FirewallCollector initialization with custom logger."""
        mock_logger = Mock()
        collector = FirewallCollector(logger=mock_logger)
        assert collector.logger == mock_logger

    def test_init_without_logger(self):
        """Test FirewallCollector initialization without logger."""
        collector = FirewallCollector()
        assert collector.logger is not None

    def test_init_creates_helper_modules(self):
        """Test that helper modules are created on init."""
        collector = FirewallCollector()
        assert collector.linux_parsers is not None
        assert collector.bsd_parsers is not None
        assert collector.port_helpers is not None


class TestEmptyStatus:
    """Test cases for empty status generation."""

    def test_empty_status(self):
        """Test _empty_status returns correct structure."""
        collector = FirewallCollector()
        status = collector._empty_status()

        assert status["firewall_name"] is None
        assert status["enabled"] is False
        assert status["tcp_open_ports"] is None
        assert status["udp_open_ports"] is None
        assert status["ipv4_ports"] is None
        assert status["ipv6_ports"] is None


class TestBuildFirewallStatus:
    """Test cases for building firewall status dictionaries."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_build_firewall_status_with_ipv6(self):
        """Test building status with full IPv4/IPv6 separation."""
        status = self.collector._build_firewall_status_with_ipv6(
            name="ufw",
            enabled=True,
            ipv4_tcp_ports=["22", "80"],
            ipv4_udp_ports=["53"],
            ipv6_tcp_ports=["22"],
            ipv6_udp_ports=[],
        )

        assert status["firewall_name"] == "ufw"
        assert status["enabled"] is True

        tcp_ports = json.loads(status["tcp_open_ports"])
        assert "22" in tcp_ports
        assert "80" in tcp_ports

        udp_ports = json.loads(status["udp_open_ports"])
        assert "53" in udp_ports

        ipv4_ports = json.loads(status["ipv4_ports"])
        assert any(p["port"] == "22" for p in ipv4_ports)

        ipv6_ports = json.loads(status["ipv6_ports"])
        assert any(p["port"] == "22" for p in ipv6_ports)

    def test_build_firewall_status_with_ipv6_empty_ports(self):
        """Test building status with empty port lists."""
        status = self.collector._build_firewall_status_with_ipv6(
            name="ufw",
            enabled=True,
            ipv4_tcp_ports=[],
            ipv4_udp_ports=[],
            ipv6_tcp_ports=[],
            ipv6_udp_ports=[],
        )

        assert status["firewall_name"] == "ufw"
        assert status["enabled"] is True
        assert status["tcp_open_ports"] is None
        assert status["udp_open_ports"] is None
        assert status["ipv4_ports"] is None
        assert status["ipv6_ports"] is None

    def test_build_firewall_status_legacy(self):
        """Test building legacy status (IPv4-only)."""
        status = self.collector._build_firewall_status_legacy(
            name="iptables",
            enabled=True,
            ipv4_tcp_ports=["22", "80"],
            ipv4_udp_ports=["53"],
        )

        assert status["firewall_name"] == "iptables"
        assert status["enabled"] is True
        assert status["ipv6_ports"] is None

        tcp_ports = json.loads(status["tcp_open_ports"])
        assert "22" in tcp_ports
        assert "80" in tcp_ports

    def test_build_disabled_status(self):
        """Test building disabled firewall status."""
        status = self.collector._build_disabled_status("firewalld")

        assert status["firewall_name"] == "firewalld"
        assert status["enabled"] is False
        assert status["tcp_open_ports"] is None
        assert status["udp_open_ports"] is None
        assert status["ipv4_ports"] is None
        assert status["ipv6_ports"] is None


class TestNpfHelpers:
    """Test cases for NPF firewall helpers."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_is_npf_enabled_active(self):
        """Test detecting NPF as active."""
        output = "# filtering:    active"
        assert self.collector._is_npf_enabled(output) is True

    def test_is_npf_enabled_inactive(self):
        """Test detecting NPF as inactive."""
        output = "# filtering:    inactive"
        assert self.collector._is_npf_enabled(output) is False

    def test_is_npf_enabled_no_status(self):
        """Test detecting NPF without status line."""
        output = "some other output"
        assert self.collector._is_npf_enabled(output) is False

    def test_get_npf_ports_with_rules(self):
        """Test getting NPF ports from rules."""
        output = "pass in on inet proto tcp to any port 22"

        # Mock bsd_parsers to return parsed ports
        self.collector.bsd_parsers.parse_npf_rules = Mock(
            return_value=(["22"], [], [], [])
        )

        ipv4_tcp, _ipv4_udp, _ipv6_tcp, _ipv6_udp = self.collector._get_npf_ports(
            output
        )
        assert ipv4_tcp == ["22"]

    def test_get_npf_ports_fallback_to_listening(self):
        """Test falling back to listening ports when no NPF rules found."""
        output = ""

        # Mock bsd_parsers to return empty
        self.collector.bsd_parsers.parse_npf_rules = Mock(return_value=([], [], [], []))

        # Mock port_helpers to return listening ports
        self.collector.port_helpers.get_listening_ports = Mock(
            return_value=(["22", "80"], [], ["22"], [])
        )

        ipv4_tcp, _ipv4_udp, _ipv6_tcp, _ipv6_udp = self.collector._get_npf_ports(
            output
        )
        assert "22" in ipv4_tcp
        assert "80" in ipv4_tcp


class TestIpfwHelpers:
    """Test cases for IPFW firewall helpers."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_is_ipfw_enabled_true(self):
        """Test detecting IPFW as enabled."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "1"

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            assert self.collector._is_ipfw_enabled() is True

    def test_is_ipfw_enabled_false(self):
        """Test detecting IPFW as disabled."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "0"

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            assert self.collector._is_ipfw_enabled() is False

    def test_is_ipfw_enabled_command_failure(self):
        """Test detecting IPFW when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            assert self.collector._is_ipfw_enabled() is False

    def test_is_ipfw_enabled_file_not_found(self):
        """Test detecting IPFW when sysctl not found."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            assert self.collector._is_ipfw_enabled() is False
