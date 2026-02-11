"""
Unit tests for src.sysmanage_agent.operations.firewall_collector module.
Tests firewall status collection across different operating systems.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import json
import subprocess
from unittest.mock import Mock, patch

import pytest

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

    def test_build_firewall_status_legacy_empty_ports(self):
        """Test building legacy status with empty port lists."""
        status = self.collector._build_firewall_status_legacy(
            name="iptables",
            enabled=False,
            ipv4_tcp_ports=[],
            ipv4_udp_ports=[],
        )

        assert status["firewall_name"] == "iptables"
        assert status["enabled"] is False
        assert status["tcp_open_ports"] is None
        assert status["udp_open_ports"] is None
        assert status["ipv4_ports"] is None
        assert status["ipv6_ports"] is None

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

    def test_is_npf_enabled_case_insensitive(self):
        """Test NPF detection is case insensitive."""
        output = "# FILTERING:    ACTIVE"
        assert self.collector._is_npf_enabled(output) is True

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

    def test_is_ipfw_enabled_timeout(self):
        """Test detecting IPFW when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("sysctl", 5),
        ):
            assert self.collector._is_ipfw_enabled() is False


class TestCollectFirewallStatus:
    """Test cases for the main collect_firewall_status method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_firewall_status_linux(self):
        """Test collecting firewall status on Linux."""
        self.collector.system = "Linux"
        expected_result = {
            "firewall_name": "ufw",
            "enabled": True,
            "tcp_open_ports": '["22"]',
            "udp_open_ports": None,
            "ipv4_ports": '[{"port": "22", "protocols": ["tcp"]}]',
            "ipv6_ports": None,
        }

        with patch.object(
            self.collector, "_collect_linux_firewall", return_value=expected_result
        ):
            result = self.collector.collect_firewall_status()
            assert result == expected_result

    def test_collect_firewall_status_windows(self):
        """Test collecting firewall status on Windows."""
        self.collector.system = "Windows"
        expected_result = {
            "firewall_name": "Windows Firewall",
            "enabled": True,
            "tcp_open_ports": '["80"]',
            "udp_open_ports": None,
            "ipv4_ports": '[{"port": "80", "protocols": ["tcp"]}]',
            "ipv6_ports": None,
        }

        with patch.object(
            self.collector, "_collect_windows_firewall", return_value=expected_result
        ):
            result = self.collector.collect_firewall_status()
            assert result == expected_result

    def test_collect_firewall_status_macos(self):
        """Test collecting firewall status on macOS."""
        self.collector.system = "Darwin"
        expected_result = {
            "firewall_name": "pf (Packet Filter)",
            "enabled": True,
            "tcp_open_ports": '["443"]',
            "udp_open_ports": None,
            "ipv4_ports": '[{"port": "443", "protocols": ["tcp"]}]',
            "ipv6_ports": None,
        }

        with patch.object(
            self.collector, "_collect_macos_firewall", return_value=expected_result
        ):
            result = self.collector.collect_firewall_status()
            assert result == expected_result

    @pytest.mark.parametrize("bsd_system", ["FreeBSD", "OpenBSD", "NetBSD"])
    def test_collect_firewall_status_bsd(self, bsd_system):
        """Test collecting firewall status on BSD systems."""
        self.collector.system = bsd_system
        expected_result = {
            "firewall_name": "pf",
            "enabled": True,
            "tcp_open_ports": '["22"]',
            "udp_open_ports": None,
            "ipv4_ports": '[{"port": "22", "protocols": ["tcp"]}]',
            "ipv6_ports": None,
        }

        with patch.object(
            self.collector, "_collect_bsd_firewall", return_value=expected_result
        ):
            result = self.collector.collect_firewall_status()
            assert result == expected_result

    def test_collect_firewall_status_unsupported_os(self):
        """Test collecting firewall status on unsupported OS."""
        self.collector.system = "SomeUnknownOS"
        result = self.collector.collect_firewall_status()

        assert result["firewall_name"] is None
        assert result["enabled"] is False

    def test_collect_firewall_status_exception(self):
        """Test collecting firewall status when exception occurs."""
        self.collector.system = "Linux"

        with patch.object(
            self.collector,
            "_collect_linux_firewall",
            side_effect=Exception("Test error"),
        ):
            result = self.collector.collect_firewall_status()

            assert result["firewall_name"] is None
            assert result["enabled"] is False


class TestCollectLinuxFirewall:
    """Test cases for Linux firewall collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_linux_firewall_ufw(self):
        """Test collecting Linux firewall when UFW is available."""
        expected = {"firewall_name": "ufw", "enabled": True}

        with patch.object(self.collector, "_collect_ufw", return_value=expected):
            result = self.collector._collect_linux_firewall()
            assert result == expected

    def test_collect_linux_firewall_firewalld(self):
        """Test collecting Linux firewall when firewalld is available."""
        expected = {"firewall_name": "firewalld", "enabled": True}

        with patch.object(self.collector, "_collect_ufw", return_value=None):
            with patch.object(
                self.collector, "_collect_firewalld", return_value=expected
            ):
                result = self.collector._collect_linux_firewall()
                assert result == expected

    def test_collect_linux_firewall_iptables(self):
        """Test collecting Linux firewall when iptables is available."""
        expected = {"firewall_name": "iptables", "enabled": True}

        with patch.object(self.collector, "_collect_ufw", return_value=None):
            with patch.object(self.collector, "_collect_firewalld", return_value=None):
                with patch.object(
                    self.collector, "_collect_iptables", return_value=expected
                ):
                    result = self.collector._collect_linux_firewall()
                    assert result == expected

    def test_collect_linux_firewall_nftables(self):
        """Test collecting Linux firewall when nftables is available."""
        expected = {"firewall_name": "nftables", "enabled": True}

        with patch.object(self.collector, "_collect_ufw", return_value=None):
            with patch.object(self.collector, "_collect_firewalld", return_value=None):
                with patch.object(
                    self.collector, "_collect_iptables", return_value=None
                ):
                    with patch.object(
                        self.collector, "_collect_nftables", return_value=expected
                    ):
                        result = self.collector._collect_linux_firewall()
                        assert result == expected

    def test_collect_linux_firewall_none_found(self):
        """Test collecting Linux firewall when none is found."""
        with patch.object(self.collector, "_collect_ufw", return_value=None):
            with patch.object(self.collector, "_collect_firewalld", return_value=None):
                with patch.object(
                    self.collector, "_collect_iptables", return_value=None
                ):
                    with patch.object(
                        self.collector, "_collect_nftables", return_value=None
                    ):
                        result = self.collector._collect_linux_firewall()
                        assert result["firewall_name"] is None
                        assert result["enabled"] is False


class TestCollectUfw:
    """Test cases for UFW collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_ufw_active(self):
        """Test collecting active UFW status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
"""

        self.collector.linux_parsers.parse_ufw_rules = Mock(
            return_value=(["22", "80"], [], ["22"], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_ufw()

            assert result is not None
            assert result["firewall_name"] == "ufw"
            assert result["enabled"] is True

    def test_collect_ufw_inactive(self):
        """Test collecting inactive UFW status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Status: inactive"

        self.collector.linux_parsers.parse_ufw_rules = Mock(
            return_value=([], [], [], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_ufw()

            assert result is not None
            assert result["firewall_name"] == "ufw"
            assert result["enabled"] is False

    def test_collect_ufw_command_fails(self):
        """Test collecting UFW when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_ufw()
            assert result is None

    def test_collect_ufw_not_found(self):
        """Test collecting UFW when not installed."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_ufw()
            assert result is None

    def test_collect_ufw_timeout(self):
        """Test collecting UFW when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("ufw", 5),
        ):
            result = self.collector._collect_ufw()
            assert result is None


class TestCollectFirewalld:
    """Test cases for firewalld collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_firewalld_running(self):
        """Test collecting running firewalld status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "running"

        self.collector.linux_parsers.get_firewalld_ports = Mock(
            return_value=(["22", "80"], ["53"], ["22"], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_firewalld()

            assert result is not None
            assert result["firewall_name"] == "firewalld"
            assert result["enabled"] is True

    def test_collect_firewalld_not_running(self):
        """Test collecting firewalld when not running."""
        mock_result = Mock()
        mock_result.returncode = 252
        mock_result.stdout = "not running"

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_firewalld()

            assert result is not None
            assert result["firewall_name"] == "firewalld"
            assert result["enabled"] is False

    def test_collect_firewalld_command_failure_returns_disabled(self):
        """Test collecting firewalld when command returns non-zero."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_firewalld()

            assert result is not None
            assert result["firewall_name"] == "firewalld"
            assert result["enabled"] is False

    def test_collect_firewalld_not_found(self):
        """Test collecting firewalld when not installed."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_firewalld()
            assert result is None

    def test_collect_firewalld_timeout(self):
        """Test collecting firewalld when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("firewall-cmd", 5),
        ):
            result = self.collector._collect_firewalld()
            assert result is None

    def test_collect_firewalld_unknown_state(self):
        """Test collecting firewalld with unknown state output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "unknown state"

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_firewalld()
            assert result is None


class TestCollectIptables:
    """Test cases for iptables collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_iptables_with_rules(self):
        """Test collecting iptables with rules configured."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
"""

        self.collector.linux_parsers.parse_iptables_rules = Mock(
            return_value=(["22", "80", "443"], [], [], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_iptables()

            assert result is not None
            assert result["firewall_name"] == "iptables"
            assert result["enabled"] is True

    def test_collect_iptables_no_rules(self):
        """Test collecting iptables with minimal rules (not active)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
"""

        self.collector.linux_parsers.parse_iptables_rules = Mock(
            return_value=([], [], [], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_iptables()

            assert result is not None
            assert result["firewall_name"] == "iptables"
            assert result["enabled"] is False

    def test_collect_iptables_command_fails(self):
        """Test collecting iptables when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_iptables()
            assert result is None

    def test_collect_iptables_not_found(self):
        """Test collecting iptables when not installed."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_iptables()
            assert result is None

    def test_collect_iptables_timeout(self):
        """Test collecting iptables when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("iptables", 5),
        ):
            result = self.collector._collect_iptables()
            assert result is None


class TestCollectNftables:
    """Test cases for nftables collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_nftables_with_rules(self):
        """Test collecting nftables with rules configured."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport 22 accept
        tcp dport { 80, 443 } accept
    }
}
"""

        self.collector.linux_parsers.parse_nftables_rules = Mock(
            return_value=(["22", "80", "443"], [], [], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_nftables()

            assert result is not None
            assert result["firewall_name"] == "nftables"
            assert result["enabled"] is True

    def test_collect_nftables_empty_ruleset(self):
        """Test collecting nftables with empty ruleset."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_nftables()
            assert result is None

    def test_collect_nftables_command_fails(self):
        """Test collecting nftables when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_nftables()
            assert result is None

    def test_collect_nftables_not_found(self):
        """Test collecting nftables when not installed."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_nftables()
            assert result is None

    def test_collect_nftables_timeout(self):
        """Test collecting nftables when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("nft", 5),
        ):
            result = self.collector._collect_nftables()
            assert result is None


class TestCollectWindowsFirewall:
    """Test cases for Windows firewall collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_windows_firewall_enabled(self):
        """Test collecting enabled Windows Firewall status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Domain Profile Settings:
State                                 ON

Private Profile Settings:
State                                 ON

Public Profile Settings:
State                                 ON
"""

        self.collector.port_helpers.get_windows_firewall_ports = Mock(
            return_value=(["80", "443"], [], ["80", "443"], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_windows_firewall()

            assert result["firewall_name"] == "Windows Firewall"
            assert result["enabled"] is True

    def test_collect_windows_firewall_disabled(self):
        """Test collecting disabled Windows Firewall status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Domain Profile Settings:
State                                 OFF

Private Profile Settings:
State                                 OFF

Public Profile Settings:
State                                 OFF
"""

        self.collector.port_helpers.get_windows_firewall_ports = Mock(
            return_value=([], [], [], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_windows_firewall()

            assert result["firewall_name"] == "Windows Firewall"
            assert result["enabled"] is False

    def test_collect_windows_firewall_command_fails(self):
        """Test collecting Windows Firewall when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_windows_firewall()

            assert result["firewall_name"] is None
            assert result["enabled"] is False

    def test_collect_windows_firewall_not_found(self):
        """Test collecting Windows Firewall when netsh not found."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_windows_firewall()

            assert result["firewall_name"] is None
            assert result["enabled"] is False

    def test_collect_windows_firewall_timeout(self):
        """Test collecting Windows Firewall when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("netsh", 5),
        ):
            result = self.collector._collect_windows_firewall()

            assert result["firewall_name"] is None
            assert result["enabled"] is False

    def test_collect_windows_firewall_with_ports(self):
        """Test collecting Windows Firewall with ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "State                                 ON"

        self.collector.port_helpers.get_windows_firewall_ports = Mock(
            return_value=(["3389", "5985"], ["53"], ["3389"], [])
        )
        self.collector.port_helpers.merge_ports_with_protocols = Mock(
            side_effect=[
                [
                    {"port": "3389", "protocols": ["tcp"]},
                    {"port": "53", "protocols": ["udp"]},
                ],
                [{"port": "3389", "protocols": ["tcp"]}],
            ]
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_windows_firewall()

            assert result["firewall_name"] == "Windows Firewall"
            assert result["enabled"] is True
            assert result["tcp_open_ports"] is not None


class TestCollectMacosFirewall:
    """Test cases for macOS firewall collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_macos_firewall_enabled(self):
        """Test collecting enabled macOS pf status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Status: Enabled for 0 days 01:23:45
"""

        self.collector.bsd_parsers.get_pf_ports = Mock(
            return_value=(["22", "80"], [], ["22"], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_macos_firewall()

            assert result["firewall_name"] == "pf (Packet Filter)"
            assert result["enabled"] is True

    def test_collect_macos_firewall_disabled(self):
        """Test collecting disabled macOS pf status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Status: Disabled
"""

        self.collector.bsd_parsers.get_pf_ports = Mock(return_value=([], [], [], []))

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_macos_firewall()

            assert result["firewall_name"] == "pf (Packet Filter)"
            assert result["enabled"] is False

    def test_collect_macos_firewall_command_fails(self):
        """Test collecting macOS pf when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_macos_firewall()

            assert result["firewall_name"] is None
            assert result["enabled"] is False

    def test_collect_macos_firewall_not_found(self):
        """Test collecting macOS pf when pfctl not found."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_macos_firewall()

            assert result["firewall_name"] is None
            assert result["enabled"] is False

    def test_collect_macos_firewall_timeout(self):
        """Test collecting macOS pf when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("pfctl", 5),
        ):
            result = self.collector._collect_macos_firewall()

            assert result["firewall_name"] is None
            assert result["enabled"] is False

    def test_collect_macos_firewall_permission_error(self):
        """Test collecting macOS pf when permission denied."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=PermissionError(),
        ):
            result = self.collector._collect_macos_firewall()

            assert result["firewall_name"] is None
            assert result["enabled"] is False

    def test_collect_macos_firewall_with_ipv6_ports(self):
        """Test collecting macOS pf with IPv6 ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Status: Enabled"

        self.collector.bsd_parsers.get_pf_ports = Mock(
            return_value=(["22", "80"], ["53"], ["22", "80"], ["53"])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_macos_firewall()

            assert result["firewall_name"] == "pf (Packet Filter)"
            assert result["enabled"] is True
            assert result["tcp_open_ports"] is not None
            assert result["ipv6_ports"] is not None


class TestCollectBsdFirewall:
    """Test cases for BSD firewall collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_bsd_firewall_netbsd_npf(self):
        """Test collecting BSD firewall on NetBSD with NPF."""
        self.collector.system = "NetBSD"
        expected = {"firewall_name": "npf", "enabled": True}

        with patch.object(self.collector, "_collect_npf", return_value=expected):
            result = self.collector._collect_bsd_firewall()
            assert result == expected

    def test_collect_bsd_firewall_netbsd_pf_fallback(self):
        """Test collecting BSD firewall on NetBSD with pf fallback."""
        self.collector.system = "NetBSD"
        expected = {"firewall_name": "pf", "enabled": True}

        with patch.object(self.collector, "_collect_npf", return_value=None):
            with patch.object(self.collector, "_collect_pf", return_value=expected):
                result = self.collector._collect_bsd_firewall()
                assert result == expected

    def test_collect_bsd_firewall_freebsd_pf(self):
        """Test collecting BSD firewall on FreeBSD with pf."""
        self.collector.system = "FreeBSD"
        expected = {"firewall_name": "pf", "enabled": True}

        with patch.object(self.collector, "_collect_pf", return_value=expected):
            result = self.collector._collect_bsd_firewall()
            assert result == expected

    def test_collect_bsd_firewall_freebsd_ipfw_fallback(self):
        """Test collecting BSD firewall on FreeBSD with ipfw fallback."""
        self.collector.system = "FreeBSD"
        expected = {"firewall_name": "ipfw", "enabled": True}

        with patch.object(self.collector, "_collect_pf", return_value=None):
            with patch.object(self.collector, "_collect_ipfw", return_value=expected):
                result = self.collector._collect_bsd_firewall()
                assert result == expected

    def test_collect_bsd_firewall_openbsd_pf(self):
        """Test collecting BSD firewall on OpenBSD with pf."""
        self.collector.system = "OpenBSD"
        expected = {"firewall_name": "pf", "enabled": True}

        with patch.object(self.collector, "_collect_pf", return_value=expected):
            result = self.collector._collect_bsd_firewall()
            assert result == expected

    def test_collect_bsd_firewall_none_found(self):
        """Test collecting BSD firewall when none is found."""
        self.collector.system = "FreeBSD"

        with patch.object(self.collector, "_collect_pf", return_value=None):
            with patch.object(self.collector, "_collect_ipfw", return_value=None):
                result = self.collector._collect_bsd_firewall()
                assert result["firewall_name"] is None
                assert result["enabled"] is False


class TestCollectNpf:
    """Test cases for NPF (NetBSD) collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_npf_active(self):
        """Test collecting active NPF status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """# filtering:    active
# some other info
"""

        self.collector.bsd_parsers.parse_npf_rules = Mock(
            return_value=(["22", "80"], [], [], [])
        )

        with patch.object(self.collector, "_is_npf_enabled", return_value=True):
            with patch.object(
                self.collector,
                "_get_npf_ports",
                return_value=(["22", "80"], [], [], []),
            ):
                with patch(
                    "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
                    return_value=mock_result,
                ):
                    result = self.collector._collect_npf()

                    assert result is not None
                    assert result["firewall_name"] == "npf"
                    assert result["enabled"] is True

    def test_collect_npf_inactive(self):
        """Test collecting inactive NPF status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "# filtering:    inactive"

        with patch.object(self.collector, "_is_npf_enabled", return_value=False):
            with patch.object(
                self.collector, "_get_npf_ports", return_value=([], [], [], [])
            ):
                with patch(
                    "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
                    return_value=mock_result,
                ):
                    result = self.collector._collect_npf()

                    assert result is not None
                    assert result["firewall_name"] == "npf"
                    assert result["enabled"] is False

    def test_collect_npf_command_fails(self):
        """Test collecting NPF when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_npf()
            assert result is None

    def test_collect_npf_not_found(self):
        """Test collecting NPF when npfctl not found."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_npf()
            assert result is None

    def test_collect_npf_timeout(self):
        """Test collecting NPF when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("npfctl", 5),
        ):
            result = self.collector._collect_npf()
            assert result is None

    def test_collect_npf_permission_error(self):
        """Test collecting NPF when permission denied."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=PermissionError(),
        ):
            result = self.collector._collect_npf()
            assert result is None


class TestCollectPf:
    """Test cases for pf (OpenBSD/FreeBSD) collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_pf_enabled(self):
        """Test collecting enabled pf status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Status: Enabled for 0 days 01:23:45
"""

        self.collector.bsd_parsers.get_pf_ports = Mock(
            return_value=(["22", "80"], [], ["22"], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_pf()

            assert result is not None
            assert result["firewall_name"] == "pf"
            assert result["enabled"] is True

    def test_collect_pf_disabled(self):
        """Test collecting disabled pf status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Status: Disabled
"""

        self.collector.bsd_parsers.get_pf_ports = Mock(return_value=([], [], [], []))

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_pf()

            assert result is not None
            assert result["firewall_name"] == "pf"
            assert result["enabled"] is False

    def test_collect_pf_command_fails(self):
        """Test collecting pf when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_pf()
            assert result is None

    def test_collect_pf_not_found(self):
        """Test collecting pf when pfctl not found."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_pf()
            assert result is None

    def test_collect_pf_timeout(self):
        """Test collecting pf when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("pfctl", 5),
        ):
            result = self.collector._collect_pf()
            assert result is None

    def test_collect_pf_permission_error(self):
        """Test collecting pf when permission denied."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=PermissionError(),
        ):
            result = self.collector._collect_pf()
            assert result is None


class TestCollectIpfw:
    """Test cases for ipfw (FreeBSD) collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_collect_ipfw_enabled(self):
        """Test collecting enabled ipfw status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """00100 allow tcp from any to any 22
00200 allow tcp from any to any 80
65535 deny ip from any to any
"""

        self.collector.bsd_parsers.parse_ipfw_rules = Mock(
            return_value=(["22", "80"], [], [], [])
        )

        with patch.object(self.collector, "_is_ipfw_enabled", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
                return_value=mock_result,
            ):
                result = self.collector._collect_ipfw()

                assert result is not None
                assert result["firewall_name"] == "ipfw"
                assert result["enabled"] is True

    def test_collect_ipfw_disabled(self):
        """Test collecting disabled ipfw status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "65535 deny ip from any to any"

        self.collector.bsd_parsers.parse_ipfw_rules = Mock(
            return_value=([], [], [], [])
        )

        with patch.object(self.collector, "_is_ipfw_enabled", return_value=False):
            with patch(
                "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
                return_value=mock_result,
            ):
                result = self.collector._collect_ipfw()

                assert result is not None
                assert result["firewall_name"] == "ipfw"
                assert result["enabled"] is False

    def test_collect_ipfw_empty_output(self):
        """Test collecting ipfw with empty output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_ipfw()
            assert result is None

    def test_collect_ipfw_command_fails(self):
        """Test collecting ipfw when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector._collect_ipfw()
            assert result is None

    def test_collect_ipfw_not_found(self):
        """Test collecting ipfw when not found."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = self.collector._collect_ipfw()
            assert result is None

    def test_collect_ipfw_timeout(self):
        """Test collecting ipfw when command times out."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("ipfw", 5),
        ):
            result = self.collector._collect_ipfw()
            assert result is None

    def test_collect_ipfw_permission_error(self):
        """Test collecting ipfw when permission denied."""
        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            side_effect=PermissionError(),
        ):
            result = self.collector._collect_ipfw()
            assert result is None


class TestIntegrationScenarios:
    """Integration test scenarios for firewall collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = FirewallCollector()

    def test_full_linux_ufw_collection(self):
        """Test full Linux UFW collection scenario."""
        self.collector.system = "Linux"

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
80/tcp (v6)                ALLOW       Anywhere (v6)
443/tcp (v6)               ALLOW       Anywhere (v6)
"""

        self.collector.linux_parsers.parse_ufw_rules = Mock(
            return_value=(["22", "80", "443"], [], ["22", "80", "443"], [])
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector.collect_firewall_status()

            assert result["firewall_name"] == "ufw"
            assert result["enabled"] is True
            assert result["tcp_open_ports"] is not None
            tcp_ports = json.loads(result["tcp_open_ports"])
            assert "22" in tcp_ports
            assert "80" in tcp_ports
            assert "443" in tcp_ports

    def test_windows_firewall_with_empty_ports(self):
        """Test Windows Firewall collection with no open ports."""
        self.collector.system = "Windows"

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "State                                 ON"

        self.collector.port_helpers.get_windows_firewall_ports = Mock(
            return_value=([], [], [], [])
        )
        self.collector.port_helpers.merge_ports_with_protocols = Mock(return_value=[])

        with patch(
            "src.sysmanage_agent.operations.firewall_collector.subprocess.run",
            return_value=mock_result,
        ):
            result = self.collector.collect_firewall_status()

            assert result["firewall_name"] == "Windows Firewall"
            assert result["enabled"] is True
            assert result["tcp_open_ports"] is None
            assert result["udp_open_ports"] is None
