# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Unit tests for src.sysmanage_agent.operations.firewall_collector module.
Tests platform-specific firewall status collection (Windows, macOS, BSD).
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import json
import subprocess
from unittest.mock import Mock, patch

from src.sysmanage_agent.operations.firewall_collector import FirewallCollector


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
