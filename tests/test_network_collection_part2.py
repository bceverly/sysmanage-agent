# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for network information collection (part 2).

Split from test_network_collection.py to keep files under the line limit.
Covers BSD, macOS, and Windows network collection, network statistics and
routing, multi-platform collection, and error handling.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init,unused-argument

import socket
import subprocess
from unittest.mock import Mock, mock_open, patch

import pytest

from src.sysmanage_agent.communication.network_utils import NetworkUtils
from src.sysmanage_agent.collection.hardware_collector_linux import (
    HardwareCollectorLinux,
)
from src.sysmanage_agent.collection.hardware_collector_bsd import HardwareCollectorBSD
from src.sysmanage_agent.collection.hardware_collector_macos import (
    HardwareCollectorMacOS,
)
from src.sysmanage_agent.collection.hardware_collector_windows import (
    HardwareCollectorWindows,
)


class TestBSDNetworkCollection:
    """Tests for BSD-specific network information collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = HardwareCollectorBSD()

    def test_get_network_info_success(self):
        """Test successful network collection on BSD."""
        ifconfig_output = """em0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 00:11:22:33:44:55
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2001:db8::1 prefixlen 64
\tmedia: Ethernet autoselect (1000baseT <full-duplex>)
em1: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tmedia: Ethernet autoselect
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 33200
\tinet 127.0.0.1 netmask 0xff000000
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ifconfig_output

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector.get_network_info()

        # Should have 2 interfaces (em0 and em1, not lo0)
        assert len(result) == 2

        em0 = next((i for i in result if i["name"] == "em0"), None)
        assert em0 is not None
        assert em0["mac_address"] == "00:11:22:33:44:55"
        assert em0["ipv4_address"] == "192.168.1.100"
        assert em0["ipv6_address"] == "2001:db8::1"
        assert em0["is_active"] is True

    def test_get_network_info_command_failure(self):
        """Test handling ifconfig command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector.get_network_info()

        assert not result

    def test_get_network_info_exception(self):
        """Test handling unexpected exception."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = self.collector.get_network_info()

        assert len(result) == 1
        assert "error" in result[0]

    def test_parse_interface_ether(self):
        """Test parsing MAC address from ether line."""
        interface = {"mac_address": ""}
        self.collector._parse_interface_ether("ether 00:11:22:33:44:55", interface)

        assert interface["mac_address"] == "00:11:22:33:44:55"

    def test_parse_interface_inet(self):
        """Test parsing IPv4 address and netmask."""
        interface = {"ipv4_address": None, "subnet_mask": None}
        self.collector._parse_interface_inet(
            "inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255", interface
        )

        assert interface["ipv4_address"] == "192.168.1.100"
        assert interface["subnet_mask"] == "255.255.255.0"

    def test_parse_interface_inet6_skips_link_local(self):
        """Test that link-local IPv6 addresses are skipped."""
        interface = {"ipv6_address": None}
        self.collector._parse_interface_inet6("inet6 fe80::1%em0", interface)

        assert interface["ipv6_address"] is None

    def test_parse_interface_inet6_global(self):
        """Test parsing global IPv6 address."""
        interface = {"ipv6_address": None}
        self.collector._parse_interface_inet6(
            "inet6 2001:db8::1 prefixlen 64", interface
        )

        assert interface["ipv6_address"] == "2001:db8::1"

    def test_parse_interface_media_ethernet(self):
        """Test parsing Ethernet media type."""
        interface = {"interface_type": "", "hardware_type": ""}
        self.collector._parse_interface_media("media: Ethernet autoselect", interface)

        assert interface["interface_type"] == "ethernet"
        assert interface["hardware_type"] == "ethernet"

    def test_parse_interface_media_wireless(self):
        """Test parsing wireless media type."""
        interface = {"interface_type": "", "hardware_type": ""}
        self.collector._parse_interface_media("media: IEEE802.11 autoselect", interface)

        assert interface["interface_type"] == "wireless"
        assert interface["hardware_type"] == "wireless"

    def test_detect_interface_header_new_interface(self):
        """Test detecting new interface header line."""
        result = self.collector._detect_interface_header(
            "em0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500",
            "em0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500",
        )

        assert result is not None
        assert result["name"] == "em0"
        assert result["is_active"] is True

    def test_detect_interface_header_loopback_skipped(self):
        """Test that loopback interface header returns empty dict."""
        result = self.collector._detect_interface_header(
            "lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 33200",
            "lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 33200",
        )

        assert not result

    def test_detect_interface_header_detail_line(self):
        """Test that detail lines are not detected as headers."""
        result = self.collector._detect_interface_header(
            "ether 00:11:22:33:44:55", "\tether 00:11:22:33:44:55"
        )

        assert result is None


class TestMacOSNetworkCollection:
    """Tests for macOS-specific network information collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = HardwareCollectorMacOS()

    def test_get_network_info_success(self):
        """Test successful network collection on macOS."""
        system_profiler_output = {
            "SPNetworkDataType": [
                {
                    "_name": "Wi-Fi",
                    "type": "Wi-Fi",
                    "hardware": "AirPort",
                    "interface": "en0",
                    "has_ip_assigned": True,
                },
                {
                    "_name": "Ethernet",
                    "type": "Ethernet",
                    "hardware": "Ethernet",
                    "interface": "en1",
                    "has_ip_assigned": False,
                },
            ]
        }

        ifconfig_output = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 00:11:22:33:44:55
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2001:db8::1 prefixlen 64
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
"""

        mock_profiler_result = Mock()
        mock_profiler_result.returncode = 0
        mock_profiler_result.stdout = __import__("json").dumps(system_profiler_output)

        mock_ifconfig_result = Mock()
        mock_ifconfig_result.returncode = 0
        mock_ifconfig_result.stdout = ifconfig_output

        def run_side_effect(cmd, **kwargs):
            if "system_profiler" in cmd:
                return mock_profiler_result
            if "ifconfig" in cmd:
                return mock_ifconfig_result
            return Mock(returncode=1)

        with patch("subprocess.run", side_effect=run_side_effect):
            result = self.collector.get_network_info()

        assert len(result) == 2

        wifi = next((i for i in result if i["name"] == "Wi-Fi"), None)
        assert wifi is not None
        assert wifi["mac_address"] == "00:11:22:33:44:55"
        assert wifi["ipv4_address"] == "192.168.1.100"

    def test_get_network_info_ifconfig_failure(self):
        """Test network collection when ifconfig fails."""
        system_profiler_output = {
            "SPNetworkDataType": [
                {"_name": "Wi-Fi", "type": "Wi-Fi", "interface": "en0"}
            ]
        }

        mock_profiler_result = Mock()
        mock_profiler_result.returncode = 0
        mock_profiler_result.stdout = __import__("json").dumps(system_profiler_output)

        mock_ifconfig_result = Mock()
        mock_ifconfig_result.returncode = 1
        mock_ifconfig_result.stdout = ""

        def run_side_effect(cmd, **kwargs):
            if "system_profiler" in cmd:
                return mock_profiler_result
            return mock_ifconfig_result

        with patch("subprocess.run", side_effect=run_side_effect):
            result = self.collector.get_network_info()

        # Should still return network interface from system_profiler
        assert len(result) == 1
        assert result[0]["name"] == "Wi-Fi"

    def test_parse_ifconfig_interface_details(self):
        """Test parsing ifconfig output into interface details."""
        ifconfig_output = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 00:11:22:33:44:55
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2001:db8::1 prefixlen 64
"""
        result = self.collector._parse_ifconfig_interface_details(ifconfig_output)

        assert "en0" in result
        assert result["en0"]["mac_address"] == "00:11:22:33:44:55"
        assert result["en0"]["ipv4_address"] == "192.168.1.100"
        assert result["en0"]["is_active"] is True

    def test_parse_ifconfig_detail_line_mac(self):
        """Test parsing MAC address from ifconfig detail line."""
        details = {"mac_address": None}
        self.collector._parse_ifconfig_detail_line("\tether 00:11:22:33:44:55", details)

        assert details["mac_address"] == "00:11:22:33:44:55"

    def test_parse_ifconfig_ipv4_line(self):
        """Test parsing IPv4 address and netmask."""
        details = {"ipv4_address": None, "subnet_mask": None}
        self.collector._parse_ifconfig_ipv4_line(
            "\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255", details
        )

        assert details["ipv4_address"] == "192.168.1.100"
        assert details["subnet_mask"] == "255.255.255.0"


class TestWindowsNetworkCollection:
    """Tests for Windows-specific network information collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = HardwareCollectorWindows()

    def test_get_network_info_success(self):
        """Test successful network collection on Windows."""
        ipconfig_output = """
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-ABC123
   Primary Dns Suffix  . . . . . . . : example.com

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : example.com
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.100(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 8.8.8.8

Wireless LAN adapter Wi-Fi:

   Media State . . . . . . . . . . . : Media disconnected
   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ipconfig_output

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector.get_network_info()

        assert len(result) == 2

        ethernet = next((i for i in result if "Ethernet" in i["name"]), None)
        assert ethernet is not None
        assert ethernet["mac_address"] == "00-11-22-33-44-55"
        assert "192.168.1.100" in ethernet["ip_addresses"]
        assert ethernet["dhcp_enabled"] is True
        assert ethernet["type"] == "Ethernet"

        wifi = next((i for i in result if "Wi-Fi" in i["name"]), None)
        assert wifi is not None
        assert wifi["is_active"] is False

    def test_get_network_info_command_failure(self):
        """Test handling ipconfig command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector.get_network_info()

        assert not result

    def test_detect_new_adapter_ethernet(self):
        """Test detecting Ethernet adapter header."""
        result = self.collector._detect_new_adapter(
            "Ethernet adapter Ethernet:", "Ethernet adapter Ethernet:"
        )

        assert result is not None
        assert result["name"] == "Ethernet adapter Ethernet"

    def test_detect_new_adapter_detail_line(self):
        """Test that detail lines are not detected as adapter headers."""
        result = self.collector._detect_new_adapter(
            "Description . . . . . . . . . . . : Intel Ethernet",
            "   Description . . . . . . . . . . . : Intel Ethernet",
        )

        assert result is None

    def test_should_skip_ipconfig_line(self):
        """Test skipping irrelevant ipconfig lines."""
        assert self.collector._should_skip_ipconfig_line("") is True
        assert (
            self.collector._should_skip_ipconfig_line("Windows IP Configuration")
            is True
        )
        assert self.collector._should_skip_ipconfig_line("Host Name . . . : PC") is True
        assert (
            self.collector._should_skip_ipconfig_line("Description . . : Intel")
            is False
        )

    def test_handle_media_state_connected(self):
        """Test handling connected media state."""
        adapter = {
            "is_active": False,
            "connection_status": "Unknown",
            "media_state": "Unknown",
        }
        self.collector._handle_media_state(adapter, "Connected")

        assert adapter["is_active"] is True
        assert adapter["connection_status"] == "Connected"

    def test_handle_media_state_disconnected(self):
        """Test handling disconnected media state."""
        adapter = {
            "is_active": True,
            "connection_status": "Unknown",
            "media_state": "Unknown",
        }
        self.collector._handle_media_state(adapter, "Media disconnected")

        assert adapter["is_active"] is False
        assert adapter["connection_status"] == "Disconnected"

    def test_handle_description_wireless(self):
        """Test detecting wireless adapter type from description."""
        adapter = {"name": "Wi-Fi Adapter", "type": "Unknown"}
        self.collector._handle_description(adapter, "Intel Wi-Fi 6 AX201")

        assert adapter["type"] == "Wireless"

    def test_handle_description_bluetooth(self):
        """Test detecting Bluetooth adapter type."""
        adapter = {"name": "Bluetooth Network", "type": "Unknown"}
        self.collector._handle_description(adapter, "Bluetooth Device")

        assert adapter["type"] == "Bluetooth"

    def test_handle_ip_address_ipv4(self):
        """Test handling IPv4 address."""
        adapter = {
            "ip_addresses": [],
            "is_active": False,
            "connection_status": "Unknown",
        }
        self.collector._handle_ip_address(adapter, "192.168.1.100(Preferred)")

        assert "192.168.1.100" in adapter["ip_addresses"]
        assert adapter["is_active"] is True

    def test_handle_ip_address_ipv6(self):
        """Test handling IPv6 address with zone ID."""
        adapter = {
            "ip_addresses": [],
            "is_active": False,
            "connection_status": "Unknown",
        }
        self.collector._handle_ip_address(adapter, "fe80::1%12")

        assert "fe80::1" in adapter["ip_addresses"]


class TestNetworkStatisticsAndRouting:
    """Tests for network statistics and routing information collection."""

    def test_network_interface_state_detection(self):
        """Test that interface state is correctly detected."""
        collector = HardwareCollectorLinux()

        def mock_open_factory(path, *args, **kwargs):
            if "operstate" in path:
                return mock_open(read_data="up")()
            return mock_open(read_data="")()

        with patch("os.path.exists", return_value=True):
            with patch("os.path.join", side_effect=lambda *a: "/".join(a)):
                with patch("builtins.open", side_effect=mock_open_factory):
                    result = collector._collect_interface_sysfs_attr(
                        "/sys/class/net/eth0", "operstate"
                    )

        assert result == "up"

    def test_network_mac_address_detection(self):
        """Test that MAC address is correctly parsed."""
        collector = HardwareCollectorLinux()

        def mock_open_factory(path, *args, **kwargs):
            if "address" in path:
                return mock_open(read_data="00:11:22:33:44:55\n")()
            return mock_open(read_data="")()

        with patch("os.path.exists", return_value=True):
            with patch("os.path.join", side_effect=lambda *a: "/".join(a)):
                with patch("builtins.open", side_effect=mock_open_factory):
                    result = collector._collect_interface_sysfs_attr(
                        "/sys/class/net/eth0", "address"
                    )

        assert result == "00:11:22:33:44:55"


class TestMultiPlatformNetworkCollection:
    """Tests for cross-platform network collection consistency."""

    def test_all_collectors_return_list(self):
        """Test that all platform collectors return a list."""
        collectors = [
            HardwareCollectorLinux(),
            HardwareCollectorBSD(),
            HardwareCollectorMacOS(),
            HardwareCollectorWindows(),
        ]

        for collector in collectors:
            with patch("subprocess.run") as mock_run:
                mock_result = Mock()
                mock_result.returncode = 1
                mock_result.stdout = ""
                mock_run.return_value = mock_result

                with patch("os.path.exists", return_value=False):
                    result = collector.get_network_info()

                assert isinstance(
                    result, list
                ), f"{type(collector).__name__} should return a list"

    def test_interface_dict_common_keys(self):
        """Test that common interface keys are present across platforms."""
        # Linux test
        linux_collector = HardwareCollectorLinux()
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", return_value=["eth0"]):
                with patch("builtins.open", mock_open(read_data="up")):
                    linux_result = linux_collector.get_network_info()

        if linux_result:
            assert "name" in linux_result[0]

        # BSD test
        bsd_ifconfig = """em0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
\tether 00:11:22:33:44:55
"""
        bsd_collector = HardwareCollectorBSD()
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = bsd_ifconfig

        with patch("subprocess.run", return_value=mock_result):
            bsd_result = bsd_collector.get_network_info()

        if bsd_result:
            assert "name" in bsd_result[0]
            assert "mac_address" in bsd_result[0]


class TestNetworkErrorHandling:
    """Tests for network collection error handling."""

    def test_linux_network_collection_permission_error(self):
        """Test Linux network collection handles permission errors."""
        collector = HardwareCollectorLinux()

        failed_ip = Mock()
        failed_ip.returncode = 1
        failed_ip.stdout = ""
        failed_ip.stderr = "ip: command not found"

        with patch("subprocess.run", return_value=failed_ip):
            with patch("os.path.exists", return_value=True):
                with patch("os.listdir", side_effect=PermissionError("Access denied")):
                    result = collector.get_network_info()

        assert len(result) == 1
        assert "error" in result[0]

    def test_bsd_network_collection_subprocess_error(self):
        """Test BSD network collection handles subprocess errors."""
        collector = HardwareCollectorBSD()

        with patch(
            "subprocess.run", side_effect=subprocess.SubprocessError("Command failed")
        ):
            result = collector.get_network_info()

        assert len(result) == 1
        assert "error" in result[0]

    def test_macos_network_collection_json_error(self):
        """Test macOS network collection handles JSON parsing errors."""
        collector = HardwareCollectorMacOS()

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json {"

        with patch("subprocess.run", return_value=mock_result):
            result = collector.get_network_info()

        assert len(result) == 1
        assert "error" in result[0]

    def test_windows_network_collection_encoding_error(self):
        """Test Windows network collection handles encoding errors."""
        collector = HardwareCollectorWindows()

        with patch(
            "subprocess.run",
            side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "invalid"),
        ):
            result = collector.get_network_info()

        assert len(result) == 1
        assert "error" in result[0]

    def test_network_utils_socket_timeout(self):
        """Test NetworkUtils handles socket timeouts."""
        network_utils = NetworkUtils()

        mock_sock = Mock()
        mock_sock.connect.side_effect = socket.timeout("Connection timed out")
        mock_sock.__enter__ = Mock(return_value=mock_sock)
        mock_sock.__exit__ = Mock(return_value=None)

        with patch("socket.socket", return_value=mock_sock):
            ipv4, ipv6 = network_utils.get_ip_addresses()

        assert ipv4 is None
        assert ipv6 is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
