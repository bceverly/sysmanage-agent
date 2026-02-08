"""
Comprehensive unit tests for network information collection across all platforms.

Tests network interface detection, IP address collection (IPv4, IPv6),
MAC address collection, network statistics, routing table information,
DNS configuration, multi-platform support, and error handling.
"""

# pylint: disable=protected-access,too-many-public-methods

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
from src.sysmanage_agent.operations.child_host_vmm_network_helpers import (
    detect_physical_interface,
    is_wired_interface,
    is_private_ip,
    get_host_dns_server,
    select_unused_subnet,
    format_subnet_info,
    _get_used_subnets_ifconfig,
    _find_unused_subnet,
)


class TestNetworkUtilsHostnameValidation:
    """Tests for hostname validation in NetworkUtils."""

    def setup_method(self):
        """Set up test fixtures."""
        self.network_utils = NetworkUtils()

    def test_is_valid_hostname_with_valid_hostname(self):
        """Test valid hostname detection."""
        assert self.network_utils._is_valid_hostname("server1.example.com") is True
        assert self.network_utils._is_valid_hostname("myhost") is True
        assert self.network_utils._is_valid_hostname("host-123") is True

    def test_is_valid_hostname_with_localhost(self):
        """Test that localhost is not considered valid."""
        assert self.network_utils._is_valid_hostname("localhost") is False
        assert self.network_utils._is_valid_hostname("localhost.localdomain") is False

    def test_is_valid_hostname_with_empty_or_none(self):
        """Test that empty or None hostnames are invalid."""
        assert self.network_utils._is_valid_hostname(None) is False
        assert self.network_utils._is_valid_hostname("") is False
        assert self.network_utils._is_valid_hostname("   ") is False

    def test_is_valid_fqdn_with_valid_fqdn(self):
        """Test valid FQDN detection."""
        assert self.network_utils._is_valid_fqdn("server.example.com") is True
        assert self.network_utils._is_valid_fqdn("a.b") is True

    def test_is_valid_fqdn_with_simple_hostname(self):
        """Test that simple hostnames without dots are not FQDNs."""
        assert self.network_utils._is_valid_fqdn("myhost") is False
        assert self.network_utils._is_valid_fqdn("server123") is False

    def test_is_valid_fqdn_with_localhost(self):
        """Test that localhost variants are not valid FQDNs."""
        assert self.network_utils._is_valid_fqdn("localhost") is False
        assert self.network_utils._is_valid_fqdn("localhost.localdomain") is False


class TestNetworkUtilsIPAddressCollection:
    """Tests for IP address collection functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.network_utils = NetworkUtils()

    def test_get_ip_addresses_both_successful(self):
        """Test successful collection of both IPv4 and IPv6 addresses."""
        mock_ipv4_sock = Mock()
        mock_ipv4_sock.getsockname.return_value = ("192.168.1.100", 12345)
        mock_ipv4_sock.__enter__ = Mock(return_value=mock_ipv4_sock)
        mock_ipv4_sock.__exit__ = Mock(return_value=None)

        mock_ipv6_sock = Mock()
        mock_ipv6_sock.getsockname.return_value = ("2001:db8::1", 12345, 0, 0)
        mock_ipv6_sock.__enter__ = Mock(return_value=mock_ipv6_sock)
        mock_ipv6_sock.__exit__ = Mock(return_value=None)

        def socket_side_effect(family, sock_type):
            if family == socket.AF_INET:
                return mock_ipv4_sock
            if family == socket.AF_INET6:
                return mock_ipv6_sock
            raise ValueError(f"Unexpected socket family: {family}")

        with patch("socket.socket", side_effect=socket_side_effect):
            ipv4, ipv6 = self.network_utils.get_ip_addresses()

        assert ipv4 == "192.168.1.100"
        assert ipv6 == "2001:db8::1"

    def test_get_ip_addresses_ipv4_only(self):
        """Test IP collection when only IPv4 is available."""
        mock_ipv4_sock = Mock()
        mock_ipv4_sock.getsockname.return_value = ("10.0.0.50", 12345)
        mock_ipv4_sock.__enter__ = Mock(return_value=mock_ipv4_sock)
        mock_ipv4_sock.__exit__ = Mock(return_value=None)

        def socket_side_effect(family, sock_type):
            if family == socket.AF_INET:
                return mock_ipv4_sock
            if family == socket.AF_INET6:
                raise OSError("IPv6 not available")
            raise ValueError(f"Unexpected socket family: {family}")

        with patch("socket.socket", side_effect=socket_side_effect):
            ipv4, ipv6 = self.network_utils.get_ip_addresses()

        assert ipv4 == "10.0.0.50"
        assert ipv6 is None

    def test_get_ip_addresses_ipv6_only(self):
        """Test IP collection when only IPv6 is available."""
        mock_ipv6_sock = Mock()
        mock_ipv6_sock.getsockname.return_value = (
            "2001:db8:85a3::8a2e:370:7334",
            12345,
            0,
            0,
        )
        mock_ipv6_sock.__enter__ = Mock(return_value=mock_ipv6_sock)
        mock_ipv6_sock.__exit__ = Mock(return_value=None)

        def socket_side_effect(family, sock_type):
            if family == socket.AF_INET:
                raise OSError("IPv4 not available")
            if family == socket.AF_INET6:
                return mock_ipv6_sock
            raise ValueError(f"Unexpected socket family: {family}")

        with patch("socket.socket", side_effect=socket_side_effect):
            ipv4, ipv6 = self.network_utils.get_ip_addresses()

        assert ipv4 is None
        assert ipv6 == "2001:db8:85a3::8a2e:370:7334"

    def test_get_ip_addresses_both_fail(self):
        """Test IP collection when both IPv4 and IPv6 fail."""
        with patch("socket.socket", side_effect=OSError("Network unavailable")):
            ipv4, ipv6 = self.network_utils.get_ip_addresses()

        assert ipv4 is None
        assert ipv6 is None

    def test_get_ip_addresses_connection_error(self):
        """Test IP collection when socket connect fails."""
        mock_sock = Mock()
        mock_sock.connect.side_effect = OSError("Connection refused")
        mock_sock.__enter__ = Mock(return_value=mock_sock)
        mock_sock.__exit__ = Mock(return_value=None)

        with patch("socket.socket", return_value=mock_sock):
            ipv4, ipv6 = self.network_utils.get_ip_addresses()

        assert ipv4 is None
        assert ipv6 is None


class TestNetworkUtilsHostnameResolution:
    """Tests for hostname resolution and fallback behavior."""

    def setup_method(self):
        """Set up test fixtures."""
        self.network_utils = NetworkUtils()

    @patch("subprocess.run")
    def test_try_hostname_command_success(self, mock_run):
        """Test successful hostname -f command execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "server.example.com\n"
        mock_run.return_value = mock_result

        result = self.network_utils._try_hostname_command()

        assert result == "server.example.com"
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_try_hostname_command_failure(self, mock_run):
        """Test hostname -f command failure handling."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        result = self.network_utils._try_hostname_command()

        assert result is None

    @patch("subprocess.run")
    def test_try_hostname_command_timeout(self, mock_run):
        """Test hostname -f command timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="hostname -f", timeout=5)

        result = self.network_utils._try_hostname_command()

        assert result is None

    @patch("subprocess.run")
    def test_try_hostname_command_returns_localhost(self, mock_run):
        """Test hostname -f returning localhost is rejected."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "localhost\n"
        mock_run.return_value = mock_result

        result = self.network_utils._try_hostname_command()

        assert result is None

    @patch("socket.getfqdn")
    def test_try_socket_getfqdn_success(self, mock_getfqdn):
        """Test successful socket.getfqdn() call."""
        mock_getfqdn.return_value = "host.domain.com"

        result = self.network_utils._try_socket_getfqdn()

        assert result == "host.domain.com"

    @patch("socket.getfqdn")
    def test_try_socket_getfqdn_returns_localhost(self, mock_getfqdn):
        """Test socket.getfqdn() returning localhost."""
        mock_getfqdn.return_value = "localhost"

        result = self.network_utils._try_socket_getfqdn()

        assert result is None

    @patch("socket.getfqdn")
    @patch("socket.gethostname")
    def test_try_socket_gethostname_with_fqdn_enhancement(
        self, mock_gethostname, mock_getfqdn
    ):
        """Test gethostname with FQDN enhancement."""
        mock_gethostname.return_value = "myserver"
        mock_getfqdn.return_value = "myserver.example.com"

        result = self.network_utils._try_socket_gethostname()

        assert result == "myserver.example.com"

    @patch("socket.gethostname")
    def test_try_socket_gethostname_error(self, mock_gethostname):
        """Test gethostname error handling."""
        mock_gethostname.side_effect = socket.error("DNS failure")

        result = self.network_utils._try_socket_gethostname()

        assert result is None

    def test_try_hostname_from_files_etc_hostname(self):
        """Test reading hostname from /etc/hostname."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/etc/hostname"
            with patch("builtins.open", mock_open(read_data="filehost.example.com\n")):
                result = self.network_utils._try_hostname_from_files()

        assert result == "filehost.example.com"

    def test_try_hostname_from_files_etc_myname(self):
        """Test reading hostname from /etc/myname (OpenBSD)."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/etc/myname"
            with patch("builtins.open", mock_open(read_data="openbsd.example.com\n")):
                result = self.network_utils._try_hostname_from_files()

        assert result == "openbsd.example.com"

    def test_try_hostname_from_files_not_exists(self):
        """Test when no hostname files exist."""
        with patch("os.path.exists", return_value=False):
            result = self.network_utils._try_hostname_from_files()

        assert result is None

    def test_try_hostname_from_ip_success(self):
        """Test hostname resolution via IP reverse DNS lookup."""
        mock_sock = Mock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 12345)
        mock_sock.__enter__ = Mock(return_value=mock_sock)
        mock_sock.__exit__ = Mock(return_value=None)

        with patch("socket.socket", return_value=mock_sock):
            with patch(
                "socket.gethostbyaddr", return_value=("resolved-host.local", [], [])
            ):
                result = self.network_utils._try_hostname_from_ip()

        assert result == "resolved-host.local"

    def test_try_hostname_from_ip_reverse_dns_failure(self):
        """Test hostname resolution when reverse DNS fails."""
        mock_sock = Mock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 12345)
        mock_sock.__enter__ = Mock(return_value=mock_sock)
        mock_sock.__exit__ = Mock(return_value=None)

        with patch("socket.socket", return_value=mock_sock):
            with patch(
                "socket.gethostbyaddr", side_effect=socket.herror("Host not found")
            ):
                result = self.network_utils._try_hostname_from_ip()

        assert result == "host-192-168-1-100"

    def test_resolve_ip_to_hostname_success(self):
        """Test successful IP to hostname resolution."""
        with patch("socket.gethostbyaddr", return_value=("myhost.local", [], [])):
            result = self.network_utils._resolve_ip_to_hostname("10.0.0.1")

        assert result == "myhost.local"

    def test_resolve_ip_to_hostname_failure(self):
        """Test IP to hostname resolution failure fallback."""
        with patch("socket.gethostbyaddr", side_effect=socket.error("DNS error")):
            result = self.network_utils._resolve_ip_to_hostname("172.16.0.1")

        assert result == "host-172-16-0-1"


class TestLinuxNetworkCollection:
    """Tests for Linux-specific network information collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = HardwareCollectorLinux()

    def test_get_network_info_success(self):
        """Test successful network interface collection on Linux."""
        interfaces = ["eth0", "wlan0", "lo"]

        def mock_listdir(path):
            if path == "/sys/class/net":
                return interfaces
            return []

        def mock_exists(path):
            return True

        def mock_open_factory(path, *args, **kwargs):
            if "eth0/type" in path:
                return mock_open(read_data="1")()
            if "eth0/operstate" in path:
                return mock_open(read_data="up")()
            if "eth0/address" in path:
                return mock_open(read_data="00:11:22:33:44:55")()
            if "wlan0/type" in path:
                return mock_open(read_data="1")()
            if "wlan0/operstate" in path:
                return mock_open(read_data="down")()
            if "wlan0/address" in path:
                return mock_open(read_data="aa:bb:cc:dd:ee:ff")()
            return mock_open(read_data="")()

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.listdir", side_effect=mock_listdir):
                with patch("builtins.open", side_effect=mock_open_factory):
                    result = self.collector.get_network_info()

        # Should have 2 interfaces (eth0 and wlan0, not lo)
        assert len(result) == 2

        eth0 = next((i for i in result if i["name"] == "eth0"), None)
        assert eth0 is not None
        assert eth0["state"] == "up"
        assert eth0["mac_address"] == "00:11:22:33:44:55"

        wlan0 = next((i for i in result if i["name"] == "wlan0"), None)
        assert wlan0 is not None
        assert wlan0["state"] == "down"

    def test_get_network_info_skips_loopback(self):
        """Test that loopback interface is skipped."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", return_value=["lo", "eth0"]):
                with patch("builtins.open", mock_open(read_data="up")):
                    result = self.collector.get_network_info()

        interface_names = [i.get("name") for i in result]
        assert "lo" not in interface_names
        assert "eth0" in interface_names

    def test_get_network_info_no_interfaces(self):
        """Test network collection when no interfaces exist."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", return_value=[]):
                result = self.collector.get_network_info()

        assert result == []

    def test_get_network_info_sysfs_not_available(self):
        """Test network collection when /sys/class/net doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = self.collector.get_network_info()

        assert result == []

    def test_get_network_info_error_handling(self):
        """Test error handling during network collection."""
        with patch("os.path.exists", side_effect=Exception("Filesystem error")):
            result = self.collector.get_network_info()

        assert len(result) == 1
        assert "error" in result[0]

    def test_collect_single_interface_info_complete(self):
        """Test collecting complete interface information."""

        def mock_exists(path):
            return True

        def mock_open_factory(path, *args, **kwargs):
            if "type" in path:
                return mock_open(read_data="1")()
            if "operstate" in path:
                return mock_open(read_data="up")()
            if "address" in path:
                return mock_open(read_data="de:ad:be:ef:ca:fe")()
            return mock_open(read_data="")()

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.path.join", side_effect=lambda *a: "/".join(a)):
                with patch("builtins.open", side_effect=mock_open_factory):
                    result = self.collector._collect_single_interface_info("eth0")

        assert result["name"] == "eth0"
        assert result["type"] == "1"
        assert result["state"] == "up"
        assert result["mac_address"] == "de:ad:be:ef:ca:fe"

    def test_collect_interface_sysfs_attr_missing(self):
        """Test reading non-existent sysfs attribute."""
        with patch("os.path.exists", return_value=False):
            result = self.collector._collect_interface_sysfs_attr(
                "/sys/class/net/eth0", "speed"
            )

        assert result == ""


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

        assert result == []

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

        assert result == {}

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

        assert result == []

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


class TestVMMNetworkHelpers:
    """Tests for VMM network helper functions."""

    def test_is_wired_interface_wired(self):
        """Test wired interface detection."""
        assert is_wired_interface("em0") is True
        assert is_wired_interface("re0") is True
        assert is_wired_interface("vio0") is True
        assert is_wired_interface("bge0") is True

    def test_is_wired_interface_wireless(self):
        """Test wireless interface detection."""
        assert is_wired_interface("iwn0") is False
        assert is_wired_interface("iwm0") is False
        assert is_wired_interface("athn0") is False

    def test_is_wired_interface_unknown(self):
        """Test unknown interface defaults to wired."""
        assert is_wired_interface("xyz0") is True

    def test_is_private_ip_class_a(self):
        """Test Class A private IP detection."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_is_private_ip_class_b(self):
        """Test Class B private IP detection."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True
        assert is_private_ip("172.15.0.1") is False
        assert is_private_ip("172.32.0.1") is False

    def test_is_private_ip_class_c(self):
        """Test Class C private IP detection."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True
        assert is_private_ip("192.169.0.1") is False

    def test_is_private_ip_public(self):
        """Test public IP detection."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_is_private_ip_invalid(self):
        """Test invalid IP handling."""
        assert is_private_ip("invalid") is False
        assert is_private_ip("192.168") is False
        assert is_private_ip("") is False

    def test_format_subnet_info(self):
        """Test subnet info formatting."""
        result = format_subnet_info("10.0.0.0")

        assert result["network"] == "10.0.0.0"
        assert result["netmask"] == "255.255.255.0"
        assert result["gateway_ip"] == "10.0.0.1"
        assert result["dhcp_start"] == "10.0.0.10"
        assert result["dhcp_end"] == "10.0.0.254"

    def test_get_used_subnets_ifconfig(self):
        """Test extracting used subnets from ifconfig output."""
        ifconfig_output = """em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
em1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.0.0.1 netmask 0xff000000 broadcast 10.255.255.255
"""
        result = _get_used_subnets_ifconfig(ifconfig_output)

        assert "192.168.1.0" in result
        assert "10.0.0.0" in result

    def test_find_unused_subnet_first_available(self):
        """Test finding first unused subnet."""
        used = {"192.168.1.0", "10.0.0.0"}
        candidates = ["100.64.0.0", "10.0.0.0", "192.168.100.0"]

        result = _find_unused_subnet(used, candidates)

        assert result == "100.64.0.0"

    def test_find_unused_subnet_all_used(self):
        """Test finding subnet when all candidates are used."""
        used = {"100.64.0.0", "10.0.0.0", "10.1.0.0", "10.2.0.0"}
        candidates = ["100.64.0.0", "10.0.0.0", "10.1.0.0", "10.2.0.0"]

        result = _find_unused_subnet(used, candidates)

        assert result == "10.3.0.0"

    def test_detect_physical_interface_success(self):
        """Test detecting physical interface."""
        ifconfig_output = """em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 33200
\tinet 127.0.0.1 netmask 0xff000000
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ifconfig_output

        mock_logger = Mock()

        with patch("subprocess.run", return_value=mock_result):
            result = detect_physical_interface(mock_logger)

        assert result == "em0"

    def test_detect_physical_interface_no_interfaces(self):
        """Test detecting interface when no suitable interfaces exist."""
        ifconfig_output = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 33200
\tinet 127.0.0.1 netmask 0xff000000
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ifconfig_output

        mock_logger = Mock()

        with patch("subprocess.run", return_value=mock_result):
            result = detect_physical_interface(mock_logger)

        assert result is None

    def test_detect_physical_interface_command_failure(self):
        """Test detecting interface when ifconfig fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        mock_logger = Mock()

        with patch("subprocess.run", return_value=mock_result):
            result = detect_physical_interface(mock_logger)

        assert result is None

    def test_get_host_dns_server_success(self):
        """Test getting DNS server from resolv.conf."""
        resolv_content = """# Generated by dhclient
nameserver 8.8.8.8
nameserver 8.8.4.4
"""
        mock_logger = Mock()

        with patch("builtins.open", mock_open(read_data=resolv_content)):
            result = get_host_dns_server(mock_logger)

        assert result == "8.8.8.8"

    def test_get_host_dns_server_with_comments(self):
        """Test DNS server extraction skips comments."""
        resolv_content = """# Comment
# nameserver 1.1.1.1
nameserver 9.9.9.9  # inline comment
"""
        mock_logger = Mock()

        with patch("builtins.open", mock_open(read_data=resolv_content)):
            result = get_host_dns_server(mock_logger)

        assert result == "9.9.9.9"

    def test_get_host_dns_server_no_nameserver(self):
        """Test handling resolv.conf without nameserver."""
        resolv_content = """# Empty config
search example.com
"""
        mock_logger = Mock()

        with patch("builtins.open", mock_open(read_data=resolv_content)):
            result = get_host_dns_server(mock_logger)

        assert result is None

    def test_get_host_dns_server_file_error(self):
        """Test handling resolv.conf read error."""
        mock_logger = Mock()

        with patch("builtins.open", side_effect=IOError("File not found")):
            result = get_host_dns_server(mock_logger)

        assert result is None
        mock_logger.warning.assert_called()

    def test_select_unused_subnet_success(self):
        """Test selecting unused subnet."""
        ifconfig_output = """em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ifconfig_output

        mock_logger = Mock()

        with patch("subprocess.run", return_value=mock_result):
            result = select_unused_subnet(mock_logger)

        assert result is not None
        assert "network" in result
        assert "netmask" in result
        assert "gateway_ip" in result

    def test_select_unused_subnet_command_failure(self):
        """Test subnet selection when ifconfig fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        mock_logger = Mock()

        with patch("subprocess.run", return_value=mock_result):
            result = select_unused_subnet(mock_logger)

        # Should return default fallback
        assert result is not None
        assert result["network"] == "10.0.0.0"


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
