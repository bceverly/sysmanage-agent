# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for network information collection across all platforms.

Tests network interface detection, IP address collection (IPv4, IPv6),
MAC address collection, network statistics, routing table information,
DNS configuration, multi-platform support, and error handling.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init,unused-argument

import socket
import subprocess
import sys
from unittest.mock import Mock, mock_open, patch

import pytest

from src.sysmanage_agent.communication.network_utils import NetworkUtils
from src.sysmanage_agent.collection.hardware_collector_linux import (
    HardwareCollectorLinux,
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

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Linux sysfs fallback test patches /sys/class/net paths; on Windows the iproute2 mock path produces a different result shape",
    )
    def test_get_network_info_success(self):
        """Test successful network interface collection on Linux (sysfs fallback)."""
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

        # Mock subprocess.run to fail so the code falls through to the sysfs path
        mock_ip_result = Mock()
        mock_ip_result.returncode = 1
        mock_ip_result.stdout = ""

        with patch("subprocess.run", return_value=mock_ip_result):
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
        mock_ip_result = Mock()
        mock_ip_result.returncode = 1
        mock_ip_result.stdout = ""

        with patch("subprocess.run", return_value=mock_ip_result):
            with patch("os.path.exists", return_value=True):
                with patch("os.listdir", return_value=["lo", "eth0"]):
                    with patch("builtins.open", mock_open(read_data="up")):
                        result = self.collector.get_network_info()

        interface_names = [i.get("name") for i in result]
        assert "lo" not in interface_names
        assert "eth0" in interface_names

    def test_get_network_info_no_interfaces(self):
        """Test network collection when no interfaces exist."""
        mock_ip_result = Mock()
        mock_ip_result.returncode = 1
        mock_ip_result.stdout = ""

        with patch("subprocess.run", return_value=mock_ip_result):
            with patch("os.path.exists", return_value=True):
                with patch("os.listdir", return_value=[]):
                    result = self.collector.get_network_info()

        assert not result

    def test_get_network_info_sysfs_not_available(self):
        """Test network collection when /sys/class/net doesn't exist."""
        mock_ip_result = Mock()
        mock_ip_result.returncode = 1
        mock_ip_result.stdout = ""

        with patch("subprocess.run", return_value=mock_ip_result):
            with patch("os.path.exists", return_value=False):
                result = self.collector.get_network_info()

        assert not result

    def test_get_network_info_error_handling(self):
        """Test error handling during network collection."""
        mock_ip_result = Mock()
        mock_ip_result.returncode = 1
        mock_ip_result.stdout = ""

        with patch("subprocess.run", return_value=mock_ip_result):
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
