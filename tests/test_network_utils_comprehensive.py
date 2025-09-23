"""
Comprehensive unit tests for src.sysmanage_agent.communication.network_utils module.
Tests network utilities for hostname and IP address detection.
"""

# pylint: disable=attribute-defined-outside-init

import socket
from unittest.mock import Mock, mock_open, patch

from src.sysmanage_agent.communication.network_utils import NetworkUtils


class TestNetworkUtils:  # pylint: disable=too-many-public-methods
    """Test cases for NetworkUtils class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_config = Mock()
        self.mock_config.get_hostname_override.return_value = None
        self.network_utils = NetworkUtils(self.mock_config)

    def test_init_with_config(self):
        """Test NetworkUtils initialization with config manager."""
        assert self.network_utils.config == self.mock_config
        assert self.network_utils.logger is not None

    def test_init_without_config(self):
        """Test NetworkUtils initialization without config manager."""
        utils = NetworkUtils()
        assert utils.config is None
        assert utils.logger is not None

    def test_get_hostname_with_override(self):
        """Test hostname retrieval with config override."""
        self.mock_config.get_hostname_override.return_value = "override-hostname"

        result = self.network_utils.get_hostname()

        assert result == "override-hostname"

    def test_get_hostname_with_empty_override(self):
        """Test hostname retrieval with empty config override."""
        self.mock_config.get_hostname_override.return_value = ""

        with patch("socket.getfqdn", return_value="test.example.com"):
            result = self.network_utils.get_hostname()

            assert result == "test.example.com"

    def test_get_hostname_fqdn_success(self):
        """Test hostname retrieval using socket.getfqdn() successfully."""
        utils = NetworkUtils()  # No config manager

        with patch("socket.getfqdn", return_value="test.example.com"):
            result = utils.get_hostname()

            assert result == "test.example.com"

    def test_get_hostname_fqdn_localhost(self):
        """Test hostname retrieval when getfqdn() returns localhost."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value="localhost"):
            with patch("socket.gethostname", return_value="test-host"):
                result = utils.get_hostname()

                assert result == "test-host"

    def test_get_hostname_gethostname_fallback(self):
        """Test hostname retrieval falling back to gethostname()."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value=None):
            with patch("socket.gethostname", return_value="test-host"):
                result = utils.get_hostname()

                assert result == "test-host"

    def test_get_hostname_gethostname_localhost(self):
        """Test hostname retrieval when gethostname() returns localhost."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value="localhost"):
            with patch("socket.gethostname", return_value="localhost"):
                with patch("os.path.exists", return_value=True):
                    with patch("builtins.open", mock_open(read_data="real-hostname\n")):
                        result = utils.get_hostname()

                        assert result == "real-hostname"

    def test_get_hostname_gethostname_fqdn_enhancement(self):
        """Test hostname retrieval with FQDN enhancement from gethostname()."""
        utils = NetworkUtils()

        with patch("socket.getfqdn") as mock_getfqdn:
            mock_getfqdn.side_effect = ["localhost", "test.example.com"]
            with patch("socket.gethostname", return_value="test"):
                result = utils.get_hostname()

                assert result == "test.example.com"

    def test_get_hostname_gethostname_fqdn_same(self):
        """Test hostname retrieval when FQDN enhancement returns same name."""
        utils = NetworkUtils()

        with patch("socket.getfqdn") as mock_getfqdn:
            mock_getfqdn.side_effect = ["localhost", "test"]
            with patch("socket.gethostname", return_value="test"):
                result = utils.get_hostname()

                assert result == "test"

    def test_get_hostname_gethostname_fqdn_error(self):
        """Test hostname retrieval when FQDN enhancement raises error."""
        utils = NetworkUtils()

        with patch("socket.getfqdn") as mock_getfqdn:
            mock_getfqdn.side_effect = ["localhost", socket.error("FQDN error")]
            with patch("socket.gethostname", return_value="test"):
                result = utils.get_hostname()

                assert result == "test"

    def test_get_hostname_gethostname_error(self):
        """Test hostname retrieval when gethostname() raises error."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value="localhost"):
            with patch(
                "socket.gethostname", side_effect=socket.error("Hostname error")
            ):
                with patch("os.path.exists", return_value=True):
                    with patch("builtins.open", mock_open(read_data="file-hostname\n")):
                        result = utils.get_hostname()

                        assert result == "file-hostname"

    def test_get_hostname_etc_hostname_file(self):
        """Test hostname retrieval from /etc/hostname file."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value="localhost"):
            with patch("socket.gethostname", return_value="localhost"):
                with patch("os.path.exists") as mock_exists:
                    mock_exists.side_effect = lambda path: path == "/etc/hostname"
                    with patch(
                        "builtins.open", mock_open(read_data="hostname-from-file\n")
                    ):
                        result = utils.get_hostname()

                        assert result == "hostname-from-file"

    def test_get_hostname_etc_myname_file(self):
        """Test hostname retrieval from /etc/myname file (OpenBSD)."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value="localhost"):
            with patch("socket.gethostname", return_value="localhost"):
                with patch("os.path.exists") as mock_exists:
                    mock_exists.side_effect = lambda path: path == "/etc/myname"
                    with patch(
                        "builtins.open", mock_open(read_data="openbsd-hostname\n")
                    ):
                        result = utils.get_hostname()

                        assert result == "openbsd-hostname"

    def test_get_hostname_file_read_error(self):
        """Test hostname retrieval when file reading raises error."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value="localhost"):
            with patch("socket.gethostname", return_value="localhost"):
                with patch("os.path.exists", return_value=True):
                    with patch("builtins.open", side_effect=OSError("File read error")):
                        with patch("socket.socket") as mock_socket:
                            mock_sock = Mock()
                            mock_sock.getsockname.return_value = (
                                "192.168.1.100",
                                12345,
                            )
                            mock_socket.return_value.__enter__.return_value = mock_sock
                            with patch(
                                "socket.gethostbyaddr",
                                return_value=("resolved-host", [], []),
                            ):
                                result = utils.get_hostname()

                                assert result == "resolved-host"

    def test_get_hostname_ip_fallback_success(self):
        """Test hostname retrieval using IP address fallback successfully."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value="localhost"):
            with patch("socket.gethostname", return_value="localhost"):
                with patch("os.path.exists", return_value=False):
                    with patch("socket.socket") as mock_socket:
                        mock_sock = Mock()
                        mock_sock.getsockname.return_value = ("192.168.1.100", 12345)
                        mock_socket.return_value.__enter__.return_value = mock_sock
                        with patch(
                            "socket.gethostbyaddr",
                            return_value=("ip-resolved-host", [], []),
                        ):
                            result = utils.get_hostname()

                            assert result == "ip-resolved-host"

    def test_get_hostname_ip_fallback_socket_error(self):
        """Test hostname retrieval when IP socket connection fails."""
        utils = NetworkUtils()

        # Need to force all hostname detection methods to fail to reach the IP fallback
        with patch("socket.getfqdn", return_value=None):
            with patch("socket.gethostname", return_value=None):
                with patch("os.path.exists", return_value=False):
                    with patch(
                        "socket.socket", side_effect=socket.error("Socket error")
                    ):
                        result = utils.get_hostname()

                        assert result == "unknown-host"

    def test_get_hostname_ip_fallback_no_ip(self):
        """Test hostname retrieval when IP address is not available."""
        utils = NetworkUtils()

        # Need to force all hostname detection methods to fail to reach the IP fallback
        with patch("socket.getfqdn", return_value=None):
            with patch("socket.gethostname", return_value=None):
                with patch("os.path.exists", return_value=False):
                    with patch("socket.socket") as mock_socket:
                        mock_sock = Mock()
                        mock_sock.getsockname.return_value = (None, 12345)
                        mock_socket.return_value.__enter__.return_value = mock_sock
                        result = utils.get_hostname()

                        assert result == "unknown-host"

    def test_get_hostname_ip_fallback_reverse_dns_error(self):
        """Test hostname retrieval when reverse DNS lookup fails."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value="localhost"):
            with patch("socket.gethostname", return_value="localhost"):
                with patch("os.path.exists", return_value=False):
                    with patch("socket.socket") as mock_socket:
                        mock_sock = Mock()
                        mock_sock.getsockname.return_value = ("192.168.1.100", 12345)
                        mock_socket.return_value.__enter__.return_value = mock_sock
                        with patch(
                            "socket.gethostbyaddr",
                            side_effect=socket.error("DNS error"),
                        ):
                            result = utils.get_hostname()

                            assert result == "host-192-168-1-100"

    def test_get_hostname_final_fallback(self):
        """Test hostname retrieval final fallback to unknown-host."""
        utils = NetworkUtils()

        with patch("socket.getfqdn", return_value=None):
            with patch("socket.gethostname", return_value=None):
                with patch("os.path.exists", return_value=False):
                    with patch(
                        "socket.socket", side_effect=socket.error("All methods fail")
                    ):
                        result = utils.get_hostname()

                        assert result == "unknown-host"

    def test_get_ip_addresses_success(self):
        """Test successful IP address retrieval for both IPv4 and IPv6."""
        with patch("socket.socket") as mock_socket:
            # Mock IPv4 socket
            mock_ipv4_sock = Mock()
            mock_ipv4_sock.getsockname.return_value = ("192.168.1.100", 12345)

            # Mock IPv6 socket
            mock_ipv6_sock = Mock()
            mock_ipv6_sock.getsockname.return_value = ("2001:db8::1", 12345, 0, 0)

            # Return different mocks for different socket families
            def socket_side_effect(family, *args):
                if family == socket.AF_INET:
                    return mock_ipv4_sock
                if family == socket.AF_INET6:
                    return mock_ipv6_sock
                return Mock()

            mock_socket.side_effect = socket_side_effect
            mock_ipv4_sock.__enter__ = Mock(return_value=mock_ipv4_sock)
            mock_ipv4_sock.__exit__ = Mock(return_value=None)
            mock_ipv6_sock.__enter__ = Mock(return_value=mock_ipv6_sock)
            mock_ipv6_sock.__exit__ = Mock(return_value=None)

            ipv4, ipv6 = self.network_utils.get_ip_addresses()

            assert ipv4 == "192.168.1.100"
            assert ipv6 == "2001:db8::1"

    def test_get_ip_addresses_ipv4_only(self):
        """Test IP address retrieval when only IPv4 is available."""
        with patch("socket.socket") as mock_socket:
            # Mock IPv4 socket success
            mock_ipv4_sock = Mock()
            mock_ipv4_sock.getsockname.return_value = ("192.168.1.100", 12345)
            mock_ipv4_sock.__enter__ = Mock(return_value=mock_ipv4_sock)
            mock_ipv4_sock.__exit__ = Mock(return_value=None)

            # Mock IPv6 socket failure
            mock_ipv6_sock = Mock()
            mock_ipv6_sock.connect.side_effect = Exception("IPv6 not available")
            mock_ipv6_sock.__enter__ = Mock(return_value=mock_ipv6_sock)
            mock_ipv6_sock.__exit__ = Mock(return_value=None)

            def socket_side_effect(family, *args):
                if family == socket.AF_INET:
                    return mock_ipv4_sock
                if family == socket.AF_INET6:
                    return mock_ipv6_sock
                return Mock()

            mock_socket.side_effect = socket_side_effect

            ipv4, ipv6 = self.network_utils.get_ip_addresses()

            assert ipv4 == "192.168.1.100"
            assert ipv6 is None

    def test_get_ip_addresses_ipv6_only(self):
        """Test IP address retrieval when only IPv6 is available."""
        with patch("socket.socket") as mock_socket:
            # Mock IPv4 socket failure
            mock_ipv4_sock = Mock()
            mock_ipv4_sock.connect.side_effect = Exception("IPv4 not available")
            mock_ipv4_sock.__enter__ = Mock(return_value=mock_ipv4_sock)
            mock_ipv4_sock.__exit__ = Mock(return_value=None)

            # Mock IPv6 socket success
            mock_ipv6_sock = Mock()
            mock_ipv6_sock.getsockname.return_value = ("2001:db8::1", 12345, 0, 0)
            mock_ipv6_sock.__enter__ = Mock(return_value=mock_ipv6_sock)
            mock_ipv6_sock.__exit__ = Mock(return_value=None)

            def socket_side_effect(family, *args):
                if family == socket.AF_INET:
                    return mock_ipv4_sock
                if family == socket.AF_INET6:
                    return mock_ipv6_sock
                return Mock()

            mock_socket.side_effect = socket_side_effect

            ipv4, ipv6 = self.network_utils.get_ip_addresses()

            assert ipv4 is None
            assert ipv6 == "2001:db8::1"

    def test_get_ip_addresses_both_fail(self):
        """Test IP address retrieval when both IPv4 and IPv6 fail."""
        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect.side_effect = Exception("Network error")
            mock_sock.__enter__ = Mock(return_value=mock_sock)
            mock_sock.__exit__ = Mock(return_value=None)
            mock_socket.return_value = mock_sock

            ipv4, ipv6 = self.network_utils.get_ip_addresses()

            assert ipv4 is None
            assert ipv6 is None
