"""
Tests for the network utilities module.
"""

import json
import socket
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.communication.network_utils import NetworkUtils


class TestNetworkUtils:
    """Test network utilities functionality."""

    @pytest.fixture
    def network_utils(self):
        """Create a network utils instance for testing."""
        mock_config = Mock()
        mock_config.get_hostname_override.return_value = None
        return NetworkUtils(mock_config)

    @pytest.fixture
    def network_utils_no_config(self):
        """Create a network utils instance without config."""
        return NetworkUtils()

    def test_network_utils_initialization(self, network_utils):
        """Test that NetworkUtils initializes correctly."""
        assert network_utils is not None
        assert hasattr(network_utils, "logger")
        assert hasattr(network_utils, "config")

    def test_network_utils_initialization_no_config(self, network_utils_no_config):
        """Test that NetworkUtils initializes correctly without config."""
        assert network_utils_no_config is not None
        assert network_utils_no_config.config is None

    @patch("subprocess.run")
    @patch("socket.getfqdn")
    def test_get_hostname_success(self, mock_getfqdn, mock_subprocess, network_utils):
        """Test hostname collection."""
        # Mock hostname -f command to return test hostname
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test-host.example.com"
        mock_subprocess.return_value = mock_result

        mock_getfqdn.return_value = "test-host.example.com"

        result = network_utils.get_hostname()

        assert result == "test-host.example.com"
        mock_subprocess.assert_called_once()

    @patch("socket.getfqdn")
    def test_get_hostname_with_config_override(self, mock_getfqdn, network_utils):
        """Test hostname collection with config override."""
        # Set up config override
        network_utils.config.get_hostname_override.return_value = (
            "override-host.example.com"
        )
        mock_getfqdn.return_value = "original-host.example.com"

        result = network_utils.get_hostname()

        # Should use override, not call getfqdn
        assert result == "override-host.example.com"
        mock_getfqdn.assert_not_called()

    def test_get_hostname_fallback(self, network_utils_no_config):
        """Test hostname collection fallback behavior."""
        with (
            patch("subprocess.run") as mock_subprocess,
            patch("socket.getfqdn") as mock_getfqdn,
        ):
            # Mock hostname -f to return test hostname
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = "fallback-host.example.com"
            mock_subprocess.return_value = mock_result

            mock_getfqdn.return_value = "fallback-host.example.com"

            result = network_utils_no_config.get_hostname()

            assert result == "fallback-host.example.com"
            mock_subprocess.assert_called_once()

    def test_get_ip_addresses_success(self, network_utils):
        """Test IP address collection success case."""
        # Mock successful IPv4 connection
        mock_ipv4_socket = Mock()
        mock_ipv4_socket.getsockname.return_value = ("192.168.1.100", 12345)
        mock_ipv4_socket.__enter__ = Mock(return_value=mock_ipv4_socket)
        mock_ipv4_socket.__exit__ = Mock(return_value=None)

        # Mock successful IPv6 connection
        mock_ipv6_socket = Mock()
        mock_ipv6_socket.getsockname.return_value = ("2001:db8::1", 12345, 0, 0)
        mock_ipv6_socket.__enter__ = Mock(return_value=mock_ipv6_socket)
        mock_ipv6_socket.__exit__ = Mock(return_value=None)

        with patch("socket.socket") as mock_socket:

            def socket_side_effect(family, _sock_type):
                if family == socket.AF_INET:
                    return mock_ipv4_socket
                if family == socket.AF_INET6:
                    return mock_ipv6_socket
                raise ValueError(f"Unexpected socket family: {family}")

            mock_socket.side_effect = socket_side_effect

            ipv4, ipv6 = network_utils.get_ip_addresses()

            assert ipv4 == "192.168.1.100"
            assert ipv6 == "2001:db8::1"

    def test_get_ip_addresses_ipv4_only(self, network_utils):
        """Test IP address collection with only IPv4."""
        # Mock successful IPv4 connection
        mock_ipv4_socket = Mock()
        mock_ipv4_socket.getsockname.return_value = ("10.0.0.100", 12345)
        mock_ipv4_socket.__enter__ = Mock(return_value=mock_ipv4_socket)
        mock_ipv4_socket.__exit__ = Mock(return_value=None)

        # Mock failed IPv6 connection
        mock_ipv6_socket = Mock()
        mock_ipv6_socket.connect.side_effect = Exception("IPv6 not available")
        mock_ipv6_socket.__enter__ = Mock(return_value=mock_ipv6_socket)
        mock_ipv6_socket.__exit__ = Mock(return_value=None)

        with patch("socket.socket") as mock_socket:

            def socket_side_effect(family, _sock_type):
                if family == socket.AF_INET:
                    return mock_ipv4_socket
                if family == socket.AF_INET6:
                    return mock_ipv6_socket
                raise ValueError(f"Unexpected socket family: {family}")

            mock_socket.side_effect = socket_side_effect

            ipv4, ipv6 = network_utils.get_ip_addresses()

            assert ipv4 == "10.0.0.100"
            assert ipv6 is None

    def test_get_ip_addresses_partial_failure(self, network_utils):
        """Test IP address collection with partial failures."""
        # Mock successful IPv4, failed IPv6
        mock_ipv4_socket = Mock()
        mock_ipv4_socket.getsockname.return_value = ("172.16.0.100", 12345)
        mock_ipv4_socket.__enter__ = Mock(return_value=mock_ipv4_socket)
        mock_ipv4_socket.__exit__ = Mock(return_value=None)

        def socket_side_effect(family, _sock_type):
            if family == socket.AF_INET:
                return mock_ipv4_socket
            if family == socket.AF_INET6:
                # IPv6 socket creation fails
                raise OSError("IPv6 not supported")
            raise ValueError(f"Unexpected socket family: {family}")

        with patch("socket.socket", side_effect=socket_side_effect):
            ipv4, ipv6 = network_utils.get_ip_addresses()

            assert ipv4 == "172.16.0.100"
            assert ipv6 is None

    def test_integration_with_actual_network(self, network_utils):
        """Test actual network detection (integration test)."""
        # This test uses real network calls - may fail in isolated environments
        hostname = network_utils.get_hostname()
        ipv4, ipv6 = network_utils.get_ip_addresses()

        # Basic sanity checks
        assert isinstance(hostname, str)
        assert len(hostname) > 0

        # At least one IP should be available in most environments
        assert ipv4 is not None or ipv6 is not None

        if ipv4:
            assert isinstance(ipv4, str)
            # Basic IPv4 format check
            parts = ipv4.split(".")
            assert len(parts) == 4
            for part in parts:
                assert 0 <= int(part) <= 255

        if ipv6:
            assert isinstance(ipv6, str)
            # IPv6 should contain colons
            assert ":" in ipv6

    def test_data_consistency(self, network_utils):
        """Test that data returned is consistent across calls."""
        # Multiple calls should return same data (assuming network doesn't change)
        hostname1 = network_utils.get_hostname()
        hostname2 = network_utils.get_hostname()

        assert hostname1 == hostname2

        # IP addresses might change but should be consistent format
        ipv4_1, ipv6_1 = network_utils.get_ip_addresses()
        ipv4_2, ipv6_2 = network_utils.get_ip_addresses()

        # Types should be consistent
        assert type(ipv4_1) == type(ipv4_2)
        assert type(ipv6_1) == type(ipv6_2)

    def test_json_serialization_network_data(self, network_utils):
        """Test that network data can be JSON serialized."""
        hostname = network_utils.get_hostname()
        ipv4, ipv6 = network_utils.get_ip_addresses()

        network_data = {
            "hostname": hostname,
            "ipv4": ipv4,
            "ipv6": ipv6,
        }

        # Should be JSON serializable
        json_str = json.dumps(network_data)
        assert isinstance(json_str, str)

        # Should be able to deserialize
        deserialized = json.loads(json_str)
        assert isinstance(deserialized, dict)
        assert "hostname" in deserialized
