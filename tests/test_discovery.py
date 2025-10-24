"""
Unit tests for agent auto-discovery functionality.
"""

import json
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.registration.discovery import ServerDiscoveryClient


class TestServerDiscoveryClient:
    """Test cases for ServerDiscoveryClient."""

    def setup_method(self):
        """Set up test fixtures."""
        # pylint: disable-next=attribute-defined-outside-init
        self.client = ServerDiscoveryClient(
            discovery_port_arg=31337, broadcast_port_arg=31338
        )

    @pytest.mark.asyncio
    async def test_discover_servers_no_servers(self):
        """Test discovery when no servers are available."""
        with (
            patch.object(self.client, "broadcast_discovery", return_value=[]),
            patch.object(self.client, "listen_for_announcements", return_value=[]),
        ):

            servers = await self.client.discover_servers(timeout=1)
            assert servers == []

    @pytest.mark.asyncio
    async def test_discover_servers_with_broadcast_response(self):
        """Test discovery with servers responding to broadcast."""
        mock_server = {
            "service": "sysmanage-server",
            "server_info": {
                "hostname": "test-server",
                "api_port": 8000,
                "websocket_endpoint": "/api/agent/connect",
            },
            "discovered_via": "broadcast",
            "server_ip": "192.168.1.100",
        }

        with (
            patch.object(
                self.client, "broadcast_discovery", return_value=[mock_server]
            ),
            patch.object(self.client, "listen_for_announcements", return_value=[]),
        ):

            servers = await self.client.discover_servers(timeout=1)
            assert len(servers) == 1
            assert servers[0]["server_ip"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_discover_servers_with_announcements(self):
        """Test discovery with server announcements."""
        mock_server = {
            "service": "sysmanage-server",
            "server_info": {
                "hostname": "test-server",
                "api_port": 8000,
                "websocket_endpoint": "/api/agent/connect",
            },
            "discovered_via": "announcement",
            "server_ip": "192.168.1.101",
        }

        with (
            patch.object(self.client, "broadcast_discovery", return_value=[]),
            patch.object(
                self.client, "listen_for_announcements", return_value=[mock_server]
            ),
        ):

            servers = await self.client.discover_servers(timeout=1)
            assert len(servers) == 1
            assert servers[0]["discovered_via"] == "announcement"

    @pytest.mark.asyncio
    @patch("socket.socket")
    async def test_broadcast_discovery_success(self, mock_socket_class):
        """Test successful broadcast discovery."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        # Mock server response
        server_response = {
            "service": "sysmanage-server",
            "server_info": {
                "hostname": "test-server",
                "api_port": 8000,
                "websocket_endpoint": "/api/agent/connect",
            },
        }

        mock_socket.recvfrom.side_effect = [
            (json.dumps(server_response).encode("utf-8"), ("192.168.1.100", 31337)),
            # Then timeout to end the loop
            Exception("timeout"),
        ]

        with (
            patch.object(
                self.client,
                "_get_broadcast_addresses",
                return_value=["255.255.255.255"],
            ),
            patch("asyncio.get_event_loop") as mock_loop,
        ):

            mock_loop.return_value.time.side_effect = [0, 0.1, 10]  # Simulate timeout

            servers = await self.client.broadcast_discovery(timeout=5)

            assert len(servers) == 1
            assert servers[0]["server_ip"] == "192.168.1.100"
            assert servers[0]["discovered_via"] == "broadcast"

    @pytest.mark.asyncio
    @patch("socket.socket")
    async def test_listen_for_announcements_success(self, mock_socket_class):
        """Test successful listening for server announcements."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        # Mock server announcement
        announcement = {
            "service": "sysmanage-server",
            "announcement_type": "server_broadcast",
            "server_info": {
                "hostname": "test-server",
                "api_port": 8000,
                "discovery_port": 31337,
            },
        }

        mock_socket.recvfrom.side_effect = [
            (json.dumps(announcement).encode("utf-8"), ("192.168.1.101", 31338)),
            # Then timeout to end the loop
            Exception("timeout"),
        ]

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.time.side_effect = [0, 0.1, 10]  # Simulate timeout

            servers = await self.client.listen_for_announcements(timeout=5)

            assert len(servers) == 1
            assert servers[0]["server_ip"] == "192.168.1.101"
            assert servers[0]["discovered_via"] == "announcement"

    def test_select_best_server_ssl_preference(self):
        """Test server selection with SSL preference."""
        servers = [
            {
                "server_info": {"use_ssl": False},
                "server_ip": "192.168.1.100",
                "discovered_via": "broadcast",
            },
            {
                "server_info": {"use_ssl": True},
                "server_ip": "192.168.1.101",
                "discovered_via": "broadcast",
            },
        ]

        best = self.client.select_best_server(servers)
        assert best["server_ip"] == "192.168.1.101"  # SSL server should win

    def test_select_best_server_local_network_preference(self):
        """Test server selection with local network preference."""
        servers = [
            {
                "server_info": {"use_ssl": False},
                "server_ip": "203.0.113.100",  # Public IP
                "discovered_via": "broadcast",
            },
            {
                "server_info": {"use_ssl": False},
                "server_ip": "192.168.1.100",  # Private IP
                "discovered_via": "broadcast",
            },
        ]

        best = self.client.select_best_server(servers)
        assert best["server_ip"] == "192.168.1.100"  # Local network should win

    def test_select_best_server_broadcast_preference(self):
        """Test server selection with broadcast discovery preference."""
        servers = [
            {
                "server_info": {"use_ssl": False},
                "server_ip": "192.168.1.100",
                "discovered_via": "announcement",
            },
            {
                "server_info": {"use_ssl": False},
                "server_ip": "192.168.1.101",
                "discovered_via": "broadcast",
            },
        ]

        best = self.client.select_best_server(servers)
        assert best["server_ip"] == "192.168.1.101"  # Broadcast should win

    def test_select_best_server_no_servers(self):
        """Test server selection with no servers."""
        best = self.client.select_best_server([])
        assert best is None

    def test_create_agent_config_from_discovery_with_default_config(self):
        """Test config creation when server provides default config."""
        server_info = {
            "server_ip": "192.168.1.100",
            "default_config": {
                "server": {"hostname": "old-hostname", "port": 8000},
                "logging": {"level": "INFO"},
            },
        }

        config = self.client.create_agent_config_from_discovery(server_info)

        # Should use provided config but override hostname with discovered IP
        assert config["server"]["hostname"] == "192.168.1.100"
        assert config["server"]["port"] == 8000
        assert config["logging"]["level"] == "INFO"

    def test_create_agent_config_from_discovery_basic(self):
        """Test basic config creation from server info."""
        server_info = {
            "server_ip": "192.168.1.100",
            "server_info": {"api_port": 8443, "use_ssl": True},
        }

        config = self.client.create_agent_config_from_discovery(server_info)

        assert config["server"]["hostname"] == "192.168.1.100"
        assert config["server"]["port"] == 8443
        assert config["server"]["use_https"] is True
        assert config["websocket"]["auto_reconnect"] is True

    @patch("builtins.__import__")
    def test_get_broadcast_addresses_with_netifaces(self, mock_import):
        """Test getting broadcast addresses using netifaces."""
        mock_netifaces = Mock()
        mock_netifaces.interfaces.return_value = ["eth0", "lo"]
        mock_netifaces.ifaddresses.return_value = {
            2: [  # AF_INET = 2
                {
                    "addr": "192.168.1.10",
                    "netmask": "255.255.255.0",
                    "broadcast": "192.168.1.255",
                }
            ]
        }
        mock_netifaces.AF_INET = 2

        def import_side_effect(name, *args, **kwargs):
            if name == "netifaces":
                return mock_netifaces
            return __import__(name, *args, **kwargs)

        mock_import.side_effect = import_side_effect

        addresses = (
            self.client._get_broadcast_addresses()  # pylint: disable=protected-access
        )

        # Should include both default addresses and discovered broadcast
        assert "255.255.255.255" in addresses
        assert "192.168.1.255" in addresses

    @patch("builtins.__import__")
    def test_get_broadcast_addresses_without_netifaces(self, mock_import):
        """Test getting broadcast addresses when netifaces is not available."""

        def import_side_effect(name, *args, **kwargs):
            if name == "netifaces":
                raise ImportError("No module named 'netifaces'")
            return __import__(name, *args, **kwargs)

        mock_import.side_effect = import_side_effect

        addresses = (
            self.client._get_broadcast_addresses()  # pylint: disable=protected-access
        )

        # Should return default addresses
        # pylint: disable-next=duplicate-code
        expected_defaults = [
            "255.255.255.255",
            "192.168.1.255",
            "192.168.0.255",
            "10.0.0.255",
            "172.16.255.255",
        ]

        for addr in expected_defaults:
            assert addr in addresses

    def test_validate_server_response_valid(self):
        """Test validation of valid server response."""
        response = {
            "service": "sysmanage-server",
            "server_info": {
                "hostname": "test-server",
                "api_port": 8000,
                "websocket_endpoint": "/api/agent/connect",
            },
        }

        is_valid = (
            self.client._validate_server_response(  # pylint: disable=protected-access
                response, ("192.168.1.100", 31337)
            )
        )
        assert is_valid is True

    def test_validate_server_response_invalid_service(self):
        """Test validation of response with invalid service."""
        response = {
            "service": "wrong-service",
            "server_info": {
                "hostname": "test-server",
                "api_port": 8000,
                "websocket_endpoint": "/api/agent/connect",
            },
        }

        is_valid = (
            self.client._validate_server_response(  # pylint: disable=protected-access
                response, ("192.168.1.100", 31337)
            )
        )
        assert is_valid is False

    def test_validate_server_response_missing_info(self):
        """Test validation of response with missing server info."""
        response = {"service": "sysmanage-server"}

        is_valid = (
            self.client._validate_server_response(  # pylint: disable=protected-access
                response, ("192.168.1.100", 31337)
            )
        )
        assert is_valid is False

    def test_validate_server_announcement_valid(self):
        """Test validation of valid server announcement."""
        announcement = {
            "service": "sysmanage-server",
            "announcement_type": "server_broadcast",
            "server_info": {"hostname": "test-server"},
        }

        is_valid = self.client._validate_server_announcement(  # pylint: disable=protected-access
            announcement, ("192.168.1.100", 31338)
        )
        assert is_valid is True

    def test_validate_server_announcement_invalid(self):
        """Test validation of invalid server announcement."""
        announcement = {
            "service": "wrong-service",
            "announcement_type": "server_broadcast",
        }

        is_valid = self.client._validate_server_announcement(  # pylint: disable=protected-access
            announcement, ("192.168.1.100", 31338)
        )
        assert is_valid is False

    def test_deduplicate_servers(self):
        """Test deduplication of servers by IP address."""
        servers = [
            {"server_ip": "192.168.1.100", "discovered_via": "broadcast"},
            {
                "server_ip": "192.168.1.100",
                "discovered_via": "announcement",
            },  # Duplicate
            {"server_ip": "192.168.1.101", "discovered_via": "broadcast"},
        ]

        unique_servers = (
            self.client._deduplicate_servers(  # pylint: disable=protected-access
                servers
            )
        )

        assert len(unique_servers) == 2
        server_ips = [s["server_ip"] for s in unique_servers]
        assert "192.168.1.100" in server_ips
        assert "192.168.1.101" in server_ips
