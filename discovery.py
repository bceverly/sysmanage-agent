"""
Network discovery client for SysManage agent.
Provides automatic server discovery and configuration retrieval.
"""

import asyncio
import json
import logging
import socket
import platform
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import netifaces
except ImportError:
    netifaces = None

logger = logging.getLogger(__name__)


class ServerDiscoveryClient:
    """
    Client for discovering SysManage servers on the network.
    Uses UDP broadcast/multicast to find available servers.
    """

    def __init__(self, discovery_port: int = 31337, broadcast_port: int = 31338):
        self.discovery_port = discovery_port
        self.broadcast_port = broadcast_port
        self.hostname = platform.node()

    async def discover_servers(self, timeout: int = 10) -> List[Dict[str, Any]]:
        """
        Discover SysManage servers on the network.

        Args:
            timeout: Discovery timeout in seconds

        Returns:
            List of discovered server information
        """
        discovered_servers = []

        # Try multiple discovery methods
        broadcast_servers = await self.broadcast_discovery(timeout // 2)
        if broadcast_servers:
            discovered_servers.extend(broadcast_servers)

        # Listen for server announcements
        announcement_servers = await self.listen_for_announcements(timeout // 2)
        if announcement_servers:
            discovered_servers.extend(announcement_servers)

        # Remove duplicates based on server hostname/IP
        unique_servers = self._deduplicate_servers(discovered_servers)

        if unique_servers:
            logger.info("Discovered %s SysManage server(s)", len(unique_servers))
        else:
            logger.warning("No SysManage servers discovered on the network")

        return unique_servers

    async def broadcast_discovery(self, timeout: int = 5) -> List[Dict[str, Any]]:
        """
        Send broadcast discovery requests and collect responses.

        Args:
            timeout: Timeout for discovery responses

        Returns:
            List of server responses
        """
        servers = []

        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)  # Short timeout for individual receives

            # Create discovery request
            discovery_request = {
                "service": "sysmanage-agent",
                "hostname": self.hostname,
                "platform": platform.system(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_config": True,
            }
            request_data = json.dumps(discovery_request).encode("utf-8")

            # Get broadcast addresses to try
            broadcast_addresses = self._get_broadcast_addresses()

            # Send discovery requests
            for broadcast_addr in broadcast_addresses:
                try:
                    sock.sendto(request_data, (broadcast_addr, self.discovery_port))
                    logger.debug(
                        "Discovery request sent to %s:%s",
                        broadcast_addr,
                        self.discovery_port,
                    )
                except Exception as e:
                    logger.debug("Failed to send to %s: %s", broadcast_addr, e)

            # Collect responses
            start_time = asyncio.get_event_loop().time()
            while (asyncio.get_event_loop().time() - start_time) < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    response = json.loads(data.decode("utf-8"))

                    if self._validate_server_response(response, addr):
                        response["discovered_via"] = "broadcast"
                        response["server_ip"] = addr[0]
                        servers.append(response)
                        logger.info("Server discovered at %s", addr[0])

                except socket.timeout:
                    continue
                except json.JSONDecodeError:
                    logger.warning(
                        "Invalid JSON response from %s",
                        addr[0] if "addr" in locals() else "unknown",
                    )
                except Exception as e:
                    logger.debug("Error receiving discovery response: %s", e)
                    continue

            sock.close()

        except Exception as e:
            logger.error("Error during broadcast discovery: %s", e)

        return servers

    async def listen_for_announcements(self, timeout: int = 5) -> List[Dict[str, Any]]:
        """
        Listen for server announcement broadcasts.

        Args:
            timeout: Time to listen for announcements

        Returns:
            List of servers from announcements
        """
        servers = []

        try:
            # Create UDP socket for listening
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", self.broadcast_port))
            sock.settimeout(0.5)

            logger.debug(
                "Listening for server announcements on port %s", self.broadcast_port
            )

            start_time = asyncio.get_event_loop().time()
            while (asyncio.get_event_loop().time() - start_time) < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    announcement = json.loads(data.decode("utf-8"))

                    if self._validate_server_announcement(announcement, addr):
                        # Convert announcement to server response format
                        server_info = {
                            "service": "sysmanage-server",
                            "timestamp": announcement.get("timestamp"),
                            "server_info": announcement.get("server_info", {}),
                            "discovered_via": "announcement",
                            "server_ip": addr[0],
                        }
                        servers.append(server_info)
                        logger.info("Server announcement received from %s", addr[0])

                except socket.timeout:
                    continue
                except json.JSONDecodeError:
                    logger.warning(
                        "Invalid JSON announcement from %s",
                        addr[0] if "addr" in locals() else "unknown",
                    )
                except Exception as e:
                    logger.debug("Error receiving announcement: %s", e)
                    continue

            sock.close()

        except Exception as e:
            logger.error("Error listening for announcements: %s", e)

        return servers

    def select_best_server(
        self, servers: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Select the best server from discovered servers.

        Args:
            servers: List of discovered servers

        Returns:
            Best server or None
        """
        if not servers:
            return None

        # Scoring criteria (higher is better):
        # - SSL enabled: +10 points
        # - Broadcast discovery (more reliable): +5 points
        # - Local network (192.168.x.x, 10.x.x.x): +3 points

        scored_servers = []

        for server in servers:
            score = 0
            server_info = server.get("server_info", {})
            server_ip = server.get("server_ip", "")

            # SSL bonus
            if server_info.get("use_ssl", False):
                score += 10

            # Discovery method bonus
            if server.get("discovered_via") == "broadcast":
                score += 5

            # Local network bonus
            if (
                server_ip.startswith("192.168.")
                or server_ip.startswith("10.")
                or server_ip.startswith("172.")
            ):
                score += 3

            scored_servers.append((score, server))

        # Sort by score (descending) and return the best
        scored_servers.sort(key=lambda x: x[0], reverse=True)
        best_server = scored_servers[0][1]

        logger.info(
            "Selected server at %s (score: %s)",
            best_server.get("server_ip"),
            scored_servers[0][0],
        )
        return best_server

    def create_agent_config_from_discovery(
        self, server_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create agent configuration from discovered server information.

        Args:
            server_info: Discovered server information

        Returns:
            Agent configuration dictionary
        """
        server_data = server_info.get("server_info", {})
        server_ip = server_info.get("server_ip", "localhost")

        # Use provided default config if available
        if "default_config" in server_info:
            config = server_info["default_config"].copy()
            # Override server hostname with discovered IP
            config["server"]["hostname"] = server_ip
            return config

        # Create basic configuration
        config = {
            "server": {
                "hostname": server_ip,
                "port": server_data.get("api_port", 8000),
                "use_https": server_data.get("use_ssl", False),
                "api_path": "/api",
            },
            "client": {
                "hostname_override": None,
                "registration_retry_interval": 30,
                "max_registration_retries": 10,
            },
            "logging": {
                "level": "INFO",
                # pylint: disable-next=consider-using-f-string
                "file": "/var/log/sysmanage-agent-%s.log" % self.hostname,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            },
            "websocket": {
                "auto_reconnect": True,
                "reconnect_interval": 5,
                "ping_interval": 30,
            },
            "i18n": {"language": "en"},
        }

        return config

    def _get_broadcast_addresses(self) -> List[str]:
        """Get list of broadcast addresses to try."""
        # Common broadcast addresses for discovery
        addresses = [
            "255.255.255.255",  # Global broadcast
            "192.168.1.255",  # Common home network
            "192.168.0.255",  # Common home network
            "10.0.0.255",  # Common corporate network
            "172.16.255.255",  # Common corporate network
        ]

        # Try to determine actual broadcast addresses
        if not netifaces:
            logger.debug("netifaces not available, using default broadcast addresses")
            return addresses
        try:
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET not in addrs:
                    continue
                for addr_info in addrs[netifaces.AF_INET]:
                    broadcast = addr_info.get("broadcast")
                    if broadcast and broadcast not in addresses:
                        addresses.append(broadcast)
        except Exception as e:
            logger.debug("Error determining broadcast addresses: %s", e)

        return addresses

    def _validate_server_response(
        self, response: Dict[str, Any], addr: Tuple[str, int]
    ) -> bool:
        """Validate a server discovery response."""
        try:
            # Check required fields
            if response.get("service") != "sysmanage-server":
                return False

            if "server_info" not in response:
                return False

            server_info = response["server_info"]
            required_fields = ["hostname", "api_port", "websocket_endpoint"]

            for field in required_fields:
                if field not in server_info:
                    return False

            return True

        except Exception:
            return False

    def _validate_server_announcement(
        self, announcement: Dict[str, Any], addr: Tuple[str, int]
    ) -> bool:
        """Validate a server announcement."""
        try:
            if announcement.get("service") != "sysmanage-server":
                return False

            if announcement.get("announcement_type") != "server_broadcast":
                return False

            if "server_info" not in announcement:
                return False

            return True

        except Exception:
            return False

    def _deduplicate_servers(
        self, servers: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicate servers based on IP address."""
        seen_ips = set()
        unique_servers = []

        for server in servers:
            server_ip = server.get("server_ip")
            if server_ip and server_ip not in seen_ips:
                seen_ips.add(server_ip)
                unique_servers.append(server)

        return unique_servers


# Global instance
discovery_client = ServerDiscoveryClient()
