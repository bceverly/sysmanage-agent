"""
Base class for firewall operations across different operating systems.
"""

import logging
import platform
from typing import List, Optional, Tuple


class FirewallBase:
    """Base class for firewall operations with common functionality."""

    def __init__(self, agent, logger: Optional[logging.Logger] = None):
        """Initialize the firewall operations manager."""
        self.agent = agent
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system()

    def _get_agent_communication_ports(self) -> Tuple[List[int], str]:
        """
        Dynamically determine the port and protocol used for agent-server communication.

        Returns:
            Tuple of (list of ports, protocol) where protocol is 'tcp' or 'udp'
        """
        try:
            server_config = self.agent.config.get_server_config()
            port = server_config.get("port", 8080)

            # WebSocket communication uses TCP
            protocol = "tcp"

            self.logger.info("Agent communication port detected: %d/%s", port, protocol)

            return ([port], protocol)
        except Exception as exc:
            self.logger.error("Error detecting agent communication ports: %s", exc)
            # Default to port 8080/tcp if detection fails
            return ([8080], "tcp")

    def _get_local_server_ports(self) -> List[int]:
        """
        Detect if the SysManage server is running on this host and return its ports.

        Returns:
            List of ports the server is using (e.g., [8080, 3000])
        """
        # pylint: disable=import-outside-toplevel,too-many-nested-blocks
        import psutil

        server_ports = []

        try:
            # Check for processes listening on typical SysManage server ports
            # Port 8080: API server
            # Port 3000: WebUI server
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN":
                    # Check if this is likely a SysManage server process
                    # Look for python processes on ports 8080 or 3000
                    if conn.laddr.port in [8080, 3000]:
                        try:
                            proc = psutil.Process(conn.pid)
                            cmdline = " ".join(proc.cmdline())
                            # Check if it's a Python process that might be the SysManage server
                            if "python" in cmdline.lower() and (
                                "uvicorn" in cmdline.lower()
                                or "sysmanage" in cmdline.lower()
                                or "node" in proc.name().lower()
                            ):
                                if conn.laddr.port not in server_ports:
                                    server_ports.append(conn.laddr.port)
                                    self.logger.info(
                                        "Detected SysManage server running on port %d (process: %s)",
                                        conn.laddr.port,
                                        proc.name(),
                                    )
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
        except Exception as exc:
            self.logger.warning("Error detecting local server ports: %s", exc)

        return server_ports

    async def _send_firewall_status_update(self):
        """Send updated firewall status back to server via queue."""
        try:
            # pylint: disable=import-outside-toplevel
            from src.sysmanage_agent.operations.firewall_collector import (
                FirewallCollector,
            )

            collector = FirewallCollector(self.logger)
            firewall_info = collector.collect_firewall_status()

            # Get host approval for host_id
            host_approval = self.agent.registration_manager.get_host_approval_from_db()
            if not host_approval:
                self.logger.warning(
                    "Cannot send firewall status update: host not approved"
                )
                return

            # Prepare firewall status message
            firewall_message_data = {
                "hostname": self.agent.registration.get_system_info()["hostname"],
                "host_id": str(host_approval.host_id),
                "firewall_name": firewall_info["firewall_name"],
                "enabled": firewall_info["enabled"],
                "tcp_open_ports": firewall_info["tcp_open_ports"],
                "udp_open_ports": firewall_info["udp_open_ports"],
                "ipv4_ports": firewall_info.get("ipv4_ports"),
                "ipv6_ports": firewall_info.get("ipv6_ports"),
            }

            # Create and queue the message for sending
            message = self.agent.message_handler.create_message(
                message_type="firewall_status_update",
                data=firewall_message_data,
            )
            await self.agent.message_handler.queue_outbound_message(message)

            self.logger.info("Firewall status update queued for sending to server")

        except Exception as exc:
            self.logger.error(
                "Error sending firewall status update: %s", exc, exc_info=True
            )
