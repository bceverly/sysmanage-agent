"""
Network utilities module for SysManage Agent.
Handles network-related functionality like IP address detection and hostname resolution.
"""

import socket
import logging
from typing import Optional, Tuple


class NetworkUtils:
    """Handles network-related utilities for the agent."""

    def __init__(self, config_manager=None):
        self.config = config_manager
        self.logger = logging.getLogger(__name__)

    def get_hostname(self) -> str:
        """Get the hostname, with optional override from config."""
        if self.config:
            override = self.config.get_hostname_override()
            if override:
                return override
        return socket.getfqdn()

    def get_ip_addresses(self) -> Tuple[Optional[str], Optional[str]]:
        """Get both IPv4 and IPv6 addresses of the machine."""
        ipv4 = None
        ipv6 = None

        try:
            # Get IPv4 address by connecting to a remote host
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ipv4 = s.getsockname()[0]
        except Exception as e:
            self.logger.debug("Could not determine IPv4 address: %s", e)

        try:
            # Get IPv6 address by connecting to a remote host
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.connect(("2001:4860:4860::8888", 80))
                ipv6 = s.getsockname()[0]
        except Exception as e:
            self.logger.debug("Could not determine IPv6 address: %s", e)

        return ipv4, ipv6
