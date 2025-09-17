"""
Network utilities module for SysManage Agent.
Handles network-related functionality like IP address detection and hostname resolution.
"""

import socket
import logging
import os
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
                self.logger.debug("Using hostname override: %s", override)
                return override

        # Try multiple methods to get a proper hostname, especially for FreeBSD/OpenBSD
        hostname = None
        self.logger.debug("Starting hostname detection...")

        # First try socket.getfqdn()
        fqdn = socket.getfqdn()
        self.logger.debug("socket.getfqdn() returned: %r", fqdn)
        if (
            fqdn
            and fqdn.strip()
            and fqdn != "localhost"
            and fqdn != "localhost.localdomain"
        ):
            hostname = fqdn.strip()
            self.logger.debug("Using FQDN as hostname: %s", hostname)

        # If that didn't work, try socket.gethostname()
        if not hostname:
            try:
                hostname = socket.gethostname()
                if hostname and hostname.strip() and hostname != "localhost":
                    hostname = hostname.strip()
                    # Try to get FQDN from hostname
                    try:
                        fqdn = socket.getfqdn(hostname)
                        if (
                            fqdn
                            and fqdn.strip()
                            and fqdn != "localhost"
                            and fqdn != hostname
                        ):
                            hostname = fqdn.strip()
                    except (socket.error, OSError):
                        pass
            except (socket.error, OSError):
                pass

        # If still no good hostname, try reading from system files (Unix/Linux/BSD)
        if not hostname or hostname == "localhost":
            try:
                # Try reading /etc/hostname (common on BSD systems)
                if os.path.exists("/etc/hostname"):
                    with open("/etc/hostname", "r", encoding="utf-8") as f:
                        file_hostname = f.read().strip()
                        if file_hostname and file_hostname != "localhost":
                            hostname = file_hostname
                # Try reading /etc/myname (OpenBSD specific)
                elif os.path.exists("/etc/myname"):
                    with open("/etc/myname", "r", encoding="utf-8") as f:
                        file_hostname = f.read().strip()
                        if file_hostname and file_hostname != "localhost":
                            hostname = file_hostname
            except (OSError, IOError):
                pass

        # If still no hostname, use the IP-based approach as fallback
        if not hostname or hostname == "localhost":
            try:
                # Connect to a remote address to determine local IP
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    if local_ip:
                        try:
                            hostname = socket.gethostbyaddr(local_ip)[0]
                        except (socket.error, OSError):
                            hostname = f"host-{local_ip.replace('.', '-')}"
            except (socket.error, OSError):
                pass

        # Final fallback
        if not hostname:
            hostname = "unknown-host"
            self.logger.warning(
                "Could not determine hostname, using fallback: %s", hostname
            )
        else:
            self.logger.debug("Final hostname determined: %s", hostname)

        # Ensure hostname is never empty or None
        if not hostname or not hostname.strip():
            hostname = "unknown-host"
            self.logger.warning("Hostname was empty, using fallback: %s", hostname)

        return hostname.strip()

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
