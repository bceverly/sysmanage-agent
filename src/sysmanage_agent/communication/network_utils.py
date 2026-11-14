# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Network utilities module for SysManage Agent.
Handles network-related functionality like IP address detection and hostname resolution.
"""

import logging
import os
import socket
import subprocess  # nosec B404 # Required for hostname detection
from typing import Optional, Tuple
from urllib.parse import urlsplit

from src.i18n import _


class NetworkUtils:
    """Handles network-related utilities for the agent."""

    def __init__(self, config_manager=None):
        self.config = config_manager
        self.logger = logging.getLogger(__name__)

    def _is_valid_hostname(self, hostname: Optional[str]) -> bool:
        """Check if a hostname is valid and not a localhost variant."""
        if not hostname or not hostname.strip():
            return False
        hostname = hostname.strip()
        if hostname in ("localhost", "localhost.localdomain"):
            return False
        return True

    def _is_valid_fqdn(self, hostname: Optional[str]) -> bool:
        """Check if a hostname is a valid FQDN."""
        return self._is_valid_hostname(hostname) and "." in hostname

    def _try_hostname_command(self) -> Optional[str]:
        """Try to get hostname using the hostname -f command."""
        try:
            result = subprocess.run(
                ["hostname", "-f"],  # nosec B603, B607 # Safe: no user input
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                cmd_fqdn = result.stdout.strip()
                self.logger.debug("hostname -f returned: %r", cmd_fqdn)
                if self._is_valid_hostname(cmd_fqdn):
                    self.logger.debug("Using hostname -f result: %s", cmd_fqdn)
                    return cmd_fqdn
        except (subprocess.TimeoutExpired, OSError) as error:
            self.logger.debug("hostname -f command failed: %s", error)
        return None

    def _try_socket_getfqdn(self) -> Optional[str]:
        """Try to get hostname using socket.getfqdn()."""
        fqdn = socket.getfqdn()
        self.logger.debug("socket.getfqdn() returned: %r", fqdn)
        if self._is_valid_hostname(fqdn):
            self.logger.debug("Using FQDN as hostname: %s", fqdn)
            return fqdn.strip()
        return None

    def _try_socket_gethostname(self) -> Optional[str]:
        """Try to get hostname using socket.gethostname()."""
        try:
            hostname = socket.gethostname()
            if self._is_valid_hostname(hostname):
                hostname = hostname.strip()
                # Try to enhance with FQDN
                enhanced = self._enhance_hostname_with_fqdn(hostname)
                return enhanced if enhanced else hostname
        except (socket.error, OSError):
            pass
        return None

    def _enhance_hostname_with_fqdn(self, hostname: str) -> Optional[str]:
        """Try to enhance a hostname by getting its FQDN."""
        try:
            fqdn = socket.getfqdn(hostname)
            if self._is_valid_hostname(fqdn) and fqdn != hostname:
                return fqdn.strip()
        except (socket.error, OSError):
            pass
        return None

    def _try_hostname_from_files(self) -> Optional[str]:
        """Try to read hostname from system files (Unix/Linux/BSD)."""
        try:
            # Try reading /etc/hostname (common on BSD systems)
            if os.path.exists("/etc/hostname"):
                hostname = self._read_hostname_file("/etc/hostname")
                if hostname:
                    return hostname
            # Try reading /etc/myname (OpenBSD specific)
            elif os.path.exists("/etc/myname"):
                hostname = self._read_hostname_file("/etc/myname")
                if hostname:
                    return hostname
        except (OSError, IOError):
            pass
        return None

    def _read_hostname_file(self, filepath: str) -> Optional[str]:
        """Read and validate hostname from a file."""
        with open(filepath, "r", encoding="utf-8") as file_handle:
            file_hostname = file_handle.read().strip()
            if self._is_valid_hostname(file_hostname):
                return file_hostname
        return None

    def _try_hostname_from_ip(self) -> Optional[str]:
        """Try to determine hostname using IP-based reverse DNS lookup."""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))  # NOSONAR
                local_ip = sock.getsockname()[0]
                if local_ip:
                    return self._resolve_ip_to_hostname(local_ip)
        except (socket.error, OSError):
            pass
        return None

    def _resolve_ip_to_hostname(self, ip_address: str) -> str:
        """Resolve an IP address to a hostname."""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.error, OSError):
            return f"host-{ip_address.replace('.', '-')}"

    def get_hostname(self) -> str:
        """Get the hostname, with optional override from config."""
        # Check for config override first
        if self.config:
            override = self.config.get_hostname_override()
            if override:
                self.logger.debug("Using hostname override: %s", override)
                return override

        self.logger.debug("Starting hostname detection...")

        # Try multiple methods in order of preference
        hostname = (
            self._try_hostname_command()
            or self._try_socket_getfqdn()
            or self._try_socket_gethostname()
            or self._try_hostname_from_files()
            or self._try_hostname_from_ip()
        )

        # Final fallback and validation
        if not hostname or not hostname.strip():
            hostname = "unknown-host"
            self.logger.warning(
                _("Could not determine hostname, using fallback: %s"), hostname
            )
        else:
            self.logger.debug("Final hostname determined: %s", hostname)

        return hostname.strip()

    def _server_host(self) -> Optional[str]:
        """The SysManage server's host name or address, from the config."""
        if not self.config:
            return None
        try:
            return urlsplit(self.config.get_server_url()).hostname
        except Exception:  # pylint: disable=broad-exception-caught
            return None

    def _source_address(self, family: int, destination: str) -> Optional[str]:
        """This machine's address on the route to ``destination`` (a UDP
        connect sends nothing), or None where there is no such route."""
        try:
            infos = socket.getaddrinfo(destination, 80, family, socket.SOCK_DGRAM)
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect(infos[0][4])
                return sock.getsockname()[0]
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.debug("No route to %s: %s", destination, error)
            return None

    def get_ip_addresses(self) -> Tuple[Optional[str], Optional[str]]:
        """Get both IPv4 and IPv6 addresses of the machine: the address on
        the route to the internet, else on the route to the SysManage server.
        An air-gapped network has no default route, so the first never
        answers there, and every host reported no address -- an NFS export
        cannot be limited to a host with none (lab, 2026-11-14)."""
        server = self._server_host()
        ipv4 = self._source_address(socket.AF_INET, "8.8.8.8")  # NOSONAR
        if ipv4 is None and server:
            ipv4 = self._source_address(socket.AF_INET, server)
        ipv6 = self._source_address(socket.AF_INET6, "2001:4860:4860::8888")  # NOSONAR
        if ipv6 is None and server:
            ipv6 = self._source_address(socket.AF_INET6, server)
        return ipv4, ipv6
