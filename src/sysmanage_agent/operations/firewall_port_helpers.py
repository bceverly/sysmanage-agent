"""
Helper functions for firewall port collection and formatting.

This module contains utility functions for port detection and formatting.
"""

import subprocess  # nosec B404
from typing import Optional


def _empty_port_lists() -> tuple:
    """Return empty port lists for IPv4/IPv6 TCP/UDP."""
    return [], [], [], []


def _add_port_to_list(port: str, port_list: list) -> None:
    """Add port to list if not already present."""
    if port not in port_list:
        port_list.append(port)


def _extract_port_from_address(local_addr: str, use_dot_separator: bool = False) -> str:
    """Extract port number from local address string.

    Args:
        local_addr: Address string like '*:22', '0.0.0.0:22', '[::]:22', or '*.22'
        use_dot_separator: If True, try dot separator for BSD-style addresses

    Returns:
        Port number as string, or empty string if invalid
    """
    if ":" not in local_addr and "." not in local_addr:
        return ""

    # Try colon first (IPv6 and some IPv4)
    if ":" in local_addr:
        port = local_addr.rsplit(":", 1)[-1]
    elif use_dot_separator:
        # BSD style: 192.168.1.1.22 or *.22
        port = local_addr.rsplit(".", 1)[-1]
    else:
        return ""

    return port if port.isdigit() else ""


def _is_ipv6_address(local_addr: str, proto: str = "") -> bool:
    """Determine if address is IPv6.

    Args:
        local_addr: Address string to check
        proto: Protocol string (may contain '6' for IPv6)

    Returns:
        True if address is IPv6
    """
    return "6" in proto or "[" in local_addr or local_addr.startswith("::")


def _categorize_port(
    port: str,
    proto: str,
    is_ipv6: bool,
    ipv4_tcp: list,
    ipv4_udp: list,
    ipv6_tcp: list,
    ipv6_udp: list,
) -> None:
    """Categorize port by protocol and IP version, adding to appropriate list.

    Args:
        port: Port number as string
        proto: Protocol string (should contain 'tcp' or 'udp')
        is_ipv6: Whether this is an IPv6 address
        ipv4_tcp: List to add IPv4 TCP ports to
        ipv4_udp: List to add IPv4 UDP ports to
        ipv6_tcp: List to add IPv6 TCP ports to
        ipv6_udp: List to add IPv6 UDP ports to
    """
    if "tcp" in proto:
        target_list = ipv6_tcp if is_ipv6 else ipv4_tcp
        _add_port_to_list(port, target_list)
    elif "udp" in proto:
        target_list = ipv6_udp if is_ipv6 else ipv4_udp
        _add_port_to_list(port, target_list)


class FirewallPortHelpers:
    """Helper functions for port collection and formatting."""

    def __init__(self, logger):
        """Initialize firewall port helpers."""
        self.logger = logger

    def merge_ports_with_protocols(self, tcp_ports: list, udp_ports: list) -> list:
        """
        Merge TCP and UDP port lists into a unified format with protocol tags.

        Args:
            tcp_ports: List of TCP ports
            udp_ports: List of UDP ports

        Returns:
            List of dicts like [{"port": "22", "protocols": ["tcp"]}, {"port": "53", "protocols": ["tcp", "udp"]}]
        """
        port_map = {}

        # Add TCP ports
        for port in tcp_ports:
            if port not in port_map:
                port_map[port] = []
            if "tcp" not in port_map[port]:
                port_map[port].append("tcp")

        # Add UDP ports
        for port in udp_ports:
            if port not in port_map:
                port_map[port] = []
            if "udp" not in port_map[port]:
                port_map[port].append("udp")

        # Convert to list format and sort numerically by port number
        def port_sort_key(item):
            """Extract numeric value from port for sorting (handles ranges like 33434-33600)."""
            port = item[0]
            # Handle port ranges - sort by first port number
            if "-" in str(port):
                port = str(port).split("-", maxsplit=1)[0]
            try:
                return int(port)
            except (ValueError, TypeError):
                # If not numeric, sort alphabetically at the end
                return float("inf")

        result = [
            {"port": port, "protocols": sorted(protocols)}
            for port, protocols in sorted(port_map.items(), key=port_sort_key)
        ]
        return result

    def _parse_windows_protocol_line(self, line: str) -> str:
        """Parse protocol from Windows Firewall rule line.

        Args:
            line: Line containing "Protocol:" prefix

        Returns:
            'tcp', 'udp', or empty string if not recognized
        """
        if "TCP" in line:
            return "tcp"
        if "UDP" in line:
            return "udp"
        return ""

    def _extract_windows_port(self, line: str) -> str:
        """Extract port from Windows Firewall LocalPort line.

        Args:
            line: Line containing "LocalPort:" prefix

        Returns:
            Port string or empty string if invalid
        """
        parts = line.split(":", 1)
        if len(parts) <= 1:
            return ""

        port = parts[1].strip()
        if not port or port == "Any":
            return ""
        return port

    def _add_windows_port(
        self,
        port: str,
        proto: str,
        ipv4_tcp: list,
        ipv4_udp: list,
        ipv6_tcp: list,
        ipv6_udp: list,
    ) -> None:
        """Add port to both IPv4 and IPv6 lists for Windows Firewall.

        Windows Firewall rules apply to both IPv4/IPv6 unless scoped.

        Args:
            port: Port number as string
            proto: Protocol ('tcp' or 'udp')
            ipv4_tcp: IPv4 TCP port list
            ipv4_udp: IPv4 UDP port list
            ipv6_tcp: IPv6 TCP port list
            ipv6_udp: IPv6 UDP port list
        """
        if proto == "tcp":
            ipv4_tcp.append(port)
            ipv6_tcp.append(port)
        elif proto == "udp":
            ipv4_udp.append(port)
            ipv6_udp.append(port)

    def _run_netsh_command(self) -> subprocess.CompletedProcess:
        """Run netsh command to get Windows Firewall rules.

        Returns:
            CompletedProcess result or None if command failed
        """
        return subprocess.run(  # nosec B603 B607
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def get_windows_firewall_ports(self) -> tuple:
        """Get open ports from Windows Firewall for IPv4 and IPv6.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        try:
            result = self._run_netsh_command()
            if result.returncode != 0:
                return _empty_port_lists()

            current_proto = None
            for line in result.stdout.split("\n"):
                if "Profiles:" in line:
                    continue

                if "Protocol:" in line:
                    current_proto = self._parse_windows_protocol_line(line)
                    continue

                if "LocalPort:" not in line or not current_proto:
                    continue

                port = self._extract_windows_port(line)
                if not port:
                    continue

                self._add_windows_port(
                    port,
                    current_proto,
                    ipv4_tcp_ports,
                    ipv4_udp_ports,
                    ipv6_tcp_ports,
                    ipv6_udp_ports,
                )

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def _run_ss_command(self) -> subprocess.CompletedProcess:
        """Run ss command to get listening ports.

        Returns:
            CompletedProcess result
        """
        return subprocess.run(  # nosec B603 B607
            ["ss", "-tuln"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def _run_netstat_command(self) -> subprocess.CompletedProcess:
        """Run netstat command to get listening ports.

        Returns:
            CompletedProcess result
        """
        return subprocess.run(  # nosec B603 B607
            ["netstat", "-an"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def _is_ss_listening_line(self, line: str) -> bool:
        """Check if ss output line represents a listening socket.

        Args:
            line: Line from ss output

        Returns:
            True if this is a listening socket line
        """
        return "LISTEN" in line or "UNCONN" in line

    def _parse_ss_line(self, line: str) -> tuple:
        """Parse ss output line to extract protocol and local address.

        Args:
            line: Line from ss output

        Returns:
            Tuple of (proto, local_addr) or (None, None) if invalid
        """
        parts = line.split()
        if len(parts) < 5:
            return None, None

        proto = parts[0].lower()
        local_addr = parts[4]
        return proto, local_addr

    def _parse_netstat_line(self, line: str) -> tuple:
        """Parse netstat output line to extract protocol and local address.

        Args:
            line: Line from netstat output

        Returns:
            Tuple of (proto, local_addr) or (None, None) if invalid
        """
        parts = line.split()
        if len(parts) < 4:
            return None, None

        proto = parts[0].lower()
        local_addr = parts[3]
        return proto, local_addr

    def _extract_port_from_ss_addr(self, local_addr: str) -> str:
        """Extract port from ss address format.

        Args:
            local_addr: Address like '*:22', '0.0.0.0:22', '[::]:22'

        Returns:
            Port string or empty string if invalid
        """
        if ":" not in local_addr:
            return ""

        port = local_addr.rsplit(":", 1)[-1]
        return port if port.isdigit() else ""

    def _process_ss_output(
        self,
        output: str,
        ipv4_tcp: list,
        ipv4_udp: list,
        ipv6_tcp: list,
        ipv6_udp: list,
    ) -> None:
        """Process ss command output and populate port lists.

        Args:
            output: Raw output from ss command
            ipv4_tcp: IPv4 TCP port list to populate
            ipv4_udp: IPv4 UDP port list to populate
            ipv6_tcp: IPv6 TCP port list to populate
            ipv6_udp: IPv6 UDP port list to populate
        """
        for line in output.split("\n"):
            if not self._is_ss_listening_line(line):
                continue

            proto, local_addr = self._parse_ss_line(line)
            if proto is None:
                continue

            port = self._extract_port_from_ss_addr(local_addr)
            if not port:
                continue

            is_ipv6 = _is_ipv6_address(local_addr)
            _categorize_port(
                port, proto, is_ipv6, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
            )

    def _process_netstat_output(
        self,
        output: str,
        ipv4_tcp: list,
        ipv4_udp: list,
        ipv6_tcp: list,
        ipv6_udp: list,
    ) -> None:
        """Process netstat command output and populate port lists.

        Args:
            output: Raw output from netstat command
            ipv4_tcp: IPv4 TCP port list to populate
            ipv4_udp: IPv4 UDP port list to populate
            ipv6_tcp: IPv6 TCP port list to populate
            ipv6_udp: IPv6 UDP port list to populate
        """
        for line in output.split("\n"):
            if "LISTEN" not in line:
                continue

            proto, local_addr = self._parse_netstat_line(line)
            if proto is None or not local_addr:
                continue

            port = _extract_port_from_address(local_addr, use_dot_separator=True)
            if not port:
                continue

            is_ipv6 = _is_ipv6_address(local_addr, proto)
            # Note: UDP doesn't have LISTEN state, so only TCP ports are caught with netstat
            if "tcp" in proto:
                _categorize_port(
                    port, proto, is_ipv6, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
                )

    def _sort_port_lists(
        self, ipv4_tcp: list, ipv4_udp: list, ipv6_tcp: list, ipv6_udp: list
    ) -> tuple:
        """Sort all port lists and return as tuple.

        Args:
            ipv4_tcp: IPv4 TCP port list
            ipv4_udp: IPv4 UDP port list
            ipv6_tcp: IPv6 TCP port list
            ipv6_udp: IPv6 UDP port list

        Returns:
            Tuple of sorted port lists
        """
        return (
            sorted(ipv4_tcp),
            sorted(ipv4_udp),
            sorted(ipv6_tcp),
            sorted(ipv6_udp),
        )

    def _try_ss_ports(self) -> Optional[tuple]:
        """Try to get listening ports using ss command.

        Returns:
            Tuple of port lists or None if ss failed
        """
        try:
            result = self._run_ss_command()
            if result.returncode != 0:
                return None

            ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
            self._process_ss_output(
                result.stdout, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
            )
            return self._sort_port_lists(ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _try_netstat_ports(self) -> Optional[tuple]:
        """Try to get listening ports using netstat command.

        Returns:
            Tuple of port lists or None if netstat failed
        """
        try:
            result = self._run_netstat_command()
            if result.returncode != 0:
                return None

            ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp = [], [], [], []
            self._process_netstat_output(
                result.stdout, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
            )
            return self._sort_port_lists(ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def get_listening_ports(self) -> tuple:
        """
        Get actually listening ports using ss or netstat.

        This is used as a fallback when firewall rules don't show explicit port rules.
        Returns the actual ports that services are listening on.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        # Try ss first (more modern, available on Linux and some BSDs)
        result = self._try_ss_ports()
        if result is not None:
            return result

        # Fall back to netstat (more universal, available on all Unix-like systems)
        result = self._try_netstat_ports()
        if result is not None:
            return result

        return _empty_port_lists()
