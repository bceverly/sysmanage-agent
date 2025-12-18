"""
Helper functions for firewall port collection and formatting.

This module contains utility functions for port detection and formatting.
"""

# pylint: disable=too-many-nested-blocks

import subprocess  # nosec B404


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
            result = subprocess.run(  # nosec B603 B607
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

            current_proto = None
            for line in result.stdout.split("\n"):
                # Windows Firewall doesn't explicitly separate IPv4/IPv6
                # Rules apply to both unless specifically scoped to an interface type
                if "Profiles:" in line:
                    # Skip profile lines (future: could use to determine IPv4/IPv6 scope)
                    continue

                if "Protocol:" in line:
                    if "TCP" in line:
                        current_proto = "tcp"
                    elif "UDP" in line:
                        current_proto = "udp"
                    continue

                if "LocalPort:" not in line or not current_proto:
                    continue

                parts = line.split(":", 1)
                if len(parts) <= 1:
                    continue

                port = parts[1].strip()
                if not port or port == "Any":
                    continue

                # Windows Firewall rules don't explicitly separate IPv4/IPv6 by default
                # Rules apply to both unless specifically scoped to an interface type
                # For now, add to both IPv4 and IPv6 lists
                if current_proto == "tcp":
                    ipv4_tcp_ports.append(port)
                    ipv6_tcp_ports.append(port)
                elif current_proto == "udp":
                    ipv4_udp_ports.append(port)
                    ipv6_udp_ports.append(port)

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def get_listening_ports(self) -> tuple:
        """
        Get actually listening ports using ss or netstat.

        This is used as a fallback when firewall rules don't show explicit port rules.
        Returns the actual ports that services are listening on.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        # Try ss first (more modern, available on Linux and some BSDs)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ss", "-tuln"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "LISTEN" not in line and "UNCONN" not in line:
                        continue

                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    proto = parts[0].lower()
                    local_addr = parts[4]

                    # Extract port from address (format: *:22 or 0.0.0.0:22 or [::]:22)
                    if ":" not in local_addr:
                        continue

                    port = local_addr.rsplit(":", 1)[-1]
                    if not port.isdigit():
                        continue

                    # Determine if IPv4 or IPv6
                    is_ipv6 = "[" in local_addr or local_addr.startswith("::")

                    # Categorize by protocol and IP version
                    if "tcp" in proto:
                        if is_ipv6:
                            if port not in ipv6_tcp_ports:
                                ipv6_tcp_ports.append(port)
                        else:
                            if port not in ipv4_tcp_ports:
                                ipv4_tcp_ports.append(port)
                    elif "udp" in proto:
                        if is_ipv6:
                            if port not in ipv6_udp_ports:
                                ipv6_udp_ports.append(port)
                        else:
                            if port not in ipv4_udp_ports:
                                ipv4_udp_ports.append(port)

                return (
                    sorted(ipv4_tcp_ports),
                    sorted(ipv4_udp_ports),
                    sorted(ipv6_tcp_ports),
                    sorted(ipv6_udp_ports),
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fall back to netstat (more universal, available on all Unix-like systems)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["netstat", "-an"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "LISTEN" not in line:
                        continue

                    parts = line.split()
                    if len(parts) < 4:
                        continue

                    # netstat format varies by OS, but typically:
                    # Proto Recv-Q Send-Q Local-Address Foreign-Address State
                    proto = parts[0].lower()
                    local_addr = parts[3] if len(parts) > 3 else ""

                    # Extract port from address
                    if ":" not in local_addr and "." not in local_addr:
                        continue

                    # NetBSD/BSD format: address.port or address:port
                    # Try colon first (IPv6 and some IPv4)
                    if ":" in local_addr:
                        port = local_addr.rsplit(":", 1)[-1]
                    else:
                        # BSD style: 192.168.1.1.22 or *.22
                        port = local_addr.rsplit(".", 1)[-1]

                    if not port.isdigit():
                        continue

                    # Determine if IPv4 or IPv6
                    is_ipv6 = (
                        "6" in proto or "[" in local_addr or local_addr.startswith("::")
                    )

                    # Categorize by protocol and IP version
                    if "tcp" in proto:
                        if is_ipv6:
                            if port not in ipv6_tcp_ports:
                                ipv6_tcp_ports.append(port)
                        else:
                            if port not in ipv4_tcp_ports:
                                ipv4_tcp_ports.append(port)
                    # Note: UDP doesn't have LISTEN state, so this won't catch UDP ports with netstat

                return (
                    sorted(ipv4_tcp_ports),
                    sorted(ipv4_udp_ports),
                    sorted(ipv6_tcp_ports),
                    sorted(ipv6_udp_ports),
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return [], [], [], []
