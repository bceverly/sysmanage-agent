"""
BSD firewall rule parsers for pf, ipfw, and npf.

This module contains parsing logic for different BSD firewall systems.
"""

import subprocess  # nosec B404


class BsdFirewallParsers:
    """Parsers for BSD firewall systems."""

    def __init__(self, logger):
        """Initialize BSD firewall parsers."""
        self.logger = logger

    def get_pf_ports(self) -> tuple:
        """Get open ports from pf (macOS/BSD).

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        try:
            result = subprocess.run(  # nosec B603 B607
                ["pfctl", "-s", "rules"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

            for line in result.stdout.split("\n"):
                # PF rule format: pass in proto tcp from any to any port 22
                # or: pass in inet proto tcp to port 80
                # or: pass in inet6 proto tcp to port 80
                if "pass" not in line or "port" not in line:
                    continue

                # Determine if IPv4 or IPv6
                is_ipv6 = False
                if "inet6" in line:
                    is_ipv6 = True
                elif "inet " in line:
                    is_ipv6 = False
                # If neither specified, could be either - default to IPv4

                # Extract port number
                parts = line.split("port")
                if len(parts) <= 1:
                    continue

                port_str = parts[1].strip().split()[0].strip("=")

                # Check protocol
                line_lower = line.lower()
                if "proto tcp" in line_lower or " tcp " in line_lower:
                    if is_ipv6:
                        ipv6_tcp_ports.append(port_str)
                    else:
                        ipv4_tcp_ports.append(port_str)
                elif "proto udp" in line_lower or " udp " in line_lower:
                    if is_ipv6:
                        ipv6_udp_ports.append(port_str)
                    else:
                        ipv4_udp_ports.append(port_str)
                # If no specific protocol, might be both - add to both
                elif "proto" not in line_lower:
                    if is_ipv6:
                        ipv6_tcp_ports.append(port_str)
                        ipv6_udp_ports.append(port_str)
                    else:
                        ipv4_tcp_ports.append(port_str)
                        ipv4_udp_ports.append(port_str)

        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            pass

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def parse_ipfw_rules(self, output: str) -> tuple:
        """Parse ipfw rules to extract open ports.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        for line in output.split("\n"):
            if "allow" not in line.lower():
                continue

            # Skip generic allow rules that don't specify protocols/ports
            if (
                "from any to any" in line
                and "tcp" not in line.lower()
                and "udp" not in line.lower()
            ):
                continue

            # Determine if IPv4 or IPv6
            # IPFW uses "ip" for IPv4 and "ip6" for IPv6
            is_ipv6 = "ip6" in line.lower() or "ipv6" in line.lower()

            # Parse port from IPFW rule formats:
            # Format 1: "allow tcp from any to any 22" (port at end)
            # Format 2: "allow tcp from any to any dst-port 22" (dst-port keyword)
            port = None

            # Check for TCP
            if "tcp" in line.lower():
                # Try dst-port format first
                if "dst-port" in line.lower():
                    parts = line.split("dst-port")
                    if len(parts) > 1:
                        port = parts[1].strip().split()[0].strip(",")
                # Try port-at-end format: "to any <port>"
                elif " to any " in line:
                    # Get everything after "to any"
                    parts = line.split(" to any ")
                    if len(parts) > 1:
                        # Port is the last number on the line
                        last_part = parts[-1].strip()
                        port_match = last_part.split()
                        if port_match and port_match[0].isdigit():
                            port = port_match[0]

                if port:
                    if is_ipv6:
                        ipv6_tcp_ports.append(port)
                    else:
                        ipv4_tcp_ports.append(port)

            # Check for UDP
            elif "udp" in line.lower():
                # Try dst-port format first
                if "dst-port" in line.lower():
                    parts = line.split("dst-port")
                    if len(parts) > 1:
                        port = parts[1].strip().split()[0].strip(",")
                # Try port-at-end format: "to any <port>"
                elif " to any " in line:
                    # Get everything after "to any"
                    parts = line.split(" to any ")
                    if len(parts) > 1:
                        # Port is the last number on the line
                        last_part = parts[-1].strip()
                        port_match = last_part.split()
                        if port_match and port_match[0].isdigit():
                            port = port_match[0]

                if port:
                    if is_ipv6:
                        ipv6_udp_ports.append(port)
                    else:
                        ipv4_udp_ports.append(port)

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def parse_npf_rules(self, output: str) -> tuple:
        """Parse NPF rules to extract open ports.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        for line in output.split("\n"):
            # NPF rule format: pass in proto tcp to port 22
            # or: pass in family inet proto tcp to port 80
            # or: pass in family inet6 proto tcp to port 80
            # or: pass in proto tcp to any port { 80, 443, 25 }  (port list)
            # or: pass in proto udp to any port 33434-33600  (port range)
            if "pass" not in line or "port" not in line:
                continue

            # Determine if IPv4 or IPv6
            is_ipv6 = False
            if "family inet6" in line or "inet6" in line:
                is_ipv6 = True
            elif "family inet" in line or " inet " in line or "family inet4" in line:
                is_ipv6 = False
            # If neither specified, could be either - default to IPv4

            # Extract port number(s)
            parts = line.split("port")
            if len(parts) <= 1:
                continue

            port_part = parts[1].strip()

            # Handle port lists: { 80, 443, 25 }
            if port_part.startswith("{"):
                # Extract everything between { and }
                if "}" in port_part:
                    port_list_str = port_part[
                        port_part.index("{") + 1 : port_part.index("}")
                    ].strip()
                    port_strings = [p.strip() for p in port_list_str.split(",")]
                else:
                    continue
            # Handle port ranges: 33434-33600
            elif "-" in port_part.split()[0]:
                port_strings = [port_part.split()[0].strip()]
            # Handle single ports: 22
            else:
                port_strings = [port_part.split()[0].strip(",")]

            # Check protocol
            line_lower = line.lower()
            if "proto tcp" in line_lower or " tcp " in line_lower:
                if is_ipv6:
                    ipv6_tcp_ports.extend(port_strings)
                else:
                    ipv4_tcp_ports.extend(port_strings)
            elif "proto udp" in line_lower or " udp " in line_lower:
                if is_ipv6:
                    ipv6_udp_ports.extend(port_strings)
                else:
                    ipv4_udp_ports.extend(port_strings)
            # If no specific protocol, might be both - add to both
            elif "proto" not in line_lower:
                if is_ipv6:
                    ipv6_tcp_ports.extend(port_strings)
                    ipv6_udp_ports.extend(port_strings)
                else:
                    ipv4_tcp_ports.extend(port_strings)
                    ipv4_udp_ports.extend(port_strings)

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports
