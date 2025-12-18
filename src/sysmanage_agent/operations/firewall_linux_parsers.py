"""
Linux firewall rule parsers for UFW, firewalld, iptables, and nftables.

This module contains parsing logic for different Linux firewall systems.
"""

import subprocess  # nosec B404


class LinuxFirewallParsers:
    """Parsers for Linux firewall systems."""

    def __init__(self, logger):
        """Initialize Linux firewall parsers."""
        self.logger = logger

    def parse_ufw_rules(self, output: str) -> tuple:
        """Parse UFW rules to extract open ports, separating IPv4 and IPv6.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        # pylint: disable=too-many-nested-blocks
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        for line in output.split("\n"):
            if "ALLOW" in line:
                parts = line.split()
                if len(parts) >= 1:
                    port_info = parts[0]
                    # Check if this is an IPv6 rule by looking for "(v6)" in the line
                    is_ipv6 = "(v6)" in line

                    if "/" in port_info:
                        # Port with explicit protocol: 22/tcp or 53/udp
                        port, proto = port_info.split("/", 1)
                        if proto.upper() == "TCP":
                            if is_ipv6:
                                ipv6_tcp_ports.append(port)
                            else:
                                ipv4_tcp_ports.append(port)
                        elif proto.upper() == "UDP":
                            if is_ipv6:
                                ipv6_udp_ports.append(port)
                            else:
                                ipv4_udp_ports.append(port)
                    elif port_info.isdigit():
                        # Port without protocol (e.g., "3000 ALLOW Anywhere")
                        # means both TCP and UDP are allowed
                        port = port_info
                        if is_ipv6:
                            ipv6_tcp_ports.append(port)
                            ipv6_udp_ports.append(port)
                        else:
                            ipv4_tcp_ports.append(port)
                            ipv4_udp_ports.append(port)

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def get_firewalld_ports(self) -> tuple:
        """Get open ports from firewalld.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)

        Note: Firewalld ports apply to both IPv4 and IPv6 by default unless
        rich rules specify otherwise. We return the same ports for both families.
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []

        try:
            result = subprocess.run(  # nosec B603 B607
                ["firewall-cmd", "--list-ports"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                for port_proto in result.stdout.split():
                    if "/" in port_proto:
                        port, proto = port_proto.split("/", 1)
                        if proto.lower() == "tcp":
                            ipv4_tcp_ports.append(port)
                        elif proto.lower() == "udp":
                            ipv4_udp_ports.append(port)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # In firewalld, ports apply to both IPv4 and IPv6 by default
        # unless rich rules specify family=ipv4 or family=ipv6
        ipv6_tcp_ports = ipv4_tcp_ports.copy()
        ipv6_udp_ports = ipv4_udp_ports.copy()

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def parse_iptables_rules(self) -> tuple:
        """Parse iptables and ip6tables rules to extract open ports.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        # Parse IPv4 iptables rules
        try:
            result = subprocess.run(  # nosec B603 B607
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "ACCEPT" in line and "dpt:" in line:
                        if "tcp" in line.lower():
                            port = line.split("dpt:")[1].split()[0]
                            ipv4_tcp_ports.append(port)
                        elif "udp" in line.lower():
                            port = line.split("dpt:")[1].split()[0]
                            ipv4_udp_ports.append(port)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Parse IPv6 ip6tables rules
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ip6tables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "ACCEPT" in line and "dpt:" in line:
                        if "tcp" in line.lower():
                            port = line.split("dpt:")[1].split()[0]
                            ipv6_tcp_ports.append(port)
                        elif "udp" in line.lower():
                            port = line.split("dpt:")[1].split()[0]
                            ipv6_udp_ports.append(port)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def parse_nftables_rules(self, output: str) -> tuple:
        """Parse nftables rules to extract open ports for IPv4 and IPv6.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        # Track current table's family (ip, ip6, inet, etc.)
        current_family = None

        for line in output.split("\n"):
            line = line.strip()

            # Detect table family
            if line.startswith("table "):
                parts = line.split()
                if len(parts) >= 2:
                    current_family = parts[1]  # ip, ip6, inet, etc.
                continue

            # Look for accept rules with destination port
            if "accept" not in line.lower():
                continue

            # Parse port from various nftables formats:
            # tcp dport 22 accept
            # tcp dport { 22, 80, 443 } accept
            # meta l4proto tcp th dport 22 accept
            if "dport" not in line:
                continue

            # Determine protocol
            is_tcp = "tcp" in line.lower()
            is_udp = "udp" in line.lower()

            if not is_tcp and not is_udp:
                continue

            # Extract port(s)
            if "{" in line and "}" in line:
                # Port set: { 22, 80, 443 }
                port_section = line.split("{")[1].split("}")[0]
                ports = [p.strip() for p in port_section.split(",")]
            elif "dport" in line:
                # Single port
                parts = line.split("dport")
                if len(parts) > 1:
                    port_part = parts[1].strip().split()[0]
                    ports = [port_part]
                else:
                    continue
            else:
                continue

            # Determine IPv4 vs IPv6 based on table family
            # inet = both IPv4 and IPv6
            # ip = IPv4 only
            # ip6 = IPv6 only
            for port in ports:
                if current_family == "ip6":
                    # IPv6 only
                    if is_tcp:
                        ipv6_tcp_ports.append(port)
                    elif is_udp:
                        ipv6_udp_ports.append(port)
                elif current_family == "ip":
                    # IPv4 only
                    if is_tcp:
                        ipv4_tcp_ports.append(port)
                    elif is_udp:
                        ipv4_udp_ports.append(port)
                elif current_family == "inet":
                    # Both IPv4 and IPv6
                    if is_tcp:
                        ipv4_tcp_ports.append(port)
                        ipv6_tcp_ports.append(port)
                    elif is_udp:
                        ipv4_udp_ports.append(port)
                        ipv6_udp_ports.append(port)

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports
