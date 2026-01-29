"""
Linux firewall rule parsers for UFW, firewalld, iptables, and nftables.

This module contains parsing logic for different Linux firewall systems.
"""

from __future__ import annotations

import subprocess  # nosec B404


class LinuxFirewallParsers:
    """Parsers for Linux firewall systems."""

    def __init__(self, logger):
        """Initialize Linux firewall parsers."""
        self.logger = logger

    def _add_port_to_list(
        self, port: str, is_ipv6: bool, tcp_v4: list, tcp_v6: list
    ) -> None:
        """Add a port to the appropriate IPv4 or IPv6 list."""
        if is_ipv6:
            tcp_v6.append(port)
        else:
            tcp_v4.append(port)

    def _parse_ufw_port_with_protocol(
        self,
        port_info: str,
        is_ipv6: bool,
        ipv4_tcp: list,
        ipv4_udp: list,
        ipv6_tcp: list,
        ipv6_udp: list,
    ) -> None:
        """Parse a UFW port entry that includes protocol (e.g., 22/tcp)."""
        port, proto = port_info.split("/", 1)
        proto_upper = proto.upper()
        if proto_upper == "TCP":
            self._add_port_to_list(port, is_ipv6, ipv4_tcp, ipv6_tcp)
        elif proto_upper == "UDP":
            self._add_port_to_list(port, is_ipv6, ipv4_udp, ipv6_udp)

    def _parse_ufw_port_without_protocol(
        self,
        port: str,
        is_ipv6: bool,
        ipv4_tcp: list,
        ipv4_udp: list,
        ipv6_tcp: list,
        ipv6_udp: list,
    ) -> None:
        """Parse a UFW port entry without protocol (applies to both TCP and UDP)."""
        self._add_port_to_list(port, is_ipv6, ipv4_tcp, ipv6_tcp)
        self._add_port_to_list(port, is_ipv6, ipv4_udp, ipv6_udp)

    def _parse_ufw_line(
        self,
        line: str,
        ipv4_tcp: list,
        ipv4_udp: list,
        ipv6_tcp: list,
        ipv6_udp: list,
    ) -> None:
        """Parse a single UFW rule line and extract port information."""
        if "ALLOW" not in line:
            return

        parts = line.split()
        if len(parts) < 1:
            return

        port_info = parts[0]
        is_ipv6 = "(v6)" in line

        if "/" in port_info:
            self._parse_ufw_port_with_protocol(
                port_info, is_ipv6, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
            )
        elif port_info.isdigit():
            self._parse_ufw_port_without_protocol(
                port_info, is_ipv6, ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp
            )

    def parse_ufw_rules(self, output: str) -> tuple:
        """Parse UFW rules to extract open ports, separating IPv4 and IPv6.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        ipv4_tcp_ports = []
        ipv4_udp_ports = []
        ipv6_tcp_ports = []
        ipv6_udp_ports = []

        for line in output.split("\n"):
            self._parse_ufw_line(
                line, ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports
            )

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

    def _run_iptables_command(self, command: list) -> str | None:
        """Run an iptables command and return stdout if successful."""
        try:
            result = subprocess.run(  # nosec B603 B607
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def _parse_iptables_line(self, line: str, tcp_ports: list, udp_ports: list) -> None:
        """Parse a single iptables line and extract port if it's an ACCEPT rule."""
        if "ACCEPT" not in line or "dpt:" not in line:
            return

        port = line.split("dpt:")[1].split()[0]
        if "tcp" in line.lower():
            tcp_ports.append(port)
        elif "udp" in line.lower():
            udp_ports.append(port)

    def _parse_iptables_output(
        self, output: str, tcp_ports: list, udp_ports: list
    ) -> None:
        """Parse iptables output and populate port lists."""
        for line in output.split("\n"):
            self._parse_iptables_line(line, tcp_ports, udp_ports)

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
        ipv4_output = self._run_iptables_command(
            ["iptables", "-L", "INPUT", "-n", "--line-numbers"]
        )
        if ipv4_output:
            self._parse_iptables_output(ipv4_output, ipv4_tcp_ports, ipv4_udp_ports)

        # Parse IPv6 ip6tables rules
        ipv6_output = self._run_iptables_command(
            ["ip6tables", "-L", "INPUT", "-n", "--line-numbers"]
        )
        if ipv6_output:
            self._parse_iptables_output(ipv6_output, ipv6_tcp_ports, ipv6_udp_ports)

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def _extract_nftables_table_family(self, line: str) -> str | None:
        """Extract table family from a nftables table declaration line.

        Returns:
            Family name (ip, ip6, inet) or None if not a table line.
        """
        if not line.startswith("table "):
            return None
        parts = line.split()
        if len(parts) >= 2:
            return parts[1]
        return None

    def _is_nftables_accept_rule(self, line: str) -> bool:
        """Check if this is an accept rule with a destination port."""
        return "accept" in line.lower() and "dport" in line

    def _get_nftables_protocol(self, line: str) -> tuple:
        """Determine protocol from nftables rule line.

        Returns:
            tuple: (is_tcp, is_udp)
        """
        line_lower = line.lower()
        return "tcp" in line_lower, "udp" in line_lower

    def _extract_nftables_ports(self, line: str) -> list | None:
        """Extract port(s) from an nftables rule line.

        Handles formats like:
        - tcp dport 22 accept
        - tcp dport { 22, 80, 443 } accept

        Returns:
            List of ports or None if parsing fails.
        """
        if "{" in line and "}" in line:
            port_section = line.split("{")[1].split("}")[0]
            return [p.strip() for p in port_section.split(",")]

        parts = line.split("dport")
        if len(parts) > 1:
            port_part = parts[1].strip().split()[0]
            return [port_part]

        return None

    def _add_nftables_port_by_family(
        self,
        port: str,
        family: str,
        is_tcp: bool,
        is_udp: bool,
        port_lists: dict,
    ) -> None:
        """Add a port to the appropriate lists based on table family and protocol.

        Args:
            port: The port number to add
            family: Table family (ip, ip6, inet)
            is_tcp: Whether this is a TCP rule
            is_udp: Whether this is a UDP rule
            port_lists: Dictionary containing ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp lists
        """
        if family == "ip6":
            self._add_port_by_protocol(
                port, is_tcp, is_udp, port_lists["ipv6_tcp"], port_lists["ipv6_udp"]
            )
        elif family == "ip":
            self._add_port_by_protocol(
                port, is_tcp, is_udp, port_lists["ipv4_tcp"], port_lists["ipv4_udp"]
            )
        elif family == "inet":
            self._add_port_by_protocol(
                port, is_tcp, is_udp, port_lists["ipv4_tcp"], port_lists["ipv4_udp"]
            )
            self._add_port_by_protocol(
                port, is_tcp, is_udp, port_lists["ipv6_tcp"], port_lists["ipv6_udp"]
            )

    def _add_port_by_protocol(
        self, port: str, is_tcp: bool, is_udp: bool, tcp_list: list, udp_list: list
    ) -> None:
        """Add port to TCP or UDP list based on protocol."""
        if is_tcp:
            tcp_list.append(port)
        elif is_udp:
            udp_list.append(port)

    def _parse_nftables_line(
        self,
        line: str,
        current_family: str | None,
        port_lists: dict,
    ) -> None:
        """Parse a single nftables rule line and extract port information.

        Args:
            line: The nftables rule line to parse
            current_family: Current table family (ip, ip6, inet)
            port_lists: Dictionary containing ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp lists
        """
        if not self._is_nftables_accept_rule(line):
            return

        is_tcp, is_udp = self._get_nftables_protocol(line)
        if not is_tcp and not is_udp:
            return

        ports = self._extract_nftables_ports(line)
        if not ports or not current_family:
            return

        for port in ports:
            self._add_nftables_port_by_family(
                port, current_family, is_tcp, is_udp, port_lists
            )

    def parse_nftables_rules(self, output: str) -> tuple:
        """Parse nftables rules to extract open ports for IPv4 and IPv6.

        Returns:
            tuple: (ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports)
        """
        port_lists = {
            "ipv4_tcp": [],
            "ipv4_udp": [],
            "ipv6_tcp": [],
            "ipv6_udp": [],
        }

        current_family = None

        for line in output.split("\n"):
            line = line.strip()

            # Check for table family declaration
            family = self._extract_nftables_table_family(line)
            if family is not None:
                current_family = family
                continue

            # Parse rule line
            self._parse_nftables_line(line, current_family, port_lists)

        return (
            port_lists["ipv4_tcp"],
            port_lists["ipv4_udp"],
            port_lists["ipv6_tcp"],
            port_lists["ipv6_udp"],
        )
