"""
BSD firewall rule parsers for pf, ipfw, and npf.

This module contains parsing logic for different BSD firewall systems.
"""

import subprocess  # nosec B404

# Constants for rule parsing
_TO_ANY_PATTERN = " to any "


class BsdFirewallParsers:
    """Parsers for BSD firewall systems."""

    def __init__(self, logger):
        """Initialize BSD firewall parsers."""
        self.logger = logger

    def _add_port_to_list(
        self,
        port: str,
        is_ipv6: bool,
        is_tcp: bool,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
        ipv6_tcp_ports: list,
        ipv6_udp_ports: list,
    ) -> None:
        """Add a port to the appropriate list based on protocol and IP version."""
        if is_tcp:
            if is_ipv6:
                ipv6_tcp_ports.append(port)
            else:
                ipv4_tcp_ports.append(port)
        else:
            if is_ipv6:
                ipv6_udp_ports.append(port)
            else:
                ipv4_udp_ports.append(port)

    def _add_port_to_both_protocols(
        self,
        port: str,
        is_ipv6: bool,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
        ipv6_tcp_ports: list,
        ipv6_udp_ports: list,
    ) -> None:
        """Add a port to both TCP and UDP lists for the appropriate IP version."""
        if is_ipv6:
            ipv6_tcp_ports.append(port)
            ipv6_udp_ports.append(port)
        else:
            ipv4_tcp_ports.append(port)
            ipv4_udp_ports.append(port)

    def _extend_ports_to_list(
        self,
        ports: list,
        is_ipv6: bool,
        is_tcp: bool,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
        ipv6_tcp_ports: list,
        ipv6_udp_ports: list,
    ) -> None:
        """Extend the appropriate port list based on protocol and IP version."""
        if is_tcp:
            if is_ipv6:
                ipv6_tcp_ports.extend(ports)
            else:
                ipv4_tcp_ports.extend(ports)
        else:
            if is_ipv6:
                ipv6_udp_ports.extend(ports)
            else:
                ipv4_udp_ports.extend(ports)

    def _extend_ports_to_both_protocols(
        self,
        ports: list,
        is_ipv6: bool,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
        ipv6_tcp_ports: list,
        ipv6_udp_ports: list,
    ) -> None:
        """Extend both TCP and UDP lists for the appropriate IP version."""
        if is_ipv6:
            ipv6_tcp_ports.extend(ports)
            ipv6_udp_ports.extend(ports)
        else:
            ipv4_tcp_ports.extend(ports)
            ipv4_udp_ports.extend(ports)

    def _is_pf_ipv6_rule(self, line: str) -> bool:
        """Determine if a pf rule is for IPv6."""
        if "inet6" in line:
            return True
        return False

    def _extract_pf_port(self, line: str) -> str | None:
        """Extract port number from a pf rule line."""
        parts = line.split("port")
        if len(parts) <= 1:
            return None
        return parts[1].strip().split()[0].strip("=")

    def _get_pf_protocol(self, line_lower: str) -> str | None:
        """Determine the protocol from a pf rule line.

        Returns:
            'tcp', 'udp', 'both', or None if no protocol is specified.
        """
        if "proto tcp" in line_lower or " tcp " in line_lower:
            return "tcp"
        if "proto udp" in line_lower or " udp " in line_lower:
            return "udp"
        if "proto" not in line_lower:
            return "both"
        return None

    def _process_pf_rule(
        self,
        line: str,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
        ipv6_tcp_ports: list,
        ipv6_udp_ports: list,
    ) -> None:
        """Process a single pf rule and extract port information."""
        if "pass" not in line or "port" not in line:
            return

        is_ipv6 = self._is_pf_ipv6_rule(line)
        port_str = self._extract_pf_port(line)
        if port_str is None:
            return

        protocol = self._get_pf_protocol(line.lower())
        if protocol == "tcp":
            self._add_port_to_list(
                port_str,
                is_ipv6,
                True,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )
        elif protocol == "udp":
            self._add_port_to_list(
                port_str,
                is_ipv6,
                False,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )
        elif protocol == "both":
            self._add_port_to_both_protocols(
                port_str,
                is_ipv6,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )

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
                self._process_pf_rule(
                    line,
                    ipv4_tcp_ports,
                    ipv4_udp_ports,
                    ipv6_tcp_ports,
                    ipv6_udp_ports,
                )

        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            pass

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def _is_ipfw_ipv6_rule(self, line: str) -> bool:
        """Determine if an ipfw rule is for IPv6."""
        line_lower = line.lower()
        return "ip6" in line_lower or "ipv6" in line_lower

    def _extract_ipfw_port_dst_port(self, line: str) -> str | None:
        """Extract port using dst-port format."""
        if "dst-port" not in line.lower():
            return None
        parts = line.split("dst-port")
        if len(parts) <= 1:
            return None
        return parts[1].strip().split()[0].strip(",")

    def _extract_ipfw_port_to_any(self, line: str) -> str | None:
        """Extract port from 'to any <port>' format."""
        if _TO_ANY_PATTERN not in line:
            return None
        parts = line.split(_TO_ANY_PATTERN)
        if len(parts) <= 1:
            return None
        last_part = parts[-1].strip()
        port_match = last_part.split()
        if port_match and port_match[0].isdigit():
            return port_match[0]
        return None

    def _extract_ipfw_port(self, line: str) -> str | None:
        """Extract port number from an ipfw rule line."""
        port = self._extract_ipfw_port_dst_port(line)
        if port is not None:
            return port
        return self._extract_ipfw_port_to_any(line)

    def _should_skip_ipfw_line(self, line: str) -> bool:
        """Check if an ipfw line should be skipped."""
        if "allow" not in line.lower():
            return True
        # Skip generic allow rules that don't specify protocols/ports
        line_lower = line.lower()
        if (
            "from any to any" in line
            and "tcp" not in line_lower
            and "udp" not in line_lower
        ):
            return True
        return False

    def _process_ipfw_rule(
        self,
        line: str,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
        ipv6_tcp_ports: list,
        ipv6_udp_ports: list,
    ) -> None:
        """Process a single ipfw rule and extract port information."""
        if self._should_skip_ipfw_line(line):
            return

        is_ipv6 = self._is_ipfw_ipv6_rule(line)
        line_lower = line.lower()

        if "tcp" in line_lower:
            port = self._extract_ipfw_port(line)
            if port:
                self._add_port_to_list(
                    port,
                    is_ipv6,
                    True,
                    ipv4_tcp_ports,
                    ipv4_udp_ports,
                    ipv6_tcp_ports,
                    ipv6_udp_ports,
                )
        elif "udp" in line_lower:
            port = self._extract_ipfw_port(line)
            if port:
                self._add_port_to_list(
                    port,
                    is_ipv6,
                    False,
                    ipv4_tcp_ports,
                    ipv4_udp_ports,
                    ipv6_tcp_ports,
                    ipv6_udp_ports,
                )

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
            self._process_ipfw_rule(
                line,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def _is_npf_ipv6_rule(self, line: str) -> bool:
        """Determine if an npf rule is for IPv6."""
        return "family inet6" in line or "inet6" in line

    def _extract_npf_port_list(self, port_part: str) -> list | None:
        """Extract ports from a port list format: { 80, 443, 25 }."""
        if not port_part.startswith("{"):
            return None
        if "}" not in port_part:
            return None
        port_list_str = port_part[
            port_part.index("{") + 1 : port_part.index("}")
        ].strip()
        return [p.strip() for p in port_list_str.split(",")]

    def _extract_npf_port_range(self, port_part: str) -> list | None:
        """Extract port range format: 33434-33600."""
        first_token = port_part.split()[0]
        if "-" not in first_token:
            return None
        return [first_token.strip()]

    def _extract_npf_single_port(self, port_part: str) -> list:
        """Extract single port from port part."""
        return [port_part.split()[0].strip(",")]

    def _extract_npf_ports(self, line: str) -> list | None:
        """Extract port number(s) from an npf rule line."""
        parts = line.split("port")
        if len(parts) <= 1:
            return None

        port_part = parts[1].strip()

        # Try port list format first
        port_list = self._extract_npf_port_list(port_part)
        if port_list is not None:
            return port_list

        # Try port range format
        port_range = self._extract_npf_port_range(port_part)
        if port_range is not None:
            return port_range

        # Default to single port
        return self._extract_npf_single_port(port_part)

    def _get_npf_protocol(self, line_lower: str) -> str | None:
        """Determine the protocol from an npf rule line.

        Returns:
            'tcp', 'udp', 'both', or None if no protocol is specified.
        """
        if "proto tcp" in line_lower or " tcp " in line_lower:
            return "tcp"
        if "proto udp" in line_lower or " udp " in line_lower:
            return "udp"
        if "proto" not in line_lower:
            return "both"
        return None

    def _process_npf_rule(
        self,
        line: str,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
        ipv6_tcp_ports: list,
        ipv6_udp_ports: list,
    ) -> None:
        """Process a single npf rule and extract port information."""
        if "pass" not in line or "port" not in line:
            return

        is_ipv6 = self._is_npf_ipv6_rule(line)
        port_strings = self._extract_npf_ports(line)
        if port_strings is None:
            return

        protocol = self._get_npf_protocol(line.lower())
        if protocol == "tcp":
            self._extend_ports_to_list(
                port_strings,
                is_ipv6,
                True,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )
        elif protocol == "udp":
            self._extend_ports_to_list(
                port_strings,
                is_ipv6,
                False,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )
        elif protocol == "both":
            self._extend_ports_to_both_protocols(
                port_strings,
                is_ipv6,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )

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
            self._process_npf_rule(
                line,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports
