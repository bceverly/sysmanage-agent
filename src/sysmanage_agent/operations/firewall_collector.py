"""
Firewall status collection for SysManage Agent.
Detects firewall software and collects open ports across different operating systems.

Security Note: This module uses subprocess to execute system firewall commands (ufw,
firewall-cmd, iptables, etc.). All commands are hardcoded with no user input, use
shell=False, and only call trusted system utilities. B603/B607 warnings are suppressed
as these subprocess calls are safe by design.
"""

# pylint: disable=too-many-lines,too-many-nested-blocks

import json
import logging
import platform
import subprocess  # nosec B404
from typing import Dict, Optional


class FirewallCollector:
    """Collects firewall status information across different operating systems."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the firewall collector."""
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system()

    def _merge_ports_with_protocols(self, tcp_ports: list, udp_ports: list) -> list:
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

        # Convert to list format and sort
        result = [
            {"port": port, "protocols": sorted(protocols)}
            for port, protocols in sorted(port_map.items())
        ]
        return result

    def collect_firewall_status(self) -> Dict:
        """
        Collect firewall status information for the current system.

        Returns:
            Dict containing:
                - firewall_name: Name of firewall software (str or None)
                - enabled: Whether firewall is enabled (bool)
                - tcp_open_ports: List of open TCP ports/ranges (list or None)
                - udp_open_ports: List of open UDP ports/ranges (list or None)
        """
        try:
            if self.system == "Linux":
                return self._collect_linux_firewall()
            if self.system == "Windows":
                return self._collect_windows_firewall()
            if self.system == "Darwin":  # macOS
                return self._collect_macos_firewall()
            if self.system in ["FreeBSD", "OpenBSD", "NetBSD"]:
                return self._collect_bsd_firewall()
            self.logger.warning(
                "Unsupported system for firewall detection: %s", self.system
            )
            return self._empty_status()
        except Exception as exc:
            self.logger.error("Error collecting firewall status: %s", exc)
            return self._empty_status()

    def _empty_status(self) -> Dict:
        """Return empty firewall status."""
        return {
            "firewall_name": None,
            "enabled": False,
            "tcp_open_ports": None,
            "udp_open_ports": None,
            "ipv4_ports": None,
            "ipv6_ports": None,
        }

    def _collect_linux_firewall(self) -> Dict:
        """Collect firewall status on Linux (ufw, firewalld, iptables, nftables)."""
        # Try ufw first (Ubuntu/Debian)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                enabled = "Status: active" in result.stdout
                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self._parse_ufw_rules(result.stdout)
                )

                # Merge IPv4 and IPv6 ports with protocol tags
                ipv4_ports = self._merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self._merge_ports_with_protocols(
                    ipv6_tcp_ports, ipv6_udp_ports
                )

                # Legacy combined lists for backward compatibility
                all_tcp_ports = sorted(set(ipv4_tcp_ports + ipv6_tcp_ports))
                all_udp_ports = sorted(set(ipv4_udp_ports + ipv6_udp_ports))

                return {
                    "firewall_name": "ufw",
                    "enabled": enabled,
                    "tcp_open_ports": (
                        json.dumps(all_tcp_ports) if all_tcp_ports else None
                    ),
                    "udp_open_ports": (
                        json.dumps(all_udp_ports) if all_udp_ports else None
                    ),
                    "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                    "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try firewalld (RHEL/CentOS/Fedora)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["firewall-cmd", "--state"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            # If firewall-cmd exists, report firewalld regardless of state
            if result.returncode == 0 and "running" in result.stdout:
                # Firewall is running
                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self._get_firewalld_ports()
                )
                tcp_ports = ipv4_tcp_ports  # For legacy compatibility
                udp_ports = ipv4_udp_ports  # For legacy compatibility
                ipv4_ports = self._merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self._merge_ports_with_protocols(
                    ipv6_tcp_ports, ipv6_udp_ports
                )
                return {
                    "firewall_name": "firewalld",
                    "enabled": True,
                    "tcp_open_ports": json.dumps(tcp_ports) if tcp_ports else None,
                    "udp_open_ports": json.dumps(udp_ports) if udp_ports else None,
                    "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                    "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                }
            if "not running" in result.stdout or result.returncode != 0:
                # Firewalld exists but is disabled/not running
                return {
                    "firewall_name": "firewalld",
                    "enabled": False,
                    "tcp_open_ports": None,
                    "udp_open_ports": None,
                    "ipv4_ports": None,
                    "ipv6_ports": None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try iptables (legacy)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                has_rules = len(result.stdout.strip().split("\n")) > 8
                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self._parse_iptables_rules()
                )
                tcp_ports = ipv4_tcp_ports  # For legacy compatibility
                udp_ports = ipv4_udp_ports  # For legacy compatibility
                ipv4_ports = self._merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self._merge_ports_with_protocols(
                    ipv6_tcp_ports, ipv6_udp_ports
                )
                return {
                    "firewall_name": "iptables",
                    "enabled": has_rules,
                    "tcp_open_ports": json.dumps(tcp_ports) if tcp_ports else None,
                    "udp_open_ports": json.dumps(udp_ports) if udp_ports else None,
                    "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                    "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try nftables
        try:
            result = subprocess.run(  # nosec B603 B607
                ["nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self._parse_nftables_rules(result.stdout)
                )
                tcp_ports = ipv4_tcp_ports  # For legacy compatibility
                udp_ports = ipv4_udp_ports  # For legacy compatibility
                ipv4_ports = self._merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self._merge_ports_with_protocols(
                    ipv6_tcp_ports, ipv6_udp_ports
                )
                return {
                    "firewall_name": "nftables",
                    "enabled": True,
                    "tcp_open_ports": json.dumps(tcp_ports) if tcp_ports else None,
                    "udp_open_ports": json.dumps(udp_ports) if udp_ports else None,
                    "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                    "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return self._empty_status()

    def _collect_windows_firewall(self) -> Dict:
        """Collect firewall status on Windows."""
        try:
            # Check if Windows Firewall is enabled
            result = subprocess.run(  # nosec B603 B607
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                enabled = "State" in result.stdout and "ON" in result.stdout
                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self._get_windows_firewall_ports()
                )
                tcp_ports = ipv4_tcp_ports  # For legacy compatibility
                udp_ports = ipv4_udp_ports  # For legacy compatibility
                ipv4_ports = self._merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self._merge_ports_with_protocols(
                    ipv6_tcp_ports, ipv6_udp_ports
                )
                return {
                    "firewall_name": "Windows Firewall",
                    "enabled": enabled,
                    "tcp_open_ports": json.dumps(tcp_ports) if tcp_ports else None,
                    "udp_open_ports": json.dumps(udp_ports) if udp_ports else None,
                    "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                    "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            self.logger.debug("Windows firewall check failed: %s", exc)

        return self._empty_status()

    def _collect_macos_firewall(self) -> Dict:
        """Collect firewall status on macOS (pf)."""
        try:
            # Check if pf (packet filter) is enabled
            result = subprocess.run(  # nosec B603 B607
                ["pfctl", "-s", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                enabled = "Status: Enabled" in result.stdout
                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self._get_pf_ports()
                )

                # Merge IPv4 and IPv6 ports with protocol tags
                ipv4_ports = self._merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self._merge_ports_with_protocols(
                    ipv6_tcp_ports, ipv6_udp_ports
                )

                # Legacy combined lists for backward compatibility
                all_tcp_ports = sorted(set(ipv4_tcp_ports + ipv6_tcp_ports))
                all_udp_ports = sorted(set(ipv4_udp_ports + ipv6_udp_ports))

                return {
                    "firewall_name": "pf (Packet Filter)",
                    "enabled": enabled,
                    "tcp_open_ports": (
                        json.dumps(all_tcp_ports) if all_tcp_ports else None
                    ),
                    "udp_open_ports": (
                        json.dumps(all_udp_ports) if all_udp_ports else None
                    ),
                    "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                    "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            pass

        return self._empty_status()

    def _collect_bsd_firewall(self) -> Dict:
        """Collect firewall status on BSD systems (pf, ipfw, npf)."""
        # Try NPF first (NetBSD default)
        if self.system == "NetBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["npfctl", "show"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0:
                    # Check if NPF is active - must have "filtering:" and "active" but NOT "inactive"
                    # Output format: "# filtering:    active" or "# filtering:    inactive"
                    output_lower = result.stdout.lower()
                    enabled = (
                        "filtering:" in output_lower
                        and "active" in output_lower
                        and "inactive" not in output_lower
                    )
                    ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                        self._parse_npf_rules(result.stdout)
                    )

                    # If no ports found from NPF rules, fallback to detecting listening ports
                    # This handles cases where NPF uses default policies without explicit rules
                    if not any(
                        [ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports]
                    ):
                        self.logger.debug(
                            "No ports found in NPF rules, falling back to listening port detection"
                        )
                        (
                            ipv4_tcp_ports,
                            ipv4_udp_ports,
                            ipv6_tcp_ports,
                            ipv6_udp_ports,
                        ) = self._get_listening_ports()

                    # Merge IPv4 and IPv6 ports with protocol tags
                    ipv4_ports = self._merge_ports_with_protocols(
                        ipv4_tcp_ports, ipv4_udp_ports
                    )
                    ipv6_ports = self._merge_ports_with_protocols(
                        ipv6_tcp_ports, ipv6_udp_ports
                    )

                    # Legacy combined lists for backward compatibility
                    all_tcp_ports = sorted(set(ipv4_tcp_ports + ipv6_tcp_ports))
                    all_udp_ports = sorted(set(ipv4_udp_ports + ipv6_udp_ports))

                    return {
                        "firewall_name": "npf",
                        "enabled": enabled,
                        "tcp_open_ports": (
                            json.dumps(all_tcp_ports) if all_tcp_ports else None
                        ),
                        "udp_open_ports": (
                            json.dumps(all_udp_ports) if all_udp_ports else None
                        ),
                        "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                        "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
                pass

        # Try pf (OpenBSD default, FreeBSD option)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["pfctl", "-s", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                enabled = "Status: Enabled" in result.stdout
                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self._get_pf_ports()
                )

                # Merge IPv4 and IPv6 ports with protocol tags
                ipv4_ports = self._merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self._merge_ports_with_protocols(
                    ipv6_tcp_ports, ipv6_udp_ports
                )

                # Legacy combined lists for backward compatibility
                all_tcp_ports = sorted(set(ipv4_tcp_ports + ipv6_tcp_ports))
                all_udp_ports = sorted(set(ipv4_udp_ports + ipv6_udp_ports))

                return {
                    "firewall_name": "pf",
                    "enabled": enabled,
                    "tcp_open_ports": (
                        json.dumps(all_tcp_ports) if all_tcp_ports else None
                    ),
                    "udp_open_ports": (
                        json.dumps(all_udp_ports) if all_udp_ports else None
                    ),
                    "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                    "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            pass

        # Try ipfw (FreeBSD option)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ipfw", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self._parse_ipfw_rules(result.stdout)
                )

                # Merge IPv4 and IPv6 ports with protocol tags
                ipv4_ports = self._merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self._merge_ports_with_protocols(
                    ipv6_tcp_ports, ipv6_udp_ports
                )

                # Legacy combined lists for backward compatibility
                all_tcp_ports = sorted(set(ipv4_tcp_ports + ipv6_tcp_ports))
                all_udp_ports = sorted(set(ipv4_udp_ports + ipv6_udp_ports))

                return {
                    "firewall_name": "ipfw",
                    "enabled": True,
                    "tcp_open_ports": (
                        json.dumps(all_tcp_ports) if all_tcp_ports else None
                    ),
                    "udp_open_ports": (
                        json.dumps(all_udp_ports) if all_udp_ports else None
                    ),
                    "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
                    "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
                }
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            pass

        return self._empty_status()

    def _parse_ufw_rules(self, output: str) -> tuple:
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

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def _get_firewalld_ports(self) -> tuple:
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

    def _parse_iptables_rules(self) -> tuple:
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

    def _parse_nftables_rules(self, output: str) -> tuple:
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

    def _get_windows_firewall_ports(self) -> tuple:
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

    def _get_pf_ports(self) -> tuple:
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

    def _parse_ipfw_rules(self, output: str) -> tuple:
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

            # Determine if IPv4 or IPv6
            # IPFW uses "ip" for IPv4 and "ip6" for IPv6
            is_ipv6 = "ip6" in line.lower()

            # Check for TCP
            if "tcp" in line.lower() and "dst-port" in line.lower():
                parts = line.split("dst-port")
                if len(parts) > 1:
                    port = parts[1].strip().split()[0].strip(",")
                    if is_ipv6:
                        ipv6_tcp_ports.append(port)
                    else:
                        ipv4_tcp_ports.append(port)
            # Check for UDP
            elif "udp" in line.lower() and "dst-port" in line.lower():
                parts = line.split("dst-port")
                if len(parts) > 1:
                    port = parts[1].strip().split()[0].strip(",")
                    if is_ipv6:
                        ipv6_udp_ports.append(port)
                    else:
                        ipv4_udp_ports.append(port)

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def _parse_npf_rules(self, output: str) -> tuple:
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

    def _get_listening_ports(self) -> tuple:
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
