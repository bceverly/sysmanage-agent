"""
Firewall status collection for SysManage Agent.
Detects firewall software and collects open ports across different operating systems.

Security Note: This module uses subprocess to execute system firewall commands (ufw,
firewall-cmd, iptables, etc.). All commands are hardcoded with no user input, use
shell=False, and only call trusted system utilities. B603/B607 warnings are suppressed
as these subprocess calls are safe by design.
"""

import json
import logging
import platform
import subprocess  # nosec B404
from typing import Dict, Optional

from src.sysmanage_agent.operations.firewall_bsd_parsers import BsdFirewallParsers
from src.sysmanage_agent.operations.firewall_linux_parsers import LinuxFirewallParsers
from src.sysmanage_agent.operations.firewall_port_helpers import FirewallPortHelpers


class FirewallCollector:
    """Collects firewall status information across different operating systems."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the firewall collector."""
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system()

        # Initialize helper modules
        self.linux_parsers = LinuxFirewallParsers(self.logger)
        self.bsd_parsers = BsdFirewallParsers(self.logger)
        self.port_helpers = FirewallPortHelpers(self.logger)

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
        # Try each firewall in order of preference
        collectors = [
            self._collect_ufw,
            self._collect_firewalld,
            self._collect_iptables,
            self._collect_nftables,
        ]

        for collector in collectors:
            result = collector()
            if result is not None:
                return result

        return self._empty_status()

    def _collect_ufw(self) -> Optional[Dict]:
        """Collect ufw firewall status (Ubuntu/Debian)."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None

            enabled = "Status: active" in result.stdout
            ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                self.linux_parsers.parse_ufw_rules(result.stdout)
            )

            return self._build_firewall_status_with_ipv6(
                "ufw",
                enabled,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _collect_firewalld(self) -> Optional[Dict]:
        """Collect firewalld status (RHEL/CentOS/Fedora)."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["firewall-cmd", "--state"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0 and "running" in result.stdout:
                ipv4_tcp_ports, ipv4_udp_ports, _ipv6_tcp, _ipv6_udp = (
                    self.linux_parsers.get_firewalld_ports()
                )
                return self._build_firewall_status_legacy(
                    "firewalld", True, ipv4_tcp_ports, ipv4_udp_ports
                )

            if "not running" in result.stdout or result.returncode != 0:
                return self._build_disabled_status("firewalld")

            return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _collect_iptables(self) -> Optional[Dict]:
        """Collect iptables firewall status (legacy Linux)."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None

            has_rules = len(result.stdout.strip().split("\n")) > 8
            ipv4_tcp_ports, ipv4_udp_ports, _ipv6_tcp, _ipv6_udp = (
                self.linux_parsers.parse_iptables_rules()
            )
            return self._build_firewall_status_legacy(
                "iptables", has_rules, ipv4_tcp_ports, ipv4_udp_ports
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _collect_nftables(self) -> Optional[Dict]:
        """Collect nftables firewall status."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            ipv4_tcp_ports, ipv4_udp_ports, _ipv6_tcp, _ipv6_udp = (
                self.linux_parsers.parse_nftables_rules(result.stdout)
            )
            return self._build_firewall_status_legacy(
                "nftables", True, ipv4_tcp_ports, ipv4_udp_ports
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _build_firewall_status_with_ipv6(
        self,
        name: str,
        enabled: bool,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
        ipv6_tcp_ports: list,
        ipv6_udp_ports: list,
    ) -> Dict:
        """Build firewall status dict with full IPv4/IPv6 separation."""
        ipv4_ports = self.port_helpers.merge_ports_with_protocols(
            ipv4_tcp_ports, ipv4_udp_ports
        )
        ipv6_ports = self.port_helpers.merge_ports_with_protocols(
            ipv6_tcp_ports, ipv6_udp_ports
        )

        # Legacy combined lists for backward compatibility
        all_tcp_ports = sorted(set(ipv4_tcp_ports + ipv6_tcp_ports))
        all_udp_ports = sorted(set(ipv4_udp_ports + ipv6_udp_ports))

        return {
            "firewall_name": name,
            "enabled": enabled,
            "tcp_open_ports": json.dumps(all_tcp_ports) if all_tcp_ports else None,
            "udp_open_ports": json.dumps(all_udp_ports) if all_udp_ports else None,
            "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
            "ipv6_ports": json.dumps(ipv6_ports) if ipv6_ports else None,
        }

    def _build_firewall_status_legacy(
        self,
        name: str,
        enabled: bool,
        ipv4_tcp_ports: list,
        ipv4_udp_ports: list,
    ) -> Dict:
        """Build firewall status dict for legacy firewalls (IPv4-only in legacy fields)."""
        ipv4_ports = self.port_helpers.merge_ports_with_protocols(
            ipv4_tcp_ports, ipv4_udp_ports
        )

        return {
            "firewall_name": name,
            "enabled": enabled,
            "tcp_open_ports": json.dumps(ipv4_tcp_ports) if ipv4_tcp_ports else None,
            "udp_open_ports": json.dumps(ipv4_udp_ports) if ipv4_udp_ports else None,
            "ipv4_ports": json.dumps(ipv4_ports) if ipv4_ports else None,
            "ipv6_ports": None,
        }

    def _build_disabled_status(self, name: str) -> Dict:
        """Build firewall status dict for a disabled firewall."""
        return {
            "firewall_name": name,
            "enabled": False,
            "tcp_open_ports": None,
            "udp_open_ports": None,
            "ipv4_ports": None,
            "ipv6_ports": None,
        }

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
                    self.port_helpers.get_windows_firewall_ports()
                )
                tcp_ports = ipv4_tcp_ports  # For legacy compatibility
                udp_ports = ipv4_udp_ports  # For legacy compatibility
                ipv4_ports = self.port_helpers.merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self.port_helpers.merge_ports_with_protocols(
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
                    self.bsd_parsers.get_pf_ports()
                )

                # Merge IPv4 and IPv6 ports with protocol tags
                ipv4_ports = self.port_helpers.merge_ports_with_protocols(
                    ipv4_tcp_ports, ipv4_udp_ports
                )
                ipv6_ports = self.port_helpers.merge_ports_with_protocols(
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
        # Try NPF first on NetBSD
        if self.system == "NetBSD":
            result = self._collect_npf()
            if result is not None:
                return result

        # Try pf (OpenBSD default, FreeBSD option)
        result = self._collect_pf()
        if result is not None:
            return result

        # Try ipfw (FreeBSD option)
        result = self._collect_ipfw()
        if result is not None:
            return result

        return self._empty_status()

    def _collect_npf(self) -> Optional[Dict]:
        """Collect NPF firewall status (NetBSD)."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["npfctl", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None

            enabled = self._is_npf_enabled(result.stdout)
            ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                self._get_npf_ports(result.stdout)
            )

            return self._build_firewall_status_with_ipv6(
                "npf",
                enabled,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            return None

    def _is_npf_enabled(self, output: str) -> bool:
        """Check if NPF is active from npfctl output."""
        # Output format: "# filtering:    active" or "# filtering:    inactive"
        output_lower = output.lower()
        return (
            "filtering:" in output_lower
            and "active" in output_lower
            and "inactive" not in output_lower
        )

    def _get_npf_ports(self, output: str) -> tuple:
        """Get ports from NPF rules, falling back to listening ports if needed."""
        ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
            self.bsd_parsers.parse_npf_rules(output)
        )

        # If no ports found from NPF rules, fallback to detecting listening ports
        # This handles cases where NPF uses default policies without explicit rules
        if not any([ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports]):
            self.logger.debug(
                "No ports found in NPF rules, falling back to listening port detection"
            )
            return self.port_helpers.get_listening_ports()

        return ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports

    def _collect_pf(self) -> Optional[Dict]:
        """Collect pf firewall status (OpenBSD default, FreeBSD option)."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["pfctl", "-s", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None

            enabled = "Status: Enabled" in result.stdout
            ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                self.bsd_parsers.get_pf_ports()
            )

            return self._build_firewall_status_with_ipv6(
                "pf",
                enabled,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            return None

    def _collect_ipfw(self) -> Optional[Dict]:
        """Collect ipfw firewall status (FreeBSD option)."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ipfw", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            enabled = self._is_ipfw_enabled()
            ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                self.bsd_parsers.parse_ipfw_rules(result.stdout)
            )

            return self._build_firewall_status_with_ipv6(
                "ipfw",
                enabled,
                ipv4_tcp_ports,
                ipv4_udp_ports,
                ipv6_tcp_ports,
                ipv6_udp_ports,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            return None

    def _is_ipfw_enabled(self) -> bool:
        """Check if IPFW is enabled via sysctl."""
        try:
            sysctl_result = subprocess.run(  # nosec B603 B607
                ["sysctl", "-n", "net.inet.ip.fw.enable"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if sysctl_result.returncode == 0:
                return sysctl_result.stdout.strip() == "1"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False
