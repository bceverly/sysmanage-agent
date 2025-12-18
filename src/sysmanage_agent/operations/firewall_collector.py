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
                    self.linux_parsers.parse_ufw_rules(result.stdout)
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
                    self.linux_parsers.get_firewalld_ports()
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
                    self.linux_parsers.parse_iptables_rules()
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
                    self.linux_parsers.parse_nftables_rules(result.stdout)
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
                        self.bsd_parsers.parse_npf_rules(result.stdout)
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
                        ) = self.port_helpers.get_listening_ports()

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
                # Check if IPFW is enabled via sysctl
                enabled = False
                try:
                    sysctl_result = subprocess.run(  # nosec B603 B607
                        ["sysctl", "-n", "net.inet.ip.fw.enable"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if sysctl_result.returncode == 0:
                        enabled = sysctl_result.stdout.strip() == "1"
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass

                ipv4_tcp_ports, ipv4_udp_ports, ipv6_tcp_ports, ipv6_udp_ports = (
                    self.bsd_parsers.parse_ipfw_rules(result.stdout)
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
                    "firewall_name": "ipfw",
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
