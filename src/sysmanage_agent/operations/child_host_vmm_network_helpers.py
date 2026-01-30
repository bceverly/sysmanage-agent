"""
Network helper functions for VMM autoinstall.

This module provides network-related utility functions for detecting
interfaces and selecting unused subnets.
"""

import subprocess  # nosec B404 # Required for system command execution
from typing import Dict, Optional

from src.i18n import _


def detect_physical_interface(logger) -> Optional[str]:
    """
    Auto-detect the best physical interface to use.

    Prioritizes:
    1. Wired over wireless
    2. Non-routable IPs over routable IPs
    3. Interfaces with IP addresses

    Args:
        logger: Logger instance for warnings

    Returns:
        Interface name (e.g., "em0") or None if no suitable interface found
    """
    try:
        # Get all interface information
        result = subprocess.run(  # nosec B603 B607
            ["ifconfig"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            return None

        # Parse ifconfig output
        interfaces = {}
        current_iface = None

        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            # New interface line (doesn't start with whitespace in original)
            if line and not line[0].isspace() and ":" in line:
                iface_name = line.split(":")[0]
                current_iface = iface_name
                interfaces[iface_name] = {
                    "name": iface_name,
                    "ip": None,
                    "is_up": "UP" in line,
                    "is_wired": is_wired_interface(iface_name),
                }
            elif current_iface and "inet " in line:
                # Extract IP address
                parts = line.split()
                if len(parts) >= 2:
                    ip_addr = parts[1]
                    interfaces[current_iface]["ip"] = ip_addr
                    interfaces[current_iface]["is_private"] = is_private_ip(ip_addr)

        # Filter for suitable interfaces (up and has IP)
        candidates = [
            iface
            for iface in interfaces.values()
            if iface["is_up"] and iface["ip"] and iface["ip"] != "127.0.0.1"
        ]

        if not candidates:
            return None

        # Sort by priority: wired > wireless, private > public
        candidates.sort(
            key=lambda x: (
                x.get("is_wired", False),
                x.get("is_private", False),
            ),
            reverse=True,
        )

        return candidates[0]["name"]

    except Exception as error:
        logger.warning(_("Error detecting physical interface: %s"), error)
        return None


def is_wired_interface(iface_name: str) -> bool:
    """Check if interface name indicates a wired connection."""
    wired_prefixes = ["em", "re", "vio", "bge", "bnx", "ix", "msk", "sk"]
    wireless_prefixes = ["iwn", "iwm", "athn", "ral", "rtw", "atu", "wi"]

    for prefix in wired_prefixes:
        if iface_name.startswith(prefix):
            return True
    for prefix in wireless_prefixes:
        if iface_name.startswith(prefix):
            return False

    # Unknown interface type, assume wired
    return True


def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private/non-routable range."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False

        first = int(parts[0])
        second = int(parts[1])

        # 10.0.0.0/8
        if first == 10:
            return True
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True

        return False
    except (ValueError, IndexError):
        return False


def _get_used_subnets_ifconfig(ifconfig_output: str) -> set:
    """
    Extract used /24 subnets from ifconfig output.

    Args:
        ifconfig_output: stdout from ifconfig command

    Returns:
        Set of subnet strings (e.g., {"192.168.1.0", "10.0.0.0"})
    """
    used_subnets = set()
    for line in ifconfig_output.split("\n"):
        if "inet " not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_addr = parts[1]
        ip_parts = ip_addr.split(".")
        if len(ip_parts) == 4:
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0"
            used_subnets.add(subnet)
    return used_subnets


def _find_unused_subnet(used_subnets: set, candidate_subnets: list) -> str:
    """
    Find the first unused subnet from candidates or generate one.

    Args:
        used_subnets: Set of already used subnet strings
        candidate_subnets: List of preferred subnets to try

    Returns:
        An unused subnet string
    """
    # Try preferred candidates first
    for subnet in candidate_subnets:
        if subnet not in used_subnets:
            return subnet

    # If all candidates are in use, try higher 10.x.0.0 range
    for i in range(3, 255):
        subnet = f"10.{i}.0.0"
        if subnet not in used_subnets:
            return subnet

    # Fallback
    return "10.0.0.0"


def select_unused_subnet(logger) -> Optional[Dict[str, str]]:
    """
    Dynamically select an unused private subnet for VM network.

    Args:
        logger: Logger instance for warnings

    Returns:
        Dict with keys: network, netmask, gateway_ip, dhcp_start, dhcp_end
        or None if no suitable subnet found
    """
    # Common private subnets to try
    candidate_subnets = [
        "100.64.0.0",  # NOSONAR - CGNAT range - won't conflict with typical networks
        "10.0.0.0",  # NOSONAR - private subnet for VM networking
        "10.1.0.0",  # NOSONAR - private subnet for VM networking
        "10.2.0.0",  # NOSONAR - private subnet for VM networking
        "192.168.100.0",  # NOSONAR - private subnet for VM networking
        "192.168.101.0",  # NOSONAR - private subnet for VM networking
        "172.16.0.0",  # NOSONAR - private subnet for VM networking
    ]

    try:
        # Get all currently used IPs on the host
        result = subprocess.run(  # nosec B603 B607
            ["ifconfig"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            return format_subnet_info("10.0.0.0")

        used_subnets = _get_used_subnets_ifconfig(result.stdout)
        subnet = _find_unused_subnet(used_subnets, candidate_subnets)
        return format_subnet_info(subnet)

    except Exception as error:
        logger.warning(_("Error selecting unused subnet: %s"), error)
        return format_subnet_info("10.0.0.0")


def format_subnet_info(network: str) -> Dict[str, str]:
    """Format subnet information for use in dhcpd and bridge config."""
    parts = network.split(".")
    return {
        "network": network,
        "netmask": "255.255.255.0",  # NOSONAR - private subnet netmask for VM networking
        "gateway_ip": f"{parts[0]}.{parts[1]}.{parts[2]}.1",
        "dhcp_start": f"{parts[0]}.{parts[1]}.{parts[2]}.10",
        "dhcp_end": f"{parts[0]}.{parts[1]}.{parts[2]}.254",
    }


def get_host_dns_server(logger) -> Optional[str]:
    """
    Get the DNS server from the host's /etc/resolv.conf.

    Args:
        logger: Logger instance for warnings

    Returns:
        First nameserver IP address or None if not found
    """
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as resolv_file:
            for line in resolv_file:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Parse nameserver lines
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_server = parts[1]
                        # Strip any trailing comments
                        if "#" in dns_server:
                            dns_server = dns_server.split("#")[0].strip()
                        logger.info(_("Detected host DNS server: %s"), dns_server)
                        return dns_server
        return None
    except Exception as error:
        logger.warning(_("Error reading /etc/resolv.conf: %s"), error)
        return None
