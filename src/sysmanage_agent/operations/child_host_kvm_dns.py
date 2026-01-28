"""DNS detection utilities for KVM VM configuration."""

import os
import re
import subprocess  # nosec B404 # Required for system command execution
from typing import List

from src.i18n import _


def is_valid_ip(addr: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, addr):
        parts = addr.split(".")
        return all(0 <= int(part) <= 255 for part in parts)
    return False


def _parse_dns_from_systemd_resolve(output: str) -> List[str]:
    """Parse DNS servers from systemd-resolve output."""
    dns_servers = []
    in_dns_section = False

    for line in output.split("\n"):
        if "DNS Servers:" in line:
            parts = line.split("DNS Servers:")
            if len(parts) > 1 and parts[1].strip():
                dns_ip = parts[1].strip().split()[0]
                if is_valid_ip(dns_ip):
                    dns_servers.append(dns_ip)
            in_dns_section = True
        elif in_dns_section:
            stripped = line.strip()
            if stripped and ":" not in line:
                dns_ip = stripped.split()[0]
                if is_valid_ip(dns_ip):
                    dns_servers.append(dns_ip)
                else:
                    break
            elif ":" in line:
                in_dns_section = False

    return dns_servers


def _get_dns_from_systemd_resolve() -> List[str]:
    """Try to get DNS from systemd-resolve --status."""
    try:
        result = subprocess.run(  # nosec B603 B607
            ["systemd-resolve", "--status"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return _parse_dns_from_systemd_resolve(result.stdout)
    except Exception:  # nosec B110 # Expected: continue to next DNS detection method
        pass
    return []


def _get_dns_from_resolvectl() -> List[str]:
    """Try to get DNS from resolvectl status (newer systemd)."""
    try:
        result = subprocess.run(  # nosec B603 B607
            ["resolvectl", "status"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return _parse_dns_from_systemd_resolve(result.stdout)
    except Exception:  # nosec B110 # Expected: continue to next DNS detection method
        pass
    return []


def _get_dns_from_resolv_conf() -> List[str]:
    """Parse DNS from /etc/resolv.conf (skip stub resolvers)."""
    dns_servers = []
    try:
        resolv_path = "/etc/resolv.conf"
        if os.path.islink(resolv_path):
            for alt_path in [
                "/run/systemd/resolve/resolv.conf",
                "/run/resolvconf/resolv.conf",
            ]:
                if os.path.exists(alt_path):
                    resolv_path = alt_path
                    break

        with open(resolv_path, "r", encoding="utf-8") as resolv_file:
            for line in resolv_file:
                line = line.strip()
                if line.startswith("nameserver"):
                    dns_ip = line.split()[1]
                    if dns_ip not in ("127.0.0.53", "127.0.0.1") and is_valid_ip(
                        dns_ip
                    ):
                        dns_servers.append(dns_ip)
    except Exception:  # nosec B110 # Expected: continue to next DNS detection method
        pass
    return dns_servers


def _parse_nmcli_dns(output: str) -> List[str]:
    """Parse DNS servers from nmcli dev show output."""
    dns_servers = []
    for line in output.split("\n"):
        if "IP4.DNS" not in line:
            continue
        parts = line.split(":")
        if len(parts) <= 1:
            continue
        dns_ip = parts[1].strip()
        if is_valid_ip(dns_ip) and dns_ip not in dns_servers:
            dns_servers.append(dns_ip)
    return dns_servers


def _get_dns_from_networkmanager() -> List[str]:
    """Get DNS from NetworkManager if available."""
    try:
        result = subprocess.run(  # nosec B603 B607
            ["nmcli", "dev", "show"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return _parse_nmcli_dns(result.stdout)
    except Exception:  # nosec B110 # Expected: continue to next DNS detection method
        pass
    return []


def get_host_dns_servers(logger) -> List[str]:
    """
    Detect the host's DNS servers for VM configuration.

    Tries multiple methods in order:
    1. systemd-resolve --status
    2. resolvectl status
    3. /etc/resolv.conf (skipping stub resolvers)
    4. NetworkManager

    Args:
        logger: Logger instance for logging messages

    Returns:
        List of DNS server IP addresses (max 3)
    """
    # Try each method in order
    dns_servers = _get_dns_from_systemd_resolve()

    if not dns_servers:
        dns_servers = _get_dns_from_resolvectl()

    if not dns_servers:
        dns_servers = _get_dns_from_resolv_conf()

    if not dns_servers:
        dns_servers = _get_dns_from_networkmanager()

    # Fallback to common public DNS
    if not dns_servers:
        logger.warning(_("Could not detect host DNS, using fallback"))
        dns_servers = ["8.8.8.8", "8.8.4.4"]  # NOSONAR - standard DNS fallback

    logger.info(_("Detected DNS servers: %s"), dns_servers)
    return dns_servers[:3]  # Limit to 3 DNS servers
