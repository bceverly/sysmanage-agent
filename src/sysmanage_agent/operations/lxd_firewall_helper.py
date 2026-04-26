"""
LXD bridge firewall helper.

This is the only firewall-touching code that survives the Phase 3
agent-side cleanup. It's specifically about LXD container networking
(IP forwarding + UFW route allows + NAT masquerade for the lxdbr0
bridge), which is intrinsic to the LXD child-host workflow rather than
to host-firewall management. Keeping it next to child_host_lxd.py also
avoids re-introducing a generic firewall_linux.py just for this one
caller.

If the host doesn't run UFW (e.g., RHEL with firewalld), this helper
emits warnings and returns a partial-success result; the operator can
configure NAT manually.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess  # nosec B404
from typing import Dict, List


def _ufw_available() -> bool:
    try:
        result = subprocess.run(  # nosec B603 B607
            ["which", "ufw"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _enable_ip_forwarding(logger: logging.Logger, errors: List[str]) -> None:
    """Enable IPv4 forwarding (idempotent)."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8") as fobj:
            if fobj.read().strip() == "1":
                return
    except OSError as exc:
        errors.append(f"Could not read /proc/sys/net/ipv4/ip_forward: {exc}")
        return

    result = subprocess.run(  # nosec B603 B607
        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        errors.append(f"Failed to enable IP forwarding: {result.stderr}")
        return

    # Persist for next boot.
    sysctl_line = "net.ipv4.ip_forward=1"
    persist = subprocess.run(  # nosec B603 B607
        [
            "sudo",
            "sh",
            "-c",
            f"grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf && "
            f"sudo sed -i 's/^net.ipv4.ip_forward.*/{sysctl_line}/' "
            f"/etc/sysctl.conf || echo '{sysctl_line}' >> /etc/sysctl.conf",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if persist.returncode != 0:
        logger.warning("Could not persist IP forwarding setting: %s", persist.stderr)


def _set_ufw_forward_policy(errors: List[str]) -> None:
    """Switch UFW DEFAULT_FORWARD_POLICY from DROP to ACCEPT."""
    result = subprocess.run(  # nosec B603 B607
        [
            "sudo",
            "sed",
            "-i",
            's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/',
            "/etc/default/ufw",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        errors.append(f"Failed to set UFW forward policy: {result.stderr}")


def _add_ufw_bridge_route_rules(logger: logging.Logger, bridge_name: str) -> None:
    """ufw route allow in/out on <bridge>, plus DHCP and DNS allows."""
    rules = [
        ["sudo", "ufw", "route", "allow", "in", "on", bridge_name],
        ["sudo", "ufw", "route", "allow", "out", "on", bridge_name],
        [
            "sudo",
            "ufw",
            "allow",
            "in",
            "on",
            bridge_name,
            "to",
            "any",
            "port",
            "67",
            "proto",
            "udp",
        ],
        ["sudo", "ufw", "allow", "in", "on", bridge_name, "to", "any", "port", "53"],
    ]
    for rule in rules:
        result = subprocess.run(  # nosec B603 B607
            rule,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if (
            result.returncode != 0
            and "Skipping" not in result.stdout
            and "already exists" not in result.stderr
        ):
            logger.warning("UFW rule failed: %s - %s", " ".join(rule), result.stderr)


def _detect_bridge_subnet(bridge_name: str) -> str:
    """Get the CIDR of <bridge>; falls back to 10.0.0.0/8 on parse failure."""
    fallback = "10.0.0.0/8"  # NOSONAR
    try:
        result = subprocess.run(  # nosec B603 B607
            ["ip", "-o", "-4", "addr", "show", bridge_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return fallback
        parts = result.stdout.split()
        for i, part in enumerate(parts):
            if part == "inet" and i + 1 < len(parts):
                network = ipaddress.ip_network(parts[i + 1], strict=False)
                return str(network)
    except (subprocess.SubprocessError, ValueError):
        pass
    return fallback


def _configure_nat_masquerade(
    logger: logging.Logger, bridge_name: str, errors: List[str]
) -> None:
    """Insert LXD NAT masquerade rules into /etc/ufw/before.rules (idempotent)."""
    subnet = _detect_bridge_subnet(bridge_name)
    nat_rules = (
        "# LXD NAT rules - added by sysmanage-agent\n"
        "*nat\n"
        ":POSTROUTING ACCEPT [0:0]\n"
        f"-A POSTROUTING -s {subnet} ! -d {subnet} -j MASQUERADE\n"
        "COMMIT\n"
        "# End LXD NAT rules\n\n"
    )

    try:
        with open("/etc/ufw/before.rules", "r", encoding="utf-8") as fobj:
            existing = fobj.read()
        if "# LXD NAT rules" in existing:
            logger.info("NAT rules already configured in before.rules")
            return
    except OSError as exc:
        errors.append(f"Could not read /etc/ufw/before.rules: {exc}")
        return

    result = subprocess.run(  # nosec B603 B607
        [
            "sudo",
            "sh",
            "-c",
            "cat /etc/ufw/before.rules > /tmp/ufw_before.rules.bak && "
            f"echo '{nat_rules}' | cat - /tmp/ufw_before.rules.bak | "
            "sudo tee /etc/ufw/before.rules > /dev/null",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        errors.append(f"Failed to add NAT rules: {result.stderr}")


def configure_lxd_firewall(logger: logging.Logger, bridge_name: str = "lxdbr0") -> Dict:
    """
    Configure UFW to allow LXD container networking on the given bridge.

    Returns: {success: bool, message: str, error?: str}
    Skipped silently with success=True if UFW isn't installed (the host
    likely uses firewalld, in which case the operator must configure NAT
    via firewalld zones manually — not in scope here).
    """
    if not _ufw_available():
        logger.info("UFW not installed; skipping LXD bridge firewall config")
        return {
            "success": True,
            "message": "UFW not installed; skipping LXD bridge firewall config",
        }

    logger.info("Configuring UFW firewall for LXD bridge: %s", bridge_name)
    errors: List[str] = []

    _enable_ip_forwarding(logger, errors)
    _set_ufw_forward_policy(errors)
    _add_ufw_bridge_route_rules(logger, bridge_name)
    _configure_nat_masquerade(logger, bridge_name, errors)

    reload_result = subprocess.run(  # nosec B603 B607
        ["sudo", "ufw", "reload"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if reload_result.returncode != 0:
        errors.append(f"Failed to reload UFW: {reload_result.stderr}")

    if errors:
        return {
            "success": False,
            "error": "; ".join(errors),
            "message": "Some LXD firewall rules failed to apply",
        }
    return {
        "success": True,
        "message": "UFW firewall configured for LXD successfully",
    }
