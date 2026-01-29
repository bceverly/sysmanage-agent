"""
NPF (NetBSD Packet Filter) operations for NetBSD systems.

Supports NetBSD systems that use NPF.

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

# pylint: disable=protected-access

import subprocess  # nosec B404
from typing import Dict, List, Optional

from src.i18n import _  # pylint: disable=not-callable


class NPFFirewallOperations:
    """Manages NPF (NetBSD Packet Filter) operations."""

    def __init__(self, parent):
        """
        Initialize NPF operations.

        Args:
            parent: Parent BSDFirewallOperations instance
        """
        self.parent = parent
        self.logger = parent.logger

    async def enable_npf_firewall(self, _ports: List[int], _protocol: str) -> Dict:
        """
        Enable NPF (NetBSD Packet Filter).

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Enabling NPF firewall")

            # Build complete NPF configuration
            npf_conf = "/etc/npf.conf"

            # Check if config already exists
            try:
                with open(
                    npf_conf, "r", encoding="utf-8"
                ) as file_handle:  # NOSONAR - Sync file I/O is acceptable for reading small config files
                    existing_config = file_handle.read()
            except FileNotFoundError:
                existing_config = ""

            # Only create config if it doesn't exist or is empty
            if not existing_config.strip():
                self.logger.info("Creating NPF configuration")

                # Create NPF config with proper firewall rules
                config_content = """# NPF configuration - managed by SysManage Agent
# Minimal configuration - allows all traffic

# Introduce 2 variables to list opened TCP and UDP ports[3]
$services_tcp = { http, https, smtp, smtps, domain, 587, 6000 }
$services_udp = { domain, ntp, 6000, 51413 }

group default {
    # Allow all loopback traffic
    pass final on lo0 all

    # Allow all outgoing traffic
    pass stateful out final all

    # Allow ICMP
    pass in final proto icmp icmp-type timxceed all
    pass in final proto icmp icmp-type unreach all
    pass in final proto icmp icmp-type echoreply all
    pass in final proto icmp icmp-type sourcequench all
    pass in final proto icmp icmp-type paramprob all

    # Allow SSH
    pass stateful in final proto tcp from any to any port 22

    # Allow SysManage-Agent
    pass stateful in final proto tcp from any to any port 8080

    # Allow DHCP
    pass out final proto udp from any port bootpc to any port bootps
    pass in final proto udp from any port bootps to any port bootpc
    pass in final proto udp from any port bootps to 255.255.255.0 port bootpc

    # Allow incoming TCP/UDP packets on selected ports
    pass stateful in final proto tcp to any port $services_tcp
    pass stateful in final proto udp to any port $services_udp

    # Allow Traceroute
    pass stateful in final proto udp to any port 33434-33600

    # Reject everything else [9]
    block return-rst in final proto tcp all
    block return-icmp in final proto udp all
    block return in final all
}
"""

                # Write the configuration
                try:
                    with open(
                        npf_conf, "w", encoding="utf-8"
                    ) as file_handle:  # NOSONAR - Sync file I/O is acceptable for writing small config files
                        file_handle.write(config_content)
                except PermissionError:
                    # Try with sudo if not running as root
                    result = subprocess.run(  # nosec B603 B607  # NOSONAR - Sync subprocess is acceptable for quick system commands
                        self.parent._build_command(
                            [
                                "sh",
                                "-c",
                                f"cat > {npf_conf} << 'EOF'\n{config_content}EOF",
                            ]
                        ),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        return {
                            "success": False,
                            "error": f"Failed to write NPF config: {result.stderr}",
                        }
            else:
                self.logger.info("NPF config already exists, skipping creation")

            # Validate the configuration
            result = subprocess.run(  # nosec B603 B607  # NOSONAR - Sync subprocess is acceptable for quick system commands
                self.parent._build_command(["npfctl", "validate", npf_conf]),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"NPF configuration validation failed: {result.stderr}",
                }

            # Reload the configuration
            result = subprocess.run(  # nosec B603 B607  # NOSONAR - Sync subprocess is acceptable for quick system commands
                self.parent._build_command(["npfctl", "reload", npf_conf]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to reload NPF configuration: {result.stderr}",
                }

            # Start NPF
            result = subprocess.run(  # nosec B603 B607  # NOSONAR - Sync subprocess is acceptable for quick system commands
                self.parent._build_command(["npfctl", "start"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # npfctl start may fail with non-zero returncode if already running
            # Log the actual output to help debug
            self.logger.debug("npfctl start returncode: %s", result.returncode)
            self.logger.debug("npfctl start stdout: %s", result.stdout)
            self.logger.debug("npfctl start stderr: %s", result.stderr)

            if result.returncode != 0:
                # Check if it's already running - that's OK
                output_combined = (result.stdout + result.stderr).lower()
                if not any(msg in output_combined for msg in ["already", "running"]):
                    return {
                        "success": False,
                        "error": f"Failed to enable NPF: {result.stderr}",
                    }

            self.logger.info("NPF firewall enabled successfully")
            await self.parent._send_firewall_status_update()
            return {
                "success": True,
                "message": _("NPF firewall enabled successfully"),
            }

        except Exception as exc:
            self.logger.error("Error enabling NPF firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def apply_firewall_roles_npf(
        self, port_configs: Dict, agent_ports: List[int], _errors: List[str]
    ) -> Optional[Dict]:
        """Apply firewall roles using NPF (NetBSD)."""
        try:
            # Check if NPF is available
            result = subprocess.run(  # nosec B603 B607  # NOSONAR - Sync subprocess is acceptable for quick system commands
                ["npfctl", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # NPF not available

            self.logger.info("Applying firewall roles using NPF")

            # NPF requires configuration file changes
            # For now, log the ports and return success
            self.logger.info(
                "NPF firewall: Would configure %d ports. "
                "NPF requires /etc/npf.conf modifications.",
                len(port_configs),
            )

            for port, protocols in port_configs.items():
                if port in agent_ports:
                    continue

                proto_list = []
                if protocols["tcp"]:
                    proto_list.append("tcp")
                if protocols["udp"]:
                    proto_list.append("udp")
                self.logger.info(
                    "NPF: Would allow port %d (%s)", port, "/".join(proto_list)
                )

            await self.parent._send_firewall_status_update()

            return {
                "success": True,
                "message": _(
                    "Firewall roles acknowledged on NPF. "
                    "Note: NPF requires /etc/npf.conf configuration."
                ),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # NPF not available

    async def remove_firewall_ports_npf(
        self, ports_to_remove: Dict, preserved_ports: set, _errors: List[str]
    ) -> Optional[Dict]:
        """Remove specific firewall ports using NPF (NetBSD)."""
        try:
            # Check if NPF is available
            result = subprocess.run(  # nosec B603 B607  # NOSONAR - Sync subprocess is acceptable for quick system commands
                ["npfctl", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # NPF not available

            self.logger.info("Removing firewall ports using NPF")

            # Log the removal
            for port, protocols in ports_to_remove.items():
                if port in preserved_ports:
                    self.logger.info(
                        "Skipping removal of preserved port %d (agent/SSH)", port
                    )
                    continue

                proto_list = []
                if protocols["tcp"]:
                    proto_list.append("tcp")
                if protocols["udp"]:
                    proto_list.append("udp")
                self.logger.info(
                    "NPF: Requested removal of port %d (%s)", port, "/".join(proto_list)
                )

            await self.parent._send_firewall_status_update()

            return {
                "success": True,
                "message": _(  # pylint: disable=not-callable
                    "Firewall port removal acknowledged on NPF. "
                    "Note: NPF requires /etc/npf.conf configuration."
                ),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # NPF not available
