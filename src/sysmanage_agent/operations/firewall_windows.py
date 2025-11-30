"""
Windows-specific firewall operations for SysManage Agent.
Uses Windows Firewall (netsh advfirewall).

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

import re
import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _  # pylint: disable=not-callable
from src.sysmanage_agent.operations.firewall_base import FirewallBase


class WindowsFirewallOperations(FirewallBase):
    """Manages firewall operations on Windows systems."""

    async def enable_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable firewall on Windows systems.

        Uses netsh advfirewall to configure Windows Firewall.

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        try:
            # Always ensure RDP (port 3389) is allowed on Windows to prevent lockout
            self.logger.info("Adding Windows Firewall rule for port 3389 (RDP)")
            result = subprocess.run(  # nosec B603 B607
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Remote Desktop (RDP)",
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    "localport=3389",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                self.logger.warning(
                    "Failed to add Windows Firewall rule for RDP: %s",
                    result.stderr,
                )

            # Add firewall rules for agent communication
            for port in ports:
                self.logger.info("Adding Windows Firewall rule for port %d", port)
                result = subprocess.run(  # nosec B603 B607
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=SysManage Agent Port {port}",
                        "dir=in",
                        "action=allow",
                        f"protocol={protocol.upper()}",
                        f"localport={port}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Failed to add Windows Firewall rule: %s", result.stderr
                    )

            # Enable Windows Firewall
            self.logger.info("Enabling Windows Firewall")
            result = subprocess.run(  # nosec B603 B607
                [
                    "netsh",
                    "advfirewall",
                    "set",
                    "allprofiles",
                    "state",
                    "on",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Windows Firewall enabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("Windows Firewall enabled successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to enable Windows Firewall: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error enabling Windows Firewall: %s", exc)
            return {"success": False, "error": str(exc)}

    async def disable_firewall(self) -> Dict:
        """
        Disable firewall on Windows systems.

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Disabling Windows Firewall")
            result = subprocess.run(  # nosec B603 B607
                [
                    "netsh",
                    "advfirewall",
                    "set",
                    "allprofiles",
                    "state",
                    "off",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Windows Firewall disabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("Windows Firewall disabled successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to disable Windows Firewall: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error disabling Windows Firewall: %s", exc)
            return {"success": False, "error": str(exc)}

    async def restart_firewall(self) -> Dict:
        """
        Restart firewall on Windows systems.

        Windows doesn't have a native "restart" for the firewall,
        so we toggle it off and on.

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Restarting Windows Firewall")
            # Windows doesn't really have a "restart" for the firewall
            # But we can toggle it off and on
            result = subprocess.run(  # nosec B603 B607
                [
                    "netsh",
                    "advfirewall",
                    "set",
                    "allprofiles",
                    "state",
                    "off",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to restart Windows Firewall: {result.stderr}",
                }

            result = subprocess.run(  # nosec B603 B607
                [
                    "netsh",
                    "advfirewall",
                    "set",
                    "allprofiles",
                    "state",
                    "on",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Windows Firewall restarted successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("Windows Firewall restarted successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to restart Windows Firewall: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error restarting Windows Firewall: %s", exc)
            return {"success": False, "error": str(exc)}

    async def deploy_firewall(self) -> Dict:
        """Deploy (enable) firewall on Windows systems."""
        try:
            self.logger.info("Deploying firewall on Windows system")
            ports, protocol = self._get_agent_communication_ports()
            server_ports = self._get_local_server_ports()
            all_ports = list(set(ports + server_ports))
            return await self.enable_firewall(all_ports, protocol)
        except Exception as exc:
            self.logger.error("Error deploying firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    def _get_windows_sysmanage_role_rules(self) -> Dict[int, Dict[str, bool]]:
        """Get current SysManage Role firewall rules from Windows Firewall."""
        current_ports: Dict[int, Dict[str, bool]] = {}
        try:
            # List all firewall rules and filter for SysManage Role rules
            result = subprocess.run(  # nosec B603 B607
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "show",
                    "rule",
                    "name=all",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return current_ports

            current_ports = self._parse_windows_firewall_rules(result.stdout)

        except Exception as exc:
            self.logger.warning("Failed to get current Windows Firewall rules: %s", exc)
        return current_ports

    def _parse_windows_firewall_rules(self, output: str) -> Dict[int, Dict[str, bool]]:
        """Parse netsh output to extract SysManage Role ports."""
        current_ports: Dict[int, Dict[str, bool]] = {}
        current_rule_name = None
        current_protocol = None

        for line in output.split("\n"):
            line = line.strip()

            # Look for rule name
            if line.startswith("Rule Name:"):
                current_rule_name = line.split(":", 1)[1].strip()
                current_protocol = None
            elif line.startswith("Protocol:"):
                current_protocol = line.split(":", 1)[1].strip().lower()
            elif line.startswith("LocalPort:"):
                self._process_localport_line(
                    line, current_rule_name, current_protocol, current_ports
                )

        return current_ports

    def _process_localport_line(
        self,
        line: str,
        rule_name: str,
        protocol: str,
        current_ports: Dict[int, Dict[str, bool]],
    ) -> None:
        """Process a LocalPort line from netsh output."""
        if not rule_name or not rule_name.startswith("SysManage Role Port"):
            return

        port_str = line.split(":", 1)[1].strip()
        match = re.search(r"(\d+)", port_str)
        if not match:
            return

        port = int(match.group(1))
        if port not in current_ports:
            current_ports[port] = {"tcp": False, "udp": False}
        if protocol == "tcp":
            current_ports[port]["tcp"] = True
        elif protocol == "udp":
            current_ports[port]["udp"] = True

    async def apply_firewall_roles(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Apply firewall roles by synchronizing open ports based on assigned roles.

        This synchronizes the firewall state - adding new ports and removing
        ports that are no longer needed.

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4
            ipv6_ports: List of {port, tcp, udp} for IPv6

        Returns:
            Dict with success status and message
        """
        self.logger.info("Synchronizing firewall roles using Windows Firewall")

        errors = []

        # Get agent communication ports (must always be preserved)
        agent_ports, _ = self._get_agent_communication_ports()
        # Also preserve RDP port 3389
        preserved_ports = set(agent_ports + [3389])

        # Build desired port configuration from both IPv4 and IPv6
        desired_ports = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in desired_ports:
                desired_ports[port] = {"tcp": False, "udp": False}
            if tcp:
                desired_ports[port]["tcp"] = True
            if udp:
                desired_ports[port]["udp"] = True

        # Get current SysManage Role rules
        current_ports = self._get_windows_sysmanage_role_rules()

        self.logger.info(
            "Current ports: %s, Desired ports: %s, Preserved: %s",
            list(current_ports.keys()),
            list(desired_ports.keys()),
            list(preserved_ports),
        )

        # Remove rules that are no longer needed
        for port, protocols in current_ports.items():
            # Skip preserved ports
            if port in preserved_ports:
                continue

            # Check if this port should be removed
            if port not in desired_ports:
                # Remove both protocol rules for this port
                if protocols.get("tcp"):
                    self.logger.info(
                        "Removing Windows Firewall rule: SysManage Role Port %d/TCP",
                        port,
                    )
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "netsh",
                            "advfirewall",
                            "firewall",
                            "delete",
                            "rule",
                            f"name=SysManage Role Port {port}/TCP",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        self.logger.warning(
                            "Failed to remove Windows Firewall rule for port %d/tcp: %s",
                            port,
                            result.stderr,
                        )

                if protocols.get("udp"):
                    self.logger.info(
                        "Removing Windows Firewall rule: SysManage Role Port %d/UDP",
                        port,
                    )
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "netsh",
                            "advfirewall",
                            "firewall",
                            "delete",
                            "rule",
                            f"name=SysManage Role Port {port}/UDP",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        self.logger.warning(
                            "Failed to remove Windows Firewall rule for port %d/udp: %s",
                            port,
                            result.stderr,
                        )
            else:
                # Port exists but check if protocols changed
                desired = desired_ports[port]
                if protocols.get("tcp") and not desired.get("tcp"):
                    self.logger.info(
                        "Removing Windows Firewall rule: SysManage Role Port %d/TCP",
                        port,
                    )
                    subprocess.run(  # nosec B603 B607
                        [
                            "netsh",
                            "advfirewall",
                            "firewall",
                            "delete",
                            "rule",
                            f"name=SysManage Role Port {port}/TCP",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                if protocols.get("udp") and not desired.get("udp"):
                    self.logger.info(
                        "Removing Windows Firewall rule: SysManage Role Port %d/UDP",
                        port,
                    )
                    subprocess.run(  # nosec B603 B607
                        [
                            "netsh",
                            "advfirewall",
                            "firewall",
                            "delete",
                            "rule",
                            f"name=SysManage Role Port {port}/UDP",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

        # Add new rules
        for port, protocols in desired_ports.items():
            # Skip agent communication ports (they're managed separately)
            if port in agent_ports:
                continue

            current = current_ports.get(port, {"tcp": False, "udp": False})

            if protocols.get("tcp") and not current.get("tcp"):
                self.logger.info("Adding Windows Firewall rule: allow %d/tcp", port)
                result = subprocess.run(  # nosec B603 B607
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=SysManage Role Port {port}/TCP",
                        "dir=in",
                        "action=allow",
                        "protocol=TCP",
                        f"localport={port}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"Failed to add TCP port {port}: {result.stderr}")
                    self.logger.warning(
                        "Failed to add Windows Firewall rule for port %d/tcp: %s",
                        port,
                        result.stderr,
                    )

            if protocols.get("udp") and not current.get("udp"):
                self.logger.info("Adding Windows Firewall rule: allow %d/udp", port)
                result = subprocess.run(  # nosec B603 B607
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=SysManage Role Port {port}/UDP",
                        "dir=in",
                        "action=allow",
                        "protocol=UDP",
                        f"localport={port}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"Failed to add UDP port {port}: {result.stderr}")
                    self.logger.warning(
                        "Failed to add Windows Firewall rule for port %d/udp: %s",
                        port,
                        result.stderr,
                    )

        # Send updated firewall status
        await self._send_firewall_status_update()

        if errors:
            return {
                "success": False,
                "error": "; ".join(errors),
                "message": _(  # pylint: disable=not-callable
                    "Some firewall rules failed to apply"
                ),
            }

        return {
            "success": True,
            "message": _(  # pylint: disable=not-callable
                "Firewall roles synchronized successfully via Windows Firewall"
            ),
        }

    async def remove_firewall_ports(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Remove specific firewall ports (explicit removal, not sync).

        This removes only the specified ports from the firewall.
        Used when a firewall role is removed from a host.

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4 to remove
            ipv6_ports: List of {port, tcp, udp} for IPv6 to remove

        Returns:
            Dict with success status and message
        """
        self.logger.info("Removing specific firewall ports using Windows Firewall")

        errors = []

        # Get agent communication ports (must always be preserved)
        agent_ports, _ = self._get_agent_communication_ports()
        # Also preserve RDP port 3389
        preserved_ports = set(agent_ports + [3389])

        # Build list of ports to remove from both IPv4 and IPv6
        ports_to_remove = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in ports_to_remove:
                ports_to_remove[port] = {"tcp": False, "udp": False}
            if tcp:
                ports_to_remove[port]["tcp"] = True
            if udp:
                ports_to_remove[port]["udp"] = True

        self.logger.info(
            "Ports to remove: %s, Preserved (will not remove): %s",
            list(ports_to_remove.keys()),
            list(preserved_ports),
        )

        # Remove the specified ports
        for port, protocols in ports_to_remove.items():
            # Skip preserved ports (agent communication, RDP)
            if port in preserved_ports:
                self.logger.info(
                    "Skipping removal of preserved port %d (agent/RDP)", port
                )
                continue

            if protocols.get("tcp"):
                self.logger.info(
                    "Removing Windows Firewall rule: SysManage Role Port %d/TCP", port
                )
                result = subprocess.run(  # nosec B603 B607
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=SysManage Role Port {port}/TCP",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    # Rule might not exist, which is fine
                    if "No rules match" not in result.stderr:
                        errors.append(
                            f"Failed to remove TCP port {port}: {result.stderr}"
                        )
                        self.logger.warning(
                            "Failed to remove Windows Firewall rule for port %d/tcp: %s",
                            port,
                            result.stderr,
                        )

            if protocols.get("udp"):
                self.logger.info(
                    "Removing Windows Firewall rule: SysManage Role Port %d/UDP", port
                )
                result = subprocess.run(  # nosec B603 B607
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=SysManage Role Port {port}/UDP",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    # Rule might not exist, which is fine
                    if "No rules match" not in result.stderr:
                        errors.append(
                            f"Failed to remove UDP port {port}: {result.stderr}"
                        )
                        self.logger.warning(
                            "Failed to remove Windows Firewall rule for port %d/udp: %s",
                            port,
                            result.stderr,
                        )

        # Send updated firewall status
        await self._send_firewall_status_update()

        if errors:
            return {
                "success": False,
                "error": "; ".join(errors),
                "message": _(  # pylint: disable=not-callable
                    "Some firewall rules failed to remove"
                ),
            }

        return {
            "success": True,
            "message": _(  # pylint: disable=not-callable
                "Firewall ports removed successfully via Windows Firewall"
            ),
        }
