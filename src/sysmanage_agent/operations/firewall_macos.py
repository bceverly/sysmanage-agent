"""
macOS-specific firewall operations for SysManage Agent.
Uses macOS Application Firewall (socketfilterfw).

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _
from src.sysmanage_agent.operations.firewall_base import FirewallBase

# Path to macOS Application Firewall command
SOCKETFILTERFW_PATH = "/usr/libexec/ApplicationFirewall/socketfilterfw"


class MacOSFirewallOperations(FirewallBase):
    """Manages firewall operations on macOS systems."""

    async def enable_firewall(self, _ports: List[int], _protocol: str) -> Dict:
        """
        Enable firewall on macOS systems.

        Uses macOS Application Firewall (socketfilterfw).
        Note: macOS Application Firewall is application-based, not port-based,
        so port configuration is not directly applicable.

        Args:
            _ports: List of ports to allow (not used on macOS)
            _protocol: Protocol to use (not used on macOS)

        Returns:
            Dict with success status and message
        """
        try:
            # Enable macOS firewall
            self.logger.info("Enabling macOS firewall")
            # NOSONAR: Using sync subprocess is acceptable here - short-lived system
            # command with timeout, async version provides no benefit for firewall ops
            result = subprocess.run(  # nosec B603 B607  # NOSONAR
                [
                    "sudo",
                    SOCKETFILTERFW_PATH,
                    "--setglobalstate",
                    "on",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("macOS firewall enabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("macOS firewall enabled successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to enable macOS firewall: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error enabling macOS firewall: %s", exc)
            return {"success": False, "error": str(exc)}

    async def disable_firewall(self) -> Dict:
        """
        Disable firewall on macOS systems.

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Disabling macOS firewall")
            # NOSONAR: Using sync subprocess is acceptable here - short-lived system
            # command with timeout, async version provides no benefit for firewall ops
            result = subprocess.run(  # nosec B603 B607  # NOSONAR
                [
                    "sudo",
                    SOCKETFILTERFW_PATH,
                    "--setglobalstate",
                    "off",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("macOS firewall disabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("macOS firewall disabled successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to disable macOS firewall: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error disabling macOS firewall: %s", exc)
            return {"success": False, "error": str(exc)}

    async def restart_firewall(self) -> Dict:
        """
        Restart firewall on macOS systems.

        macOS doesn't have a native restart command, so we toggle it off and on.

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Restarting macOS firewall")
            # macOS doesn't have a restart, so we toggle it off and on
            # NOSONAR: Using sync subprocess is acceptable here - short-lived system
            # command with timeout, async version provides no benefit for firewall ops
            result = subprocess.run(  # nosec B603 B607  # NOSONAR
                [
                    "sudo",
                    SOCKETFILTERFW_PATH,
                    "--setglobalstate",
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
                    "error": f"Failed to restart macOS firewall: {result.stderr}",
                }

            # NOSONAR: Using sync subprocess is acceptable here - short-lived system
            # command with timeout, async version provides no benefit for firewall ops
            result = subprocess.run(  # nosec B603 B607  # NOSONAR
                [
                    "sudo",
                    SOCKETFILTERFW_PATH,
                    "--setglobalstate",
                    "on",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("macOS firewall restarted successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("macOS firewall restarted successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to restart macOS firewall: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error restarting macOS firewall: %s", exc)
            return {"success": False, "error": str(exc)}

    async def deploy_firewall(self) -> Dict:
        """Deploy (enable) firewall on macOS systems."""
        try:
            self.logger.info("Deploying firewall on macOS system")
            ports, protocol = self._get_agent_communication_ports()
            server_ports = self._get_local_server_ports()
            all_ports = list(set(ports + server_ports))
            return await self.enable_firewall(all_ports, protocol)
        except Exception as exc:
            self.logger.error("Error deploying firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def apply_firewall_roles(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Synchronize firewall roles on macOS.

        Note: macOS Application Firewall (socketfilterfw) is application-based,
        not port-based. Port-based filtering would require configuring pf (packet
        filter), which requires more complex configuration file management.

        Since the Application Firewall is application-based, "synchronization" here
        means acknowledging the complete desired port list. The firewall will allow
        traffic for any application that is permitted, regardless of port.

        When roles are removed, this method is called with the updated (reduced)
        port list, which is logged for reference.

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4
            ipv6_ports: List of {port, tcp, udp} for IPv6

        Returns:
            Dict with success status and message
        """
        self.logger.info("Synchronizing firewall roles on macOS")

        # Combine and deduplicate ports
        all_ports = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in all_ports:
                all_ports[port] = {"tcp": False, "udp": False}
            if tcp:
                all_ports[port]["tcp"] = True
            if udp:
                all_ports[port]["udp"] = True

        self.logger.info(
            "macOS Application Firewall is application-based, not port-based. "
            "Desired port list has %d unique ports.",
            len(all_ports),
        )

        # Log the ports that are now desired (full synchronization)
        for port, protocols in all_ports.items():
            proto_list = []
            if protocols["tcp"]:
                proto_list.append("tcp")
            if protocols["udp"]:
                proto_list.append("udp")
            self.logger.debug(
                "Desired firewall role port: %d (%s)", port, "/".join(proto_list)
            )

        if not all_ports:
            self.logger.info(
                "No firewall role ports configured - all role ports cleared"
            )

        # Send updated firewall status
        await self._send_firewall_status_update()

        return {
            "success": True,
            "message": _(
                "Firewall roles synchronized on macOS. "
                "Note: macOS uses application-based firewall, not port-based. "
                "Ports are tracked for associated applications."
            ),
        }

    async def remove_firewall_ports(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Remove specific firewall ports on macOS.

        Note: macOS Application Firewall (socketfilterfw) is application-based,
        not port-based. This method logs the ports but cannot remove specific
        port rules.

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4 to remove
            ipv6_ports: List of {port, tcp, udp} for IPv6 to remove

        Returns:
            Dict with success status and message
        """
        self.logger.info("Remove firewall ports requested on macOS")

        # Combine and deduplicate ports
        all_ports = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in all_ports:
                all_ports[port] = {"tcp": False, "udp": False}
            if tcp:
                all_ports[port]["tcp"] = True
            if udp:
                all_ports[port]["udp"] = True

        self.logger.info(
            "macOS Application Firewall is application-based, not port-based. "
            "Requested removal of %d unique ports (ports are tracked only).",
            len(all_ports),
        )

        # Log the ports that were requested for removal
        for port, protocols in all_ports.items():
            proto_list = []
            if protocols["tcp"]:
                proto_list.append("tcp")
            if protocols["udp"]:
                proto_list.append("udp")
            self.logger.debug(
                "Requested removal of firewall port: %d (%s)",
                port,
                "/".join(proto_list),
            )

        # Send updated firewall status
        await self._send_firewall_status_update()

        return {
            "success": True,
            "message": _(
                "Firewall port removal acknowledged on macOS. "
                "Note: macOS uses application-based firewall, not port-based."
            ),
        }
