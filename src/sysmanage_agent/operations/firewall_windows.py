"""
Windows-specific firewall operations for SysManage Agent.
Uses Windows Firewall (netsh advfirewall).

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _
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
