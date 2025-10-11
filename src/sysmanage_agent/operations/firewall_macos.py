"""
macOS-specific firewall operations for SysManage Agent.
Uses macOS Application Firewall (socketfilterfw).
"""

import subprocess
from typing import Dict, List

from src.i18n import _
from src.sysmanage_agent.operations.firewall_base import FirewallBase


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
            result = subprocess.run(
                [
                    "sudo",
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
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
            result = subprocess.run(
                [
                    "sudo",
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
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
            result = subprocess.run(
                [
                    "sudo",
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
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

            result = subprocess.run(
                [
                    "sudo",
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
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
