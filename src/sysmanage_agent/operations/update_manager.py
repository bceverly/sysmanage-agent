"""
Update Manager module for SysManage agent.
Handles all update-related operations including package updates and reboot status.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.sysmanage_agent.operations.update_operations import UpdateOperations


class UpdateManager:
    """Manages all update-related operations for the agent."""

    def __init__(self, agent_instance):
        """
        Initialize update manager with agent instance.

        Args:
            agent_instance: The main SysManageAgent instance
        """
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

        # Initialize update operations component
        self.update_ops = UpdateOperations(agent_instance)

    async def check_updates(self) -> Dict[str, Any]:
        """
        Check for available updates for installed packages.

        Returns:
            Dict containing success status and update information
        """
        return await self.update_ops.check_updates()

    async def apply_updates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply updates for specified packages.

        Args:
            parameters: Dict containing package_names and package_managers

        Returns:
            Dict containing success status and update results
        """
        return await self.update_ops.apply_updates(parameters)

    async def check_reboot_status(self) -> Dict[str, Any]:
        """
        Check if the system requires a reboot.

        Returns:
            Dict containing success status and reboot_required boolean
        """
        try:
            detector = UpdateDetector()
            requires_reboot = detector.check_reboot_required()

            result = {
                "success": True,
                "reboot_required": requires_reboot,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Send reboot status update to server
            await self.send_reboot_status_update(requires_reboot)

            return result

        except Exception as error:
            self.logger.error(_("Failed to check reboot status: %s"), error)
            return {
                "success": False,
                "error": str(error),
                "reboot_required": False,
            }

    async def send_reboot_status_update(self, requires_reboot: bool) -> None:
        """
        Send reboot status update to server.

        Args:
            requires_reboot: Boolean indicating if reboot is required
        """
        try:
            self.logger.info(_("Sending reboot status update: %s"), requires_reboot)

            # Get hostname for server processing
            system_info = self.agent.registration.get_system_info()
            hostname = system_info.get("hostname", "unknown")

            reboot_data = {
                "hostname": hostname,
                "reboot_required": requires_reboot,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            reboot_message = self.agent.create_message(
                "reboot_status_update", reboot_data
            )
            await self.agent.send_message(reboot_message)

            self.logger.debug("Reboot status message sent successfully")

        except Exception as error:
            self.logger.error(_("Failed to send reboot status update: %s"), error)
