"""
Ubuntu Pro operations module for SysManage agent.
Handles Ubuntu Pro subscription management and service operations.
"""

import asyncio
import logging
import socket
from typing import Any, Dict

from src.i18n import _


class UbuntuProOperations:
    """Handles Ubuntu Pro operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize Ubuntu Pro operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def ubuntu_pro_attach(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Attach Ubuntu Pro subscription using provided token."""
        token = _parameters.get("token")

        if not token:
            return {"success": False, "error": _("Ubuntu Pro token is required")}

        try:
            self.logger.info(_("Attaching Ubuntu Pro subscription..."))

            # Run pro attach command with the provided token
            command = f"sudo pro attach {token}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                self.logger.info(_("Ubuntu Pro attached successfully"))

                # After successful attach, send updated OS info to server
                await self._send_os_update_after_pro_change()

                return {
                    "success": True,
                    "result": _("Ubuntu Pro subscription attached successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                _("Failed to attach Ubuntu Pro: %s"), result["result"]["stderr"]
            )
            return {
                "success": False,
                "error": _("Failed to attach Ubuntu Pro: %s")
                % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(_("Error attaching Ubuntu Pro: %s"), error)
            return {"success": False, "error": str(error)}

    async def ubuntu_pro_detach(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Detach Ubuntu Pro subscription."""
        try:
            self.logger.info(_("Detaching Ubuntu Pro subscription..."))

            # Run pro detach command
            command = "sudo pro detach --assume-yes"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                self.logger.info(_("Ubuntu Pro detached successfully"))

                # After successful detach, send updated OS info to server
                await self._send_os_update_after_pro_change()

                return {
                    "success": True,
                    "result": _("Ubuntu Pro subscription detached successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                _("Failed to detach Ubuntu Pro: %s"), result["result"]["stderr"]
            )
            return {
                "success": False,
                "error": _("Failed to detach Ubuntu Pro: %s")
                % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(_("Error detaching Ubuntu Pro: %s"), error)
            return {"success": False, "error": str(error)}

    async def ubuntu_pro_enable_service(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable Ubuntu Pro service."""
        service_name = _parameters.get("service")

        if not service_name:
            return {"success": False, "error": _("Service name is required")}

        try:
            self.logger.info(_("Enabling Ubuntu Pro service: %s"), service_name)

            # Run pro enable command
            command = f"sudo pro enable {service_name} --assume-yes"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                self.logger.info(
                    _("Ubuntu Pro service %s enabled successfully"), service_name
                )

                # After successful enable, send updated OS info to server
                await self._send_os_update_after_pro_change()

                return {
                    "success": True,
                    "result": _("Ubuntu Pro service %s enabled successfully")
                    % service_name,
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                _("Failed to enable Ubuntu Pro service %s: %s"),
                service_name,
                result["result"]["stderr"],
            )
            return {
                "success": False,
                "error": _("Failed to enable Ubuntu Pro service %s: %s")
                % (service_name, result["result"]["stderr"]),
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(
                _("Error enabling Ubuntu Pro service %s: %s"), service_name, error
            )
            return {"success": False, "error": str(error)}

    async def ubuntu_pro_disable_service(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable Ubuntu Pro service."""
        service_name = _parameters.get("service")

        if not service_name:
            return {"success": False, "error": _("Service name is required")}

        try:
            self.logger.info(_("Disabling Ubuntu Pro service: %s"), service_name)

            # Run pro disable command
            command = f"sudo pro disable {service_name} --assume-yes"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                self.logger.info(
                    _("Ubuntu Pro service %s disabled successfully"), service_name
                )

                # After successful disable, send updated OS info to server
                await self._send_os_update_after_pro_change()

                return {
                    "success": True,
                    "result": _("Ubuntu Pro service %s disabled successfully")
                    % service_name,
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                _("Failed to disable Ubuntu Pro service %s: %s"),
                service_name,
                result["result"]["stderr"],
            )
            return {
                "success": False,
                "error": _("Failed to disable Ubuntu Pro service %s: %s")
                % (service_name, result["result"]["stderr"]),
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(
                _("Error disabling Ubuntu Pro service %s: %s"), service_name, error
            )
            return {"success": False, "error": str(error)}

    async def _send_os_update_after_pro_change(self):
        """Send updated OS information to server after Ubuntu Pro status change."""
        try:
            # Wait a moment for the pro command to fully complete
            await asyncio.sleep(2)

            # Get updated OS info with new Ubuntu Pro status
            os_info = self.agent_instance.registration.get_os_version_info()

            # Add hostname for server processing
            system_info = self.agent_instance.registration.get_system_info()
            os_info["hostname"] = system_info.get("hostname") or socket.gethostname()

            # Create and send OS update message
            os_message = self.agent_instance.create_message(
                "os_version_update", os_info
            )
            await self.agent_instance.send_message(os_message)

            self.logger.info(
                _("Updated OS information sent to server after Ubuntu Pro change")
            )

        except Exception as error:
            self.logger.error(
                _("Failed to send OS update after Ubuntu Pro change: %s"), error
            )
