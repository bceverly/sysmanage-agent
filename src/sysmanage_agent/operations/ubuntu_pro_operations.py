# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Ubuntu Pro operations module for SysManage agent.
Handles Ubuntu Pro subscription management and service operations.
"""

import asyncio
import logging
import socket
from typing import Any, Dict
from src.i18n import _
from src.sysmanage_agent.collection import pro_status_cache


def _pro_streams(result: Dict[str, Any]) -> Dict[str, str]:
    inner = result.get("result") or {}
    return {
        "stdout": (inner.get("stdout") or "").strip(),
        "stderr": (inner.get("stderr") or "").strip(),
    }


def _pro_output(result: Dict[str, Any]) -> str:
    """What ``pro`` said: stderr if any, else stdout.

    ``pro`` reports most outcomes on STDOUT; logging only stderr produced
    "Failed to enable Ubuntu Pro service livepatch: " with nothing after it
    (beast, 2026-10-16)."""
    streams = _pro_streams(result)
    return streams["stderr"] or streams["stdout"] or str(result.get("error") or "")


def _already_in_state(result: Dict[str, Any]) -> bool:
    """``pro enable``/``disable`` exits 1 with "... - nothing to do." when the
    service is already enabled/disabled; that is the requested outcome."""
    return "nothing to do" in _pro_streams(result)["stdout"].lower()


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
            self.logger.info("Attaching Ubuntu Pro subscription...")

            # Run pro attach command with the provided token
            # Use --no-auto-enable to prevent hanging on service enablement
            # (e.g., livepatch snap install hangs in LXD containers)
            command = f"sudo pro attach --no-auto-enable {token}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command, "timeout": 180}
            )

            if result["success"]:
                self.logger.info("Ubuntu Pro attached successfully")

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
            self.logger.info("Detaching Ubuntu Pro subscription...")

            # Run pro detach command
            command = "sudo pro detach --assume-yes"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                self.logger.info("Ubuntu Pro detached successfully")

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
            self.logger.info("Enabling Ubuntu Pro service: %s", service_name)

            # Run pro enable command
            command = f"sudo -n pro enable {service_name} --assume-yes"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"] or _already_in_state(result):
                self.logger.info(
                    "Ubuntu Pro service %s enabled successfully", service_name
                )

                # After successful enable, send updated OS info to server
                await self._send_os_update_after_pro_change()

                return {
                    "success": True,
                    "result": _("Ubuntu Pro service %s enabled successfully")
                    % service_name,
                    "output": result["result"]["stdout"],
                }

            detail = _pro_output(result)
            self.logger.error(
                _("Failed to enable Ubuntu Pro service %s: %s"),
                service_name,
                detail,
            )
            return {
                "success": False,
                "error": _("Failed to enable Ubuntu Pro service %s: %s")
                % (service_name, detail),
                "output": detail,
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
            self.logger.info("Disabling Ubuntu Pro service: %s", service_name)

            # Run pro disable command
            command = f"sudo -n pro disable {service_name} --assume-yes"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"] or _already_in_state(result):
                self.logger.info(
                    "Ubuntu Pro service %s disabled successfully", service_name
                )

                # After successful disable, send updated OS info to server
                await self._send_os_update_after_pro_change()

                return {
                    "success": True,
                    "result": _("Ubuntu Pro service %s disabled successfully")
                    % service_name,
                    "output": result["result"]["stdout"],
                }

            detail = _pro_output(result)
            self.logger.error(
                _("Failed to disable Ubuntu Pro service %s: %s"),
                service_name,
                detail,
            )
            return {
                "success": False,
                "error": _("Failed to disable Ubuntu Pro service %s: %s")
                % (service_name, detail),
                "output": detail,
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
            # The cached `pro status` predates this change: ask again.
            pro_status_cache.invalidate()

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
                "Updated OS information sent to server after Ubuntu Pro change"
            )

        except Exception as error:
            self.logger.error(
                _("Failed to send OS update after Ubuntu Pro change: %s"), error
            )
