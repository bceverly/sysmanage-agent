"""
System operations module for SysManage agent.
Handles system-level commands and operations.
"""

import asyncio
import platform
import logging
from typing import Dict, Any

from update_detection import UpdateDetector
from i18n import _


class SystemOperations:
    """Handles system-level operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize system operations with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

    async def execute_shell_command(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command."""
        command = parameters.get("command")
        working_dir = parameters.get("working_directory")

        if not command:
            return {"success": False, "error": "No command specified"}

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=working_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "result": {
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode(),
                    "exit_code": process.returncode,
                },
                "exit_code": process.returncode,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_detailed_system_info(self) -> Dict[str, Any]:
        """Get detailed system information."""
        try:
            # Get basic system info
            info = {
                "hostname": self.agent.hostname,
                "platform": self.agent.platform,
                "ipv4": self.agent.ipv4,
                "ipv6": self.agent.ipv6,
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
            }

            return {"success": True, "result": info}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def install_package(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Install a package using the appropriate package manager."""
        package_name = parameters.get("package_name")
        package_manager = parameters.get("package_manager")

        if not package_name:
            return {"success": False, "error": _("No package name specified")}

        try:
            update_detector = UpdateDetector()
            result = update_detector.install_package(package_name, package_manager)
            return {"success": True, "result": result}
        except Exception as e:
            self.logger.error(_("Failed to install package %s: %s"), package_name, e)
            return {"success": False, "error": str(e)}

    async def update_system(self) -> Dict[str, Any]:
        """Update the system using the default package manager."""
        try:
            update_detector = UpdateDetector()
            result = update_detector.update_system()
            return {"success": True, "result": result}
        except Exception as e:
            self.logger.error(_("Failed to update system: %s"), e)
            return {"success": False, "error": str(e)}

    async def restart_service(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart a system service."""
        service_name = parameters.get("service_name")

        if not service_name:
            return {"success": False, "error": _("No service name specified")}

        try:
            # Try systemctl first (most common)
            command = f"sudo systemctl restart {service_name}"
            result = await self.execute_shell_command({"command": command})
            return result
        except Exception as e:
            self.logger.error(_("Failed to restart service %s: %s"), service_name, e)
            return {"success": False, "error": str(e)}

    async def reboot_system(self) -> Dict[str, Any]:
        """Reboot the system."""
        try:
            # Schedule reboot in 1 minute to allow response to be sent
            command = "sudo shutdown -r +1"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {
                    "success": True,
                    "result": _("System reboot scheduled in 1 minute"),
                }
            return result
        except Exception as e:
            self.logger.error(_("Failed to reboot system: %s"), e)
            return {"success": False, "error": str(e)}

    async def shutdown_system(self) -> Dict[str, Any]:
        """Shutdown the system."""
        try:
            # Schedule shutdown in 1 minute to allow response to be sent
            command = "sudo shutdown -h +1"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {
                    "success": True,
                    "result": _("System shutdown scheduled in 1 minute"),
                }
            return result
        except Exception as e:
            self.logger.error(_("Failed to shutdown system: %s"), e)
            return {"success": False, "error": str(e)}

    async def ubuntu_pro_attach(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Attach Ubuntu Pro subscription using provided token."""
        token = parameters.get("token")

        if not token:
            return {"success": False, "error": _("Ubuntu Pro token is required")}

        try:
            self.logger.info(_("Attaching Ubuntu Pro subscription..."))

            # Run pro attach command with the provided token
            command = f"sudo pro attach {token}"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info(_("Ubuntu Pro attached successfully"))

                # After successful attach, send updated OS info to server
                await self._send_os_update_after_pro_change()

                return {
                    "success": True,
                    "result": _("Ubuntu Pro subscription attached successfully"),
                    "output": result["result"]["stdout"],
                }
            else:
                self.logger.error(
                    _("Failed to attach Ubuntu Pro: %s"), result["result"]["stderr"]
                )
                return {
                    "success": False,
                    "error": _("Failed to attach Ubuntu Pro: %s")
                    % result["result"]["stderr"],
                    "output": result["result"]["stderr"],
                }
        except Exception as e:
            self.logger.error(_("Error attaching Ubuntu Pro: %s"), e)
            return {"success": False, "error": str(e)}

    async def ubuntu_pro_detach(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Detach Ubuntu Pro subscription."""
        try:
            self.logger.info(_("Detaching Ubuntu Pro subscription..."))

            # Run pro detach command
            command = "sudo pro detach --assume-yes"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info(_("Ubuntu Pro detached successfully"))

                # After successful detach, send updated OS info to server
                await self._send_os_update_after_pro_change()

                return {
                    "success": True,
                    "result": _("Ubuntu Pro subscription detached successfully"),
                    "output": result["result"]["stdout"],
                }
            else:
                self.logger.error(
                    _("Failed to detach Ubuntu Pro: %s"), result["result"]["stderr"]
                )
                return {
                    "success": False,
                    "error": _("Failed to detach Ubuntu Pro: %s")
                    % result["result"]["stderr"],
                    "output": result["result"]["stderr"],
                }
        except Exception as e:
            self.logger.error(_("Error detaching Ubuntu Pro: %s"), e)
            return {"success": False, "error": str(e)}

    async def ubuntu_pro_enable_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable Ubuntu Pro service."""
        service_name = parameters.get("service")

        if not service_name:
            return {"success": False, "error": _("Service name is required")}

        try:
            self.logger.info(_("Enabling Ubuntu Pro service: %s"), service_name)

            # Run pro enable command
            command = f"sudo pro enable {service_name} --assume-yes"
            result = await self.execute_shell_command({"command": command})

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
            else:
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
        except Exception as e:
            self.logger.error(
                _("Error enabling Ubuntu Pro service %s: %s"), service_name, e
            )
            return {"success": False, "error": str(e)}

    async def ubuntu_pro_disable_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable Ubuntu Pro service."""
        service_name = parameters.get("service")

        if not service_name:
            return {"success": False, "error": _("Service name is required")}

        try:
            self.logger.info(_("Disabling Ubuntu Pro service: %s"), service_name)

            # Run pro disable command
            command = f"sudo pro disable {service_name} --assume-yes"
            result = await self.execute_shell_command({"command": command})

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
            else:
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
        except Exception as e:
            self.logger.error(
                _("Error disabling Ubuntu Pro service %s: %s"), service_name, e
            )
            return {"success": False, "error": str(e)}

    async def _send_os_update_after_pro_change(self):
        """Send updated OS information to server after Ubuntu Pro status change."""
        try:
            # Wait a moment for the pro command to fully complete
            await asyncio.sleep(2)

            # Get updated OS info with new Ubuntu Pro status
            os_info = self.agent.registration.get_os_version_info()

            # Add hostname for server processing
            system_info = self.agent.registration.get_system_info()
            os_info["hostname"] = system_info["hostname"]

            # Create and send OS update message
            os_message = self.agent.create_message("os_version_update", os_info)
            await self.agent.send_message(os_message)

            self.logger.info(
                _("Updated OS information sent to server after Ubuntu Pro change")
            )

        except Exception as e:
            self.logger.error(
                _("Failed to send OS update after Ubuntu Pro change: %s"), e
            )
