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
