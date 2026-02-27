"""
System control operations module for SysManage agent.
Handles system control commands like shell execution, reboot, shutdown, and system updates.
"""

import asyncio
import logging
import platform
import socket
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector
from src.sysmanage_agent.collection.commercial_antivirus_collection import (
    CommercialAntivirusCollector,
)
from src.sysmanage_agent.collection.update_detection import UpdateDetector


class SystemControl:
    """Handles system control operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize system control with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def execute_shell_command(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command with optional timeout."""
        command = parameters.get("command")
        working_dir = parameters.get("working_directory")
        timeout = parameters.get("timeout", 300)  # Default 5 minute timeout

        if not command:
            return {"success": False, "error": "No command specified"}

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=working_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                # Kill the hung process
                try:
                    process.kill()
                    await process.wait()
                except ProcessLookupError:
                    pass
                return {
                    "success": False,
                    "error": _("Command timed out after %d seconds: %s")
                    % (timeout, command),
                    "result": {
                        "stdout": "",
                        "stderr": _("Command timed out after %d seconds") % timeout,
                        "exit_code": -1,
                    },
                    "exit_code": -1,
                }

            return {
                "success": process.returncode == 0,
                "result": {
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode(),
                    "exit_code": process.returncode,
                },
                "exit_code": process.returncode,
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def get_detailed_system_info(self) -> Dict[str, Any]:
        """
        Get detailed system information and send all data to server.
        This triggers collection and sending of OS version, hardware, storage,
        network, users, groups, software, Ubuntu Pro info, and antivirus status.
        """
        try:
            # Trigger all the standard data collection and sending
            await self.agent_instance.update_os_version()
            await self.agent_instance.update_hardware()

            # Collect and send antivirus status (open source)
            try:
                antivirus_collector = AntivirusCollector()
                antivirus_status = antivirus_collector.collect_antivirus_status()
                await self._send_antivirus_status_update(antivirus_status)
            except Exception as error:
                self.logger.warning(
                    "Failed to collect/send antivirus status: %s", str(error)
                )

            # Collect and send commercial antivirus status
            try:
                commercial_antivirus_collector = CommercialAntivirusCollector()
                commercial_antivirus_status = (
                    commercial_antivirus_collector.collect_commercial_antivirus_status()
                )
                if commercial_antivirus_status:
                    await self._send_commercial_antivirus_status_update(
                        commercial_antivirus_status
                    )
            except Exception as error:
                self.logger.warning(
                    "Failed to collect/send commercial antivirus status: %s", str(error)
                )

            # Collect and send Graylog attachment status
            try:
                await self.agent_instance.data_collector._send_graylog_status_update()  # pylint: disable=protected-access
            except Exception as error:
                self.logger.warning(
                    "Failed to collect/send Graylog status: %s", str(error)
                )

            return {"success": True, "result": "System info refresh initiated"}
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def update_system(
        self,
    ) -> Dict[str, Any]:  # NOSONAR - async required by interface
        """Update the system using the default package manager."""
        await asyncio.sleep(0)  # Yield to event loop for interface consistency
        try:
            update_detector = UpdateDetector()
            result = update_detector.update_system()
            return {"success": True, "result": result}
        except Exception as error:
            self.logger.error(_("Failed to update system: %s"), error)
            return {"success": False, "error": str(error)}

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
        except Exception as error:
            self.logger.error(
                _("Failed to restart service %s: %s"), service_name, error
            )
            return {"success": False, "error": str(error)}

    async def reboot_system(self) -> Dict[str, Any]:
        """Reboot the system."""
        try:
            # Schedule reboot to allow response to be sent
            if platform.system().lower() == "windows":
                # Windows: shutdown /r /t 60 (reboot in 60 seconds)
                # The agent runs as SYSTEM so no elevation needed
                command = 'shutdown /r /t 60 /c "Reboot initiated by SysManage"'
            else:
                # Linux/Unix: shutdown -r +1 (reboot in 1 minute)
                command = "sudo shutdown -r +1"

            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {
                    "success": True,
                    "result": _("System reboot scheduled in 1 minute"),
                }
            return result
        except Exception as error:
            self.logger.error(_("Failed to reboot system: %s"), error)
            return {"success": False, "error": str(error)}

    async def shutdown_system(self) -> Dict[str, Any]:
        """Shutdown the system."""
        try:
            # Schedule shutdown to allow response to be sent
            if platform.system().lower() == "windows":
                # Windows: shutdown /s /t 60 (shutdown in 60 seconds)
                # The agent runs as SYSTEM so no elevation needed
                command = 'shutdown /s /t 60 /c "Shutdown initiated by SysManage"'
            else:
                # Linux/Unix: shutdown -h +1 (halt in 1 minute)
                command = "sudo shutdown -h +1"

            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {
                    "success": True,
                    "result": _("System shutdown scheduled in 1 minute"),
                }
            return result
        except Exception as error:
            self.logger.error(_("Failed to shutdown system: %s"), error)
            return {"success": False, "error": str(error)}

    async def update_agent(self) -> Dict[str, Any]:
        """Update the sysmanage-agent package to the latest version."""
        try:
            system = platform.system().lower()
            if system == "linux":
                return await self._update_agent_linux()
            if system.startswith("freebsd"):
                return await self._update_agent_freebsd()
            if system == "windows":
                return {
                    "success": False,
                    "error": _("Agent update not yet supported on Windows"),
                }
            if system == "darwin":
                return {
                    "success": False,
                    "error": _("Agent update not yet supported on macOS"),
                }
            return {
                "success": False,
                "error": _("Unsupported platform: %s") % system,
            }
        except Exception as error:
            self.logger.error(_("Failed to update agent: %s"), error)
            return {"success": False, "error": str(error)}

    @staticmethod
    def _detect_linux_distro() -> tuple:
        """Detect Linux distribution ID and ID_LIKE values."""
        try:
            os_release = platform.freedesktop_os_release()
            return (
                os_release.get("ID", "").lower(),
                os_release.get("ID_LIKE", "").lower(),
            )
        except OSError:
            pass

        try:
            distro_id = ""
            distro_id_like = ""
            with open("/etc/os-release", encoding="utf-8") as os_release_file:
                for line in os_release_file:
                    if line.startswith("ID="):
                        distro_id = line.strip().split("=", 1)[1].strip('"').lower()
                    elif line.startswith("ID_LIKE="):
                        distro_id_like = (
                            line.strip().split("=", 1)[1].strip('"').lower()
                        )
            return distro_id, distro_id_like
        except FileNotFoundError:
            return None, None

    async def _update_agent_linux(self) -> Dict[str, Any]:
        """Update agent on Linux using the appropriate package manager."""
        distro_id, distro_id_like = self._detect_linux_distro()
        if distro_id is None:
            return {
                "success": False,
                "error": _("Cannot detect Linux distribution"),
            }

        combined = f"{distro_id} {distro_id_like}"

        if "debian" in combined or "ubuntu" in combined:
            command = (
                "sudo apt-get update "
                "&& sudo apt-get install --only-upgrade -y sysmanage-agent"
            )
        elif "fedora" in combined or "rhel" in combined:
            command = "sudo dnf upgrade -y sysmanage-agent"
        elif "suse" in combined:
            command = "sudo zypper --non-interactive update sysmanage-agent"
        elif distro_id == "alpine":
            command = "sudo apk update && sudo apk upgrade sysmanage-agent"
        else:
            return {
                "success": False,
                "error": _("Unsupported Linux distribution: %s") % distro_id,
            }

        result = await self.execute_shell_command({"command": command})
        if result["success"]:
            return {
                "success": True,
                "result": _("Agent updated successfully"),
            }
        return result

    async def _update_agent_freebsd(self) -> Dict[str, Any]:
        """Update agent on FreeBSD using pkg."""
        command = "sudo pkg update && sudo pkg upgrade -y sysmanage-agent"
        result = await self.execute_shell_command({"command": command})
        if result["success"]:
            return {
                "success": True,
                "result": _("Agent updated successfully"),
            }
        return result

    async def _send_antivirus_status_update(self, antivirus_status: Dict[str, Any]):
        """Send antivirus status update to server."""
        try:
            system_info = self.agent_instance.registration.get_system_info()
            message = self.agent_instance.create_message(
                "antivirus_status_update",
                {
                    "hostname": system_info.get("hostname") or socket.gethostname(),
                    "software_name": antivirus_status.get("software_name"),
                    "install_path": antivirus_status.get("install_path"),
                    "version": antivirus_status.get("version"),
                    "enabled": antivirus_status.get("enabled"),
                },
            )
            await self.agent_instance.send_message(message)
            self.logger.info("Sent antivirus status update to server")
        except Exception as error:
            self.logger.error("Failed to send antivirus status update: %s", error)

    async def _send_commercial_antivirus_status_update(
        self, commercial_antivirus_status: Dict[str, Any]
    ):
        """Send commercial antivirus status update to server."""
        try:
            system_info = self.agent_instance.registration.get_system_info()
            message = self.agent_instance.create_message(
                "commercial_antivirus_status_update",
                {
                    "hostname": system_info.get("hostname") or socket.gethostname(),
                    "product_name": commercial_antivirus_status.get("product_name"),
                    "product_version": commercial_antivirus_status.get(
                        "product_version"
                    ),
                    "service_enabled": commercial_antivirus_status.get(
                        "service_enabled"
                    ),
                    "antispyware_enabled": commercial_antivirus_status.get(
                        "antispyware_enabled"
                    ),
                    "antivirus_enabled": commercial_antivirus_status.get(
                        "antivirus_enabled"
                    ),
                    "realtime_protection_enabled": commercial_antivirus_status.get(
                        "realtime_protection_enabled"
                    ),
                    "full_scan_age": commercial_antivirus_status.get("full_scan_age"),
                    "quick_scan_age": commercial_antivirus_status.get("quick_scan_age"),
                    "full_scan_end_time": commercial_antivirus_status.get(
                        "full_scan_end_time"
                    ),
                    "quick_scan_end_time": commercial_antivirus_status.get(
                        "quick_scan_end_time"
                    ),
                    "signature_last_updated": commercial_antivirus_status.get(
                        "signature_last_updated"
                    ),
                    "signature_version": commercial_antivirus_status.get(
                        "signature_version"
                    ),
                    "tamper_protection_enabled": commercial_antivirus_status.get(
                        "tamper_protection_enabled"
                    ),
                },
            )
            await self.agent_instance.send_message(message)
            self.logger.info("Sent commercial antivirus status update to server")
        except Exception as error:
            self.logger.error(
                "Failed to send commercial antivirus status update: %s", error
            )
