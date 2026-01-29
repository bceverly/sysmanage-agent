"""
Antivirus Service Management Module for SysManage Agent

This module handles enable/disable/remove operations for antivirus services
across multiple platforms.
"""

# pylint: disable=import-error
import asyncio
import logging
import os
import platform
from typing import Any, Dict

from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector

# Module-level constants for repeated string literals
_MSG_NO_ANTIVIRUS_DETECTED = "No antivirus software detected"
_MSG_DETECTED_ANTIVIRUS = "Detected antivirus software: %s"
_PATH_BREW_LOCAL = "/usr/local/bin/brew"
_PATH_BREW_OPT = "/opt/homebrew/bin/brew"
_PATH_PKGIN = "/usr/pkg/bin/pkgin"
_PATH_PKG = "/usr/sbin/pkg"
_PATH_PKG_ADD = "/usr/sbin/pkg_add"
_PATH_ZYPPER = "/usr/bin/zypper"
_PATH_DNF = "/usr/bin/dnf"
_PATH_YUM = "/usr/bin/yum"


class AntivirusServiceManager:
    """Handles antivirus service management operations (enable, disable, remove)."""

    def __init__(self, agent_instance):
        """
        Initialize the AntivirusServiceManager instance.

        Args:
            agent_instance: Reference to the parent agent instance for messaging
        """
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def send_antivirus_status_update(self, antivirus_status: Dict[str, Any]):
        """
        Send antivirus status update to the server.

        Args:
            antivirus_status: Dictionary containing antivirus status information
        """
        try:
            # Create message using agent's create_message method which uses the queue
            message = self.agent_instance.create_message(
                "antivirus_status_update", {"antivirus_status": antivirus_status}
            )
            success = await self.agent_instance.send_message(message)
            if success:
                self.logger.info("Sent antivirus status update to server")
            else:
                self.logger.warning("Failed to send antivirus status update")
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to send antivirus status update: %s", error)

    async def enable_antivirus(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enable antivirus service(s)."""
        self.logger.info("Enabling antivirus service")

        try:
            antivirus_collector = AntivirusCollector()
            antivirus_status = antivirus_collector.collect_antivirus_status()

            if not antivirus_status or not antivirus_status.get("software_name"):
                return {
                    "success": False,
                    "error": _MSG_NO_ANTIVIRUS_DETECTED,
                }

            software_name = antivirus_status["software_name"]
            self.logger.info(_MSG_DETECTED_ANTIVIRUS, software_name)

            context = self._detect_service_context(software_name)
            if context is None:
                return {
                    "success": False,
                    "error": f"Unknown antivirus software: {software_name}",
                }

            service_name, method = context

            result = await self._enable_service(service_name, method)
            if isinstance(result, dict):
                return result

            process, stderr = result
            success = process.returncode == 0
            if success:
                self.logger.info(
                    "Antivirus service %s enabled successfully", service_name
                )
                antivirus_status = antivirus_collector.collect_antivirus_status()
                await self.send_antivirus_status_update(antivirus_status)
            else:
                self.logger.error(
                    "Failed to enable antivirus service: %s", stderr.decode()
                )

            return {
                "success": success,
                "service_name": service_name,
                "error": stderr.decode() if not success else None,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to enable antivirus: %s", error)
            return {"success": False, "error": str(error)}

    def _detect_service_context(self, software_name: str):
        """
        Detect the appropriate service name and management method.

        Returns:
            Tuple of (service_name, method_string) or None if unknown software.
        """
        if software_name.lower() != "clamav":
            return None

        if platform.system() == "Windows":
            return "ClamAV", "windows"
        if os.path.exists(_PATH_BREW_LOCAL) or os.path.exists(_PATH_BREW_OPT):
            return "clamav", "brew"
        if os.path.exists("/usr/sbin/rcctl"):
            return "clamd", "rcctl"
        if os.path.exists(_PATH_PKGIN):
            return "clamd", "bsd"
        if os.path.exists(_PATH_PKG) and not os.path.exists(_PATH_PKG_ADD):
            return "clamav_clamd", "bsd"
        if os.path.exists(_PATH_ZYPPER):
            return "clamd.service", "systemctl"
        if os.path.exists(_PATH_DNF) or os.path.exists(_PATH_YUM):
            return "clamd@scan", "systemctl"
        return "clamav_freshclam", "systemctl"

    async def _enable_service(self, service_name: str, method: str):
        """
        Enable and start an antivirus service using the appropriate system method.

        Returns:
            Tuple of (process, stderr) on success, or a dict for early error returns.
        """
        if method == "bsd":
            return await self._enable_bsd_service(service_name)
        if method == "rcctl":
            return await self._enable_rcctl_service(service_name)
        if method == "brew":
            return await self._enable_brew_service(service_name)
        if method == "windows":
            return await self._enable_windows_service(service_name)
        return await self._enable_systemctl_service(service_name)

    async def _enable_bsd_service(self, service_name: str):
        """Enable and start BSD-style services."""
        services_to_start = [service_name]
        if os.path.exists(_PATH_PKGIN):
            services_to_start = ["freshclamd", "clamd"]

        for svc in services_to_start:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "service",
                svc,
                "start",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to start service {svc}: {stderr.decode() if stderr else 'unknown error'}",
                }

            self.logger.info("Service %s enabled and started successfully", svc)
            await asyncio.sleep(1)

        return process, stderr

    async def _enable_rcctl_service(self, service_name: str):
        """Enable and start a service using OpenBSD rcctl."""
        process = await asyncio.create_subprocess_exec(
            "rcctl",
            "enable",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "rcctl",
            "start",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return process, stderr

    async def _enable_brew_service(self, service_name: str):
        """Enable and start a service using macOS brew services."""
        brew_cmd = (
            _PATH_BREW_OPT if os.path.exists(_PATH_BREW_OPT) else _PATH_BREW_LOCAL
        )
        process = await asyncio.create_subprocess_exec(
            brew_cmd,
            "services",
            "start",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return process, stderr

    async def _enable_windows_service(self, service_name: str):
        """Enable and start a Windows service using sc command."""
        process = await asyncio.create_subprocess_exec(
            "sc",
            "query",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, _ = await process.communicate()

        if process.returncode != 0:
            return {
                "success": False,
                "error": "ClamAV service not configured. Windows ClamAV requires manual service setup.",
            }

        process = await asyncio.create_subprocess_exec(
            "sc",
            "start",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return process, stderr

    async def _enable_systemctl_service(self, service_name: str):
        """Enable and start a service using systemctl."""
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "enable",
            "--now",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return process, stderr

    async def disable_antivirus(  # pylint: disable=too-many-branches,too-many-statements
        self, _parameters: Dict[str, Any]  # NOSONAR - reserved for future use
    ) -> Dict[str, Any]:
        """Disable antivirus service(s)."""
        self.logger.info("Disabling antivirus service")

        try:
            # Collect current antivirus status to determine what service to disable
            antivirus_collector = AntivirusCollector()
            antivirus_status = antivirus_collector.collect_antivirus_status()

            if not antivirus_status or not antivirus_status.get("software_name"):
                return {
                    "success": False,
                    "error": "No antivirus software detected",
                }

            software_name = antivirus_status["software_name"]
            self.logger.info("Detected antivirus software: %s", software_name)

            # Determine service name and command based on OS and antivirus software
            service_name = None
            use_rcctl = False
            use_bsd_service = False
            use_brew_services = False
            use_windows_service = False
            if software_name.lower() == "clamav":
                # Check OS type and use appropriate service name
                if platform.system() == "Windows":
                    # Windows - use sc command for service management
                    service_name = "ClamAV"
                    use_windows_service = True
                elif os.path.exists("/usr/local/bin/brew") or os.path.exists(
                    "/opt/homebrew/bin/brew"
                ):
                    # macOS - use brew services
                    service_name = "clamav"
                    use_brew_services = True
                elif os.path.exists("/usr/sbin/rcctl"):
                    # OpenBSD - use rcctl instead of systemctl
                    service_name = "clamd"
                    use_rcctl = True
                elif os.path.exists("/usr/pkg/bin/pkgin"):
                    # NetBSD - use service command
                    service_name = "clamd"
                    use_bsd_service = True
                elif os.path.exists("/usr/sbin/pkg") and not os.path.exists(
                    "/usr/sbin/pkg_add"
                ):
                    # FreeBSD - use service command
                    service_name = "clamav_clamd"
                    use_bsd_service = True
                elif os.path.exists("/usr/bin/zypper"):
                    # openSUSE
                    service_name = "clamd.service"
                elif os.path.exists("/usr/bin/dnf") or os.path.exists("/usr/bin/yum"):
                    # RHEL/CentOS
                    service_name = "clamd@scan"
                else:
                    # Debian/Ubuntu
                    service_name = "clamav_freshclam"

            if not service_name:
                return {
                    "success": False,
                    "error": f"Unknown antivirus software: {software_name}",
                }

            # Stop and disable the service
            if use_bsd_service:
                # BSD uses service command
                # NetBSD has two services: freshclamd and clamd
                services_to_stop = [service_name]
                if os.path.exists("/usr/pkg/bin/pkgin"):
                    # NetBSD - also stop freshclamd
                    services_to_stop = ["clamd", "freshclamd"]

                for svc in services_to_stop:
                    process = await asyncio.create_subprocess_exec(
                        "sudo",
                        "service",
                        svc,
                        "stop",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, stderr = await process.communicate()

                    if process.returncode != 0:
                        self.logger.warning(
                            "Failed to stop service %s: %s",
                            svc,
                            stderr.decode() if stderr else "unknown error",
                        )
                    else:
                        self.logger.info("Service %s disabled successfully", svc)

                await asyncio.sleep(1)

            elif use_rcctl:
                # OpenBSD uses rcctl
                process = await asyncio.create_subprocess_exec(
                    "rcctl",
                    "stop",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                process = await asyncio.create_subprocess_exec(
                    "rcctl",
                    "disable",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
            elif use_brew_services:
                # macOS uses brew services
                brew_cmd = (
                    "/opt/homebrew/bin/brew"
                    if os.path.exists("/opt/homebrew/bin/brew")
                    else "/usr/local/bin/brew"
                )
                process = await asyncio.create_subprocess_exec(
                    brew_cmd,
                    "services",
                    "stop",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
            elif use_windows_service:
                # Windows uses sc command for service management
                process = await asyncio.create_subprocess_exec(
                    "sc",
                    "stop",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
            else:
                # Linux uses systemctl
                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "disable",
                    "--now",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

            success = process.returncode == 0
            if success:
                self.logger.info(
                    "Antivirus service %s disabled successfully", service_name
                )
                # Collect and send updated status
                antivirus_status = antivirus_collector.collect_antivirus_status()
                await self.send_antivirus_status_update(antivirus_status)
            else:
                self.logger.error(
                    "Failed to disable antivirus service: %s", stderr.decode()
                )

            return {
                "success": success,
                "service_name": service_name,
                "error": stderr.decode() if not success else None,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to disable antivirus: %s", error)
            return {"success": False, "error": str(error)}

    async def remove_antivirus(  # pylint: disable=too-many-branches,too-many-statements
        self, _parameters: Dict[str, Any]  # NOSONAR - reserved for future use
    ) -> Dict[str, Any]:
        """Remove antivirus software from the system."""
        self.logger.info("Removing antivirus software")

        try:
            # Collect current antivirus status to determine what to remove
            antivirus_collector = AntivirusCollector()
            antivirus_status = antivirus_collector.collect_antivirus_status()

            if not antivirus_status or not antivirus_status.get("software_name"):
                return {
                    "success": False,
                    "error": "No antivirus software detected",
                }

            software_name = antivirus_status["software_name"]
            self.logger.info("Detected antivirus software: %s", software_name)

            # Map antivirus software to removal commands
            if software_name.lower() != "clamav":
                return {
                    "success": False,
                    "error": f"Unknown antivirus software: {software_name}",
                }

            # Remove ClamAV - detect package manager and use appropriate commands
            error = None
            if os.path.exists("/usr/local/bin/brew") or os.path.exists(
                "/opt/homebrew/bin/brew"
            ):
                # macOS - stop service and remove via brew
                from src.sysmanage_agent.operations.antivirus_remover_unix import (  # pylint: disable=import-outside-toplevel,no-name-in-module
                    AntivirusRemoverUnix,
                )

                remover = AntivirusRemoverUnix(self.logger)
                error = await remover.remove_macos()

            elif os.path.exists("/usr/pkg/bin/pkgin"):
                # NetBSD
                from src.sysmanage_agent.operations.antivirus_remover_unix import (  # pylint: disable=import-outside-toplevel,no-name-in-module
                    AntivirusRemoverUnix,
                )

                remover = AntivirusRemoverUnix(self.logger)
                error = await remover.remove_netbsd()

            elif os.path.exists("/usr/sbin/pkg") and not os.path.exists(
                "/usr/sbin/pkg_add"
            ):
                # FreeBSD
                from src.sysmanage_agent.operations.antivirus_remover_unix import (  # pylint: disable=import-outside-toplevel,no-name-in-module
                    AntivirusRemoverUnix,
                )

                remover = AntivirusRemoverUnix(self.logger)
                error = await remover.remove_freebsd()

            elif os.path.exists("/usr/sbin/pkg_delete"):
                # OpenBSD
                from src.sysmanage_agent.operations.antivirus_remover_unix import (  # pylint: disable=import-outside-toplevel,no-name-in-module
                    AntivirusRemoverUnix,
                )

                remover = AntivirusRemoverUnix(self.logger)
                error = await remover.remove_openbsd()

            elif os.path.exists("/usr/bin/zypper"):
                # openSUSE
                from src.sysmanage_agent.operations.antivirus_remover_linux import (  # pylint: disable=import-outside-toplevel,no-name-in-module
                    AntivirusRemoverLinux,
                )

                remover = AntivirusRemoverLinux(self.logger)
                error = await remover.remove_opensuse()

            elif os.path.exists("/usr/bin/apt"):
                # Debian/Ubuntu
                from src.sysmanage_agent.operations.antivirus_remover_linux import (  # pylint: disable=import-outside-toplevel,no-name-in-module
                    AntivirusRemoverLinux,
                )

                remover = AntivirusRemoverLinux(self.logger)
                error = await remover.remove_debian()

            elif os.path.exists("/usr/bin/dnf") or os.path.exists("/usr/bin/yum"):
                # RHEL/CentOS
                from src.sysmanage_agent.operations.antivirus_remover_linux import (  # pylint: disable=import-outside-toplevel,no-name-in-module
                    AntivirusRemoverLinux,
                )

                remover = AntivirusRemoverLinux(self.logger)
                error = await remover.remove_redhat()

            elif platform.system() == "Windows":
                # Windows
                from src.sysmanage_agent.operations.antivirus_remover_windows import (  # pylint: disable=import-outside-toplevel,no-name-in-module
                    AntivirusRemoverWindows,
                )

                remover = AntivirusRemoverWindows(self.logger)
                error = await remover.remove_windows()

            else:
                error = "Unsupported package manager"

            if error:
                self.logger.error("Failed to remove antivirus: %s", error)
                return {"success": False, "error": error}

            self.logger.info("Antivirus software removed successfully")

            # Send updated status (should show no antivirus)
            antivirus_status = antivirus_collector.collect_antivirus_status()
            await self.send_antivirus_status_update(antivirus_status)

            return {
                "success": True,
                "software_name": software_name,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to remove antivirus: %s", error)
            return {"success": False, "error": str(error)}
