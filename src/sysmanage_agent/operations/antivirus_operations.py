"""
Antivirus Operations Module for SysManage Agent

This module handles all antivirus-related operations including:
- Deployment of antivirus software (ClamAV) across multiple platforms
- Enabling and disabling antivirus services
- Removal of antivirus software
- Status updates and reporting

Supported platforms:
- Linux (Debian/Ubuntu, RHEL/CentOS, openSUSE)
- macOS (via Homebrew)
- Windows (via Chocolatey - ClamWin)
- BSD (FreeBSD, OpenBSD, NetBSD)
"""

import asyncio
import logging
import os
import platform
from typing import Any, Dict

from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector
from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.sysmanage_agent.operations import antivirus_deployment_helpers
from src.sysmanage_agent.operations import antivirus_removal_helpers

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


def _get_brew_user():
    """Get the user that owns the Homebrew installation."""
    import pwd  # pylint: disable=import-outside-toplevel,import-error

    # Check both possible Homebrew locations
    brew_dirs = ["/opt/homebrew", "/usr/local/Homebrew"]
    for brew_dir in brew_dirs:
        if os.path.exists(brew_dir):
            try:
                stat_info = os.stat(brew_dir)
                return pwd.getpwuid(stat_info.st_uid).pw_name
            except (OSError, KeyError):
                continue

    # Fallback to SUDO_USER if available
    return os.environ.get("SUDO_USER")


class AntivirusOperations:
    """Handles antivirus software deployment, management, and removal operations."""

    def __init__(self, agent_instance):
        """
        Initialize the AntivirusOperations instance.

        Args:
            agent_instance: Reference to the parent agent instance for messaging
        """
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def _send_antivirus_status_update(self, antivirus_status: Dict[str, Any]):
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

    async def deploy_antivirus(  # pylint: disable=too-many-locals
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Deploy antivirus software to the system."""
        antivirus_package = parameters.get("antivirus_package")

        if not antivirus_package:
            return {"success": False, "error": "No antivirus package specified"}

        self.logger.info("Deploying antivirus package: %s", antivirus_package)

        try:
            # Validate ClamAV package
            if "clamav" not in antivirus_package.lower():
                return {
                    "success": False,
                    "error": f"Unsupported antivirus package: {antivirus_package}",
                    "package_name": antivirus_package,
                }

            # Detect platform and deploy using appropriate helper
            update_detector = UpdateDetector()

            if os.path.exists(_PATH_BREW_LOCAL) or os.path.exists(_PATH_BREW_OPT):
                success, error_message, installed_version, result = (
                    await antivirus_deployment_helpers.deploy_clamav_macos(
                        update_detector
                    )
                )
            elif os.path.exists(_PATH_PKGIN):
                success, error_message, installed_version, result = (
                    await antivirus_deployment_helpers.deploy_clamav_netbsd(
                        update_detector
                    )
                )
            elif os.path.exists(_PATH_PKG) and not os.path.exists(_PATH_PKG_ADD):
                success, error_message, installed_version, result = (
                    await antivirus_deployment_helpers.deploy_clamav_freebsd(
                        update_detector
                    )
                )
            elif os.path.exists(_PATH_PKG_ADD):
                success, error_message, installed_version, result = (
                    await antivirus_deployment_helpers.deploy_clamav_openbsd(
                        update_detector
                    )
                )
            elif os.path.exists(_PATH_ZYPPER):
                success, error_message, installed_version, result = (
                    await antivirus_deployment_helpers.deploy_clamav_opensuse(
                        update_detector
                    )
                )
            elif os.path.exists(_PATH_YUM) or os.path.exists(_PATH_DNF):
                success, error_message, installed_version, result = (
                    await antivirus_deployment_helpers.deploy_clamav_rhel(
                        update_detector
                    )
                )
            elif platform.system() == "Windows":
                success, error_message, installed_version, result = (
                    await antivirus_deployment_helpers.deploy_clamav_windows(
                        update_detector
                    )
                )
            else:
                # Default to Debian/Ubuntu
                success, error_message, installed_version, result = (
                    await antivirus_deployment_helpers.deploy_clamav_debian(
                        update_detector
                    )
                )

            # Collect antivirus status and send it back to server
            try:
                antivirus_collector = AntivirusCollector()
                antivirus_status = antivirus_collector.collect_antivirus_status()
                await self._send_antivirus_status_update(antivirus_status)
            except Exception as status_error:
                self.logger.warning(
                    "Failed to collect/send antivirus status after installation: %s",
                    str(status_error),
                )

            return {
                "success": success,
                "result": result,
                "package_name": antivirus_package,
                "installed_version": installed_version,
                "error": error_message,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            error_message = str(error)
            self.logger.error(
                "Failed to deploy antivirus %s: %s", antivirus_package, error
            )

            return {
                "success": False,
                "error": error_message,
                "package_name": antivirus_package,
            }

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
                await self._send_antivirus_status_update(antivirus_status)
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

    async def disable_antivirus(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Disable antivirus service(s)."""
        self.logger.info("Disabling antivirus service")

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

            process, stderr = await self._disable_service(service_name, method)
            success = process.returncode == 0
            if success:
                self.logger.info(
                    "Antivirus service %s disabled successfully", service_name
                )
                antivirus_status = antivirus_collector.collect_antivirus_status()
                await self._send_antivirus_status_update(antivirus_status)
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

    async def _disable_service(self, service_name: str, method: str):
        """
        Stop and disable an antivirus service using the appropriate system method.

        Returns:
            Tuple of (process, stderr).
        """
        if method == "bsd":
            return await self._disable_bsd_service(service_name)
        if method == "rcctl":
            return await self._disable_rcctl_service(service_name)
        if method == "brew":
            return await self._disable_brew_service(service_name)
        if method == "windows":
            return await self._disable_windows_service(service_name)
        return await self._disable_systemctl_service(service_name)

    async def _disable_bsd_service(self, service_name: str):
        """Stop BSD-style services."""
        services_to_stop = [service_name]
        if os.path.exists(_PATH_PKGIN):
            services_to_stop = ["clamd", "freshclamd"]

        process = None
        stderr = None
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
        return process, stderr

    async def _disable_rcctl_service(self, service_name: str):
        """Stop and disable a service using OpenBSD rcctl."""
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
        return process, stderr

    async def _disable_brew_service(self, service_name: str):
        """Stop a service using macOS brew services."""
        brew_cmd = (
            _PATH_BREW_OPT if os.path.exists(_PATH_BREW_OPT) else _PATH_BREW_LOCAL
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
        return process, stderr

    async def _disable_windows_service(self, service_name: str):
        """Stop a Windows service using sc command."""
        process = await asyncio.create_subprocess_exec(
            "sc",
            "stop",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return process, stderr

    async def _disable_systemctl_service(self, service_name: str):
        """Stop and disable a service using systemctl."""
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "disable",
            "--now",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return process, stderr

    async def remove_antivirus(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove antivirus software from the system."""
        self.logger.info("Removing antivirus software")

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

            if software_name.lower() != "clamav":
                return {
                    "success": False,
                    "error": f"Unknown antivirus software: {software_name}",
                }

            error = await self._remove_clamav_by_platform()

            if error:
                self.logger.error("Failed to remove antivirus: %s", error)
                return {"success": False, "error": error}

            self.logger.info("Antivirus software removed successfully")

            # Send updated status (should show no antivirus)
            antivirus_status = antivirus_collector.collect_antivirus_status()
            await self._send_antivirus_status_update(antivirus_status)

            return {
                "success": True,
                "software_name": software_name,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to remove antivirus: %s", error)
            return {"success": False, "error": str(error)}

    async def _remove_clamav_by_platform(self):
        """Detect platform and remove ClamAV using the appropriate helper."""
        if os.path.exists(_PATH_BREW_LOCAL) or os.path.exists(_PATH_BREW_OPT):
            return await antivirus_removal_helpers.remove_clamav_macos()
        if os.path.exists(_PATH_PKGIN):
            return await antivirus_removal_helpers.remove_clamav_netbsd()
        if os.path.exists(_PATH_PKG) and not os.path.exists(_PATH_PKG_ADD):
            return await antivirus_removal_helpers.remove_clamav_freebsd()
        if os.path.exists("/usr/sbin/pkg_delete"):
            return await antivirus_removal_helpers.remove_clamav_openbsd()
        if os.path.exists(_PATH_ZYPPER):
            return await antivirus_removal_helpers.remove_clamav_opensuse()
        if os.path.exists("/usr/bin/apt"):
            return await antivirus_removal_helpers.remove_clamav_debian()
        if os.path.exists(_PATH_DNF) or os.path.exists(_PATH_YUM):
            return await antivirus_removal_helpers.remove_clamav_rhel()
        if platform.system() == "Windows":
            return await antivirus_removal_helpers.remove_clamav_windows()
        return "Unsupported package manager"
