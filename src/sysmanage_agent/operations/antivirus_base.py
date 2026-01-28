"""
Antivirus Operations Base Module for SysManage Agent

This module provides the base class and common methods for antivirus operations.
Platform-specific deployment methods are implemented in separate modules.
"""

# pylint: disable=import-error
import asyncio
import glob
import logging
import os
from typing import Any, Dict, Optional, Tuple

from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector

# Module-level constants for repeated strings
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
_SERVICE_CLAMD = "clamd.service"
_SERVICE_CLAMD_AT_SCAN = "clamd@scan"


def _get_brew_user():
    """Get the user that owns the Homebrew installation."""
    import pwd  # pylint: disable=import-outside-toplevel

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


def _detect_clamav_service_context() -> Tuple[Optional[str], bool, bool, bool, bool]:
    """
    Detect the appropriate ClamAV service name and management method based on the OS.

    Returns:
        Tuple of (service_name, use_rcctl, use_bsd_service, use_brew_services, use_windows_service)
    """
    import platform  # pylint: disable=import-outside-toplevel

    if platform.system() == "Windows":
        return "ClamAV", False, False, False, True
    if os.path.exists(_PATH_BREW_LOCAL) or os.path.exists(_PATH_BREW_OPT):
        return "clamav", False, False, True, False
    if os.path.exists("/usr/sbin/rcctl"):
        return "clamd", True, False, False, False
    if os.path.exists(_PATH_PKGIN):
        return "clamd", False, True, False, False
    if os.path.exists(_PATH_PKG) and not os.path.exists(_PATH_PKG_ADD):
        return "clamav_clamd", False, True, False, False
    if os.path.exists(_PATH_ZYPPER):
        return _SERVICE_CLAMD, False, False, False, False
    if os.path.exists(_PATH_DNF) or os.path.exists(_PATH_YUM):
        return _SERVICE_CLAMD_AT_SCAN, False, False, False, False
    # Debian/Ubuntu
    return "clamav_freshclam", False, False, False, False


class AntivirusOperationsBase:
    """Base class for antivirus software deployment, management, and removal operations."""

    def __init__(self, agent_instance):
        """
        Initialize the AntivirusOperationsBase instance.

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

    async def enable_antivirus(  # pylint: disable=too-many-branches,too-many-statements
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
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

            if software_name.lower() != "clamav":
                return {
                    "success": False,
                    "error": f"Unknown antivirus software: {software_name}",
                }

            (
                service_name,
                use_rcctl,
                use_bsd_service,
                use_brew_services,
                use_windows_service,
            ) = _detect_clamav_service_context()

            if not service_name:
                return {
                    "success": False,
                    "error": f"Unknown antivirus software: {software_name}",
                }

            # Start and enable the service
            process, stderr = await self._enable_service(
                service_name,
                use_rcctl,
                use_bsd_service,
                use_brew_services,
                use_windows_service,
            )

            if process is None:
                # _enable_service returned an early result (e.g. Windows service not found)
                return stderr  # type: ignore[return-value]  # stderr holds the error dict

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

    async def _enable_service(
        self,
        service_name: str,
        use_rcctl: bool,
        use_bsd_service: bool,
        use_brew_services: bool,
        use_windows_service: bool,
    ):
        """
        Enable and start an antivirus service using the appropriate system method.

        Returns:
            Tuple of (process, stderr) on success, or (None, error_dict) for early returns.
        """
        if use_bsd_service:
            return await self._enable_bsd_service(service_name)
        if use_rcctl:
            return await self._enable_rcctl_service(service_name)
        if use_brew_services:
            return await self._enable_brew_service(service_name)
        if use_windows_service:
            return await self._enable_windows_service(service_name)
        return await self._enable_systemctl_service(service_name, enable=True)

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
                return None, {
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
            return None, {
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

    async def _enable_systemctl_service(self, service_name: str, enable: bool = True):
        """Enable and start (or stop and disable) a service using systemctl."""
        if enable:
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "enable",
                "--now",
                service_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
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

    async def disable_antivirus(  # pylint: disable=too-many-branches,too-many-statements
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
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

            if software_name.lower() != "clamav":
                return {
                    "success": False,
                    "error": f"Unknown antivirus software: {software_name}",
                }

            (
                service_name,
                use_rcctl,
                use_bsd_service,
                use_brew_services,
                use_windows_service,
            ) = _detect_clamav_service_context()

            if not service_name:
                return {
                    "success": False,
                    "error": f"Unknown antivirus software: {software_name}",
                }

            # Stop and disable the service
            process, stderr = await self._disable_service(
                service_name,
                use_rcctl,
                use_bsd_service,
                use_brew_services,
                use_windows_service,
            )

            success = process.returncode == 0
            if success:
                self.logger.info(
                    "Antivirus service %s disabled successfully", service_name
                )
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

    async def _disable_service(
        self,
        service_name: str,
        use_rcctl: bool,
        use_bsd_service: bool,
        use_brew_services: bool,
        use_windows_service: bool,
    ):
        """
        Stop and disable an antivirus service using the appropriate system method.

        Returns:
            Tuple of (process, stderr).
        """
        if use_bsd_service:
            return await self._disable_bsd_service(service_name)
        if use_rcctl:
            return await self._disable_rcctl_service(service_name)
        if use_brew_services:
            return await self._disable_brew_service(service_name)
        if use_windows_service:
            return await self._disable_windows_service(service_name)
        return await self._enable_systemctl_service(service_name, enable=False)

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

    async def remove_antivirus(  # pylint: disable=too-many-branches,too-many-statements
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
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

            # Remove ClamAV - detect package manager and use appropriate commands
            import platform  # pylint: disable=import-outside-toplevel

            error = await self._remove_clamav(platform.system())

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

    async def _remove_clamav(self, platform_system: str) -> Optional[str]:
        """
        Remove ClamAV using the appropriate package manager for the current OS.

        Returns:
            None if successful, error message string if failed.
        """
        if os.path.exists(_PATH_BREW_LOCAL) or os.path.exists(_PATH_BREW_OPT):
            return await self._remove_clamav_macos()
        if os.path.exists(_PATH_PKGIN):
            return await self._remove_clamav_netbsd()
        if os.path.exists(_PATH_PKG) and not os.path.exists(_PATH_PKG_ADD):
            return await self._remove_clamav_freebsd()
        if os.path.exists("/usr/sbin/pkg_delete"):
            return await self._remove_clamav_openbsd()
        if os.path.exists(_PATH_ZYPPER):
            return await self._remove_clamav_opensuse()
        if os.path.exists("/usr/bin/apt"):
            return await self._remove_clamav_debian()
        if os.path.exists(_PATH_DNF) or os.path.exists(_PATH_YUM):
            return await self._remove_clamav_rhel()
        if platform_system == "Windows":
            return await self._remove_clamav_windows()
        return "Unsupported package manager"

    async def _remove_clamav_macos(self) -> Optional[str]:
        """Remove ClamAV on macOS via Homebrew."""
        brew_cmd = (
            _PATH_BREW_OPT if os.path.exists(_PATH_BREW_OPT) else _PATH_BREW_LOCAL
        )

        brew_user = _get_brew_user() if os.geteuid() == 0 else None

        # Stop service first
        if brew_user:
            self.logger.info("Running brew as user: %s", brew_user)
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-u",
                brew_user,
                brew_cmd,
                "services",
                "stop",
                "clamav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                brew_cmd,
                "services",
                "stop",
                "clamav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        await process.communicate()

        await asyncio.sleep(2)

        # Remove package with --force flag
        if brew_user:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-u",
                brew_user,
                brew_cmd,
                "uninstall",
                "--force",
                "clamav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                brew_cmd,
                "uninstall",
                "--force",
                "clamav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            error = stderr.decode()
            self.logger.warning(
                "brew uninstall failed: %s, attempting manual cleanup", error
            )
            cleanup_error = await self._cleanup_clamav_cellar_macos()
            if cleanup_error is None:
                return None
            return error

        return None

    async def _remove_clamav_netbsd(self) -> Optional[str]:
        """Remove ClamAV on NetBSD via pkgin."""
        for service in ["clamd", "freshclamd"]:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "service",
                service,
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "sh",
            "-c",
            "sudo sed -i '' '/^freshclamd=/d; /^clamd=/d' /etc/rc.conf",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        cmd = (
            ["pkgin", "-y", "remove", "clamav"]
            if os.geteuid() == 0
            else ["sudo", "pkgin", "-y", "remove", "clamav"]
        )
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return stderr.decode() if process.returncode != 0 else None

    async def _remove_clamav_freebsd(self) -> Optional[str]:
        """Remove ClamAV on FreeBSD via pkg."""
        for service in ["clamav_clamd", "clamav_freshclam"]:
            process = await asyncio.create_subprocess_exec(
                "service",
                service,
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        for sysrc_arg in ["clamav_clamd_enable=NO", "clamav_freshclam_enable=NO"]:
            process = await asyncio.create_subprocess_exec(
                "sysrc",
                sysrc_arg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        cmd = (
            ["pkg", "delete", "-y", "clamav"]
            if os.geteuid() == 0
            else ["sudo", "pkg", "delete", "-y", "clamav"]
        )
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return stderr.decode() if process.returncode != 0 else None

    async def _remove_clamav_openbsd(self) -> Optional[str]:
        """Remove ClamAV on OpenBSD via pkg_delete."""
        for service in ["clamd", "freshclam"]:
            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "stop",
                service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "disable",
                service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        cmd = (
            ["pkg_delete", "clamav"]
            if os.geteuid() == 0
            else ["doas", "pkg_delete", "clamav"]
        )
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return stderr.decode() if process.returncode != 0 else None

    async def _remove_clamav_opensuse(self) -> Optional[str]:
        """Remove ClamAV on openSUSE via zypper."""
        for service in [_SERVICE_CLAMD, "freshclam.service"]:
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "stop",
                service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "disable",
                service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "zypper",
            "remove",
            "-y",
            "clamav",
            "clamav_freshclam",
            "clamav-daemon",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        return stderr.decode() if process.returncode != 0 else None

    async def _remove_clamav_debian(self) -> Optional[str]:
        """Remove ClamAV on Debian/Ubuntu via apt."""
        process = await asyncio.create_subprocess_exec(
            "apt",
            "remove",
            "--purge",
            "-y",
            "clamav",
            "clamav-base",
            "clamav_freshclam",
            "libclamav12",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            return stderr.decode()

        # Run autoremove to clean up unused dependencies
        process = await asyncio.create_subprocess_exec(
            "apt",
            "autoremove",
            "-y",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        return None

    async def _remove_clamav_rhel(self) -> Optional[str]:
        """Remove ClamAV on RHEL/CentOS via dnf/yum."""
        pkg_manager = "dnf" if os.path.exists(_PATH_DNF) else "yum"

        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "stop",
            _SERVICE_CLAMD_AT_SCAN,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "disable",
            _SERVICE_CLAMD_AT_SCAN,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            pkg_manager,
            "remove",
            "-y",
            "clamav",
            "clamd",
            "clamav-update",
            "clamav-data",
            "clamav-lib",
            "clamav-filesystem",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            return stderr.decode()

        # Run autoremove
        process = await asyncio.create_subprocess_exec(
            pkg_manager,
            "autoremove",
            "-y",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        return None

    async def _remove_clamav_windows(self) -> Optional[str]:
        """Remove ClamAV on Windows via Chocolatey."""
        self.logger.info("Removing ClamAV from Windows using Chocolatey")

        # Try to stop the service if it exists
        process = await asyncio.create_subprocess_exec(
            "sc",
            "query",
            "ClamAV",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        if process.returncode == 0:
            process = await asyncio.create_subprocess_exec(
                "sc",
                "stop",
                "ClamAV",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            await asyncio.sleep(2)

        # Remove ClamAV/ClamWin via Chocolatey
        for package in ["clamwin", "clamav"]:
            process = await asyncio.create_subprocess_exec(
                "choco",
                "uninstall",
                package,
                "-y",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()

            if process.returncode == 0:
                self.logger.info("Successfully uninstalled %s", package)
                return None
            self.logger.debug(
                "Failed to uninstall %s: %s",
                package,
                stderr.decode() if stderr else "unknown",
            )

        return f"Failed to uninstall ClamAV/ClamWin: {stderr.decode() if stderr else 'unknown error'}"

    async def _cleanup_clamav_cellar_macos(self) -> Optional[str]:
        """
        Manually remove ClamAV from Homebrew Cellar directory.

        Returns:
            None if successful, error message string if failed
        """
        # Determine the Cellar directory based on architecture
        cellar_dir = (
            "/opt/homebrew/Cellar"
            if os.path.exists("/opt/homebrew")
            else "/usr/local/Cellar"
        )

        # Find all clamav version directories
        clamav_path = f"{cellar_dir}/clamav"
        if not os.path.exists(clamav_path):
            return None

        version_dirs = glob.glob(f"{clamav_path}/*")
        if not version_dirs:
            return None

        last_error = None
        for version_dir in version_dirs:
            self.logger.info("Removing clamav directory: %s", version_dir)
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "rm",
                "-rf",
                version_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode()
                self.logger.error(
                    "Manual cleanup of %s failed: %s", version_dir, error_msg
                )
                last_error = error_msg
            else:
                self.logger.info("Manual cleanup of %s successful", version_dir)

        # Remove the parent clamav directory if empty
        try:
            os.rmdir(clamav_path)
            self.logger.info("Removed empty clamav directory")
        except OSError:
            # Directory not empty or doesn't exist, that's fine
            pass

        return last_error
