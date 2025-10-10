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
from typing import Any, Dict, Optional

from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector


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
            # Import here to avoid circular dependencies
            # pylint: disable=import-outside-toplevel
            from websocket.messages import Message, MessageType

            message = Message(
                message_type=MessageType.ANTIVIRUS_STATUS_UPDATE,
                data={"antivirus_status": antivirus_status},
            )
            await self.agent_instance.websocket_client.send_message(message.to_dict())
            self.logger.info("Sent antivirus status update to server")
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to send antivirus status update: %s", error)

    async def enable_antivirus(  # pylint: disable=unused-argument,too-many-branches,too-many-statements
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable antivirus service(s)."""
        self.logger.info("Enabling antivirus service")

        try:
            # Collect current antivirus status to determine what service to enable
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
                import platform  # pylint: disable=import-outside-toplevel

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

            # Start and enable the service
            if use_bsd_service:
                # BSD uses service command
                # NetBSD has two services: freshclamd and clamd
                services_to_start = [service_name]
                if os.path.exists("/usr/pkg/bin/pkgin"):
                    # NetBSD - also start freshclamd
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

            elif use_rcctl:
                # OpenBSD uses rcctl
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
                    "start",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
            elif use_windows_service:
                # Windows uses sc command for service management
                # First check if service exists
                process = await asyncio.create_subprocess_exec(
                    "sc",
                    "query",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, _ = await process.communicate()

                if process.returncode != 0:
                    # Service doesn't exist yet - this is expected after fresh install
                    # Note: Manual service setup is required for ClamAV on Windows
                    return {
                        "success": False,
                        "error": "ClamAV service not configured. Windows ClamAV requires manual service setup.",
                    }

                # Service exists, try to start it
                process = await asyncio.create_subprocess_exec(
                    "sc",
                    "start",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
            else:
                # Linux uses systemctl
                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "enable",
                    "--now",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

            success = process.returncode == 0
            if success:
                self.logger.info(
                    "Antivirus service %s enabled successfully", service_name
                )
                # Collect and send updated status
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

    async def disable_antivirus(  # pylint: disable=unused-argument,too-many-branches,too-many-statements
        self, parameters: Dict[str, Any]
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
                import platform  # pylint: disable=import-outside-toplevel

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

    async def remove_antivirus(  # pylint: disable=unused-argument,too-many-branches,too-many-statements
        self, parameters: Dict[str, Any]
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
            import platform  # pylint: disable=import-outside-toplevel

            error = None
            if os.path.exists("/usr/local/bin/brew") or os.path.exists(
                "/opt/homebrew/bin/brew"
            ):
                # macOS - stop service and remove via brew
                brew_cmd = (
                    "/opt/homebrew/bin/brew"
                    if os.path.exists("/opt/homebrew/bin/brew")
                    else "/usr/local/bin/brew"
                )

                # If running as root, use sudo -u to run as the actual user
                # Homebrew doesn't allow running as root
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

                # Wait a moment for service to fully stop
                await asyncio.sleep(2)

                # Remove package with --force flag to handle any locked files
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
                    # If brew uninstall failed, try manual removal with sudo rm -rf
                    # This handles cases where files are locked or permissions prevent removal
                    self.logger.warning(
                        "brew uninstall failed: %s, attempting manual cleanup", error
                    )
                    cleanup_error = await self._cleanup_clamav_cellar_macos()
                    if cleanup_error is None:
                        error = None  # Manual cleanup succeeded

            elif os.path.exists("/usr/pkg/bin/pkgin"):
                # NetBSD - service name is freshclamd (with d)
                # Stop and disable services first
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

                # Disable services in rc.conf using sed
                process = await asyncio.create_subprocess_exec(
                    "sh",
                    "-c",
                    "sudo sed -i '' '/^freshclamd=/d; /^clamd=/d' /etc/rc.conf",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                # Remove ClamAV package
                if os.geteuid() == 0:
                    cmd = ["pkgin", "-y", "remove", "clamav"]
                else:
                    cmd = ["sudo", "pkgin", "-y", "remove", "clamav"]

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                if process.returncode != 0:
                    error = stderr.decode()

            elif os.path.exists("/usr/sbin/pkg") and not os.path.exists(
                "/usr/sbin/pkg_add"
            ):
                # FreeBSD
                # Stop and disable services first
                for service in ["clamav_clamd", "clamav_freshclam"]:
                    process = await asyncio.create_subprocess_exec(
                        "service",
                        service,
                        "stop",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                # Disable services in rc.conf
                process = await asyncio.create_subprocess_exec(
                    "sysrc",
                    "clamav_clamd_enable=NO",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                process = await asyncio.create_subprocess_exec(
                    "sysrc",
                    "clamav_freshclam_enable=NO",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                # Remove ClamAV package
                if os.geteuid() == 0:
                    cmd = ["pkg", "delete", "-y", "clamav"]
                else:
                    cmd = ["sudo", "pkg", "delete", "-y", "clamav"]

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                if process.returncode != 0:
                    error = stderr.decode()

            elif os.path.exists("/usr/sbin/pkg_delete"):
                # OpenBSD
                # Stop and disable services first
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

                # Remove ClamAV package (use doas only if not root)
                if os.geteuid() == 0:
                    cmd = ["pkg_delete", "clamav"]
                else:
                    cmd = ["doas", "pkg_delete", "clamav"]

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                if process.returncode != 0:
                    error = stderr.decode()

            elif os.path.exists("/usr/bin/zypper"):
                # openSUSE
                # Stop and disable services first
                for service in ["clamd.service", "freshclam.service"]:
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

                # Remove ClamAV packages
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

                if process.returncode != 0:
                    error = stderr.decode()

            elif os.path.exists("/usr/bin/apt"):
                # Debian/Ubuntu
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
                    error = stderr.decode()
                else:
                    # Run autoremove to clean up unused dependencies
                    process = await asyncio.create_subprocess_exec(
                        "apt",
                        "autoremove",
                        "-y",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

            elif os.path.exists("/usr/bin/dnf") or os.path.exists("/usr/bin/yum"):
                # RHEL/CentOS - determine which command to use
                pkg_manager = "dnf" if os.path.exists("/usr/bin/dnf") else "yum"

                # Stop and disable the service first
                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "stop",
                    "clamd@scan",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "disable",
                    "clamd@scan",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                # Remove ClamAV packages
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
                    error = stderr.decode()
                else:
                    # Run autoremove
                    process = await asyncio.create_subprocess_exec(
                        pkg_manager,
                        "autoremove",
                        "-y",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

            elif platform.system() == "Windows":
                # Windows - stop service (if running) and remove via chocolatey
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
                    # Service exists, stop it
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
                # Try clamwin first, then clamav as fallback
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
                        break
                    self.logger.debug(
                        "Failed to uninstall %s: %s",
                        package,
                        stderr.decode() if stderr else "unknown",
                    )

                if process.returncode != 0:
                    error = f"Failed to uninstall ClamAV/ClamWin: {stderr.decode() if stderr else 'unknown error'}"

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
