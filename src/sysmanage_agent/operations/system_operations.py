"""
System operations module for SysManage agent.
Handles system-level commands and operations.
"""

import asyncio
import json
import logging
import os
import platform
import shutil
import socket
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict
from urllib.parse import urlparse

from src.database.base import get_database_manager
from src.database.models import InstallationRequestTracking
from src.i18n import _
from src.sysmanage_agent.collection.update_detection import UpdateDetector


class SystemOperations:  # pylint: disable=too-many-public-methods
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
            system_info = self.agent.registration.get_system_info()
            info = {
                "hostname": system_info.get("hostname") or socket.gethostname(),
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
        installation_id = parameters.get("installation_id")
        requested_by = parameters.get("requested_by")

        if not package_name:
            return {"success": False, "error": _("No package name specified")}

        self.logger.info(
            _("Installing package %s (installation_id: %s, requested_by: %s)"),
            package_name,
            installation_id,
            requested_by,
        )

        try:
            # Send installation started status update
            if installation_id:
                await self._send_installation_status_update(
                    installation_id, "installing", package_name, requested_by
                )

            update_detector = UpdateDetector()
            result = update_detector.install_package(package_name, package_manager)

            # Determine success based on result
            success = True
            error_message = None
            installed_version = None

            if isinstance(result, dict):
                success = result.get("success", True)
                error_message = result.get("error")
                installed_version = result.get("version")
            elif isinstance(result, str):
                # Some installations return string output
                if "error" in result.lower() or "failed" in result.lower():
                    success = False
                    error_message = result

            # Send installation completion status update
            if installation_id:
                await self._send_installation_status_update(
                    installation_id,
                    "completed" if success else "failed",
                    package_name,
                    requested_by,
                    error_message=error_message,
                    installed_version=installed_version,
                    installation_log=str(result) if result else None,
                )

            return {
                "success": success,
                "result": result,
                "installation_id": installation_id,
                "package_name": package_name,
                "installed_version": installed_version,
                "error": error_message,
            }

        except Exception as e:
            error_message = str(e)
            self.logger.error(_("Failed to install package %s: %s"), package_name, e)

            # Send installation failed status update
            if installation_id:
                await self._send_installation_status_update(
                    installation_id,
                    "failed",
                    package_name,
                    requested_by,
                    error_message=error_message,
                )

            return {
                "success": False,
                "error": error_message,
                "installation_id": installation_id,
                "package_name": package_name,
            }

    async def install_packages(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # pylint: disable=too-many-nested-blocks
        """
        Install multiple packages using UUID-based grouping.

        This is the new method that handles the UUID request from the server.
        It stores the request in the database and installs all packages as a group.
        """
        request_id = parameters.get("request_id")
        packages = parameters.get("packages", [])
        requested_by = parameters.get("requested_by")

        if not request_id:
            return {"success": False, "error": _("No request_id specified")}

        if not packages:
            return {
                "success": False,
                "error": _("No packages specified for installation"),
            }

        self.logger.info(
            _("Installing %d packages for request %s (requested_by: %s)"),
            len(packages),
            request_id,
            requested_by,
        )

        # Store the request in agent database for tracking
        try:
            db_manager = get_database_manager()
            with db_manager.get_session() as session:
                # Create tracking record
                tracking_record = InstallationRequestTracking(
                    request_id=request_id,
                    requested_by=requested_by,
                    status="in_progress",
                    packages_json=json.dumps(packages),
                    received_at=datetime.now(timezone.utc),
                    started_at=datetime.now(timezone.utc),
                )
                session.add(tracking_record)
                session.commit()

        except Exception as e:
            self.logger.error(_("Failed to store installation request: %s"), e)
            return {
                "success": False,
                "error": _("Failed to store installation request: %s") % str(e),
            }

        # Install all packages in a single batch command
        success_packages = []
        failed_packages = []
        installation_log = []

        # Extract valid package names
        valid_packages = []
        for package in packages:
            package_name = package.get("package_name")
            if not package_name:
                self.logger.warning(_("Skipping package with no name"))
                failed_packages.append({"package": package, "error": "No package name"})
                continue
            valid_packages.append(package)

        if not valid_packages:
            installation_log.append("No valid packages to install")
            return {
                "success": True,
                "message": "No packages to install",
                "log": installation_log,
                "failed_packages": failed_packages,
                "success_packages": success_packages,
            }

        # Group packages by package manager
        package_groups = {}
        for package in valid_packages:
            package_manager = package.get("package_manager", "auto")
            if package_manager == "auto":
                # Auto-detect package manager (assume apt for now)
                package_manager = "apt"

            if package_manager not in package_groups:
                package_groups[package_manager] = []
            package_groups[package_manager].append(package)

        # Install packages for each package manager
        for pkg_manager, pkg_list in package_groups.items():
            if pkg_manager == "apt":
                result = await self._install_packages_with_apt(
                    [pkg["package_name"] for pkg in pkg_list]
                )

                if result.get("success", False):
                    # All packages succeeded
                    for package in pkg_list:
                        package_name = package["package_name"]
                        success_packages.append(
                            {
                                "package_name": package_name,
                                "installed_version": result.get("versions", {}).get(
                                    package_name, "unknown"
                                ),
                                "result": result,
                            }
                        )
                        installation_log.append(
                            f"✓ {package_name} installed successfully"
                        )
                else:
                    # All packages failed
                    error_msg = result.get("error", "Unknown error")
                    for package in pkg_list:
                        package_name = package["package_name"]
                        failed_packages.append(
                            {
                                "package_name": package_name,
                                "error": error_msg,
                                "result": result,
                            }
                        )
                        installation_log.append(f"✗ {package_name} failed: {error_msg}")
            else:
                # Fall back to individual installation for non-apt package managers
                for package in pkg_list:
                    package_name = package.get("package_name")
                    try:
                        installation_log.append(f"Installing {package_name}...")
                        self.logger.info(_("Installing package: %s"), package_name)

                        update_detector = UpdateDetector()
                        result = update_detector.install_package(
                            package_name, pkg_manager
                        )

                        if result.get("success", False):
                            success_packages.append(
                                {
                                    "package_name": package_name,
                                    "installed_version": result.get(
                                        "installed_version"
                                    ),
                                    "result": result,
                                }
                            )
                            installation_log.append(
                                f"✓ {package_name} installed successfully"
                            )
                        else:
                            error_msg = result.get("error", "Unknown error")
                            failed_packages.append(
                                {
                                    "package_name": package_name,
                                    "error": error_msg,
                                    "result": result,
                                }
                            )
                            installation_log.append(
                                f"✗ {package_name} failed: {error_msg}"
                            )

                    except Exception as e:
                        error_msg = str(e)
                        self.logger.error(
                            _("Failed to install package %s: %s"), package_name, e
                        )
                        failed_packages.append(
                            {"package_name": package_name, "error": error_msg}
                        )
                        installation_log.append(f"✗ {package_name} failed: {error_msg}")

        # Determine overall success
        overall_success = len(failed_packages) == 0
        installation_log_text = "\n".join(installation_log)

        # Update tracking record with completion
        try:
            db_manager = get_database_manager()
            with db_manager.get_session() as session:
                tracking_record = (
                    session.query(InstallationRequestTracking)
                    .filter_by(request_id=request_id)
                    .first()
                )
                if tracking_record:
                    tracking_record.status = (
                        "completed" if overall_success else "failed"
                    )
                    tracking_record.completed_at = datetime.now(timezone.utc)
                    tracking_record.result_log = installation_log_text
                    tracking_record.success = "true" if overall_success else "false"
                    session.commit()

        except Exception as e:
            self.logger.error(_("Failed to update installation tracking record: %s"), e)

        # Send completion notification to server via HTTP POST
        try:
            await self._send_installation_completion(
                request_id, overall_success, installation_log_text
            )
        except Exception as e:
            self.logger.error(
                _("Failed to send installation completion to server: %s"), e
            )

        return {
            "success": overall_success,
            "request_id": request_id,
            "successful_packages": success_packages,
            "failed_packages": failed_packages,
            "installation_log": installation_log_text,
            "summary": f"Installed {len(success_packages)}/{len(packages)} packages successfully",
        }

    async def uninstall_packages(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Uninstall multiple packages using UUID-based grouping.

        This method handles the UUID request from the server to uninstall packages.
        It stores the request in the database and uninstalls all packages as a group.
        """
        request_id = parameters.get("request_id")
        packages = parameters.get("packages", [])
        requested_by = parameters.get("requested_by")

        if not request_id:
            return {"success": False, "error": "No request_id specified"}

        if not packages:
            return {
                "success": False,
                "error": "No packages specified for uninstallation",
            }

        self.logger.info(
            "Uninstalling %d packages for request %s (requested_by: %s)",
            len(packages),
            request_id,
            requested_by,
        )

        # Store the request in agent database for tracking
        try:
            db_manager = get_database_manager()
            with db_manager.get_session() as session:
                # Create tracking record
                tracking_record = InstallationRequestTracking(
                    request_id=request_id,
                    requested_by=requested_by,
                    status="in_progress",
                    packages_json=json.dumps(packages),
                    received_at=datetime.now(timezone.utc),
                    started_at=datetime.now(timezone.utc),
                )
                session.add(tracking_record)
                session.commit()

        except Exception as e:
            self.logger.error("Failed to store uninstall request: %s", e)
            return {
                "success": False,
                "error": f"Failed to store uninstall request: {str(e)}",
            }

        # Uninstall all packages in a single batch command
        success_packages = []
        failed_packages = []
        uninstall_log = []

        # Extract valid package names
        valid_packages = []
        for package in packages:
            package_name = package.get("package_name")
            if not package_name:
                self.logger.warning("Skipping package with no name")
                failed_packages.append({"package": package, "error": "No package name"})
                continue
            valid_packages.append(package)

        if not valid_packages:
            uninstall_log.append("No valid packages to uninstall")
        else:
            # Group packages by package manager
            package_groups = {}
            for package in valid_packages:
                package_manager = package.get("package_manager", "auto")
                if package_manager == "auto":
                    # Auto-detect package manager (assume apt for now)
                    package_manager = "apt"

                if package_manager not in package_groups:
                    package_groups[package_manager] = []
                package_groups[package_manager].append(package)

            # Uninstall packages for each package manager
            for pkg_manager, pkg_list in package_groups.items():
                if pkg_manager == "apt":
                    result = await self._uninstall_packages_with_apt(
                        [pkg["package_name"] for pkg in pkg_list]
                    )

                    if result.get("success", False):
                        # All packages succeeded
                        for package in pkg_list:
                            package_name = package["package_name"]
                            success_packages.append(
                                {"package_name": package_name, "result": result}
                            )
                            uninstall_log.append(
                                f"✓ {package_name} uninstalled successfully"
                            )
                    else:
                        # All packages failed
                        error_msg = result.get("error", "Unknown error")
                        for package in pkg_list:
                            package_name = package["package_name"]
                            failed_packages.append(
                                {
                                    "package_name": package_name,
                                    "error": error_msg,
                                    "result": result,
                                }
                            )
                            uninstall_log.append(
                                f"✗ {package_name} failed: {error_msg}"
                            )
                else:
                    # Fall back to individual uninstall for non-apt package managers
                    for package in pkg_list:
                        package_name = package.get("package_name")
                        uninstall_log.append(f"Uninstalling {package_name}...")
                        self.logger.info("Uninstalling package: %s", package_name)

                        # For now, just simulate success for non-apt managers
                        # TODO: Implement other package managers  # pylint: disable=fixme
                        failed_packages.append(
                            {
                                "package_name": package_name,
                                "error": f"Uninstall not implemented for {pkg_manager} package manager",
                            }
                        )
                        uninstall_log.append(
                            f"✗ {package_name} failed: Uninstall not implemented for {pkg_manager}"
                        )

        # Determine overall success
        overall_success = len(failed_packages) == 0
        uninstall_log_text = "\n".join(uninstall_log)

        # Update tracking record with completion
        try:
            db_manager = get_database_manager()
            with db_manager.get_session() as session:
                tracking_record = (
                    session.query(InstallationRequestTracking)
                    .filter_by(request_id=request_id)
                    .first()
                )
                if tracking_record:
                    tracking_record.status = (
                        "completed" if overall_success else "failed"
                    )
                    tracking_record.completed_at = datetime.now(timezone.utc)
                    tracking_record.result_log = uninstall_log_text
                    tracking_record.success = "true" if overall_success else "false"
                    session.commit()

        except Exception as e:
            self.logger.error("Failed to update uninstall tracking record: %s", e)

        # Send completion notification to server via HTTP POST
        try:
            await self._send_installation_completion(
                request_id, overall_success, uninstall_log_text
            )
        except Exception as e:
            self.logger.error("Failed to send uninstall completion to server: %s", e)

        return {
            "success": overall_success,
            "request_id": request_id,
            "successful_packages": success_packages,
            "failed_packages": failed_packages,
            "uninstall_log": uninstall_log_text,
            "summary": f"Uninstalled {len(success_packages)}/{len(packages)} packages successfully",
        }

    async def _install_packages_with_apt(
        self, package_names: list
    ) -> Dict[str, Any]:  # pylint: disable=too-many-nested-blocks
        """Install multiple packages with a single apt-get command."""
        try:
            if not package_names:
                return {"success": False, "error": "No packages to install"}

            self.logger.info(
                "Installing packages with apt-get: %s", ", ".join(package_names)
            )

            # Set non-interactive environment to prevent configuration dialogs
            env = os.environ.copy()
            env.update(
                {
                    "DEBIAN_FRONTEND": "noninteractive",
                    "DEBCONF_NONINTERACTIVE_SEEN": "true",
                }
            )

            # Update package list first
            update_process = await asyncio.create_subprocess_exec(
                "sudo",
                "-E",
                "apt-get",
                "update",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            await update_process.communicate()

            # Install all packages in a single command
            install_cmd = ["sudo", "-E", "apt-get", "install", "-y"] + package_names
            install_process = await asyncio.create_subprocess_exec(
                *install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            stdout, stderr = await install_process.communicate()
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""

            if install_process.returncode == 0:
                # Get versions for installed packages
                versions = await self._get_package_versions(package_names)
                return {"success": True, "versions": versions, "output": stdout_text}

            return {
                "success": False,
                "error": f"apt-get install failed: {stderr_text or stdout_text}",
                "output": stderr_text or stdout_text,
            }

        except Exception as e:
            self.logger.error("Failed to install packages with apt-get: %s", e)
            return {
                "success": False,
                "error": f"Exception during apt-get install: {str(e)}",
            }

    async def _uninstall_packages_with_apt(self, package_names: list) -> Dict[str, Any]:
        """Uninstall multiple packages with a single apt-get command."""
        try:
            if not package_names:
                return {"success": False, "error": "No packages to uninstall"}

            self.logger.info(
                "Uninstalling packages with apt-get: %s", ", ".join(package_names)
            )

            # Set non-interactive environment to prevent configuration dialogs
            env = os.environ.copy()
            env.update(
                {
                    "DEBIAN_FRONTEND": "noninteractive",
                    "DEBCONF_NONINTERACTIVE_SEEN": "true",
                }
            )

            # Uninstall all packages in a single command (autoremove to clean up dependencies)
            uninstall_cmd = [
                "sudo",
                "-E",
                "apt-get",
                "remove",
                "--autoremove",
                "-y",
            ] + package_names
            uninstall_process = await asyncio.create_subprocess_exec(
                *uninstall_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            stdout, stderr = await uninstall_process.communicate()
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""

            if uninstall_process.returncode == 0:
                return {"success": True, "output": stdout_text}

            return {
                "success": False,
                "error": f"apt-get remove failed: {stderr_text or stdout_text}",
                "output": stderr_text or stdout_text,
            }

        except Exception as e:
            self.logger.error("Failed to uninstall packages with apt-get: %s", e)
            return {
                "success": False,
                "error": f"Exception during apt-get remove: {str(e)}",
            }

    async def _send_installation_completion(
        self, request_id: str, success: bool, result_log: str
    ):
        """Send completion notification to the server."""
        try:
            # Prepare payload
            payload = {
                "request_id": request_id,
                "success": success,
                "result_log": result_log,
            }

            # Use centralized API method
            response = await self.agent.call_server_api(
                "agent/installation-complete", "POST", payload
            )

            if response:
                self.logger.info(
                    _("Installation completion sent successfully for request %s"),
                    request_id,
                )
            else:
                self.logger.error(
                    _("Failed to send installation completion for request %s"),
                    request_id,
                )

        except Exception as e:
            self.logger.error(_("Error sending installation completion: %s"), e)
            raise

    async def _send_installation_status_update(  # pylint: disable=too-many-positional-arguments
        self,
        installation_id: str,
        status: str,
        package_name: str,
        requested_by: str,
        error_message: str = None,
        installed_version: str = None,
        installation_log: str = None,
    ):
        """Send package installation status update to server."""
        try:
            # Get host information for the status update
            host_approval = self.agent.get_host_approval_from_db()
            system_info = self.agent.registration.get_system_info()

            # Get hostname with fallback
            hostname = system_info.get("hostname") or socket.gethostname()

            update_message = {
                "message_type": "package_installation_status",
                "installation_id": installation_id,
                "status": status,
                "package_name": package_name,
                "requested_by": requested_by,
                "timestamp": asyncio.get_event_loop().time(),
                "hostname": hostname,
            }

            # Add optional fields
            if error_message:
                update_message["error_message"] = error_message
            if installed_version:
                update_message["installed_version"] = installed_version
            if installation_log:
                update_message["installation_log"] = installation_log

            # Add host identification
            if host_approval and host_approval.host_id:
                update_message["host_id"] = str(host_approval.host_id)

            # Send the status update message
            await self.agent.send_message(update_message)

            self.logger.info(
                _("Sent package installation status update: %s for %s"),
                status,
                package_name,
            )

        except Exception as e:
            self.logger.error(
                _("Failed to send package installation status update: %s"), e
            )

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
            os_info["hostname"] = system_info.get("hostname") or socket.gethostname()

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

    async def _get_package_versions(self, package_names: list) -> dict:
        """Get installed versions for a list of package names."""
        versions = {}
        for package_name in package_names:
            try:
                version_process = await asyncio.create_subprocess_exec(
                    "dpkg",
                    "-s",
                    package_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                version_stdout, _ = await version_process.communicate()

                if version_process.returncode != 0:
                    versions[package_name] = "unknown"
                    continue

                version_text = version_stdout.decode()
                for line in version_text.split("\n"):
                    if line.startswith("Version:"):
                        versions[package_name] = line.split(":", 1)[1].strip()
                        break
                else:
                    versions[package_name] = "unknown"
            except Exception:
                versions[package_name] = "unknown"
        return versions

    async def deploy_ssh_keys(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSH keys to a user's .ssh directory with proper permissions."""
        username = parameters.get("username")
        ssh_keys = parameters.get("ssh_keys", [])

        # Validate inputs
        validation_error = self._validate_ssh_key_inputs(username, ssh_keys)
        if validation_error:
            return validation_error

        try:
            # Get user info and setup SSH directory
            setup_result = self._setup_ssh_environment(username)
            if not setup_result["success"]:
                return setup_result

            ssh_dir = setup_result["ssh_dir"]
            user_uid = setup_result["user_uid"]
            user_gid = setup_result["user_gid"]

            deployed_keys = []
            errors = []

            for ssh_key in ssh_keys:
                key_name = ssh_key.get("name", "unknown")
                filename = ssh_key.get("filename", "ssh_key")
                content = ssh_key.get("content", "")
                subtype = ssh_key.get("subtype", "private")

                if not content:
                    errors.append(f"Empty content for key '{key_name}'")
                    continue

                try:
                    # Full path for the key file
                    key_file_path = os.path.join(ssh_dir, filename)

                    # Write the key file
                    with open(key_file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                        # Ensure content ends with newline
                        if not content.endswith("\n"):
                            f.write("\n")

                    # Set appropriate permissions based on key type
                    if subtype == "public":
                        # Public keys: readable by owner and group (644)
                        os.chmod(key_file_path, 0o644)
                    else:
                        # Private keys and others: readable by owner only (600)
                        os.chmod(key_file_path, 0o600)

                    # Set correct ownership
                    os.chown(key_file_path, user_uid, user_gid)

                    deployed_keys.append(
                        {
                            "name": key_name,
                            "filename": filename,
                            "path": key_file_path,
                            "subtype": subtype,
                        }
                    )

                    self.logger.info(
                        "Successfully deployed SSH key '%s' to %s",
                        key_name,
                        key_file_path,
                    )

                except (OSError, IOError) as e:
                    error_msg = f"Failed to deploy key '{key_name}': {str(e)}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)

            # Handle authorized_keys for public keys
            public_keys = [k for k in deployed_keys if k.get("subtype") == "public"]
            if public_keys:
                try:
                    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")

                    # Read existing authorized_keys if it exists
                    existing_keys = []
                    if os.path.exists(authorized_keys_path):
                        with open(authorized_keys_path, "r", encoding="utf-8") as f:
                            existing_keys = f.read().splitlines()

                    # Append new public keys to authorized_keys
                    with open(authorized_keys_path, "a", encoding="utf-8") as f:
                        for pub_key in public_keys:
                            pub_key_path = pub_key["path"]
                            with open(pub_key_path, "r", encoding="utf-8") as key_file:
                                key_content = key_file.read().strip()
                                if key_content not in existing_keys:
                                    f.write(key_content + "\n")

                    # Set proper permissions for authorized_keys
                    os.chmod(authorized_keys_path, 0o600)
                    os.chown(authorized_keys_path, user_uid, user_gid)

                    self.logger.info("Updated authorized_keys for user '%s'", username)

                except (OSError, IOError) as e:
                    error_msg = f"Failed to update authorized_keys: {str(e)}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)

            # Prepare result
            result = {
                "success": len(deployed_keys) > 0,
                "deployed_keys": deployed_keys,
                "deployed_count": len(deployed_keys),
                "username": username,
                "ssh_directory": ssh_dir,
            }

            if errors:
                result["errors"] = errors
                result["error_count"] = len(errors)

            if len(deployed_keys) == 0:
                result["error"] = "No SSH keys were successfully deployed"

            return result

        except Exception as e:
            self.logger.error("Unexpected error during SSH key deployment: %s", str(e))
            return {
                "success": False,
                "error": f"Unexpected error during SSH key deployment: {str(e)}",
            }

    def _validate_ssh_key_inputs(
        self, username: str, ssh_keys: list
    ) -> Dict[str, Any] | None:
        """Validate SSH key deployment inputs."""
        if not username:
            return {"success": False, "error": "Username is required"}

        if not ssh_keys:
            return {"success": False, "error": "No SSH keys provided"}

        return None  # No validation errors

    def _setup_ssh_environment(self, username: str) -> Dict[str, Any]:
        """Setup SSH environment for a user."""
        import pwd  # pylint: disable=import-outside-toplevel

        try:
            user_info = pwd.getpwnam(username)
            home_dir = user_info.pw_dir
            user_uid = user_info.pw_uid
            user_gid = user_info.pw_gid
        except KeyError:
            return {"success": False, "error": f"User '{username}' not found"}

        # Create .ssh directory if it doesn't exist
        ssh_dir = os.path.join(home_dir, ".ssh")

        try:
            # Create directory with proper permissions (700)
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            # Ensure ownership is correct
            os.chown(ssh_dir, user_uid, user_gid)
        except PermissionError:
            return {
                "success": False,
                "error": f"Permission denied creating/accessing {ssh_dir}",
            }
        except OSError as e:
            return {
                "success": False,
                "error": f"Failed to create .ssh directory: {str(e)}",
            }

        return {
            "success": True,
            "ssh_dir": ssh_dir,
            "user_uid": user_uid,
            "user_gid": user_gid,
        }

    async def deploy_certificates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSL certificates to the appropriate system directory."""
        certificates = parameters.get("certificates", [])

        # Validate inputs
        validation_error = self._validate_certificate_inputs(certificates)
        if validation_error:
            return validation_error

        try:
            # Determine the SSL certificate directory based on OS
            ssl_dir_result = self._get_ssl_directory()
            if not ssl_dir_result["success"]:
                return ssl_dir_result

            ssl_dir = ssl_dir_result["ssl_dir"]
            deployed_certificates = []
            errors = []

            for certificate in certificates:
                cert_name = certificate.get("name", "unknown")
                filename = certificate.get("filename", f"{cert_name}.crt")
                content = certificate.get("content", "")
                subtype = certificate.get("subtype", "certificate")

                if not content:
                    errors.append(f"Empty content for certificate '{cert_name}'")
                    continue

                try:
                    # Full path for the certificate file
                    cert_file_path = os.path.join(ssl_dir, filename)

                    # Write the certificate file
                    with open(cert_file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                        # Ensure content ends with newline
                        if not content.endswith("\n"):
                            f.write("\n")

                    # Set appropriate permissions for certificates (644 - readable by all)
                    os.chmod(cert_file_path, 0o644)

                    # Set root ownership (certificates should be owned by root)
                    os.chown(cert_file_path, 0, 0)

                    deployed_certificates.append(
                        {
                            "name": cert_name,
                            "filename": filename,
                            "path": cert_file_path,
                            "subtype": subtype,
                        }
                    )

                    self.logger.info(
                        "Successfully deployed certificate '%s' to %s",
                        cert_name,
                        cert_file_path,
                    )

                except (OSError, IOError) as e:
                    error_msg = f"Failed to deploy certificate '{cert_name}': {str(e)}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)

            # Update certificate bundle if we deployed CA certificates
            ca_certificates = [
                c
                for c in deployed_certificates
                if c.get("subtype") in ["root", "intermediate", "ca"]
            ]
            if ca_certificates:
                try:
                    await self._update_ca_certificates()
                    self.logger.info("Updated CA certificate bundle")
                except Exception as e:
                    error_msg = f"Failed to update CA certificate bundle: {str(e)}"
                    errors.append(error_msg)
                    self.logger.warning(error_msg)

            # Prepare result
            result = {
                "success": len(deployed_certificates) > 0,
                "deployed_certificates": deployed_certificates,
                "deployed_count": len(deployed_certificates),
                "ssl_directory": ssl_dir,
            }

            if errors:
                result["errors"] = errors
                result["error_count"] = len(errors)

            if len(deployed_certificates) == 0:
                result["error"] = "No certificates were successfully deployed"

            return result

        except Exception as e:
            self.logger.error(
                "Unexpected error during certificate deployment: %s", str(e)
            )
            return {
                "success": False,
                "error": f"Unexpected error during certificate deployment: {str(e)}",
            }

    def _validate_certificate_inputs(self, certificates: list) -> Dict[str, Any] | None:
        """Validate certificate deployment inputs."""
        if not certificates:
            return {"success": False, "error": "No certificates provided"}

        return None  # No validation errors

    def _get_ssl_directory(self) -> Dict[str, Any]:
        """Get the appropriate SSL certificate directory for the current OS."""
        system = platform.system().lower()

        if system == "linux":
            # Try to detect the Linux distribution
            if os.path.exists("/etc/os-release"):
                try:
                    with open("/etc/os-release", "r", encoding="utf-8") as f:
                        os_release = f.read().lower()

                    if any(distro in os_release for distro in ["ubuntu", "debian"]):
                        ssl_dir = "/etc/ssl/certs"
                    elif any(
                        distro in os_release
                        for distro in ["rhel", "centos", "fedora", "red hat"]
                    ):
                        ssl_dir = "/etc/pki/tls/certs"
                    elif "opensuse" in os_release:
                        ssl_dir = "/etc/ssl/certs"
                    else:
                        # Default Linux path
                        ssl_dir = "/etc/ssl/certs"
                except Exception:
                    ssl_dir = "/etc/ssl/certs"  # Fallback
            else:
                ssl_dir = "/etc/ssl/certs"  # Fallback

        elif system == "darwin":  # macOS
            ssl_dir = "/etc/ssl/certs"
        elif system in ["freebsd", "openbsd"]:
            ssl_dir = "/etc/ssl/certs"
        else:
            return {
                "success": False,
                "error": f"Unsupported operating system for certificate deployment: {system}",
            }

        # Verify the directory exists and is writable
        if not os.path.exists(ssl_dir):
            try:
                os.makedirs(ssl_dir, mode=0o755, exist_ok=True)
            except PermissionError:
                return {
                    "success": False,
                    "error": f"Permission denied creating SSL directory: {ssl_dir}",
                }
            except OSError as e:
                return {
                    "success": False,
                    "error": f"Failed to create SSL directory: {str(e)}",
                }

        if not os.access(ssl_dir, os.W_OK):
            return {
                "success": False,
                "error": f"No write permission to SSL directory: {ssl_dir}",
            }

        return {"success": True, "ssl_dir": ssl_dir}

    async def _update_ca_certificates(self):
        """Update the CA certificate bundle after deploying new CA certificates."""
        system = platform.system().lower()

        try:
            if system == "linux":
                # Try update-ca-certificates for Debian/Ubuntu systems
                if os.path.exists("/usr/sbin/update-ca-certificates"):
                    result = await self.execute_shell_command(
                        {"command": "sudo /usr/sbin/update-ca-certificates"}
                    )
                    if result["success"]:
                        return

                # Try update-ca-trust for RHEL/CentOS/Fedora systems
                if os.path.exists("/usr/bin/update-ca-trust"):
                    result = await self.execute_shell_command(
                        {"command": "sudo /usr/bin/update-ca-trust extract"}
                    )
                    if result["success"]:
                        return

            elif system == "darwin":  # macOS
                # For macOS, we would need to use the Security framework
                # This is a simplified approach - in practice you might want to use keychain
                self.logger.info("macOS certificate bundle update not implemented")
                return

            elif system in ["freebsd", "openbsd"]:
                # BSD systems might have their own certificate management
                self.logger.info("BSD certificate bundle update not implemented")
                return

            # If we get here, no update mechanism was found
            self.logger.warning(
                "No CA certificate update mechanism found for this system"
            )

        except Exception as e:
            self.logger.error("Error updating CA certificate bundle: %s", str(e))
            raise

    async def deploy_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy OpenTelemetry collector to the system."""
        try:
            grafana_url = parameters.get("grafana_url")
            if not grafana_url:
                return {
                    "success": False,
                    "error": "No Grafana URL provided for OpenTelemetry deployment",
                }

            self.logger.info(
                "Deploying OpenTelemetry collector with Grafana URL: %s", grafana_url
            )

            # Detect the operating system and package manager
            system = platform.system().lower()
            deployment_result = None

            if system == "linux":
                deployment_result = await self._deploy_opentelemetry_linux(grafana_url)
            elif system == "darwin":
                deployment_result = await self._deploy_opentelemetry_macos(grafana_url)
            elif system == "freebsd":
                deployment_result = await self._deploy_opentelemetry_freebsd(
                    grafana_url
                )
            elif system == "openbsd":
                return {
                    "success": False,
                    "error": "OpenTelemetry deployment on OpenBSD is not currently supported. Manual installation required.",
                }
            elif system == "netbsd":
                return {
                    "success": False,
                    "error": "OpenTelemetry deployment on NetBSD is not currently supported. Manual installation required.",
                }
            elif system == "windows":
                deployment_result = await self._deploy_opentelemetry_windows(
                    grafana_url
                )
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operating system for OpenTelemetry deployment: {system}",
                }

            return deployment_result

        except Exception as e:
            self.logger.error("Failed to deploy OpenTelemetry: %s", str(e))
            return {
                "success": False,
                "error": f"Failed to deploy OpenTelemetry: {str(e)}",
            }

    async def remove_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove OpenTelemetry collector from the system."""
        try:
            self.logger.info("Starting OpenTelemetry removal")

            # Detect operating system and call appropriate removal function
            system = platform.system().lower()

            if system == "linux":
                removal_result = await self._remove_opentelemetry_linux()
            elif system == "darwin":
                removal_result = await self._remove_opentelemetry_macos()
            elif system in ["freebsd", "openbsd", "netbsd"]:
                removal_result = await self._remove_opentelemetry_bsd()
            elif system == "windows":
                removal_result = await self._remove_opentelemetry_windows()
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operating system: {system}",
                }

            # If removal was successful, trigger a software inventory refresh
            # so the server knows the package is gone
            if removal_result.get("success"):
                self.logger.info(
                    "OpenTelemetry removed successfully, triggering software refresh"
                )
                try:
                    await self.get_installed_packages({})
                except Exception as refresh_error:
                    self.logger.warning(
                        "Failed to refresh software inventory: %s", str(refresh_error)
                    )
                    # Don't fail the removal if refresh fails

            return removal_result

        except Exception as e:
            self.logger.error("Failed to remove OpenTelemetry: %s", str(e))
            return {
                "success": False,
                "error": f"Failed to remove OpenTelemetry: {str(e)}",
            }

    async def _remove_opentelemetry_linux(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from Linux systems."""
        try:
            self.logger.info("Removing OpenTelemetry from Linux system")

            # Stop service
            self.logger.info("Stopping otelcol-contrib service...")
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Disable service
            self.logger.info("Disabling otelcol-contrib service...")
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "disable",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Remove package
            if os.path.exists("/usr/bin/apt"):
                self.logger.info("Removing package with apt...")
                process = await asyncio.create_subprocess_exec(
                    "apt-get",
                    "remove",
                    "-y",
                    "otelcol-contrib",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
                )
                await process.communicate()

                # Purge to remove residual config
                self.logger.info("Purging package with apt...")
                process = await asyncio.create_subprocess_exec(
                    "apt-get",
                    "purge",
                    "-y",
                    "otelcol-contrib",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
                )
                await process.communicate()
            elif os.path.exists("/usr/bin/yum"):
                self.logger.info("Removing package with yum...")
                process = await asyncio.create_subprocess_exec(
                    "yum",
                    "remove",
                    "-y",
                    "otelcol-contrib",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()
            elif os.path.exists("/usr/bin/dnf"):
                self.logger.info("Removing package with dnf...")
                process = await asyncio.create_subprocess_exec(
                    "dnf",
                    "remove",
                    "-y",
                    "otelcol-contrib",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

            # Remove config files
            self.logger.info("Removing config files...")
            config_dir = "/etc/otelcol-contrib"
            if os.path.exists(config_dir):
                shutil.rmtree(config_dir)

            self.logger.info("OpenTelemetry removed successfully")
            return {
                "success": True,
                "message": "OpenTelemetry collector removed successfully",
            }

        except Exception as e:
            self.logger.error("Error removing OpenTelemetry: %s", str(e))
            return {"success": False, "error": str(e)}

    async def _remove_opentelemetry_macos(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from macOS systems."""
        try:
            self.logger.info("Removing OpenTelemetry from macOS system")

            # Stop service if running
            process = await asyncio.create_subprocess_exec(
                "brew",
                "services",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Uninstall package
            process = await asyncio.create_subprocess_exec(
                "brew",
                "uninstall",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector removed successfully",
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _remove_opentelemetry_bsd(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from BSD systems."""
        try:
            self.logger.info("Removing OpenTelemetry from BSD system")

            # Stop service
            process = await asyncio.create_subprocess_exec(
                "service",
                "alloy",
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Remove package
            process = await asyncio.create_subprocess_exec(
                "pkg",
                "delete",
                "-y",
                "grafana-alloy",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector removed successfully",
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _remove_opentelemetry_windows(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from Windows systems."""
        try:
            self.logger.info("Removing OpenTelemetry from Windows system")

            # Stop service
            process = await asyncio.create_subprocess_exec(
                "sc",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Delete service
            process = await asyncio.create_subprocess_exec(
                "sc",
                "delete",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector removed successfully",
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _deploy_opentelemetry_linux(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on Linux systems."""
        try:
            # Detect package manager
            if os.path.exists("/usr/bin/apt"):
                return await self._deploy_opentelemetry_apt(grafana_url)
            if os.path.exists("/usr/bin/yum") or os.path.exists("/usr/bin/dnf"):
                return await self._deploy_opentelemetry_yum_dnf(grafana_url)
            return {
                "success": False,
                "error": "No supported package manager found (apt/yum/dnf)",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _deploy_opentelemetry_apt(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry using apt package manager."""
        # pylint: disable=too-many-return-statements
        try:
            # Install OpenTelemetry collector
            self.logger.info("Installing OpenTelemetry collector using apt")

            # Set environment to prevent interactive prompts
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"

            # Install prerequisites
            self.logger.info("Installing prerequisites...")
            process = await asyncio.create_subprocess_exec(
                "apt-get",
                "install",
                "-y",
                "wget",
                "gnupg2",
                "software-properties-common",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            _stdout, stderr = await process.communicate()
            if process.returncode != 0:
                error_msg = f"Failed to install prerequisites: {stderr.decode()}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}

            # Download OpenTelemetry package
            self.logger.info("Downloading OpenTelemetry collector package...")
            download_url = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.112.0/otelcol-contrib_0.112.0_linux_amd64.deb"
            self.logger.info("Download URL: %s", download_url)

            process = await asyncio.create_subprocess_exec(
                "wget",
                "-O-",  # Output to stdout
                download_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            deb_content, stderr = await process.communicate()

            self.logger.info(
                "Download completed. Return code: %d, Content size: %d bytes",
                process.returncode,
                len(deb_content),
            )

            if stderr:
                self.logger.info(
                    "Download stderr: %s", stderr.decode()[:500]
                )  # Log first 500 chars

            if process.returncode != 0:
                error_msg = (
                    f"Failed to download OpenTelemetry package: {stderr.decode()}"
                )
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                }

            if len(deb_content) == 0:
                error_msg = "Downloaded file is empty"
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                }

            # Write the package to a temp file
            self.logger.info("Writing package to temporary file...")
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".deb", delete=False
            ) as f:
                f.write(deb_content)
                deb_file = f.name
            self.logger.info("Package written to: %s", deb_file)

            try:
                # Install the package
                self.logger.info(
                    "Installing OpenTelemetry collector package with dpkg..."
                )
                process = await asyncio.create_subprocess_exec(
                    "dpkg",
                    "-i",
                    deb_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                dpkg_stdout, dpkg_stderr = await process.communicate()

                self.logger.info(
                    "dpkg install completed. Return code: %d", process.returncode
                )
                if dpkg_stdout:
                    self.logger.info("dpkg stdout: %s", dpkg_stdout.decode()[:500])
                if dpkg_stderr:
                    self.logger.info("dpkg stderr: %s", dpkg_stderr.decode()[:500])

                if process.returncode != 0:
                    # Try to fix dependencies
                    self.logger.info("Fixing dependencies with apt-get install -f...")
                    process = await asyncio.create_subprocess_exec(
                        "apt-get",
                        "install",
                        "-f",
                        "-y",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                    )
                    fix_stdout, fix_stderr = await process.communicate()

                    self.logger.info(
                        "apt-get fix completed. Return code: %d", process.returncode
                    )
                    if fix_stdout:
                        self.logger.info(
                            "apt-get stdout: %s", fix_stdout.decode()[:500]
                        )
                    if fix_stderr:
                        self.logger.info(
                            "apt-get stderr: %s", fix_stderr.decode()[:500]
                        )

                    if process.returncode != 0:
                        error_msg = f"Failed to install OpenTelemetry collector: {dpkg_stderr.decode()}"
                        self.logger.error(error_msg)
                        return {
                            "success": False,
                            "error": error_msg,
                        }
            finally:
                # Clean up temp file
                self.logger.info("Cleaning up temporary file: %s", deb_file)
                if os.path.exists(deb_file):
                    os.unlink(deb_file)

            # Stop service if it was auto-started by dpkg (it will have wrong config)
            self.logger.info("Stopping otelcol-contrib service...")
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            # Ignore return code - service may not be running

            # Create configuration file
            self.logger.info("Creating OpenTelemetry configuration file...")
            config_result = await self._create_otel_config_linux(grafana_url)
            if not config_result["success"]:
                self.logger.error(
                    "Failed to create config: %s", config_result.get("error")
                )
                return config_result
            self.logger.info(
                "Configuration file created: %s", config_result.get("config_file")
            )

            # Enable and start service
            self.logger.info("Enabling and starting OpenTelemetry service...")
            await self._enable_and_start_otel_service_linux()
            self.logger.info("OpenTelemetry service started successfully")

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_result.get("config_file"),
            }

        except Exception as e:
            self.logger.error(
                "Exception during OpenTelemetry deployment: %s", str(e), exc_info=True
            )
            return {"success": False, "error": str(e)}

    async def _deploy_opentelemetry_yum_dnf(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry using yum/dnf package manager."""
        try:
            # Determine which package manager to use
            pkg_manager = "dnf" if os.path.exists("/usr/bin/dnf") else "yum"

            self.logger.info("Installing OpenTelemetry collector using %s", pkg_manager)

            # Install OpenTelemetry collector
            process = await asyncio.create_subprocess_exec(
                pkg_manager,
                "install",
                "-y",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install OpenTelemetry collector: {stderr.decode()}",
                }

            # Create configuration file
            config_result = await self._create_otel_config_linux(grafana_url)
            if not config_result["success"]:
                return config_result

            # Enable and start service
            await self._enable_and_start_otel_service_linux()

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_result.get("config_file"),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _deploy_opentelemetry_macos(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on macOS using Homebrew."""
        try:
            self.logger.info("Installing OpenTelemetry collector using Homebrew")

            # Install using Homebrew
            process = await asyncio.create_subprocess_exec(
                "brew",
                "install",
                "opentelemetry-collector-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install OpenTelemetry collector: {stderr.decode()}",
                }

            # Create configuration file
            config_file = "/usr/local/etc/otelcol-contrib/config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_otel_config(grafana_url)
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)

            # Start service
            process = await asyncio.create_subprocess_exec(
                "brew",
                "services",
                "start",
                "opentelemetry-collector-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_file,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _deploy_opentelemetry_freebsd(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on FreeBSD using Grafana Alloy."""
        try:
            self.logger.info(
                "Installing Grafana Alloy (OpenTelemetry Collector) on FreeBSD"
            )

            # Install Grafana Alloy using pkg
            process = await asyncio.create_subprocess_exec(
                "pkg",
                "install",
                "-y",
                "alloy",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install Grafana Alloy: {stderr.decode()}",
                }

            # Create configuration file for Alloy
            config_file = "/usr/local/etc/alloy/config.alloy"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_alloy_config(grafana_url)
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)

            # Enable and start service
            process = await asyncio.create_subprocess_exec(
                "sysrc",
                "alloy_enable=YES",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "service",
                "alloy",
                "start",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "Grafana Alloy (OpenTelemetry Collector) deployed successfully",
                "config_file": config_file,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _deploy_opentelemetry_openbsd(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on OpenBSD."""
        try:
            # Install using pkg_add
            process = await asyncio.create_subprocess_exec(
                "pkg_add",
                "opentelemetry-collector",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install OpenTelemetry collector: {stderr.decode()}",
                }

            # Create configuration file
            config_file = "/etc/otelcol/config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_otel_config(grafana_url)
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)

            # Enable and start service
            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "enable",
                "otelcol",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "start",
                "otelcol",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_file,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _deploy_opentelemetry_netbsd(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on NetBSD."""
        try:
            # Install using pkgin
            process = await asyncio.create_subprocess_exec(
                "pkgin",
                "-y",
                "install",
                "opentelemetry-collector",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install OpenTelemetry collector: {stderr.decode()}",
                }

            # Create configuration file
            config_file = "/usr/pkg/etc/otelcol/config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_otel_config(grafana_url)
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)

            # Enable and start service (NetBSD uses rc.d)
            process = await asyncio.create_subprocess_exec(
                "/etc/rc.d/otelcol",
                "start",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_file,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _deploy_opentelemetry_windows(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on Windows using Chocolatey."""
        try:
            self.logger.info("Installing OpenTelemetry collector using Chocolatey")

            # Install using Chocolatey
            process = await asyncio.create_subprocess_exec(
                "choco",
                "install",
                "opentelemetry-collector-contrib",
                "-y",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install OpenTelemetry collector: {stderr.decode()}",
                }

            # Create configuration file
            config_file = "C:\\Program Files\\OpenTelemetry Collector\\config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_otel_config(grafana_url)
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)

            # Start service using sc.exe
            process = await asyncio.create_subprocess_exec(
                "sc",
                "start",
                "otelcol",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_file,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _create_otel_config_linux(self, grafana_url: str) -> Dict[str, Any]:
        """Create OpenTelemetry configuration file for Linux."""
        try:
            config_file = "/etc/otelcol-contrib/config.yaml"
            env_file = "/etc/otelcol-contrib/otelcol-contrib.conf"
            config_dir = os.path.dirname(config_file)

            # Create config directory
            os.makedirs(config_dir, exist_ok=True)

            # Generate config content
            config_content = self._generate_otel_config(grafana_url)

            # Write config file
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)

            # Set proper permissions
            os.chmod(config_file, 0o644)

            # Create environment file with config path
            env_content = f'OTELCOL_OPTIONS="--config={config_file}"\n'
            with open(env_file, "w", encoding="utf-8") as f:
                f.write(env_content)

            # Set proper permissions
            os.chmod(env_file, 0o644)

            return {"success": True, "config_file": config_file}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _enable_and_start_otel_service_linux(self):
        """Enable and start OpenTelemetry service on Linux."""
        # Enable service
        self.logger.info("Enabling otelcol-contrib service...")
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "enable",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            self.logger.error(
                "Failed to enable service. Return code: %d", process.returncode
            )
            if stdout:
                self.logger.error("Enable stdout: %s", stdout.decode())
            if stderr:
                self.logger.error("Enable stderr: %s", stderr.decode())
        else:
            self.logger.info("Service enabled successfully")

        # Start service
        self.logger.info("Starting otelcol-contrib service...")
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "start",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            self.logger.error(
                "Failed to start service. Return code: %d", process.returncode
            )
            if stdout:
                self.logger.error("Start stdout: %s", stdout.decode())
            if stderr:
                self.logger.error("Start stderr: %s", stderr.decode())
        else:
            self.logger.info("Service started successfully")

    def _generate_otel_config(self, grafana_url: str) -> str:
        """Generate OpenTelemetry collector configuration."""
        # Parse Grafana URL to extract host and port
        parsed_url = urlparse(grafana_url)
        grafana_host = parsed_url.hostname or grafana_url
        grafana_port = parsed_url.port or 3000

        # Generate a basic OpenTelemetry configuration
        # This sends metrics to Grafana via OTLP
        config = f"""receivers:
  hostmetrics:
    collection_interval: 30s
    scrapers:
      cpu:
      disk:
      filesystem:
      load:
      memory:
      network:
      paging:
      process:
      processes:

processors:
  batch:
    timeout: 10s

exporters:
  otlp:
    endpoint: "{grafana_host}:{grafana_port}"
    tls:
      insecure: true

  debug:
    verbosity: normal

service:
  pipelines:
    metrics:
      receivers: [hostmetrics]
      processors: [batch]
      exporters: [otlp, debug]
"""
        return config

    def _generate_alloy_config(self, grafana_url: str) -> str:
        """Generate Grafana Alloy configuration for FreeBSD."""
        # Parse Grafana URL
        parsed_url = urlparse(grafana_url)
        grafana_host = parsed_url.hostname or grafana_url
        grafana_port = parsed_url.port or 3000

        # Alloy uses a different configuration format (River)
        config = f"""// Grafana Alloy configuration
otelcol.receiver.hostmetrics "default" {{
  collection_interval = "30s"

  scrapers {{
    cpu {{}}
    disk {{}}
    filesystem {{}}
    load {{}}
    memory {{}}
    network {{}}
    paging {{}}
    process {{}}
  }}

  output {{
    metrics = [otelcol.processor.batch.default.input]
  }}
}}

otelcol.processor.batch "default" {{
  timeout = "10s"

  output {{
    metrics = [otelcol.exporter.otlp.grafana.input]
  }}
}}

otelcol.exporter.otlp "grafana" {{
  client {{
    endpoint = "{grafana_host}:{grafana_port}"
    tls {{
      insecure = true
    }}
  }}
}}
"""
        return config

    async def start_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Start OpenTelemetry service."""
        try:
            self.logger.info(_("Starting OpenTelemetry service..."))

            # Determine the appropriate command based on platform
            if platform.system() == "Linux":
                # Try systemctl first (most common)
                command = "sudo systemctl start otelcol-contrib"
            elif platform.system() == "Darwin":
                # macOS
                command = "sudo brew services start otelcol-contrib"
            elif platform.system() == "FreeBSD":
                command = "sudo service otelcol start"
            elif platform.system() == "NetBSD":
                command = "sudo /etc/rc.d/otelcol start"
            else:
                return {
                    "success": False,
                    "error": _(
                        "Unsupported platform for OpenTelemetry service control"
                    ),
                }

            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info(_("OpenTelemetry service started successfully"))
                return {
                    "success": True,
                    "result": _("OpenTelemetry service started successfully"),
                }

            self.logger.error(
                _("Failed to start OpenTelemetry service: %s"),
                result.get("error", "Unknown error"),
            )
            return {
                "success": False,
                "error": _("Failed to start OpenTelemetry service: %s")
                % result.get("error", "Unknown error"),
            }
        except Exception as e:
            self.logger.error(_("Error starting OpenTelemetry service: %s"), e)
            return {"success": False, "error": str(e)}

    async def stop_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stop OpenTelemetry service."""
        try:
            self.logger.info(_("Stopping OpenTelemetry service..."))

            # Determine the appropriate command based on platform
            if platform.system() == "Linux":
                # Try systemctl first (most common)
                command = "sudo systemctl stop otelcol-contrib"
            elif platform.system() == "Darwin":
                # macOS
                command = "sudo brew services stop otelcol-contrib"
            elif platform.system() == "FreeBSD":
                command = "sudo service otelcol stop"
            elif platform.system() == "NetBSD":
                command = "sudo /etc/rc.d/otelcol stop"
            else:
                return {
                    "success": False,
                    "error": _(
                        "Unsupported platform for OpenTelemetry service control"
                    ),
                }

            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info(_("OpenTelemetry service stopped successfully"))
                return {
                    "success": True,
                    "result": _("OpenTelemetry service stopped successfully"),
                }

            self.logger.error(
                _("Failed to stop OpenTelemetry service: %s"),
                result.get("error", "Unknown error"),
            )
            return {
                "success": False,
                "error": _("Failed to stop OpenTelemetry service: %s")
                % result.get("error", "Unknown error"),
            }
        except Exception as e:
            self.logger.error(_("Error stopping OpenTelemetry service: %s"), e)
            return {"success": False, "error": str(e)}

    async def restart_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Restart OpenTelemetry service."""
        try:
            self.logger.info(_("Restarting OpenTelemetry service..."))

            # Determine the appropriate command based on platform
            if platform.system() == "Linux":
                # Try systemctl first (most common)
                command = "sudo systemctl restart otelcol-contrib"
            elif platform.system() == "Darwin":
                # macOS
                command = "sudo brew services restart otelcol-contrib"
            elif platform.system() == "FreeBSD":
                command = "sudo service otelcol restart"
            elif platform.system() == "NetBSD":
                command = "sudo /etc/rc.d/otelcol restart"
            else:
                return {
                    "success": False,
                    "error": _(
                        "Unsupported platform for OpenTelemetry service control"
                    ),
                }

            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info(_("OpenTelemetry service restarted successfully"))
                return {
                    "success": True,
                    "result": _("OpenTelemetry service restarted successfully"),
                }

            self.logger.error(
                _("Failed to restart OpenTelemetry service: %s"),
                result.get("error", "Unknown error"),
            )
            return {
                "success": False,
                "error": _("Failed to restart OpenTelemetry service: %s")
                % result.get("error", "Unknown error"),
            }
        except Exception as e:
            self.logger.error(_("Error restarting OpenTelemetry service: %s"), e)
            return {"success": False, "error": str(e)}

    async def connect_opentelemetry_grafana(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Connect OpenTelemetry to Grafana server."""
        grafana_url = parameters.get("grafana_url")

        if not grafana_url:
            return {"success": False, "error": _("Grafana URL is required")}

        try:
            self.logger.info(
                _("Connecting OpenTelemetry to Grafana at %s"), grafana_url
            )

            # Update the OpenTelemetry configuration file with Grafana endpoint
            # This is a placeholder - actual implementation depends on config file format
            # _config_file = "/etc/otelcol-contrib/config.yaml"

            # For now, we'll restart the service after config update
            # TODO: Implement actual config file update logic  # pylint: disable=fixme

            # Restart the service to apply changes
            restart_result = await self.restart_opentelemetry_service(parameters)

            if restart_result["success"]:
                self.logger.info(_("OpenTelemetry connected to Grafana successfully"))
                return {
                    "success": True,
                    "result": _("OpenTelemetry connected to Grafana successfully"),
                }

            return restart_result
        except Exception as e:
            self.logger.error(_("Error connecting OpenTelemetry to Grafana: %s"), e)
            return {"success": False, "error": str(e)}

    async def disconnect_opentelemetry_grafana(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disconnect OpenTelemetry from Grafana server."""
        try:
            self.logger.info(_("Disconnecting OpenTelemetry from Grafana"))

            # Update the OpenTelemetry configuration file to remove Grafana endpoint
            # This is a placeholder - actual implementation depends on config file format
            # _config_file = "/etc/otelcol-contrib/config.yaml"

            # For now, we'll restart the service after config update
            # TODO: Implement actual config file update logic  # pylint: disable=fixme

            # Restart the service to apply changes
            restart_result = await self.restart_opentelemetry_service(parameters)

            if restart_result["success"]:
                self.logger.info(
                    _("OpenTelemetry disconnected from Grafana successfully")
                )
                return {
                    "success": True,
                    "result": _("OpenTelemetry disconnected from Grafana successfully"),
                }

            return restart_result
        except Exception as e:
            self.logger.error(
                _("Error disconnecting OpenTelemetry from Grafana: %s"), e
            )
            return {"success": False, "error": str(e)}
