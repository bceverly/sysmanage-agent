"""
System operations module for SysManage agent.
Handles system-level commands and operations.
"""

import asyncio
import json
import logging
import os
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict

from src.database.base import get_database_manager
from src.database.models import InstallationRequestTracking
from src.i18n import _
from src.sysmanage_agent.collection.update_detection import UpdateDetector


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
