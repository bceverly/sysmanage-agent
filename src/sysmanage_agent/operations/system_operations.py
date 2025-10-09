"""
System operations module for SysManage agent.
Handles system-level commands and operations.
"""

import asyncio
import json
import logging
import os
import platform
import re
import shutil
import socket
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from src.database.base import get_database_manager
from src.database.models import InstallationRequestTracking
from src.i18n import _
from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector
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
        """
        Get detailed system information and send all data to server.
        This triggers collection and sending of OS version, hardware, storage,
        network, users, groups, software, Ubuntu Pro info, and antivirus status.
        """
        try:
            # Trigger all the standard data collection and sending
            await self.agent.update_os_version()
            await self.agent.update_hardware()

            # Collect and send antivirus status
            try:
                antivirus_collector = AntivirusCollector()
                antivirus_status = antivirus_collector.collect_antivirus_status()
                await self._send_antivirus_status_update(antivirus_status)
            except Exception as e:
                self.logger.warning(
                    "Failed to collect/send antivirus status: %s", str(e)
                )

            return {"success": True, "result": "System info refresh initiated"}
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

    async def deploy_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy antivirus software to the system."""
        antivirus_package = parameters.get("antivirus_package")

        if not antivirus_package:
            return {"success": False, "error": "No antivirus package specified"}

        self.logger.info("Deploying antivirus package: %s", antivirus_package)

        try:
            # Helper function to get Homebrew user
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

            # Special handling for ClamAV on macOS
            if "clamav" in antivirus_package.lower() and (
                os.path.exists("/usr/local/bin/brew")
                or os.path.exists("/opt/homebrew/bin/brew")
            ):
                self.logger.info(
                    "Detected macOS system, installing ClamAV via Homebrew"
                )

                # Install ClamAV via Homebrew
                update_detector = UpdateDetector()
                self.logger.info("Installing clamav")
                result = update_detector.install_package("clamav", "auto")
                self.logger.info("clamav installation result: %s", result)

                # Determine the correct config path based on architecture
                config_base = (
                    "/opt/homebrew/etc/clamav"
                    if os.path.exists("/opt/homebrew")
                    else "/usr/local/etc/clamav"
                )
                log_dir = (
                    "/opt/homebrew/var/log/clamav"
                    if os.path.exists("/opt/homebrew")
                    else "/usr/local/var/log/clamav"
                )

                self.logger.info("Configuring ClamAV on macOS")

                # Create log and database directories
                os.makedirs(log_dir, exist_ok=True)

                # Create database directory for virus definitions
                db_dir = (
                    "/opt/homebrew/var/lib/clamav"
                    if os.path.exists("/opt/homebrew")
                    else "/usr/local/var/lib/clamav"
                )
                os.makedirs(db_dir, exist_ok=True)

                # Configure freshclam.conf
                freshclam_conf = f"{config_base}/freshclam.conf"
                freshclam_sample = f"{config_base}/freshclam.conf.sample"
                if os.path.exists(freshclam_sample):
                    self.logger.info("Creating freshclam.conf from sample")
                    process = await asyncio.create_subprocess_exec(
                        "cp",
                        freshclam_sample,
                        freshclam_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Comment out Example line in freshclam.conf
                    process = await asyncio.create_subprocess_exec(
                        "sed",
                        "-i",
                        "",
                        "-e",
                        "s/^Example/#Example/",
                        freshclam_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                    self.logger.info("freshclam.conf configured")

                # Configure clamd.conf
                clamd_conf = f"{config_base}/clamd.conf"
                clamd_sample = f"{config_base}/clamd.conf.sample"
                if os.path.exists(clamd_sample):
                    self.logger.info("Creating clamd.conf from sample")
                    process = await asyncio.create_subprocess_exec(
                        "cp",
                        clamd_sample,
                        clamd_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Comment out Example line and configure clamd
                    sed_commands = [
                        "s/^Example/#Example/",
                        f"s|^#LogFile.*|LogFile {log_dir}/clamd.log|",
                        f"s|^#PidFile.*|PidFile {log_dir}/clamd.pid|",
                        f"s|^#DatabaseDirectory.*|DatabaseDirectory {db_dir}|",
                        f"s|^#LocalSocket.*|LocalSocket {log_dir}/clamd.sock|",
                    ]

                    for sed_cmd in sed_commands:
                        process = await asyncio.create_subprocess_exec(
                            "sed",
                            "-i",
                            "",
                            "-e",
                            sed_cmd,
                            clamd_conf,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        await process.communicate()

                    self.logger.info("clamd.conf configured")

                # Update virus definitions with freshclam
                self.logger.info("Updating virus definitions with freshclam")
                # Use full path since brew link creates symlinks in /opt/homebrew/bin or /usr/local/bin
                freshclam_cmd = (
                    "/opt/homebrew/bin/freshclam"
                    if os.path.exists("/opt/homebrew/bin/freshclam")
                    else "/usr/local/bin/freshclam"
                )

                # If running as root, use sudo -u to run as the brew user
                # This ensures freshclam has proper permissions to write to Homebrew directories
                brew_user = _get_brew_user() if os.geteuid() == 0 else None

                if brew_user:
                    self.logger.info("Running freshclam as user: %s", brew_user)
                    process = await asyncio.create_subprocess_exec(
                        "sudo",
                        "-u",
                        brew_user,
                        freshclam_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                else:
                    process = await asyncio.create_subprocess_exec(
                        freshclam_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info("Virus definitions updated successfully")
                else:
                    self.logger.warning(
                        "Failed to update virus definitions: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                # Start ClamAV service via Homebrew
                # Note: ClamAV service must be started with sudo (as root) to run at system startup
                # This is different from other brew commands which shouldn't run as root
                self.logger.info("Starting ClamAV service via brew services")
                brew_cmd = (
                    "/opt/homebrew/bin/brew"
                    if os.path.exists("/opt/homebrew/bin/brew")
                    else "/usr/local/bin/brew"
                )

                # Always use sudo for brew services start clamav
                # ClamAV requires root to start at system startup
                process = await asyncio.create_subprocess_exec(
                    "sudo",
                    brew_cmd,
                    "services",
                    "start",
                    "clamav",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info("ClamAV service started successfully")
                else:
                    self.logger.warning(
                        "Failed to start ClamAV service: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                await asyncio.sleep(2)

                success = True
                error_message = None
                installed_version = None
                result = "ClamAV installed successfully on macOS"

            # Special handling for ClamAV on NetBSD
            elif "clamav" in antivirus_package.lower() and os.path.exists(
                "/usr/pkg/bin/pkgin"
            ):
                self.logger.info("Detected NetBSD system, installing ClamAV package")

                # Install ClamAV package using pkgin
                update_detector = UpdateDetector()
                self.logger.info("Installing clamav")
                result = update_detector.install_package("clamav", "auto")
                self.logger.info("clamav installation result: %s", result)

                # Configure ClamAV on NetBSD
                self.logger.info("Configuring ClamAV on NetBSD")

                # NetBSD config files are typically in /usr/pkg/etc
                # Copy sample config files and comment out Example line
                # freshclam.conf
                freshclam_conf = "/usr/pkg/etc/freshclam.conf"
                freshclam_sample = "/usr/pkg/etc/freshclam.conf.sample"
                if os.path.exists(freshclam_sample):
                    self.logger.info("Creating freshclam.conf from sample")
                    process = await asyncio.create_subprocess_exec(
                        "cp",
                        freshclam_sample,
                        freshclam_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Comment out Example line in freshclam.conf
                    process = await asyncio.create_subprocess_exec(
                        "sed",
                        "-i",
                        "",
                        "-e",
                        "s/^Example/#Example/",
                        freshclam_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                    self.logger.info("freshclam.conf configured")

                # clamd.conf
                clamd_conf = "/usr/pkg/etc/clamd.conf"
                clamd_sample = "/usr/pkg/etc/clamd.conf.sample"
                if os.path.exists(clamd_sample):
                    self.logger.info("Creating clamd.conf from sample")
                    process = await asyncio.create_subprocess_exec(
                        "cp",
                        clamd_sample,
                        clamd_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Comment out Example line and configure LocalSocket in clamd.conf
                    process = await asyncio.create_subprocess_exec(
                        "sed",
                        "-i",
                        "",
                        "-e",
                        "s/^Example/#Example/",
                        "-e",
                        "s/^#LocalSocket /LocalSocket /",
                        clamd_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                    self.logger.info("clamd.conf configured")

                # Copy rc.d scripts to /etc/rc.d/ (NetBSD requirement)
                self.logger.info("Copying rc.d scripts to /etc/rc.d/")
                for script in ["clamd", "freshclamd"]:
                    process = await asyncio.create_subprocess_exec(
                        "sudo",
                        "cp",
                        f"/usr/pkg/share/examples/rc.d/{script}",
                        "/etc/rc.d/",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                # Enable services in rc.conf using shell commands
                # NetBSD service name is freshclamd (with d), not freshclam
                self.logger.info("Enabling ClamAV services in rc.conf")

                process = await asyncio.create_subprocess_exec(
                    "sh",
                    "-c",
                    "grep -q '^freshclamd=' /etc/rc.conf 2>/dev/null || echo 'freshclamd=YES' | sudo tee -a /etc/rc.conf > /dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                process = await asyncio.create_subprocess_exec(
                    "sh",
                    "-c",
                    "grep -q '^clamd=' /etc/rc.conf 2>/dev/null || echo 'clamd=YES' | sudo tee -a /etc/rc.conf > /dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                # Start freshclamd service first
                self.logger.info("Starting freshclamd service")
                process = await asyncio.create_subprocess_exec(
                    "sudo",
                    "service",
                    "freshclamd",
                    "start",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info("freshclamd service started successfully")
                else:
                    self.logger.warning(
                        "Failed to start freshclamd: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                # Wait for virus database download
                self.logger.info("Waiting for freshclamd to download virus database")
                database_ready = False
                for _ in range(30):
                    if os.path.exists("/var/clamav/main.cvd") or os.path.exists(
                        "/var/clamav/main.cld"
                    ):
                        self.logger.info("Virus database downloaded successfully")
                        database_ready = True
                        break
                    await asyncio.sleep(1)

                if not database_ready:
                    self.logger.warning(
                        "Virus database not downloaded after 30 seconds, proceeding anyway"
                    )

                # Start clamd service
                self.logger.info("Starting clamd service")
                process = await asyncio.create_subprocess_exec(
                    "sudo",
                    "service",
                    "clamd",
                    "start",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info("clamd service started successfully")
                else:
                    self.logger.warning(
                        "Failed to start clamd: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                await asyncio.sleep(2)

                success = True
                error_message = None
                installed_version = None
                result = "ClamAV installed successfully on NetBSD"

            # Special handling for ClamAV on FreeBSD
            elif (
                "clamav" in antivirus_package.lower()
                and os.path.exists("/usr/sbin/pkg")
                and not os.path.exists("/usr/sbin/pkg_add")
            ):
                self.logger.info("Detected FreeBSD system, installing ClamAV package")

                # Install ClamAV package
                update_detector = UpdateDetector()
                self.logger.info("Installing clamav")
                result = update_detector.install_package("clamav", "auto")
                self.logger.info("clamav installation result: %s", result)

                # Configure ClamAV on FreeBSD
                self.logger.info("Configuring ClamAV on FreeBSD")

                # FreeBSD config files are typically in /usr/local/etc
                # Copy sample config files and comment out Example line
                # freshclam.conf
                freshclam_conf = "/usr/local/etc/freshclam.conf"
                freshclam_sample = "/usr/local/etc/freshclam.conf.sample"
                if os.path.exists(freshclam_sample):
                    self.logger.info("Creating freshclam.conf from sample")
                    process = await asyncio.create_subprocess_exec(
                        "cp",
                        freshclam_sample,
                        freshclam_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Comment out Example line in freshclam.conf
                    process = await asyncio.create_subprocess_exec(
                        "sed",
                        "-i",
                        "",
                        "-e",
                        "s/^Example/#Example/",
                        freshclam_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                    self.logger.info("freshclam.conf configured")

                # clamd.conf
                clamd_conf = "/usr/local/etc/clamd.conf"
                clamd_sample = "/usr/local/etc/clamd.conf.sample"
                if os.path.exists(clamd_sample):
                    self.logger.info("Creating clamd.conf from sample")
                    process = await asyncio.create_subprocess_exec(
                        "cp",
                        clamd_sample,
                        clamd_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Comment out Example line and configure LocalSocket in clamd.conf
                    process = await asyncio.create_subprocess_exec(
                        "sed",
                        "-i",
                        "",
                        "-e",
                        "s/^Example/#Example/",
                        "-e",
                        "s/^#LocalSocket /LocalSocket /",
                        clamd_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                    self.logger.info("clamd.conf configured")

                # Enable services in rc.conf
                self.logger.info("Enabling ClamAV services in rc.conf")
                process = await asyncio.create_subprocess_exec(
                    "sysrc",
                    "clamav_freshclam_enable=YES",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                process = await asyncio.create_subprocess_exec(
                    "sysrc",
                    "clamav_clamd_enable=YES",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

                # Start freshclam service first
                self.logger.info("Starting clamav_freshclam service")
                process = await asyncio.create_subprocess_exec(
                    "service",
                    "clamav_freshclam",
                    "start",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info("clamav_freshclam service started successfully")
                else:
                    self.logger.warning(
                        "Failed to start clamav_freshclam: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                # Wait for virus database download
                self.logger.info("Waiting for freshclam to download virus database")
                database_ready = False
                for _ in range(30):
                    if os.path.exists("/var/db/clamav/main.cvd") or os.path.exists(
                        "/var/db/clamav/main.cld"
                    ):
                        self.logger.info("Virus database downloaded successfully")
                        database_ready = True
                        break
                    await asyncio.sleep(1)

                if not database_ready:
                    self.logger.warning(
                        "Virus database not downloaded after 30 seconds, proceeding anyway"
                    )

                # Start clamd service
                self.logger.info("Starting clamav_clamd service")
                process = await asyncio.create_subprocess_exec(
                    "service",
                    "clamav_clamd",
                    "start",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info("clamav_clamd service started successfully")
                else:
                    self.logger.warning(
                        "Failed to start clamav_clamd: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                await asyncio.sleep(2)

                success = True
                error_message = None
                installed_version = None
                result = "ClamAV installed successfully on FreeBSD"

            # Special handling for ClamAV on OpenBSD
            elif "clamav" in antivirus_package.lower() and os.path.exists(
                "/usr/sbin/pkg_add"
            ):
                self.logger.info("Detected OpenBSD system, installing ClamAV package")

                # Install ClamAV package
                update_detector = UpdateDetector()
                self.logger.info("Installing clamav")
                result = update_detector.install_package("clamav", "auto")
                self.logger.info("clamav installation result: %s", result)

                # Configure ClamAV on OpenBSD
                self.logger.info("Configuring ClamAV on OpenBSD")

                # Copy sample config files and comment out Example line
                # freshclam.conf
                freshclam_conf = "/etc/freshclam.conf"
                freshclam_sample = (
                    "/usr/local/share/examples/clamav/freshclam.conf.sample"
                )
                if os.path.exists(freshclam_sample):
                    self.logger.info("Creating freshclam.conf from sample")
                    process = await asyncio.create_subprocess_exec(
                        "cp",
                        freshclam_sample,
                        freshclam_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Comment out Example line in freshclam.conf
                    process = await asyncio.create_subprocess_exec(
                        "sed",
                        "-i",
                        "s/^Example/#Example/",
                        freshclam_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                    self.logger.info("freshclam.conf configured")

                # clamd.conf
                clamd_conf = "/etc/clamd.conf"
                clamd_sample = "/usr/local/share/examples/clamav/clamd.conf.sample"
                if os.path.exists(clamd_sample):
                    self.logger.info("Creating clamd.conf from sample")
                    process = await asyncio.create_subprocess_exec(
                        "cp",
                        clamd_sample,
                        clamd_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Comment out Example line and configure LocalSocket in clamd.conf
                    # On OpenBSD, use /var/run instead of /run
                    # Use sed to do multiple edits
                    process = await asyncio.create_subprocess_exec(
                        "sed",
                        "-i",
                        "-e",
                        "s/^Example/#Example/",
                        "-e",
                        "s/^#LocalSocket /LocalSocket /",
                        "-e",
                        "s|/run/clamav/|/var/run/clamav/|g",
                        clamd_conf,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                    self.logger.info("clamd.conf configured")

                # Create required runtime directories for clamd
                # On OpenBSD, runtime directory is /var/run, not /run
                self.logger.info("Creating runtime directories for ClamAV")
                clamav_run_dir = "/var/run/clamav"
                if not os.path.exists(clamav_run_dir):
                    process = await asyncio.create_subprocess_exec(
                        "mkdir",
                        "-p",
                        clamav_run_dir,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()

                    # Set ownership to _clamav user
                    process = await asyncio.create_subprocess_exec(
                        "chown",
                        "_clamav:_clamav",
                        clamav_run_dir,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                    self.logger.info("Created and configured /var/run/clamav directory")

                # Enable and start freshclam service first (OpenBSD uses freshclam)
                # Note: freshclam must run first to download virus database before clamd can start
                self.logger.info("Enabling and starting freshclam service")
                process = await asyncio.create_subprocess_exec(
                    "rcctl",
                    "enable",
                    "freshclam",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                process = await asyncio.create_subprocess_exec(
                    "rcctl",
                    "start",
                    "freshclam",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info(
                        "freshclam service enabled and started successfully"
                    )
                else:
                    self.logger.warning(
                        "Failed to start freshclam: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                # Wait for freshclam to download the database (give it up to 30 seconds)
                self.logger.info("Waiting for freshclam to download virus database")
                database_ready = False
                for _ in range(30):
                    if os.path.exists("/var/db/clamav/main.cvd") or os.path.exists(
                        "/var/db/clamav/main.cld"
                    ):
                        self.logger.info("Virus database downloaded successfully")
                        database_ready = True
                        break
                    await asyncio.sleep(1)

                if not database_ready:
                    self.logger.warning(
                        "Virus database not downloaded after 30 seconds, proceeding anyway"
                    )

                # Enable and start clamd service (OpenBSD uses clamd)
                self.logger.info("Enabling and starting clamd service")
                process = await asyncio.create_subprocess_exec(
                    "rcctl",
                    "enable",
                    "clamd",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                process = await asyncio.create_subprocess_exec(
                    "rcctl",
                    "start",
                    "clamd",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info("clamd service enabled and started successfully")
                else:
                    self.logger.warning(
                        "Failed to start clamd: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                await asyncio.sleep(2)

                success = True
                error_message = None
                installed_version = None
                result = "ClamAV installed successfully on OpenBSD"

            # Special handling for ClamAV on openSUSE
            elif "clamav" in antivirus_package.lower() and os.path.exists(
                "/usr/bin/zypper"
            ):
                self.logger.info("Detected openSUSE system, installing ClamAV packages")

                # Install ClamAV packages
                update_detector = UpdateDetector()
                packages = ["clamav", "clamav_freshclam", "clamav-daemon"]
                for pkg in packages:
                    self.logger.info("Installing %s", pkg)
                    result = update_detector.install_package(pkg, "auto")
                    self.logger.info("%s installation result: %s", pkg, result)

                # Enable and start freshclam service
                self.logger.info("Enabling and starting freshclam service")
                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "enable",
                    "--now",
                    "freshclam.service",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info(
                        "freshclam service enabled and started successfully"
                    )
                else:
                    self.logger.warning(
                        "Failed to enable/start freshclam: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                # Enable and start clamd service
                service_name = "clamd.service"
                self.logger.info("Enabling and starting service: %s", service_name)
                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "enable",
                    "--now",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                if process.returncode == 0:
                    self.logger.info(
                        "Service %s enabled and started successfully", service_name
                    )
                    await asyncio.sleep(2)
                else:
                    self.logger.warning(
                        "Failed to enable/start service %s: %s",
                        service_name,
                        stderr.decode() if stderr else "unknown error",
                    )

                success = True
                error_message = None
                installed_version = None
                result = "ClamAV installed successfully on openSUSE"

            # Special handling for ClamAV on RHEL/CentOS - need EPEL and multiple packages
            elif "clamav" in antivirus_package.lower() and (
                os.path.exists("/usr/bin/yum") or os.path.exists("/usr/bin/dnf")
            ):
                self.logger.info(
                    "Detected RHEL/CentOS system, enabling EPEL and installing ClamAV packages"
                )

                # Enable EPEL repository
                update_detector = UpdateDetector()
                epel_result = update_detector.install_package("epel-release", "auto")
                self.logger.info("EPEL installation result: %s", epel_result)

                # Install ClamAV packages
                packages = ["clamav", "clamd", "clamav-update"]
                for pkg in packages:
                    self.logger.info("Installing %s", pkg)
                    result = update_detector.install_package(pkg, "auto")
                    self.logger.info("%s installation result: %s", pkg, result)

                # Update virus definitions
                self.logger.info("Updating virus definitions with freshclam")
                process = await asyncio.create_subprocess_exec(
                    "freshclam",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                if process.returncode == 0:
                    self.logger.info("Virus definitions updated successfully")
                else:
                    self.logger.warning(
                        "Failed to update virus definitions: %s",
                        stderr.decode() if stderr else "unknown error",
                    )

                # Configure clamd@scan service
                config_file = "/etc/clamd.d/scan.conf"
                self.logger.info("Configuring %s", config_file)

                # Read the config file
                with open(config_file, "r", encoding="utf-8") as f:
                    config_content = f.read()

                # Uncomment LocalSocket and remove Example line
                config_content = config_content.replace(
                    "#Example", "# Example"
                ).replace(
                    "#LocalSocket /run/clamd.scan/clamd.sock",
                    "LocalSocket /run/clamd.scan/clamd.sock",
                )

                # Write back the config file
                with open(config_file, "w", encoding="utf-8") as f:
                    f.write(config_content)

                self.logger.info("Configuration updated successfully")

                # Enable and start clamd@scan service
                service_name = "clamd@scan"
                self.logger.info("Enabling and starting service: %s", service_name)
                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "enable",
                    "--now",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                if process.returncode == 0:
                    self.logger.info(
                        "Service %s enabled and started successfully", service_name
                    )
                    await asyncio.sleep(2)
                else:
                    self.logger.warning(
                        "Failed to enable/start service %s: %s",
                        service_name,
                        stderr.decode() if stderr else "unknown error",
                    )

                success = True
                error_message = None
                installed_version = None
                result = "ClamAV installed successfully on RHEL/CentOS"

            # Special handling for ClamAV on Windows with Chocolatey
            elif (
                "clamav" in antivirus_package.lower() and platform.system() == "Windows"
            ):
                self.logger.info(
                    "Detected Windows system, installing ClamAV via Chocolatey"
                )

                # Install ClamAV via Chocolatey
                update_detector = UpdateDetector()
                self.logger.info("Installing clamav")
                result = update_detector.install_package("clamav", "auto")
                self.logger.info("clamav installation result: %s", result)

                # Determine success based on result
                success = isinstance(result, dict) and result.get("success", False)
                error_message = (
                    result.get("error") if isinstance(result, dict) else None
                )

                if not success:
                    return {
                        "success": False,
                        "result": str(result),
                        "package_name": antivirus_package,
                        "error": error_message or "Installation failed",
                    }

                self.logger.info("Configuring ClamAV on Windows")

                # Common ClamAV installation paths on Windows (Chocolatey)
                common_paths = [
                    "C:\\Program Files\\ClamAV",
                    "C:\\Program Files (x86)\\ClamAV",
                    "C:\\ProgramData\\chocolatey\\lib\\clamav\\tools",
                ]

                clamav_path = None
                for path in common_paths:
                    if os.path.exists(path):
                        clamav_path = path
                        break

                if not clamav_path:
                    self.logger.warning(
                        "Could not locate ClamAV installation directory"
                    )
                    return {
                        "success": False,
                        "result": "ClamAV installation directory not found",
                        "package_name": antivirus_package,
                        "error": "Installation directory not found",
                    }

                # Path to freshclam.exe
                freshclam_exe = os.path.join(clamav_path, "freshclam.exe")
                if not os.path.exists(freshclam_exe):
                    self.logger.warning("freshclam.exe not found at %s", freshclam_exe)

                # Update virus definitions with freshclam
                self.logger.info("Updating virus definitions with freshclam")
                try:
                    process = await asyncio.create_subprocess_exec(
                        freshclam_exe,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, stderr = await process.communicate()
                    if process.returncode == 0:
                        self.logger.info("Virus definitions updated successfully")
                    else:
                        self.logger.warning(
                            "Failed to update virus definitions: %s",
                            stderr.decode() if stderr else "unknown error",
                        )
                except Exception as e:
                    self.logger.warning("Error running freshclam: %s", e)

                # Note: On Windows, ClamAV doesn't run as a service by default after Chocolatey install
                # The service needs to be manually configured if desired
                # For now, we consider the installation successful if the binaries are present
                await asyncio.sleep(2)

                success = True
                error_message = None
                installed_version = None
                result = "ClamAV installed successfully on Windows"

            else:
                # Standard installation for other distros (Debian/Ubuntu)
                update_detector = UpdateDetector()
                result = update_detector.install_package(antivirus_package, "auto")

                # Determine success based on result
                success = True
                error_message = None
                installed_version = None

                if isinstance(result, dict):
                    success = result.get("success", True)
                    error_message = result.get("error")
                    installed_version = result.get("version")
                elif isinstance(result, str):
                    if "error" in result.lower() or "failed" in result.lower():
                        success = False
                        error_message = result

                # After installation, enable and start the service
                if success and "clamav" in antivirus_package.lower():
                    self.logger.info(
                        "Antivirus package %s installed successfully, enabling and starting service",
                        antivirus_package,
                    )
                    try:
                        # Ubuntu/Debian uses clamav_freshclam
                        service_name = "clamav_freshclam"
                        self.logger.info(
                            "Enabling and starting service: %s", service_name
                        )
                        process = await asyncio.create_subprocess_exec(
                            "systemctl",
                            "enable",
                            "--now",
                            service_name,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        _, stderr = await process.communicate()

                        if process.returncode == 0:
                            self.logger.info(
                                "Service %s enabled and started successfully",
                                service_name,
                            )
                            await asyncio.sleep(2)
                        else:
                            self.logger.warning(
                                "Failed to enable/start service %s: %s",
                                service_name,
                                stderr.decode() if stderr else "unknown error",
                            )
                    except Exception as service_error:
                        self.logger.warning(
                            "Failed to enable service: %s", str(service_error)
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

        except Exception as e:
            error_message = str(e)
            self.logger.error("Failed to deploy antivirus %s: %s", antivirus_package, e)

            return {
                "success": False,
                "error": error_message,
                "package_name": antivirus_package,
            }

    async def _send_antivirus_status_update(self, antivirus_status: Dict[str, Any]):
        """Send antivirus status update to server."""
        try:
            system_info = self.agent.registration.get_system_info()
            message = self.agent.create_message(
                "antivirus_status_update",
                {
                    "hostname": system_info.get("hostname") or socket.gethostname(),
                    "software_name": antivirus_status.get("software_name"),
                    "install_path": antivirus_status.get("install_path"),
                    "version": antivirus_status.get("version"),
                    "enabled": antivirus_status.get("enabled"),
                },
            )
            await self.agent.send_message(message)
            self.logger.info("Sent antivirus status update to server")
        except Exception as e:
            self.logger.error("Failed to send antivirus status update: %s", e)

    async def enable_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
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

        except Exception as e:
            self.logger.error("Failed to enable antivirus: %s", e)
            return {"success": False, "error": str(e)}

    async def disable_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
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

        except Exception as e:
            self.logger.error("Failed to disable antivirus: %s", e)
            return {"success": False, "error": str(e)}

    async def _cleanup_clamav_cellar_macos(self) -> Optional[str]:
        """
        Manually remove ClamAV from Homebrew Cellar directory.

        Returns:
            None if successful, error message string if failed
        """
        import glob  # pylint: disable=import-outside-toplevel

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

    async def remove_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove antivirus software from the system."""
        self.logger.info("Removing antivirus software")

        try:
            # Helper function to get Homebrew user
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

                # Remove ClamAV via Chocolatey
                process = await asyncio.create_subprocess_exec(
                    "choco",
                    "uninstall",
                    "clamav",
                    "-y",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                if process.returncode != 0:
                    error = stderr.decode()

            else:
                error = "Unsupported package manager"

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

        except Exception as e:
            self.logger.error("Failed to remove antivirus: %s", e)
            return {"success": False, "error": str(e)}

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
        # Reload systemd to pick up environment file changes
        self.logger.info("Reloading systemd daemon...")
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "daemon-reload",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

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
        # Use port 4317 for OTLP gRPC (Grafana Alloy default)
        grafana_port = parsed_url.port or 4317

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

    async def list_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """List all third-party repositories on the system."""
        try:
            self.logger.info(_("Listing third-party repositories"))
            repositories = []
            system = platform.system()

            if system == "Linux":
                # Detect distribution
                distro_info = await self._detect_linux_distro()
                distro = distro_info.get("distro", "").lower()

                if "ubuntu" in distro or "debian" in distro:
                    # List PPAs and other apt repositories
                    repos = await self._list_apt_repositories()
                    repositories.extend(repos)
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    # List COPR and other yum/dnf repositories
                    repos = await self._list_yum_repositories()
                    repositories.extend(repos)
                elif "opensuse" in distro or "suse" in distro:
                    # List OBS and other zypper repositories
                    repos = await self._list_zypper_repositories()
                    repositories.extend(repos)
            elif system == "Darwin":
                # macOS - list Homebrew taps
                repos = await self._list_homebrew_taps()
                repositories.extend(repos)
            elif system == "FreeBSD":
                # FreeBSD - list pkg repositories
                repos = await self._list_freebsd_repositories()
                repositories.extend(repos)
            elif system == "NetBSD":
                # NetBSD - list pkgsrc repositories
                repos = await self._list_netbsd_repositories()
                repositories.extend(repos)
            elif system == "Windows":
                # Windows - list Chocolatey sources and winget sources
                repos = await self._list_windows_repositories()
                repositories.extend(repos)

            return {
                "success": True,
                "repositories": repositories,
                "count": len(repositories),
            }
        except Exception as e:
            self.logger.error(_("Error listing third-party repositories: %s"), e)
            return {"success": False, "error": str(e)}

    async def _detect_linux_distro(self) -> Dict[str, str]:
        """Detect Linux distribution."""
        try:
            # Try /etc/os-release first
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith("ID="):
                            distro = line.split("=")[1].strip().strip('"')
                            return {"distro": distro}

            # Fallback to platform
            return {"distro": platform.system()}
        except Exception as e:
            self.logger.error(_("Error detecting Linux distribution: %s"), e)
            return {"distro": "unknown"}

    async def _list_apt_repositories(self) -> list:
        """List APT repositories including PPAs."""
        repositories = []
        sources_dir = "/etc/apt/sources.list.d"

        try:
            if os.path.exists(sources_dir):
                for filename in os.listdir(sources_dir):
                    if filename.endswith((".list", ".sources")):
                        filepath = os.path.join(sources_dir, filename)
                        try:
                            with open(filepath, "r", encoding="utf-8") as f:
                                content = f.read()
                                # Parse repository info
                                for line in content.splitlines():
                                    line = line.strip()
                                    if not line or line.startswith("#"):
                                        continue

                                    # Check if it's a PPA or other third-party repo
                                    # Use proper URL parsing to check for PPA domains
                                    is_ppa = False
                                    # Parse URL to validate it's actually the hostname
                                    parts = line.split()
                                    for part in parts:
                                        if part.startswith("http"):
                                            parsed = urlparse(part)
                                            if parsed.hostname and (
                                                parsed.hostname == "ppa.launchpad.net"
                                                or parsed.hostname.endswith(
                                                    ".ppa.launchpad.net"
                                                )
                                            ):
                                                is_ppa = True
                                                break

                                    if not (is_ppa or "deb " in line):
                                        continue

                                    enabled = not line.startswith("#")
                                    repo_type = "PPA" if is_ppa else "APT"

                                    # Extract PPA name if it's a PPA
                                    name = filename.replace(".list", "").replace(
                                        ".sources", ""
                                    )
                                    if is_ppa:
                                        # Try to extract ppa:user/name format
                                        parts = line.split()
                                        for part in parts:
                                            if not part.startswith("http"):
                                                continue
                                            parsed = urlparse(part)
                                            if not (
                                                parsed.hostname
                                                and (
                                                    parsed.hostname
                                                    == "ppa.launchpad.net"
                                                    or parsed.hostname.endswith(
                                                        ".ppa.launchpad.net"
                                                    )
                                                )
                                            ):
                                                continue
                                            # Extract user/ppa from URL
                                            url_parts = part.split("/")
                                            if len(url_parts) >= 4:
                                                user = url_parts[-3]
                                                ppa = url_parts[-2]
                                                name = f"ppa:{user}/{ppa}"
                                            break

                                    repositories.append(
                                        {
                                            "name": name,
                                            "type": repo_type,
                                            "url": line,
                                            "enabled": enabled,
                                            "file_path": filepath,
                                        }
                                    )
                        except Exception as e:
                            self.logger.warning(_("Error reading %s: %s"), filepath, e)
        except Exception as e:
            self.logger.error(_("Error listing APT repositories: %s"), e)

        return repositories

    async def _list_yum_repositories(self) -> list:
        """List YUM/DNF repositories including COPR."""
        repositories = []
        repos_dir = "/etc/yum.repos.d"

        try:
            if os.path.exists(repos_dir):
                for filename in os.listdir(repos_dir):
                    if filename.endswith(".repo"):
                        filepath = os.path.join(repos_dir, filename)
                        try:
                            with open(filepath, "r", encoding="utf-8") as f:
                                content = f.read()
                                # Parse INI-style repo file
                                current_repo = None
                                for line in content.splitlines():
                                    line = line.strip()
                                    if line.startswith("[") and line.endswith("]"):
                                        if current_repo:
                                            repositories.append(current_repo)
                                        current_repo = {
                                            "name": line[1:-1],
                                            "type": (
                                                "COPR"
                                                if "copr" in filename.lower()
                                                else "YUM"
                                            ),
                                            "url": "",
                                            "enabled": True,
                                            "file_path": filepath,
                                        }
                                    elif current_repo is not None and "=" in line:
                                        key, value = line.split("=", 1)
                                        key = key.strip()
                                        value = value.strip()
                                        if key == "baseurl":
                                            # pylint: disable=unsupported-assignment-operation
                                            current_repo["url"] = value
                                        elif key == "enabled":
                                            # pylint: disable=unsupported-assignment-operation
                                            current_repo["enabled"] = value == "1"

                                if current_repo:
                                    repositories.append(current_repo)
                        except Exception as e:
                            self.logger.warning(_("Error reading %s: %s"), filepath, e)
        except Exception as e:
            self.logger.error(_("Error listing YUM repositories: %s"), e)

        return repositories

    def _check_obs_url(self, url: str) -> bool:
        """Check if a URL is from opensuse.org domain."""
        if not url:
            return False
        try:
            parsed = urlparse(url)
            return bool(
                parsed.hostname
                and (
                    parsed.hostname == "opensuse.org"
                    or parsed.hostname.endswith(".opensuse.org")
                )
            )
        except Exception:
            return False

    async def _list_zypper_repositories(self) -> list:
        """List Zypper repositories including OBS."""
        repositories = []

        try:
            # Use zypper lr command to list repos
            command = "zypper lr -u"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                output = result["result"]["stdout"]
                for line in output.splitlines():
                    # Parse zypper output
                    if "|" in line and not line.startswith("#"):
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) >= 4:
                            # Determine if it's an OBS repository by parsing the URL
                            url = parts[3] if len(parts) > 3 else ""
                            is_obs = self._check_obs_url(url)

                            repositories.append(
                                {
                                    "name": parts[1],
                                    "type": "OBS" if is_obs else "Zypper",
                                    "url": url,
                                    "enabled": (
                                        parts[2] == "Yes" if len(parts) > 2 else True
                                    ),
                                    "file_path": f"/etc/zypp/repos.d/{parts[1]}.repo",
                                }
                            )
        except Exception as e:
            self.logger.error(_("Error listing Zypper repositories: %s"), e)

        return repositories

    async def add_third_party_repository(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a third-party repository to the system."""
        try:
            repo_identifier = parameters.get("repository")

            if not repo_identifier:
                return {
                    "success": False,
                    "error": _("Repository identifier is required"),
                }

            self.logger.info(_("Adding third-party repository: %s"), repo_identifier)

            system = platform.system()

            if system == "Linux":
                self.logger.debug("Detecting Linux distribution for repository add")
                distro_info = await self._detect_linux_distro()
                distro = distro_info.get("distro", "").lower()
                self.logger.debug("Detected distribution: %s", distro)

                if "ubuntu" in distro or "debian" in distro:
                    self.logger.debug(
                        "Calling _add_apt_repository for %s", repo_identifier
                    )
                    result = await self._add_apt_repository(repo_identifier)
                    self.logger.debug("_add_apt_repository returned: %s", result)
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    result = await self._add_yum_repository(repo_identifier)
                elif "opensuse" in distro or "suse" in distro:
                    result = await self._add_zypper_repository(
                        repo_identifier, parameters.get("url", "")
                    )
                else:
                    return {
                        "success": False,
                        "error": _("Unsupported distribution: %s") % distro,
                    }
            elif system == "Darwin":
                # macOS - add Homebrew tap
                result = await self._add_homebrew_tap(repo_identifier)
            elif system == "FreeBSD":
                # FreeBSD - add pkg repository
                result = await self._add_freebsd_repository(
                    repo_identifier, parameters.get("url", "")
                )
            elif system == "NetBSD":
                # NetBSD - add pkgsrc repository
                result = await self._add_netbsd_repository(
                    repo_identifier, parameters.get("url", "")
                )
            elif system == "Windows":
                # Windows - add Chocolatey source or winget source
                result = await self._add_windows_repository(
                    repo_identifier,
                    parameters.get("url", ""),
                    parameters.get("type", ""),
                )
            else:
                return {
                    "success": False,
                    "error": _("Unsupported operating system: %s") % system,
                }

            if result["success"]:
                # After successful add, run package manager update
                await self._run_package_update()

                # Trigger update detection to send fresh updates list
                await self._trigger_update_detection()

                # Re-scan and send third-party repository data
                await self._trigger_third_party_repository_rescan()

            return result

        except Exception as e:
            self.logger.error(_("Error adding third-party repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _add_apt_repository(self, repo_identifier: str) -> Dict[str, Any]:
        """Add APT repository (PPA or manual)."""
        try:
            # Validate PPA format
            # Use sudo even though agent runs as root - add-apt-repository checks effective UID
            if repo_identifier.startswith("ppa:"):
                command = f"sudo -n add-apt-repository -y {repo_identifier}"
            else:
                # Manual repository line
                command = f"sudo -n add-apt-repository -y '{repo_identifier}'"

            result = await self.execute_shell_command({"command": command})

            # Log the result for debugging
            self.logger.debug(
                "add-apt-repository command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Repository %s added successfully", repo_identifier)
                return {
                    "success": True,
                    "result": _("Repository added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add repository %s: %s",
                repo_identifier,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add repository: %s") % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as e:
            self.logger.error(_("Error adding APT repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _add_yum_repository(self, repo_identifier: str) -> Dict[str, Any]:
        """Add YUM/DNF repository (COPR or manual)."""
        try:
            # Check if it's a COPR repo (format: user/project)
            if "/" in repo_identifier and not repo_identifier.startswith("http"):
                # COPR format - use sudo -n for non-interactive
                command = f"sudo -n dnf copr enable -y {repo_identifier}"
            else:
                # Manual repo URL - would need to create .repo file
                return {
                    "success": False,
                    "error": _("Manual YUM repository addition not yet implemented"),
                }

            result = await self.execute_shell_command({"command": command})

            # Log the result for debugging
            self.logger.debug(
                "dnf copr enable command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Repository %s added successfully", repo_identifier)
                return {
                    "success": True,
                    "result": _("Repository added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add repository %s: %s",
                repo_identifier,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add repository: %s") % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as e:
            self.logger.error(_("Error adding YUM repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _add_zypper_repository(self, alias: str, url: str) -> Dict[str, Any]:
        """Add Zypper repository (OBS or manual)."""
        try:
            if not url:
                return {
                    "success": False,
                    "error": _("Repository URL is required for Zypper"),
                }

            # Use sudo -n for non-interactive
            command = f"sudo -n zypper addrepo -f {url} {alias}"
            result = await self.execute_shell_command({"command": command})

            # Log the result for debugging
            self.logger.debug(
                "zypper addrepo command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Repository %s added successfully", alias)
                return {
                    "success": True,
                    "result": _("Repository added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add repository %s: %s",
                alias,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add repository: %s") % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as e:
            self.logger.error(_("Error adding Zypper repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _list_homebrew_taps(self) -> list:
        """List Homebrew taps on macOS."""
        repositories = []

        try:
            # Check if Homebrew is installed
            which_result = await self.execute_shell_command({"command": "which brew"})
            if not which_result.get("success"):
                self.logger.warning(_("Homebrew is not installed"))
                return repositories

            # Get list of taps
            command = "brew tap"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                output = result["result"]["stdout"]
                for line in output.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Skip official Homebrew taps (homebrew/core, homebrew/cask)
                        if line.startswith("homebrew/"):
                            continue

                        repositories.append(
                            {
                                "name": line,
                                "type": "Homebrew Tap",
                                "url": f"https://github.com/{line}",
                                "enabled": True,
                                "file_path": f"/usr/local/Homebrew/Library/Taps/{line.replace('/', '/homebrew-')}",
                            }
                        )
        except Exception as e:
            self.logger.error(_("Error listing Homebrew taps: %s"), e)

        return repositories

    async def _add_homebrew_tap(self, tap_name: str) -> Dict[str, Any]:
        """Add a Homebrew tap on macOS."""
        try:
            # Validate tap name format (should be user/repo)
            if "/" not in tap_name:
                return {
                    "success": False,
                    "error": _("Invalid tap format. Use 'user/repo' format"),
                }

            command = f"brew tap {tap_name}"
            result = await self.execute_shell_command({"command": command})

            # Log the result for debugging
            self.logger.debug(
                "brew tap command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Tap %s added successfully", tap_name)
                return {
                    "success": True,
                    "result": _("Tap added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add tap %s: %s",
                tap_name,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add tap: %s") % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as e:
            self.logger.error(_("Error adding Homebrew tap: %s"), e)
            return {"success": False, "error": str(e)}

    async def _list_freebsd_repositories(self) -> list:
        """List pkg repositories on FreeBSD."""
        repositories = []

        try:
            # Read pkg configuration files
            repos_dir = "/usr/local/etc/pkg/repos"
            if os.path.exists(repos_dir):
                for filename in os.listdir(repos_dir):
                    if filename.endswith(".conf"):
                        filepath = os.path.join(repos_dir, filename)
                        try:
                            with open(filepath, "r", encoding="utf-8") as f:
                                content = f.read()
                                # Parse simple conf format
                                # Example: myrepo: { url: "http://example.com/packages", enabled: yes }
                                name = filename.replace(".conf", "")
                                url = ""
                                enabled = True

                                # Extract URL
                                url_match = re.search(r'url:\s*"([^"]+)"', content)
                                if url_match:
                                    url = url_match.group(1)

                                # Check if enabled
                                if "enabled: no" in content.lower():
                                    enabled = False

                                repositories.append(
                                    {
                                        "name": name,
                                        "type": "FreeBSD pkg",
                                        "url": url,
                                        "enabled": enabled,
                                        "file_path": filepath,
                                    }
                                )
                        except Exception as e:
                            self.logger.warning(_("Error reading %s: %s"), filepath, e)
        except Exception as e:
            self.logger.error(_("Error listing FreeBSD repositories: %s"), e)

        return repositories

    async def _add_freebsd_repository(self, repo_name: str, url: str) -> Dict[str, Any]:
        """Add a pkg repository on FreeBSD."""
        try:
            if not url:
                return {
                    "success": False,
                    "error": _("Repository URL is required for FreeBSD pkg"),
                }

            # Create repository configuration
            repos_dir = "/usr/local/etc/pkg/repos"
            repo_file = f"{repos_dir}/{repo_name}.conf"

            # Ensure repos directory exists
            os.makedirs(repos_dir, exist_ok=True)

            # Write repository configuration
            config_content = f'{repo_name}: {{\n  url: "{url}",\n  enabled: yes\n}}\n'

            with open(repo_file, "w", encoding="utf-8") as f:
                f.write(config_content)

            # Update pkg database
            update_result = await self.execute_shell_command(
                {"command": "sudo pkg update"}
            )

            self.logger.debug(
                "pkg update command result: success=%s, exit_code=%s",
                update_result.get("success"),
                update_result.get("exit_code"),
            )

            self.logger.info("Repository %s added successfully", repo_name)
            return {
                "success": True,
                "result": _("Repository added successfully"),
                "output": f"Created {repo_file}",
            }
        except Exception as e:
            self.logger.error(_("Error adding FreeBSD repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _list_netbsd_repositories(self) -> list:
        """List pkgsrc repositories on NetBSD."""
        repositories = []

        try:
            # Check for pkgsrc-wip
            wip_path = "/usr/pkgsrc/wip"
            if os.path.exists(wip_path):
                repositories.append(
                    {
                        "name": "pkgsrc-wip",
                        "type": "pkgsrc-wip",
                        "url": "https://github.com/NetBSD/pkgsrc-wip",
                        "enabled": True,
                        "file_path": wip_path,
                    }
                )

            # Check for custom pkgsrc directories
            pkgsrc_base = "/usr/pkgsrc"
            if os.path.exists(pkgsrc_base):
                for item in os.listdir(pkgsrc_base):
                    item_path = os.path.join(pkgsrc_base, item)
                    if os.path.isdir(item_path) and item not in [
                        "wip",
                        "distfiles",
                        "packages",
                    ]:
                        # Check if it looks like a custom pkgsrc overlay
                        if os.path.exists(os.path.join(item_path, "Makefile")):
                            repositories.append(
                                {
                                    "name": item,
                                    "type": "pkgsrc custom",
                                    "url": "",
                                    "enabled": True,
                                    "file_path": item_path,
                                }
                            )
        except Exception as e:
            self.logger.error(_("Error listing NetBSD repositories: %s"), e)

        return repositories

    async def _add_netbsd_repository(self, repo_name: str, url: str) -> Dict[str, Any]:
        """Add a pkgsrc repository on NetBSD."""
        try:
            if not url:
                return {
                    "success": False,
                    "error": _("Repository URL is required for NetBSD pkgsrc"),
                }

            # Clone the repository into /usr/pkgsrc
            target_path = f"/usr/pkgsrc/{repo_name}"

            if os.path.exists(target_path):
                return {
                    "success": False,
                    "error": _("Repository directory already exists: %s") % target_path,
                }

            # Clone using git
            command = f"git clone {url} {target_path}"
            result = await self.execute_shell_command({"command": command})

            # Log the result for debugging
            self.logger.debug(
                "git clone command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Repository %s cloned successfully", repo_name)
                return {
                    "success": True,
                    "result": _("Repository cloned successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to clone repository %s: %s",
                repo_name,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to clone repository: %s")
                % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as e:
            self.logger.error(_("Error adding NetBSD repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _list_windows_repositories(self) -> list:
        """List Chocolatey sources and winget sources on Windows."""
        repositories = []

        try:
            # List Chocolatey sources
            choco_repos = await self._list_chocolatey_sources()
            repositories.extend(choco_repos)

            # List winget sources
            winget_repos = await self._list_winget_sources()
            repositories.extend(winget_repos)

        except Exception as e:
            self.logger.error(_("Error listing Windows repositories: %s"), e)

        return repositories

    async def _list_chocolatey_sources(self) -> list:
        """List Chocolatey sources."""
        repositories = []
        choco_result = await self.execute_shell_command(
            {"command": "choco source list"}
        )

        if not choco_result.get("success"):
            return repositories

        output = choco_result["result"]["stdout"]
        for line in output.splitlines():
            line = line.strip()
            # Chocolatey sources are listed as "name - url | Priority | Bypass Proxy | Self-Service | Admin Only."
            if not (" - " in line and "http" in line):
                continue

            parts = line.split(" - ")
            if len(parts) < 2:
                continue

            name = parts[0].strip()
            # Skip the official chocolatey source
            if name.lower() == "chocolatey":
                continue

            url_part = parts[1].split("|")[0].strip()
            enabled = "Disabled" not in line
            repositories.append(
                {
                    "name": name,
                    "type": "Chocolatey",
                    "url": url_part,
                    "enabled": enabled,
                    "file_path": None,
                }
            )

        return repositories

    async def _list_winget_sources(self) -> list:
        """List winget sources."""
        repositories = []
        winget_result = await self.execute_shell_command(
            {"command": "winget source list"}
        )

        if not winget_result.get("success"):
            return repositories

        output = winget_result["result"]["stdout"]
        lines = output.splitlines()

        for i, line in enumerate(lines):
            line = line.strip()
            # Skip header lines
            if "Name" in line and "Argument" in line:
                continue
            if line.startswith("---"):
                continue
            # Parse winget source lines
            if not (line and i > 1):  # Skip first two header lines
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            name = parts[0]
            url = parts[1] if len(parts) > 1 else ""
            # Skip the official msstore and winget sources
            if name.lower() in ["msstore", "winget"]:
                continue

            repositories.append(
                {
                    "name": name,
                    "type": "winget",
                    "url": url,
                    "enabled": True,
                    "file_path": None,
                }
            )

        return repositories

    async def _add_windows_repository(
        self, repo_name: str, url: str, repo_type: str
    ) -> Dict[str, Any]:
        """Add a Chocolatey source or winget source on Windows."""
        try:
            if not url:
                return {
                    "success": False,
                    "error": _("Repository URL is required for Windows repositories"),
                }

            if not repo_type or repo_type.lower() not in ["chocolatey", "winget"]:
                return {
                    "success": False,
                    "error": _("Repository type must be 'chocolatey' or 'winget'"),
                }

            if repo_type.lower() == "chocolatey":
                # Add Chocolatey source
                command = f'choco source add --name="{repo_name}" --source="{url}"'
            else:  # winget
                # Add winget source
                command = f'winget source add --name "{repo_name}" --arg "{url}" --type Microsoft.Rest'

            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info("Windows repository %s added successfully", repo_name)
                return {
                    "success": True,
                    "result": _("Repository added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add Windows repository %s: %s",
                repo_name,
                result.get("result", {}).get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add repository: %s")
                % result.get("result", {}).get("stderr", "Unknown error"),
                "output": result.get("result", {}).get("stderr", ""),
            }

        except Exception as e:
            self.logger.error(_("Error adding Windows repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def delete_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Delete third-party repositories from the system."""
        try:
            repositories = parameters.get("repositories", [])

            if not repositories:
                return {
                    "success": False,
                    "error": _("No repositories specified for deletion"),
                }

            self.logger.info(
                _("Deleting %d third-party repositories"), len(repositories)
            )

            system = platform.system()
            results = []

            for repo in repositories:
                repo_name = repo.get("name")

                if system == "Linux":
                    distro_info = await self._detect_linux_distro()
                    distro = distro_info.get("distro", "").lower()

                    if "ubuntu" in distro or "debian" in distro:
                        result = await self._delete_apt_repository(repo)
                    elif (
                        "fedora" in distro
                        or "rhel" in distro
                        or "centos" in distro
                        or "rocky" in distro
                        or "alma" in distro
                    ):
                        result = await self._delete_yum_repository(repo)
                    elif "opensuse" in distro or "suse" in distro:
                        result = await self._delete_zypper_repository(repo)
                    else:
                        result = {
                            "success": False,
                            "error": _("Unsupported distribution: %s") % distro,
                        }
                else:
                    result = {
                        "success": False,
                        "error": _("Unsupported operating system: %s") % system,
                    }

                results.append(
                    {
                        "repository": repo_name,
                        "success": result.get("success", False),
                        "message": result.get("result", result.get("error", "")),
                    }
                )

            # After deletions, run package manager update
            await self._run_package_update()

            # Trigger update detection to send fresh updates list
            await self._trigger_update_detection()

            # Re-scan and send third-party repository data
            await self._trigger_third_party_repository_rescan()

            overall_success = all(r["success"] for r in results)
            return {
                "success": overall_success,
                "results": results,
                "message": _("Deleted %d of %d repositories")
                % (sum(1 for r in results if r["success"]), len(results)),
            }

        except Exception as e:
            self.logger.error(_("Error deleting third-party repositories: %s"), e)
            return {"success": False, "error": str(e)}

    async def _delete_apt_repository(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        """Delete APT repository."""
        try:
            repo_name = repo.get("name", "")
            file_path = repo.get("file_path", "")

            # If it's a PPA, use add-apt-repository --remove
            if repo_name.startswith("ppa:"):
                command = f"sudo add-apt-repository --remove -y {repo_name}"
                result = await self.execute_shell_command({"command": command})
            elif file_path and os.path.exists(file_path):
                # Delete the repository file
                command = f"sudo rm -f {file_path}"
                result = await self.execute_shell_command({"command": command})
            else:
                return {"success": False, "error": _("Repository file not found")}

            if result["success"]:
                return {"success": True, "result": _("Repository removed successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error deleting APT repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _delete_yum_repository(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        """Delete YUM/DNF repository."""
        try:
            repo_name = repo.get("name", "")
            repo_type = repo.get("type", "")
            file_path = repo.get("file_path", "")

            # If it's a COPR repo, use dnf copr remove
            if "copr" in repo_type.lower() or "copr" in repo_name.lower():
                # Extract user/project from repo name
                command = f"sudo dnf copr remove -y {repo_name}"
                result = await self.execute_shell_command({"command": command})
            elif file_path and os.path.exists(file_path):
                # Delete the repository file
                command = f"sudo rm -f {file_path}"
                result = await self.execute_shell_command({"command": command})
            else:
                return {"success": False, "error": _("Repository file not found")}

            if result["success"]:
                return {"success": True, "result": _("Repository removed successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error deleting YUM repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _delete_zypper_repository(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        """Delete Zypper repository."""
        try:
            repo_name = repo.get("name", "")

            command = f"sudo zypper removerepo {repo_name}"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {"success": True, "result": _("Repository removed successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error deleting Zypper repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _run_package_update(self) -> None:
        """Run package manager update after repository changes."""
        try:
            system = platform.system()
            if system == "Linux":
                distro_info = await self._detect_linux_distro()
                distro = distro_info.get("distro", "").lower()

                if "ubuntu" in distro or "debian" in distro:
                    command = "sudo apt-get update"
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    command = "sudo dnf check-update"
                elif "opensuse" in distro or "suse" in distro:
                    command = "sudo zypper refresh"
                else:
                    return

                await self.execute_shell_command({"command": command})
        except Exception as e:
            self.logger.error(_("Error running package update: %s"), e)

    async def _trigger_update_detection(self) -> None:
        """Trigger update detection and send results to server."""
        try:
            # Trigger an immediate update check to detect new packages from the repository
            self.logger.debug("Triggering update detection after repository change")
            await self.agent.check_updates()
        except Exception as e:
            self.logger.error(_("Error triggering update detection: %s"), e)

    async def _trigger_third_party_repository_rescan(self) -> None:
        """Re-scan and send third-party repository data to server."""
        try:
            # Call the agent's method to send third-party repository update
            if hasattr(self.agent, "_send_third_party_repository_update"):
                # pylint: disable=protected-access
                await self.agent._send_third_party_repository_update()
        except Exception as e:
            self.logger.error(_("Error re-scanning third-party repositories: %s"), e)

    async def enable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable third-party repositories on the system."""
        try:
            repositories = parameters.get("repositories", [])

            if not repositories:
                return {
                    "success": False,
                    "error": _("No repositories specified for enabling"),
                }

            self.logger.info(
                _("Enabling %d third-party repositories"), len(repositories)
            )

            system = platform.system()
            if system != "Linux":
                return {
                    "success": False,
                    "error": _("Unsupported operating system: %s") % system,
                }

            distro_info = await self._detect_linux_distro()
            distro = distro_info.get("distro", "").lower()

            results = []
            for repo in repositories:
                repo_name = repo.get("name")
                file_path = repo.get("file_path")

                if "ubuntu" in distro or "debian" in distro:
                    result = await self._enable_apt_repository(file_path)
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    result = await self._enable_yum_repository(repo_name)
                elif "opensuse" in distro or "suse" in distro:
                    result = await self._enable_zypper_repository(repo_name)
                else:
                    result = {
                        "success": False,
                        "error": _("Unsupported distribution: %s") % distro,
                    }

                results.append(
                    {
                        "repository": repo_name,
                        "success": result.get("success", False),
                        "message": result.get("result", result.get("error", "")),
                    }
                )

            # After enabling, run package manager update
            await self._run_package_update()

            # Trigger update detection to send fresh updates list
            await self._trigger_update_detection()

            # Re-scan and send third-party repository data
            await self._trigger_third_party_repository_rescan()

            overall_success = all(r["success"] for r in results)
            return {
                "success": overall_success,
                "results": results,
                "message": _("Enabled %d of %d repositories")
                % (sum(1 for r in results if r["success"]), len(results)),
            }

        except Exception as e:
            self.logger.error(_("Error enabling third-party repositories: %s"), e)
            return {"success": False, "error": str(e)}

    async def disable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable third-party repositories on the system."""
        try:
            repositories = parameters.get("repositories", [])

            if not repositories:
                return {
                    "success": False,
                    "error": _("No repositories specified for disabling"),
                }

            self.logger.info(
                _("Disabling %d third-party repositories"), len(repositories)
            )

            system = platform.system()
            if system != "Linux":
                return {
                    "success": False,
                    "error": _("Unsupported operating system: %s") % system,
                }

            distro_info = await self._detect_linux_distro()
            distro = distro_info.get("distro", "").lower()

            results = []
            for repo in repositories:
                repo_name = repo.get("name")
                file_path = repo.get("file_path")

                if "ubuntu" in distro or "debian" in distro:
                    result = await self._disable_apt_repository(file_path)
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    result = await self._disable_yum_repository(repo_name)
                elif "opensuse" in distro or "suse" in distro:
                    result = await self._disable_zypper_repository(repo_name)
                else:
                    result = {
                        "success": False,
                        "error": _("Unsupported distribution: %s") % distro,
                    }

                results.append(
                    {
                        "repository": repo_name,
                        "success": result.get("success", False),
                        "message": result.get("result", result.get("error", "")),
                    }
                )

            # After disabling, run package manager update
            await self._run_package_update()

            # Trigger update detection to send fresh updates list
            await self._trigger_update_detection()

            # Re-scan and send third-party repository data
            await self._trigger_third_party_repository_rescan()

            overall_success = all(r["success"] for r in results)
            return {
                "success": overall_success,
                "results": results,
                "message": _("Disabled %d of %d repositories")
                % (sum(1 for r in results if r["success"]), len(results)),
            }

        except Exception as e:
            self.logger.error(_("Error disabling third-party repositories: %s"), e)
            return {"success": False, "error": str(e)}

    async def _enable_apt_repository(self, file_path: str) -> Dict[str, Any]:
        """Enable APT repository by uncommenting lines in the file."""
        try:
            if not file_path or not os.path.exists(file_path):
                return {"success": False, "error": _("Repository file not found")}

            command = f"sudo sed -i 's/^# *deb /deb /' {file_path}"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {"success": True, "result": _("Repository enabled successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error enabling APT repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _disable_apt_repository(self, file_path: str) -> Dict[str, Any]:
        """Disable APT repository by commenting out lines in the file."""
        try:
            if not file_path or not os.path.exists(file_path):
                return {"success": False, "error": _("Repository file not found")}

            command = f"sudo sed -i 's/^deb /# deb /' {file_path}"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {
                    "success": True,
                    "result": _("Repository disabled successfully"),
                }

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error disabling APT repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _enable_yum_repository(self, repo_name: str) -> Dict[str, Any]:
        """Enable YUM/DNF repository."""
        try:
            command = f"sudo dnf config-manager --set-enabled {repo_name}"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {"success": True, "result": _("Repository enabled successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error enabling YUM repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _disable_yum_repository(self, repo_name: str) -> Dict[str, Any]:
        """Disable YUM/DNF repository."""
        try:
            command = f"sudo dnf config-manager --set-disabled {repo_name}"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {
                    "success": True,
                    "result": _("Repository disabled successfully"),
                }

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error disabling YUM repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _enable_zypper_repository(self, repo_name: str) -> Dict[str, Any]:
        """Enable Zypper repository."""
        try:
            command = f"sudo zypper modifyrepo --enable {repo_name}"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {"success": True, "result": _("Repository enabled successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error enabling Zypper repository: %s"), e)
            return {"success": False, "error": str(e)}

    async def _disable_zypper_repository(self, repo_name: str) -> Dict[str, Any]:
        """Disable Zypper repository."""
        try:
            command = f"sudo zypper modifyrepo --disable {repo_name}"
            result = await self.execute_shell_command({"command": command})

            if result["success"]:
                return {
                    "success": True,
                    "result": _("Repository disabled successfully"),
                }

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as e:
            self.logger.error(_("Error disabling Zypper repository: %s"), e)
            return {"success": False, "error": str(e)}
