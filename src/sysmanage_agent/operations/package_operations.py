"""
Package operations module for SysManage agent.
Handles package installation, uninstallation, and related operations.
"""

import asyncio
import json
import logging
import os
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from src.database.base import get_database_manager
from src.database.models import InstallationRequestTracking
from src.i18n import _
from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.sysmanage_agent.operations import package_installation_helpers


class PackageOperations:
    """Handles package-related operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize package operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

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

        except Exception as error:
            error_message = str(error)
            self.logger.error(
                _("Failed to install package %s: %s"), package_name, error
            )

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

    async def install_packages(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
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
        success, error_msg = (
            package_installation_helpers.create_installation_tracking_record(
                request_id, requested_by, packages
            )
        )
        if not success:
            return {"success": False, "error": error_msg}

        # Validate packages and extract valid ones
        valid_packages, failed_packages = (
            package_installation_helpers.validate_packages(packages, self.logger)
        )

        if not valid_packages:
            installation_log = ["No valid packages to install"]
            return {
                "success": True,
                "message": "No packages to install",
                "log": installation_log,
                "failed_packages": failed_packages,
                "success_packages": [],
            }

        # Group packages by package manager
        package_groups = package_installation_helpers.group_packages_by_manager(
            valid_packages
        )

        # Install packages for each package manager
        success_packages = []
        installation_log = []

        for pkg_manager, pkg_list in package_groups.items():
            if pkg_manager == "apt":
                apt_success, apt_failed, apt_log = (
                    await package_installation_helpers.install_apt_packages(
                        pkg_list, self._install_packages_with_apt, self.logger
                    )
                )
                success_packages.extend(apt_success)
                failed_packages.extend(apt_failed)
                installation_log.extend(apt_log)
            else:
                non_apt_success, non_apt_failed, non_apt_log = (
                    package_installation_helpers.install_non_apt_packages(
                        pkg_list, pkg_manager, self.logger
                    )
                )
                success_packages.extend(non_apt_success)
                failed_packages.extend(non_apt_failed)
                installation_log.extend(non_apt_log)

        # Determine overall success
        overall_success = len(failed_packages) == 0
        installation_log_text = "\n".join(installation_log)

        # Update tracking record with completion
        package_installation_helpers.update_installation_tracking_record(
            request_id, overall_success, installation_log_text
        )

        # Send completion notification to server via HTTP POST
        try:
            await self._send_installation_completion(
                request_id, overall_success, installation_log_text
            )
        except Exception as error:
            self.logger.error(
                _("Failed to send installation completion to server: %s"), error
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

        except Exception as error:
            self.logger.error("Failed to store uninstall request: %s", error)
            return {
                "success": False,
                "error": f"Failed to store uninstall request: {str(error)}",
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

        except Exception as error:
            self.logger.error("Failed to update uninstall tracking record: %s", error)

        # Send completion notification to server via HTTP POST
        try:
            await self._send_installation_completion(
                request_id, overall_success, uninstall_log_text
            )
        except Exception as error:
            self.logger.error(
                "Failed to send uninstall completion to server: %s", error
            )

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

        except Exception as error:
            self.logger.error("Failed to install packages with apt-get: %s", error)
            return {
                "success": False,
                "error": f"Exception during apt-get install: {str(error)}",
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

        except Exception as error:
            self.logger.error("Failed to uninstall packages with apt-get: %s", error)
            return {
                "success": False,
                "error": f"Exception during apt-get remove: {str(error)}",
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
            response = await self.agent_instance.call_server_api(
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

        except Exception as error:
            self.logger.error(_("Error sending installation completion: %s"), error)
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
            host_approval = self.agent_instance.get_host_approval_from_db()
            system_info = self.agent_instance.registration.get_system_info()

            # Get hostname with fallback
            hostname = system_info.get("hostname") or socket.gethostname()

            update_message = {
                "message_type": "package_installation_status",
                "message_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "installation_id": installation_id,
                "status": status,
                "package_name": package_name,
                "requested_by": requested_by,
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
            await self.agent_instance.send_message(update_message)

            self.logger.info(
                _("Sent package installation status update: %s for %s"),
                status,
                package_name,
            )

        except Exception as error:
            self.logger.error(
                _("Failed to send package installation status update: %s"), error
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

    async def _run_package_update(self) -> None:
        """Run package manager update after repository changes."""
        # Import at method level to avoid circular imports
        import platform  # pylint: disable=import-outside-toplevel

        try:
            system = platform.system()
            if system == "Linux":
                # Need to call back to system_operations for execute_shell_command
                # This is handled through the agent instance
                from src.sysmanage_agent.operations.system_operations import (  # pylint: disable=import-outside-toplevel
                    SystemOperations,
                )

                if hasattr(self.agent_instance, "system_ops") and isinstance(
                    self.agent_instance.system_ops, SystemOperations
                ):
                    distro_info = (
                        await self.agent_instance.system_ops._detect_linux_distro()  # pylint: disable=protected-access
                    )
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

                    await self.agent_instance.system_ops.execute_shell_command(
                        {"command": command}
                    )
        except Exception as error:
            self.logger.error(_("Error running package update: %s"), error)

    async def _trigger_update_detection(self) -> None:
        """Trigger update detection and send results to server."""
        try:
            # Trigger an immediate update check to detect new packages from the repository
            self.logger.debug("Triggering update detection after repository change")
            await self.agent_instance.check_updates()
        except Exception as error:
            self.logger.error(_("Error triggering update detection: %s"), error)
