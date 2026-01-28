"""
Update operations module for SysManage agent.
Handles package update checking and application operations.
"""

import asyncio
import concurrent.futures
import logging
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.collection.update_detection import UpdateDetector


class UpdateOperations:
    """Handles update-related operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize update operations with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self._background_update_task = None

    async def check_updates(self) -> Dict[str, Any]:
        """Check for available updates for installed packages."""
        try:
            # Initialize update detector
            update_detector = UpdateDetector()

            # Get available updates
            update_info = update_detector.get_available_updates()

            # Add hostname to update data for server processing
            system_info = self.agent.registration.get_system_info()
            update_info["hostname"] = system_info["hostname"]

            self.logger.info(
                "Update check completed: %d updates found",
                update_info.get("total_updates", 0),
            )

            # Create update message
            update_message = self.agent.create_message(
                "package_updates_update", update_info
            )

            # Send update information to server
            await self.agent.send_message(update_message)

            return {
                "success": True,
                "result": "Update check completed",
                "total_updates": update_info.get("total_updates", 0),
            }
        except Exception as error:
            self.logger.error("Failed to check updates: %s", error)
            return {"success": False, "error": str(error)}

    async def apply_updates(  # NOSONAR - async required by interface
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply updates for specified packages."""
        try:
            # Support both old and new parameter formats
            # Old format: {"package_names": [...], "package_managers": [...]}
            # New format: {"packages": [{"package_name": "...", "bundle_id": "...", "package_manager": "..."}]}

            packages_list = parameters.get("packages", [])
            if packages_list:
                # New format with packages array
                package_names = [pkg.get("package_name") for pkg in packages_list]
                package_managers = [pkg.get("package_manager") for pkg in packages_list]
            else:
                # Old format with separate lists
                package_names = parameters.get("package_names", [])
                package_managers = parameters.get("package_managers")

            if not package_names:
                return {
                    "success": False,
                    "error": _("No packages specified for update"),
                }

            # Start the update process in a background task to avoid blocking WebSocket
            # Store task reference to prevent garbage collection
            self._background_update_task = asyncio.create_task(
                self._apply_updates_background(
                    package_names, package_managers, packages_list
                )
            )

            return {
                "success": True,
                "result": _("Updates started in background"),
                "packages": package_names,
            }
        except Exception as error:
            self.logger.error(_("Failed to start updates: %s"), error)
            return {"success": False, "error": str(error)}

    def _validate_packages_from_list(self, packages_list: list) -> list:
        """Validate packages from new format (packages array with bundle_id)."""
        valid_packages = []
        for pkg in packages_list:
            package_name = pkg.get("package_name")
            package_manager = pkg.get("package_manager")
            bundle_id = pkg.get("bundle_id")

            self.logger.info(
                _(
                    "Received update request: package='%s', manager='%s', bundle_id='%s'"
                ),
                package_name,
                package_manager,
                bundle_id if bundle_id else "NULL",
            )

            if package_name and package_manager:
                valid_packages.append(
                    {
                        "name": package_name,
                        "package_manager": package_manager,
                        "bundle_id": bundle_id,
                    }
                )
        return valid_packages

    def _validate_packages_from_managers_list(
        self, package_names: list, package_managers: list
    ) -> list:
        """Validate packages when package_managers is a list."""
        valid_packages = []
        for i, package_name in enumerate(package_names):
            if i < len(package_managers):
                valid_packages.append(
                    {"name": package_name, "package_manager": package_managers[i]}
                )
            else:
                self.logger.warning(
                    _("No package manager specified for %s"), package_name
                )
        return valid_packages

    def _validate_packages_from_managers_dict(
        self, package_names: list, package_managers, update_detector
    ) -> list:
        """Validate packages when package_managers is a dict or needs detection."""
        valid_packages = []
        for package_name in package_names:
            if package_managers and package_name in package_managers:
                valid_packages.append(
                    {
                        "name": package_name,
                        "package_manager": package_managers[package_name],
                    }
                )
            else:
                # pylint: disable-next=protected-access
                available_managers = update_detector._detect_package_managers()
                if available_managers:
                    detected_manager = available_managers[0]
                    self.logger.info(
                        _("Using detected package manager '%s' for %s"),
                        detected_manager,
                        package_name,
                    )
                    valid_packages.append(
                        {"name": package_name, "package_manager": detected_manager}
                    )
                else:
                    self.logger.warning(
                        _("Could not determine package manager for %s"), package_name
                    )
        return valid_packages

    async def _send_update_results_with_retry(self, update_message: dict) -> bool:
        """Send update results with retry logic."""
        max_retries = 30
        for retry in range(max_retries):
            if self.agent.connected and self.agent.websocket:
                success = await self.agent.send_message(update_message)
                if success:
                    self.logger.info(_("Successfully sent update results to server"))
                    return True
                self.logger.warning(_("Failed to send update results, will retry..."))
            else:
                self.logger.info(
                    _(
                        "Waiting for reconnection to send update results (attempt %d/%d)"
                    ),
                    retry + 1,
                    max_retries,
                )
            await asyncio.sleep(10)

        self.logger.error(
            _("Failed to send update results after %d attempts"), max_retries
        )
        return False

    async def _rescan_and_send_updates(self, hostname: str) -> None:
        """Rescan for available updates and send to server."""
        self.logger.info(_("Rescanning for available updates after batch completion"))
        fresh_update_detector = UpdateDetector()
        loop = asyncio.get_event_loop()

        fresh_update_info = await loop.run_in_executor(
            None, fresh_update_detector.get_available_updates
        )
        fresh_update_info["hostname"] = hostname

        self.logger.info(
            _("Post-update scan completed: %d updates remaining"),
            fresh_update_info.get("total_updates", 0),
        )

        fresh_update_message = self.agent.create_message(
            "package_updates_update", fresh_update_info
        )

        if self.agent.connected and self.agent.websocket:
            await self.agent.send_message(fresh_update_message)
            self.logger.info(_("Successfully sent fresh update list to server"))
        else:
            self.logger.warning(_("Could not send fresh update list - not connected"))

    async def _apply_updates_background(
        self, package_names: list, package_managers, packages_list=None
    ):
        """Apply updates in background to avoid blocking WebSocket connection."""
        try:
            self.logger.info(_("Starting background update process"))
            update_detector = UpdateDetector()

            # Validate packages based on input format
            if packages_list:
                valid_packages = self._validate_packages_from_list(packages_list)
            elif isinstance(package_managers, list):
                valid_packages = self._validate_packages_from_managers_list(
                    package_names, package_managers
                )
            else:
                valid_packages = self._validate_packages_from_managers_dict(
                    package_names, package_managers, update_detector
                )

            if not valid_packages:
                self.logger.error(_("No valid packages found for update"))
                return

            # Run update process in executor
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                update_results = await loop.run_in_executor(
                    executor,
                    lambda: update_detector.apply_updates(packages=valid_packages),
                )

            system_info = self.agent.registration.get_system_info()
            update_results["hostname"] = system_info["hostname"]
            self.logger.info(_("Background update process completed"))

            update_message = self.agent.create_message(
                "update_apply_result", update_results
            )
            results_sent = await self._send_update_results_with_retry(update_message)

            if results_sent:
                try:
                    await self._rescan_and_send_updates(system_info["hostname"])
                except Exception as scan_error:
                    self.logger.error(
                        _("Failed to rescan for updates after batch: %s"), scan_error
                    )

        except Exception as error:
            self.logger.error(_("Background update process failed: %s"), error)
