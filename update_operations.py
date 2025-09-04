"""
Update operations module for SysManage agent.
Handles package update checking and application operations.
"""

import asyncio
import concurrent.futures
import logging
from typing import Dict, Any

from update_detection import UpdateDetector
from i18n import _


class UpdateOperations:
    """Handles update-related operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize update operations with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

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
        except Exception as e:
            self.logger.error("Failed to check updates: %s", e)
            return {"success": False, "error": str(e)}

    async def apply_updates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply updates for specified packages."""
        try:
            package_names = parameters.get("package_names", [])
            package_managers = parameters.get("package_managers")

            if not package_names:
                return {
                    "success": False,
                    "error": _("No packages specified for update"),
                }

            # Start the update process in a background task to avoid blocking WebSocket
            asyncio.create_task(
                self._apply_updates_background(package_names, package_managers)
            )

            return {
                "success": True,
                "result": _("Updates started in background"),
                "packages": package_names,
            }
        except Exception as e:
            self.logger.error(_("Failed to start updates: %s"), e)
            return {"success": False, "error": str(e)}

    async def _apply_updates_background(self, package_names: list, package_managers):
        """Apply updates in background to avoid blocking WebSocket connection."""
        try:
            self.logger.info(_("Starting background update process"))

            # Initialize update detector
            update_detector = UpdateDetector()

            # Validate packages exist and get their package managers
            valid_packages = []
            for package_name in package_names:
                if package_managers and package_name in package_managers:
                    package_manager = package_managers[package_name]
                    valid_packages.append(
                        {"name": package_name, "package_manager": package_manager}
                    )
                else:
                    # Try to detect the package manager automatically
                    detected_manager = update_detector.detect_package_manager(
                        package_name
                    )
                    if detected_manager:
                        valid_packages.append(
                            {"name": package_name, "package_manager": detected_manager}
                        )
                    else:
                        self.logger.warning(
                            _("Could not determine package manager for %s"),
                            package_name,
                        )

            if not valid_packages:
                self.logger.error(_("No valid packages found for update"))
                return

            # Run the synchronous update process in an executor to avoid blocking
            loop = asyncio.get_event_loop()

            with concurrent.futures.ThreadPoolExecutor() as executor:
                update_results = await loop.run_in_executor(
                    executor,
                    update_detector.apply_updates,
                    valid_packages,
                    package_managers,
                )

            # Add hostname to result data
            system_info = self.agent.registration.get_system_info()
            update_results["hostname"] = system_info["hostname"]

            self.logger.info(_("Background update process completed"))

            # Create update result message
            update_message = self.agent.create_message(
                "update_apply_result", update_results
            )

            # Try to send update results, retrying if not connected
            max_retries = 30  # Try for up to 5 minutes (30 * 10 seconds)
            for retry in range(max_retries):
                if self.agent.connected and self.agent.websocket:
                    success = await self.agent.send_message(update_message)
                    if success:
                        self.logger.info(
                            _("Successfully sent update results to server")
                        )
                        break
                    self.logger.warning(
                        _("Failed to send update results, will retry...")
                    )
                else:
                    self.logger.info(
                        _(
                            "Waiting for reconnection to send update results (attempt %d/%d)"
                        ),
                        retry + 1,
                        max_retries,
                    )

                # Wait before retry
                await asyncio.sleep(10)

            else:
                self.logger.error(
                    _("Failed to send update results after %d attempts"), max_retries
                )

        except Exception as e:
            self.logger.error(_("Background update process failed: %s"), e)
