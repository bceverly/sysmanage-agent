"""
WSL child host control operations (start, stop, restart, delete).
"""

import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict

from src.i18n import _


class WslControlOperations:
    """WSL control operations for start, stop, restart, and delete."""

    def __init__(self, logger, decode_output_func):
        """
        Initialize WSL control operations.

        Args:
            logger: Logger instance
            decode_output_func: Function to decode WSL UTF-16LE output
        """
        self.logger = logger
        self._decode_wsl_output = decode_output_func

    def _get_creationflags(self) -> int:
        """Get subprocess creation flags for Windows."""
        return (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )

    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start a stopped WSL instance.

        Args:
            parameters: Dict containing:
                - child_name: Name of the WSL distribution to start

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _("Child name is required")}

        self.logger.info(_("Starting WSL instance: %s"), child_name)

        try:
            # Start the distribution by running a simple command
            # This will boot the WSL instance if it's not running
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", child_name, "--", "echo", "Started"],
                capture_output=True,
                timeout=120,
                check=False,
                creationflags=self._get_creationflags(),
            )

            output = self._decode_wsl_output(result.stdout, result.stderr)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start WSL instance: %s") % output,
                }

            self.logger.info(_("WSL instance %s started successfully"), child_name)
            return {
                "success": True,
                "child_name": child_name,
                "child_type": "wsl",
                "status": "running",
                "message": _("WSL instance '%s' started successfully") % child_name,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Start operation timed out")}
        except Exception as error:
            self.logger.error(_("Error starting WSL instance: %s"), error)
            return {"success": False, "error": str(error)}

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stop a running WSL instance.

        Args:
            parameters: Dict containing:
                - child_name: Name of the WSL distribution to stop

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _("Child name is required")}

        self.logger.info(_("Stopping WSL instance: %s"), child_name)

        try:
            # Terminate the distribution
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--terminate", child_name],
                capture_output=True,
                timeout=60,
                check=False,
                creationflags=self._get_creationflags(),
            )

            output = self._decode_wsl_output(result.stdout, result.stderr)

            if result.returncode != 0:
                # Check if already stopped
                if "not running" in output.lower():
                    return {
                        "success": True,
                        "child_name": child_name,
                        "child_type": "wsl",
                        "status": "stopped",
                        "message": _("WSL instance '%s' was already stopped")
                        % child_name,
                    }
                return {
                    "success": False,
                    "error": _("Failed to stop WSL instance: %s") % output,
                }

            self.logger.info(_("WSL instance %s stopped successfully"), child_name)
            return {
                "success": True,
                "child_name": child_name,
                "child_type": "wsl",
                "status": "stopped",
                "message": _("WSL instance '%s' stopped successfully") % child_name,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Stop operation timed out")}
        except Exception as error:
            self.logger.error(_("Error stopping WSL instance: %s"), error)
            return {"success": False, "error": str(error)}

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restart a WSL instance (stop then start).

        Args:
            parameters: Dict containing:
                - child_name: Name of the WSL distribution to restart

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _("Child name is required")}

        self.logger.info(_("Restarting WSL instance: %s"), child_name)

        # Stop the instance
        stop_result = await self.stop_child_host(parameters)
        if not stop_result.get("success"):
            # If stop failed for a reason other than "already stopped", return error
            if "already stopped" not in stop_result.get("message", ""):
                return stop_result

        # Wait a moment for the stop to complete
        import asyncio  # pylint: disable=import-outside-toplevel

        await asyncio.sleep(2)

        # Start the instance
        start_result = await self.start_child_host(parameters)
        if not start_result.get("success"):
            return start_result

        self.logger.info(_("WSL instance %s restarted successfully"), child_name)
        return {
            "success": True,
            "child_name": child_name,
            "child_type": "wsl",
            "status": "running",
            "message": _("WSL instance '%s' restarted successfully") % child_name,
        }

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Delete (unregister) a WSL instance. This permanently removes the instance
        and all its data.

        Args:
            parameters: Dict containing:
                - child_name: Name of the WSL distribution to delete

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _("Child name is required")}

        self.logger.info(_("Deleting WSL instance: %s"), child_name)

        try:
            # Unregister the distribution - this removes all data
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--unregister", child_name],
                capture_output=True,
                timeout=120,
                check=False,
                creationflags=self._get_creationflags(),
            )

            output = self._decode_wsl_output(result.stdout, result.stderr)

            if result.returncode != 0:
                # Check if it doesn't exist
                if "not registered" in output.lower() or "not found" in output.lower():
                    return {
                        "success": True,
                        "child_name": child_name,
                        "child_type": "wsl",
                        "message": _("WSL instance '%s' was already deleted")
                        % child_name,
                    }
                return {
                    "success": False,
                    "error": _("Failed to delete WSL instance: %s") % output,
                }

            self.logger.info(_("WSL instance %s deleted successfully"), child_name)
            return {
                "success": True,
                "child_name": child_name,
                "child_type": "wsl",
                "message": _("WSL instance '%s' deleted successfully") % child_name,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Delete operation timed out")}
        except Exception as error:
            self.logger.error(_("Error deleting WSL instance: %s"), error)
            return {"success": False, "error": str(error)}
