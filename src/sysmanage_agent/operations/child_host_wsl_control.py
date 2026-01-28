"""
WSL child host control operations (start, stop, restart, delete).
"""

import asyncio
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, Optional

from src.i18n import _

# String constant for validation error
_CHILD_NAME_REQUIRED = "Child name is required"

# Windows registry access for WSL GUID verification
try:
    import winreg
except ImportError:
    winreg = None  # type: ignore[misc, assignment]


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

    def _get_wsl_guid(self, distribution_name: str) -> Optional[str]:
        """
        Get the unique GUID for a WSL distribution from the Windows registry.

        WSL assigns a unique GUID to each distribution instance. This GUID changes
        when a distribution is deleted and recreated, even with the same name.

        Args:
            distribution_name: WSL distribution name (e.g., "Ubuntu-24.04")

        Returns:
            GUID string (e.g., "0283592d-be56-40d4-b935-3dc18c3aa007") or None
        """
        if winreg is None:
            return None

        try:
            lxss_key_path = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, lxss_key_path) as lxss_key:
                index = 0
                while True:
                    try:
                        guid = winreg.EnumKey(lxss_key, index)
                        with winreg.OpenKey(lxss_key, guid) as dist_key:
                            try:
                                dist_name, _ = winreg.QueryValueEx(
                                    dist_key, "DistributionName"
                                )
                                if dist_name == distribution_name:
                                    return guid.strip("{}")
                            except FileNotFoundError:
                                pass
                        index += 1
                    except OSError:
                        break
        except FileNotFoundError:
            self.logger.debug("WSL registry key not found")
        except Exception as error:
            self.logger.debug(
                "Error reading WSL GUID for %s: %s", distribution_name, error
            )

        return None

    async def start_child_host(  # NOSONAR - async required for interface compatibility
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
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
            return {"success": False, "error": _(_CHILD_NAME_REQUIRED)}

        self.logger.info(_("Starting WSL instance: %s"), child_name)

        try:
            # Start the distribution by running a simple command
            # This will boot the WSL instance if it's not running
            proc = await asyncio.create_subprocess_exec(
                "wsl",
                "-d",
                child_name,
                "--",
                "echo",
                "Started",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                proc.kill()
                return {"success": False, "error": _("Start operation timed out")}

            output = self._decode_wsl_output(stdout, stderr)

            if proc.returncode != 0:
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

        except Exception as error:
            self.logger.error(_("Error starting WSL instance: %s"), error)
            return {"success": False, "error": str(error)}

    async def stop_child_host(  # NOSONAR - async required for interface compatibility
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
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
            return {"success": False, "error": _(_CHILD_NAME_REQUIRED)}

        self.logger.info(_("Stopping WSL instance: %s"), child_name)

        try:
            # Terminate the distribution
            proc = await asyncio.create_subprocess_exec(
                "wsl",
                "--terminate",
                child_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                return {"success": False, "error": _("Stop operation timed out")}

            output = self._decode_wsl_output(stdout, stderr)

            if proc.returncode != 0:
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
            return {"success": False, "error": _(_CHILD_NAME_REQUIRED)}

        self.logger.info(_("Restarting WSL instance: %s"), child_name)

        # Stop the instance
        stop_result = await self.stop_child_host(parameters)
        if not stop_result.get("success"):
            # If stop failed for a reason other than "already stopped", return error
            if "already stopped" not in stop_result.get("message", ""):
                return stop_result

        # Wait a moment for the stop to complete
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

    async def delete_child_host(  # NOSONAR - async required for interface compatibility
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Delete (unregister) a WSL instance. This permanently removes the instance
        and all its data.

        If a wsl_guid is provided in the parameters, the agent will verify that
        the current WSL instance's GUID matches before deleting. This prevents
        stale delete commands from deleting a newly recreated instance with
        the same name.

        Args:
            parameters: Dict containing:
                - child_name: Name of the WSL distribution to delete
                - wsl_guid: (optional) Expected GUID of the instance to delete

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _(_CHILD_NAME_REQUIRED)}

        expected_guid = parameters.get("wsl_guid")

        # If a GUID was provided, verify it matches the current instance
        if expected_guid:
            guid_check = self._verify_wsl_guid(child_name, expected_guid)
            if guid_check is not None:
                return guid_check

        self.logger.info(_("Deleting WSL instance: %s"), child_name)

        try:
            # Unregister the distribution - this removes all data
            proc = await asyncio.create_subprocess_exec(
                "wsl",
                "--unregister",
                child_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                proc.kill()
                return {"success": False, "error": _("Delete operation timed out")}

            output = self._decode_wsl_output(stdout, stderr)

            if proc.returncode != 0:
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

        except Exception as error:
            self.logger.error(_("Error deleting WSL instance: %s"), error)
            return {"success": False, "error": str(error)}

    def _verify_wsl_guid(
        self, child_name: str, expected_guid: str
    ) -> Optional[Dict[str, Any]]:
        """Verify WSL GUID matches expected value. Returns None if verified."""
        current_guid = self._get_wsl_guid(child_name)

        if current_guid is None:
            self.logger.info(
                "WSL instance %s not found (expected GUID: %s)",
                child_name,
                expected_guid,
            )
            return {
                "success": True,
                "child_name": child_name,
                "child_type": "wsl",
                "message": _("WSL instance '%s' was already deleted") % child_name,
            }

        if current_guid.lower() != expected_guid.lower():
            self.logger.warning(
                "WSL GUID mismatch for %s: expected %s, found %s. "
                "Refusing to delete - this is a different instance.",
                child_name,
                expected_guid,
                current_guid,
            )
            return {
                "success": False,
                "error": _(
                    "WSL instance '%s' has a different GUID than expected. "
                    "This instance was likely recreated. Refusing to delete."
                )
                % child_name,
                "expected_guid": expected_guid,
                "current_guid": current_guid,
            }

        self.logger.info("WSL GUID verified for %s: %s", child_name, current_guid)
        return None
