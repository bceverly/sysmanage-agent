"""
bhyve-specific child host operations for FreeBSD hosts.

Supports creating VMs using FreeBSD's bhyve hypervisor.
"""

import asyncio
import os
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict

from src.i18n import _


class BhyveOperations:
    """bhyve-specific operations for child host management on FreeBSD."""

    def __init__(self, agent_instance, logger, virtualization_checks):
        """
        Initialize bhyve operations.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks

        # Track in-progress VM creations to prevent duplicate requests
        self._in_progress_vms: set = set()

    async def _run_subprocess(
        self,
        cmd: list,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess:
        """
        Run a subprocess command asynchronously.

        Uses asyncio.to_thread() to run the blocking subprocess.run call
        in a separate thread, preventing WebSocket keepalive timeouts.

        Args:
            cmd: Command and arguments as a list
            timeout: Timeout in seconds

        Returns:
            CompletedProcess instance with return code, stdout, stderr
        """
        return await asyncio.to_thread(
            subprocess.run,  # nosec B603 B607
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    async def initialize_bhyve(self, _parameters: dict) -> dict:
        """
        Initialize bhyve on FreeBSD: load vmm.ko and persist configuration.

        This is called when the user clicks "Enable bhyve" in the UI.

        Creates persistent configuration:
        - Adds vmm_load="YES" to /boot/loader.conf for persistence across reboots
        - Loads vmm.ko kernel module immediately

        Returns:
            Dict with success status and any required actions (like reboot)
        """
        try:
            self.logger.info(_("Initializing bhyve"))

            # Check current bhyve status
            bhyve_status = self.virtualization_checks.check_bhyve_support()
            if bhyve_status["enabled"] and bhyve_status["running"]:
                self.logger.info(_("bhyve is already initialized and running"))
                return {
                    "success": True,
                    "message": _("bhyve is already initialized and running"),
                    "already_initialized": True,
                }

            # Step 1: Load vmm.ko kernel module if not already loaded
            if not bhyve_status["enabled"]:
                self.logger.info(_("Loading vmm.ko kernel module"))
                result = await self._run_subprocess(["kldload", "vmm"], timeout=30)
                if result.returncode != 0:
                    # Check if it's already loaded (error code for already loaded)
                    if "already loaded" not in result.stderr.lower():
                        return {
                            "success": False,
                            "error": _("Failed to load vmm.ko: %s")
                            % (result.stderr or result.stdout),
                        }

            # Step 2: Add vmm_load="YES" to /boot/loader.conf for persistence
            loader_conf = "/boot/loader.conf"
            vmm_load_line = 'vmm_load="YES"'

            try:
                # Check if already configured
                needs_update = True
                if os.path.exists(loader_conf):
                    with open(loader_conf, "r", encoding="utf-8") as loader_file:
                        content = loader_file.read()
                        if vmm_load_line in content:
                            needs_update = False
                            self.logger.info(
                                _("vmm.ko already configured in %s"), loader_conf
                            )

                if needs_update:
                    self.logger.info(_("Adding vmm.ko to %s"), loader_conf)
                    with open(loader_conf, "a", encoding="utf-8") as loader_file:
                        loader_file.write(
                            "\n# bhyve VMM support - added by sysmanage\n"
                        )
                        loader_file.write(f"{vmm_load_line}\n")

            except PermissionError:
                return {
                    "success": False,
                    "error": _("Permission denied writing to %s") % loader_conf,
                }

            # Verify /dev/vmm directory now exists
            if not os.path.isdir("/dev/vmm"):
                return {
                    "success": False,
                    "error": _("/dev/vmm not created after loading vmm.ko"),
                }

            self.logger.info(_("bhyve initialized successfully"))
            return {
                "success": True,
                "message": _("bhyve has been initialized successfully"),
                "vmm_loaded": True,
                "loader_conf_updated": True,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Timeout initializing bhyve")}
        except Exception as error:
            self.logger.error(_("Error initializing bhyve: %s"), error)
            return {"success": False, "error": str(error)}

    async def create_bhyve_vm(self, _config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new bhyve VM.

        This is a placeholder for future implementation (Phase 5).

        Args:
            _config: VM configuration dictionary

        Returns:
            Dict with success status
        """
        # TODO: Implement VM creation in Phase 5  # pylint: disable=fixme
        return {
            "success": False,
            "error": _("bhyve VM creation not yet implemented"),
        }

    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start a bhyve VM.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _("No child_name specified")}

        # TODO: Implement in Phase 6  # pylint: disable=fixme
        return {
            "success": False,
            "error": _("bhyve VM start not yet implemented"),
        }

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stop a bhyve VM.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _("No child_name specified")}

        # TODO: Implement in Phase 6  # pylint: disable=fixme
        return {
            "success": False,
            "error": _("bhyve VM stop not yet implemented"),
        }

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restart a bhyve VM.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _("No child_name specified")}

        # TODO: Implement in Phase 6  # pylint: disable=fixme
        return {
            "success": False,
            "error": _("bhyve VM restart not yet implemented"),
        }

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Delete a bhyve VM.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {"success": False, "error": _("No child_name specified")}

        # TODO: Implement in Phase 6  # pylint: disable=fixme
        return {
            "success": False,
            "error": _("bhyve VM delete not yet implemented"),
        }
