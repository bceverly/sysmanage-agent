"""
VMM VM lifecycle operations (start, stop, restart, delete).

This module contains helper methods for managing VMM virtual machine
lifecycle operations on OpenBSD.
"""

import asyncio
import os
import subprocess  # nosec B404 # Required for system command execution
import time
from typing import Any, Dict

from src.i18n import _

# Default paths for VMM
VMM_DISK_DIR = "/var/vmm"
VMM_METADATA_DIR = "/var/vmm/metadata"


class VmmLifecycleOperations:
    """Lifecycle operations for VMM VMs (start, stop, restart, delete)."""

    def __init__(self, logger, virtualization_checks):
        """
        Initialize lifecycle operations.

        Args:
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
        """
        self.logger = logger
        self.virtualization_checks = virtualization_checks

    async def check_vmd_ready(self) -> Dict[str, Any]:
        """
        Check if vmd is operational and ready to create VMs.

        Returns:
            Dict with success status and vmd status info
        """
        try:
            # Check if vmd is running
            vmm_check = self.virtualization_checks.check_vmm_support()

            if not vmm_check.get("available"):
                return {
                    "success": False,
                    "ready": False,
                    "error": _("VMM is not available on this system"),
                }

            if not vmm_check.get("kernel_supported"):
                return {
                    "success": False,
                    "ready": False,
                    "error": _("VMM kernel support is not enabled"),
                }

            if not vmm_check.get("running"):
                return {
                    "success": True,
                    "ready": False,
                    "error": _("vmd is not running"),
                    "needs_enable": True,
                }

            # Try to run vmctl status to verify vmd is responsive
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "ready": True,
                    "enabled": vmm_check.get("enabled", False),
                    "running": True,
                    "kernel_supported": True,
                    "cpu_supported": vmm_check.get("cpu_supported", False),
                }

            return {
                "success": False,
                "ready": False,
                "error": _("vmd is not responding to commands"),
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "ready": False,
                "error": _("Timeout checking vmd status"),
            }
        except Exception as error:
            return {
                "success": False,
                "ready": False,
                "error": str(error),
            }

    async def get_vm_status(self, vm_name: str) -> Dict[str, Any]:
        """
        Get the status of a specific VM.

        Args:
            vm_name: Name of the VM to check

        Returns:
            Dict with VM status info including:
            - success: Whether the check succeeded
            - found: Whether the VM was found
            - status: running/stopped
            - vm_id: VM ID if running
            - memory: Memory allocation
            - vcpus: Number of vCPUs
        """
        try:
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "status"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to get VM status"),
                }

            # Parse vmctl status output
            # Format (9 columns):
            #   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE   NAME
            #    1 85075     1    1.0G   1006M   ttyp8        root running vm1
            #    2     -     1    1.0G       -       -        root stopped vm2
            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                return {
                    "success": True,
                    "found": False,
                    "error": _("VM not found: %s") % vm_name,
                }

            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                # 9 columns: ID, PID, VCPUS, MAXMEM, CURMEM, TTY, OWNER, STATE, NAME
                if len(parts) >= 9 and parts[8] == vm_name:
                    vm_id = parts[0]
                    vcpus = parts[2]
                    max_mem = parts[3]
                    cur_mem = parts[4]
                    state = parts[7]  # STATE column: running/stopped

                    # Use STATE column for status (more reliable than PID check)
                    if state == "running":
                        status = "running"
                    else:
                        status = "stopped"
                        vm_id = None

                    return {
                        "success": True,
                        "found": True,
                        "status": status,
                        "vm_id": vm_id,
                        "vcpus": vcpus,
                        "memory": max_mem,
                        "current_memory": cur_mem,
                    }

            return {
                "success": True,
                "found": False,
                "error": _("VM not found: %s") % vm_name,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout getting VM status"),
            }
        except Exception as error:
            return {
                "success": False,
                "error": str(error),
            }

    async def wait_for_vm_state(
        self, vm_name: str, desired_state: str, timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Wait for a VM to reach a desired state.

        Args:
            vm_name: Name of the VM
            desired_state: "running" or "stopped"
            timeout: Maximum time to wait in seconds

        Returns:
            Dict with success status
        """
        start_time = time.time()
        check_interval = 2  # seconds

        while time.time() - start_time < timeout:
            status = await self.get_vm_status(vm_name)

            if not status.get("success"):
                # Error checking status, continue waiting
                await asyncio.sleep(check_interval)
                continue

            if not status.get("found"):
                if desired_state == "stopped":
                    # VM not found counts as stopped
                    return {"success": True, "state": "stopped"}
                # For running, VM must exist
                await asyncio.sleep(check_interval)
                continue

            if status.get("status") == desired_state:
                return {"success": True, "state": desired_state}

            await asyncio.sleep(check_interval)

        return {
            "success": False,
            "error": _("Timeout waiting for VM to reach state: %s") % desired_state,
        }

    async def start_vm(self, child_name: str, wait: bool = True) -> Dict[str, Any]:
        """
        Start a stopped VMM virtual machine.

        Args:
            child_name: Name of the VM to start
            wait: If True, wait for VM to be running

        Returns:
            Dict with success status
        """
        self.logger.info(_("Starting VMM VM: %s"), child_name)

        try:
            # Start the VM using vmctl
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "start", child_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                # Wait for VM to be running if requested
                if wait:
                    wait_result = await self.wait_for_vm_state(
                        child_name, "running", timeout=30
                    )
                    if not wait_result.get("success"):
                        self.logger.warning(
                            _("VM %s started but wait verification failed: %s"),
                            child_name,
                            wait_result.get("error"),
                        )

                self.logger.info(_("VM %s started successfully"), child_name)
                return {
                    "success": True,
                    "message": _("VM %s started") % child_name,
                }

            error_msg = result.stderr or result.stdout or "Unknown error"
            self.logger.error(_("Failed to start VM %s: %s"), child_name, error_msg)
            return {
                "success": False,
                "error": _("Failed to start VM: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout starting VM %s") % child_name,
            }
        except Exception as error:
            return {
                "success": False,
                "error": _("Error starting VM: %s") % str(error),
            }

    async def stop_vm(
        self, child_name: str, force: bool = False, wait: bool = True
    ) -> Dict[str, Any]:
        """
        Stop a running VMM virtual machine.

        Args:
            child_name: Name of the VM to stop
            force: If True, force stop the VM
            wait: If True, wait for VM to be stopped

        Returns:
            Dict with success status
        """
        self.logger.info(_("Stopping VMM VM: %s (force=%s)"), child_name, force)

        try:
            # Build vmctl stop command
            cmd = ["vmctl", "stop"]
            if force:
                cmd.append("-f")
            cmd.append(child_name)

            result = subprocess.run(  # nosec B603 B607
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # Longer timeout for graceful shutdown
                check=False,
            )

            if result.returncode == 0:
                # Wait for VM to be stopped if requested
                if wait:
                    wait_result = await self.wait_for_vm_state(
                        child_name, "stopped", timeout=60
                    )
                    if not wait_result.get("success"):
                        self.logger.warning(
                            _("VM %s stop requested but wait verification failed: %s"),
                            child_name,
                            wait_result.get("error"),
                        )

                self.logger.info(_("VM %s stopped successfully"), child_name)
                return {
                    "success": True,
                    "message": _("VM %s stopped") % child_name,
                }

            error_msg = result.stderr or result.stdout or "Unknown error"
            self.logger.error(_("Failed to stop VM %s: %s"), child_name, error_msg)
            return {
                "success": False,
                "error": _("Failed to stop VM: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout stopping VM %s") % child_name,
            }
        except Exception as error:
            return {
                "success": False,
                "error": _("Error stopping VM: %s") % str(error),
            }

    async def restart_vm(self, child_name: str) -> Dict[str, Any]:
        """
        Restart a VMM virtual machine.

        Args:
            child_name: Name of the VM to restart

        Returns:
            Dict with success status
        """
        self.logger.info(_("Restarting VMM VM: %s"), child_name)

        # Stop the VM first
        stop_result = await self.stop_vm(child_name, wait=True)
        if not stop_result.get("success"):
            return stop_result

        # Then start it
        start_result = await self.start_vm(child_name, wait=True)
        if not start_result.get("success"):
            return start_result

        return {
            "success": True,
            "message": _("VM %s restarted") % child_name,
        }

    async def delete_vm(
        self, child_name: str, delete_disk: bool = False
    ) -> Dict[str, Any]:
        """
        Delete a VMM virtual machine.

        Args:
            child_name: Name of the VM to delete
            delete_disk: If True, also delete the disk image

        Returns:
            Dict with success status
        """
        self.logger.info(_("Deleting VMM VM: %s"), child_name)

        try:
            # First, try to stop the VM if it's running (force stop)
            await self.stop_vm(child_name, force=True, wait=True)

            # Delete disk image if requested
            if delete_disk:
                disk_path = os.path.join(VMM_DISK_DIR, f"{child_name}.qcow2")
                if os.path.exists(disk_path):
                    os.remove(disk_path)
                    self.logger.info(_("Deleted disk image: %s"), disk_path)

            # Delete metadata file if it exists
            metadata_path = os.path.join(VMM_METADATA_DIR, f"{child_name}.json")
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
                self.logger.info(_("Deleted VM metadata: %s"), metadata_path)

            self.logger.info(_("VM %s has been deleted"), child_name)
            return {
                "success": True,
                "message": _("VM %s has been deleted") % child_name,
            }

        except Exception as error:
            return {
                "success": False,
                "error": _("Error deleting VM: %s") % str(error),
            }
