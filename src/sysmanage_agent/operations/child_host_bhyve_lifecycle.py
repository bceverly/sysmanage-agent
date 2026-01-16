"""
bhyve VM lifecycle operations for FreeBSD hosts.

This module contains operations for managing bhyve VM lifecycle:
- Starting VMs
- Stopping VMs
- Restarting VMs
- Deleting VMs
"""

import asyncio
import os
import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.operations.child_host_bhyve_creation import (
    BHYVE_CLOUDINIT_DIR,
    BHYVE_VM_DIR,
    BhyveCreationHelper,
    delete_bhyve_metadata,
)


class BhyveLifecycleHelper:
    """Helper class for bhyve VM lifecycle operations."""

    def __init__(self, logger, creation_helper: BhyveCreationHelper):
        """
        Initialize the lifecycle helper.

        Args:
            logger: Logger instance
            creation_helper: BhyveCreationHelper instance for shared operations
        """
        self.logger = logger
        self.creation_helper = creation_helper

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

        try:
            # Check if VM is already running
            if os.path.exists(f"/dev/vmm/{child_name}"):
                return {
                    "success": True,
                    "message": _("VM is already running"),
                    "child_name": child_name,
                    "status": "running",
                }

            vm_dir = os.path.join(BHYVE_VM_DIR, child_name)
            disk_path = os.path.join(vm_dir, f"{child_name}.img")

            if not os.path.exists(disk_path):
                return {
                    "success": False,
                    "error": _("VM disk not found: %s") % disk_path,
                }

            # Create tap interface
            tap_result = self.creation_helper.create_tap_interface(child_name)
            if not tap_result.get("success"):
                return tap_result
            tap_interface = tap_result["tap"]

            # Check for cloud-init ISO
            cloudinit_iso = os.path.join(BHYVE_CLOUDINIT_DIR, f"{child_name}.iso")

            # Determine memory (default 1G)
            memory_mb = 1024

            # Build bhyve command
            cmd = [
                "bhyve",
                "-A",
                "-H",
                "-P",
                "-s",
                "0:0,hostbridge",
                "-s",
                "1:0,lpc",
                "-s",
                f"2:0,virtio-net,{tap_interface}",
                "-s",
                f"3:0,virtio-blk,{disk_path}",
                "-l",
                "com1,stdio",
                "-c",
                "1",
                "-m",
                f"{memory_mb}M",
            ]

            if os.path.exists(cloudinit_iso):
                cmd.extend(["-s", f"4:0,ahci-cd,{cloudinit_iso}"])

            # Check for UEFI firmware
            uefi_firmware = "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd"
            if os.path.exists(uefi_firmware):
                cmd.extend(["-l", f"bootrom,{uefi_firmware}"])

            cmd.append(child_name)

            # Run with daemon
            daemon_cmd = ["daemon", "-p", f"/var/run/bhyve.{child_name}.pid"]
            daemon_cmd.extend(cmd)

            result = await self._run_subprocess(daemon_cmd, timeout=60)
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start VM: %s") % result.stderr,
                }

            return {
                "success": True,
                "message": _("VM started"),
                "child_name": child_name,
                "status": "running",
            }

        except Exception as error:
            self.logger.error(_("Error starting bhyve VM: %s"), error)
            return {"success": False, "error": str(error)}

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

        try:
            # Check if VM is running
            if not os.path.exists(f"/dev/vmm/{child_name}"):
                return {
                    "success": True,
                    "message": _("VM is not running"),
                    "child_name": child_name,
                    "status": "stopped",
                }

            # Send ACPI shutdown signal (ignore result - we'll destroy anyway)
            await self._run_subprocess(
                ["bhyvectl", "--vm", child_name, "--force-poweroff"], timeout=60
            )

            # Destroy the VM resources
            await self._run_subprocess(
                ["bhyvectl", "--vm", child_name, "--destroy"], timeout=30
            )

            return {
                "success": True,
                "message": _("VM stopped"),
                "child_name": child_name,
                "status": "stopped",
            }

        except Exception as error:
            self.logger.error(_("Error stopping bhyve VM: %s"), error)
            return {"success": False, "error": str(error)}

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

        # Stop and start
        stop_result = await self.stop_child_host(parameters)
        if not stop_result.get("success"):
            return stop_result

        # Wait a moment for cleanup
        await asyncio.sleep(2)

        return await self.start_child_host(parameters)

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

        try:
            # Stop VM if running
            if os.path.exists(f"/dev/vmm/{child_name}"):
                await self.stop_child_host(parameters)

            # Remove VM directory and disk
            vm_dir = os.path.join(BHYVE_VM_DIR, child_name)
            if os.path.isdir(vm_dir):
                shutil.rmtree(vm_dir)
                self.logger.info(_("Removed VM directory: %s"), vm_dir)

            # Remove cloud-init ISO
            cloudinit_iso = os.path.join(BHYVE_CLOUDINIT_DIR, f"{child_name}.iso")
            if os.path.exists(cloudinit_iso):
                os.remove(cloudinit_iso)

            cloudinit_dir = os.path.join(BHYVE_CLOUDINIT_DIR, child_name)
            if os.path.isdir(cloudinit_dir):
                shutil.rmtree(cloudinit_dir)

            # Delete VM metadata file
            delete_bhyve_metadata(child_name, self.logger)

            return {
                "success": True,
                "message": _("VM deleted"),
                "child_name": child_name,
                "child_type": "bhyve",
            }

        except Exception as error:
            self.logger.error(_("Error deleting bhyve VM: %s"), error)
            return {"success": False, "error": str(error)}
