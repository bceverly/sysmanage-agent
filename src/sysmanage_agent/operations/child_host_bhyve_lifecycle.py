"""
bhyve VM lifecycle operations for FreeBSD hosts.

This module contains operations for managing bhyve VM lifecycle:
- Starting VMs
- Stopping VMs
- Restarting VMs
- Deleting VMs
"""

import asyncio
import json
import os
import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.operations.child_host_bhyve_creation import (
    BHYVE_CLOUDINIT_DIR,
    BHYVE_VM_DIR,
    BhyveCreationHelper,
    delete_bhyve_metadata,
)

_NO_CHILD_NAME_MSG = _("No child_name specified")
_INVALID_VM_NAME_MSG = _("Invalid VM name")

# Pattern for valid VM names: alphanumeric, hyphens, underscores only
_VALID_VM_NAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


def _is_valid_vm_name(name: str) -> bool:
    """
    Validate that a VM name contains only safe characters.

    Prevents path traversal by rejecting names with /, .., or other
    dangerous characters.

    Args:
        name: The VM name to validate

    Returns:
        True if name is valid, False otherwise
    """
    if not name or len(name) > 64:
        return False
    return all(c in _VALID_VM_NAME_CHARS for c in name)


def _validate_path_in_allowed_dirs(path: str, allowed_dirs: list) -> bool:
    """
    Validate that a path is within one of the allowed directories.

    Prevents path traversal attacks by resolving the real path and
    checking it's within expected boundaries.

    Args:
        path: The path to validate
        allowed_dirs: List of allowed base directories

    Returns:
        True if path is within an allowed directory, False otherwise
    """
    try:
        # Resolve the real path (handles symlinks and ..)
        real_path = os.path.realpath(path)
        # Check if it's within any allowed directory
        for allowed_dir in allowed_dirs:
            real_allowed = os.path.realpath(allowed_dir)
            if real_path.startswith(real_allowed + os.sep) or real_path == real_allowed:
                return True
        return False
    except (OSError, ValueError):
        return False


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

    def _load_vm_config(self, vm_name: str) -> Optional[Dict[str, Any]]:
        """
        Load VM configuration from the persistent config file.

        Args:
            vm_name: Name of the VM

        Returns:
            Dict with VM config or None if not found
        """
        config_path = os.path.join(BHYVE_VM_DIR, vm_name, "vm-config.json")
        if not os.path.exists(config_path):
            return None

        try:
            with open(config_path, "r", encoding="utf-8") as config_file:
                return json.load(config_file)
        except Exception as error:
            self.logger.warning(
                _("Failed to load VM config for %s: %s"), vm_name, error
            )
            return None

    async def _run_subprocess(
        self,
        cmd: list,
        timeout: int = 60,  # NOSONAR - timeout parameter is part of the established API contract
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

    def _parse_memory_string(self, memory_str: str) -> int:
        """
        Parse memory string to megabytes.

        Args:
            memory_str: Memory string (e.g., "1G", "1024M")

        Returns:
            Memory in megabytes
        """
        memory_str = memory_str.upper()
        if memory_str.endswith("G"):
            return int(float(memory_str[:-1]) * 1024)
        if memory_str.endswith("M"):
            return int(memory_str[:-1])
        return 1024

    def _get_vm_start_params(self, child_name: str) -> Dict[str, Any]:
        """
        Get VM start parameters from config or defaults.

        Args:
            child_name: Name of the VM

        Returns:
            Dict with memory_mb, cpus, use_uefi, disk_path, cloudinit_iso
        """
        vm_dir = os.path.join(BHYVE_VM_DIR, child_name)
        disk_path = os.path.join(vm_dir, f"{child_name}.img")
        cloudinit_iso = os.path.join(BHYVE_CLOUDINIT_DIR, f"{child_name}.iso")

        params = {
            "memory_mb": 1024,
            "cpus": 1,
            "use_uefi": True,
            "disk_path": disk_path,
            "cloudinit_iso": cloudinit_iso,
        }

        vm_config = self._load_vm_config(child_name)
        if not vm_config:
            return params

        params["memory_mb"] = self._parse_memory_string(vm_config.get("memory", "1G"))
        params["cpus"] = vm_config.get("cpus", 1)
        params["use_uefi"] = vm_config.get("use_uefi", True)

        # Validate disk_path from config to prevent path traversal
        allowed_dirs = [BHYVE_VM_DIR, BHYVE_CLOUDINIT_DIR]
        if vm_config.get("disk_path"):
            config_disk_path = vm_config["disk_path"]
            if _validate_path_in_allowed_dirs(config_disk_path, allowed_dirs):
                params["disk_path"] = config_disk_path
            else:
                # Don't log user-controlled path data to prevent log injection
                self.logger.warning(_("Ignoring invalid disk_path from VM config"))

        # Validate cloud_init_iso_path from config to prevent path traversal
        if vm_config.get("cloud_init_iso_path"):
            config_iso_path = vm_config["cloud_init_iso_path"]
            if _validate_path_in_allowed_dirs(config_iso_path, allowed_dirs):
                params["cloudinit_iso"] = config_iso_path
            else:
                # Don't log user-controlled path data to prevent log injection
                self.logger.warning(
                    _("Ignoring invalid cloud_init_iso_path from VM config")
                )

        return params

    def _build_bhyve_command(
        self,
        child_name: str,
        tap_interface: str,
        params: Dict[str, Any],
    ) -> list:
        """
        Build the bhyve command line.

        Args:
            child_name: Name of the VM
            tap_interface: Tap interface for networking
            params: VM parameters dict

        Returns:
            List of command arguments
        """
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
            f"3:0,virtio-blk,{params['disk_path']}",
            "-l",
            "com1,stdio",
            "-c",
            str(params["cpus"]),
            "-m",
            f"{params['memory_mb']}M",
        ]

        # Cloud-init ISO path is safe: either constructed from validated child_name
        # or loaded from config and validated by _validate_path_in_allowed_dirs
        cloudinit_path = params["cloudinit_iso"]
        cloudinit_exists = os.path.exists(cloudinit_path)  # NOSONAR - path validated
        if cloudinit_exists:
            cmd.extend(["-s", f"4:0,ahci-cd,{cloudinit_path}"])

        uefi_firmware = "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd"
        if params["use_uefi"] and os.path.exists(uefi_firmware):
            cmd.extend(["-l", f"bootrom,{uefi_firmware}"])

        cmd.append(child_name)
        return cmd

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
            return {"success": False, "error": _NO_CHILD_NAME_MSG}
        if not _is_valid_vm_name(child_name):
            return {"success": False, "error": _INVALID_VM_NAME_MSG}

        try:
            if os.path.exists(f"/dev/vmm/{child_name}"):
                return {
                    "success": True,
                    "message": _("VM is already running"),
                    "child_name": child_name,
                    "status": "running",
                }

            params = self._get_vm_start_params(child_name)

            # Disk path is safe: either constructed from validated child_name
            # or loaded from config and validated by _validate_path_in_allowed_dirs
            disk_path = params["disk_path"]
            disk_exists = os.path.exists(disk_path)  # NOSONAR - path validated
            if not disk_exists:
                return {"success": False, "error": _("VM disk not found")}

            tap_result = self.creation_helper.create_tap_interface(child_name)
            if not tap_result.get("success"):
                return tap_result

            cmd = self._build_bhyve_command(child_name, tap_result["tap"], params)
            daemon_cmd = ["daemon", "-p", f"/var/run/bhyve.{child_name}.pid"] + cmd

            result = await self._run_subprocess(daemon_cmd, timeout=180)
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
            return {"success": False, "error": _NO_CHILD_NAME_MSG}
        if not _is_valid_vm_name(child_name):
            return {"success": False, "error": _INVALID_VM_NAME_MSG}

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
            return {"success": False, "error": _NO_CHILD_NAME_MSG}
        if not _is_valid_vm_name(child_name):
            return {"success": False, "error": _INVALID_VM_NAME_MSG}

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
            return {"success": False, "error": _NO_CHILD_NAME_MSG}
        if not _is_valid_vm_name(child_name):
            return {"success": False, "error": _INVALID_VM_NAME_MSG}

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
