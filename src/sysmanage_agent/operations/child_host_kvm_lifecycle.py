"""
KVM/libvirt VM lifecycle operations for Linux hosts.

This module handles KVM virtual machine start, stop, restart, and delete operations.
"""

import os
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict

from src.i18n import _

# Cloud-init ISO directory
KVM_CLOUDINIT_DIR = "/var/lib/libvirt/cloud-init"


class KvmLifecycle:
    """KVM/libvirt VM lifecycle operations."""

    def __init__(self, logger):
        """
        Initialize KVM lifecycle operations.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    async def start_vm(self, parameters: dict) -> dict:
        """Start a stopped KVM virtual machine."""
        vm_name = parameters.get("child_name") or parameters.get("vm_name")
        if not vm_name:
            return {"success": False, "error": _("VM name is required")}

        try:
            self.logger.info("Starting KVM VM: %s", vm_name)

            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "start", vm_name],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "child_name": vm_name,
                    "child_type": "kvm",
                    "message": _("VM started"),
                }

            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": result.stderr or result.stdout or _("Failed to start VM"),
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": _("Start operation timed out"),
            }
        except Exception as error:
            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": str(error),
            }

    async def stop_vm(self, parameters: dict) -> dict:
        """Stop a running KVM virtual machine (graceful shutdown)."""
        vm_name = parameters.get("child_name") or parameters.get("vm_name")
        if not vm_name:
            return {"success": False, "error": _("VM name is required")}

        try:
            self.logger.info("Stopping KVM VM: %s", vm_name)

            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "shutdown", vm_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "child_name": vm_name,
                    "child_type": "kvm",
                    "message": _("VM shutdown initiated"),
                }

            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": result.stderr or result.stdout or _("Failed to stop VM"),
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": _("Stop operation timed out"),
            }
        except Exception as error:
            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": str(error),
            }

    async def restart_vm(self, parameters: dict) -> dict:
        """Restart a KVM virtual machine."""
        vm_name = parameters.get("child_name") or parameters.get("vm_name")
        if not vm_name:
            return {"success": False, "error": _("VM name is required")}

        try:
            self.logger.info("Restarting KVM VM: %s", vm_name)

            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "reboot", vm_name],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "child_name": vm_name,
                    "child_type": "kvm",
                    "message": _("VM reboot initiated"),
                }

            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": result.stderr or result.stdout or _("Failed to restart VM"),
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": _("Restart operation timed out"),
            }
        except Exception as error:
            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": str(error),
            }

    def _cleanup_cloudinit_iso(self, vm_name: str) -> None:
        """Remove cloud-init ISO file for a VM if it exists."""
        iso_path = os.path.join(KVM_CLOUDINIT_DIR, f"{vm_name}-cidata.iso")
        try:
            if os.path.exists(iso_path):
                os.remove(iso_path)
                self.logger.info("Removed cloud-init ISO: %s", iso_path)
        except Exception as error:
            self.logger.warning(
                "Failed to remove cloud-init ISO %s: %s", iso_path, error
            )

    async def delete_vm(self, parameters: dict) -> dict:
        """Delete a KVM virtual machine and its storage."""
        vm_name = parameters.get("child_name") or parameters.get("vm_name")
        if not vm_name:
            return {"success": False, "error": _("VM name is required")}

        try:
            self.logger.info("Deleting KVM VM: %s", vm_name)

            # First, try to destroy (force stop) the VM
            # Ignore destroy errors - VM might already be stopped
            subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "destroy", vm_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            # Undefine the VM (optionally with --remove-all-storage)
            undefine_result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "undefine", vm_name, "--remove-all-storage"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if undefine_result.returncode != 0:
                # Try without --remove-all-storage
                undefine_result = subprocess.run(  # nosec B603 B607
                    ["sudo", "virsh", "undefine", vm_name],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

            if undefine_result.returncode == 0:
                # Clean up cloud-init ISO if it exists
                self._cleanup_cloudinit_iso(vm_name)
                return {
                    "success": True,
                    "child_name": vm_name,
                    "child_type": "kvm",
                    "message": _("VM deleted"),
                }

            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": undefine_result.stderr
                or undefine_result.stdout
                or _("Failed to delete VM"),
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": _("Delete operation timed out"),
            }
        except Exception as error:
            return {
                "success": False,
                "child_name": vm_name,
                "child_type": "kvm",
                "error": str(error),
            }

    def check_ready(self, virtualization_checks) -> Dict[str, Any]:
        """
        Check if KVM is fully operational and ready to create VMs.

        Args:
            virtualization_checks: VirtualizationChecks instance

        Returns:
            Dict with KVM status details
        """
        kvm_check = virtualization_checks.check_kvm_support()

        return {
            "success": True,
            "ready": kvm_check.get("initialized", False),
            "available": kvm_check.get("available", False),
            "installed": kvm_check.get("installed", False),
            "enabled": kvm_check.get("enabled", False),
            "running": kvm_check.get("running", False),
            "initialized": kvm_check.get("initialized", False),
            "management": kvm_check.get("management"),
        }
