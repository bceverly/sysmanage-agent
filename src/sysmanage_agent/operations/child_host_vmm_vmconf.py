"""
VMM vm.conf management helpers for OpenBSD.

This module handles reading, writing, and modifying /etc/vm.conf
for VM persistence and boot configuration.
"""

import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Any, Dict

from src.i18n import _


class VmConfManager:
    """Manages /etc/vm.conf operations for VMM VMs."""

    VM_CONF_PATH = Path("/etc/vm.conf")

    def __init__(self, logger):
        """
        Initialize vm.conf manager.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def persist_vm(
        self,
        vm_name: str,
        disk_path: str,
        memory: str,
    ) -> bool:
        """
        Add VM definition to /etc/vm.conf for boot persistence.

        This ensures the VM will auto-start when vmd starts at boot.

        Args:
            vm_name: Name of the VM
            disk_path: Path to the VM's disk image
            memory: Memory allocation (e.g., "1G")

        Returns:
            True if successful, False otherwise
        """
        try:
            # Read existing vm.conf content
            existing_content = ""
            if self.VM_CONF_PATH.exists():
                with open(self.VM_CONF_PATH, "r", encoding="utf-8") as vm_conf_file:
                    existing_content = vm_conf_file.read()

            # Check if VM is already defined
            if f'vm "{vm_name}"' in existing_content:
                self.logger.info(_("VM '%s' already defined in /etc/vm.conf"), vm_name)
                return True

            # Create VM definition block
            # Use 'enable' to auto-start at boot
            vm_definition = f"""
vm "{vm_name}" {{
    memory {memory}
    disk "{disk_path}"
    interface {{ switch "local" }}
    owner root
    enable
}}
"""

            # Append to vm.conf
            with open(self.VM_CONF_PATH, "a", encoding="utf-8") as vm_conf_file:
                vm_conf_file.write(vm_definition)

            self.logger.info(
                _("Added VM '%s' to /etc/vm.conf for boot persistence"), vm_name
            )

            # Reload vmd to pick up the new configuration
            self._reload_vmd()

            return True

        except Exception as error:
            self.logger.error(
                _("Error persisting VM '%s' to /etc/vm.conf: %s"), vm_name, error
            )
            return False

    def remove_vm(self, vm_name: str) -> bool:
        """
        Remove VM definition from /etc/vm.conf.

        Args:
            vm_name: Name of the VM to remove

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.VM_CONF_PATH.exists():
                return True

            with open(self.VM_CONF_PATH, "r", encoding="utf-8") as vm_conf_file:
                content = vm_conf_file.read()

            # Remove the VM block using regex
            # Match: vm "vm_name" { ... }
            pattern = rf'\n?vm "{re.escape(vm_name)}" \{{[^}}]*\}}\n?'
            new_content = re.sub(pattern, "\n", content, flags=re.DOTALL)

            if new_content != content:
                with open(self.VM_CONF_PATH, "w", encoding="utf-8") as vm_conf_file:
                    vm_conf_file.write(new_content.strip() + "\n")
                self.logger.info(_("Removed VM '%s' from /etc/vm.conf"), vm_name)

                # Reload vmd to pick up the changes
                self._reload_vmd()

            return True

        except Exception as error:
            self.logger.error(
                _("Error removing VM '%s' from /etc/vm.conf: %s"), vm_name, error
            )
            return False

    def vm_defined(self, vm_name: str) -> bool:
        """
        Check if a VM is defined in /etc/vm.conf.

        Args:
            vm_name: Name of the VM to check

        Returns:
            True if VM is defined, False otherwise
        """
        try:
            if not self.VM_CONF_PATH.exists():
                return False

            with open(self.VM_CONF_PATH, "r", encoding="utf-8") as vm_conf_file:
                content = vm_conf_file.read()
                return f'vm "{vm_name}"' in content

        except Exception:
            return False

    def _reload_vmd(self) -> Dict[str, Any]:
        """Reload vmd to pick up configuration changes."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["rcctl", "reload", "vmd"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                self.logger.warning(
                    _("Could not reload vmd: %s"),
                    result.stderr or result.stdout,
                )
                return {"success": False, "error": result.stderr or result.stdout}

            return {"success": True}

        except subprocess.TimeoutExpired:
            self.logger.warning(_("Timeout reloading vmd"))
            return {"success": False, "error": "timeout"}
        except Exception as error:
            self.logger.warning(_("Error reloading vmd: %s"), error)
            return {"success": False, "error": str(error)}
