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
        enable: bool = True,
        boot_device: str = None,
    ) -> bool:
        """
        Add VM definition to /etc/vm.conf for boot persistence.

        This ensures the VM will auto-start when vmd starts at boot.

        Args:
            vm_name: Name of the VM
            disk_path: Path to the VM's disk image
            memory: Memory allocation (e.g., "1G")
            enable: If True, VM auto-starts on vmd reload/boot. Set False
                    during initial install to prevent auto-start before
                    installation completes.
            boot_device: Optional boot device path (e.g., bsd.rd for install).
                         If None, VM boots from disk.

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
            # Only include 'enable' if requested (avoid auto-start during install)
            enable_line = "    enable\n" if enable else ""
            boot_line = f'    boot "{boot_device}"\n' if boot_device else ""
            vm_definition = f"""
vm "{vm_name}" {{
    memory {memory}
    disk "{disk_path}"
{boot_line}    interface {{ switch "local" }}
    owner root
{enable_line}}}
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
            # Match: vm "vm_name" { ... } where closing } is on its own line
            # The [^}]* pattern fails because vm blocks contain nested braces
            # like: interface { switch "local" }
            # Use non-greedy .*? with DOTALL to match until final closing brace
            pattern = rf'\n?vm "{re.escape(vm_name)}" \{{.*?\n\}}\n?'
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

    def remove_boot_device(self, vm_name: str) -> bool:
        """
        Remove 'boot' line from a VM definition in /etc/vm.conf.

        This is called after installation completes so the VM boots from disk.

        Args:
            vm_name: Name of the VM

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.VM_CONF_PATH.exists():
                return False

            with open(self.VM_CONF_PATH, "r", encoding="utf-8") as vm_conf_file:
                content = vm_conf_file.read()

            # Remove the boot line from this VM's block
            # Match: boot "/path/to/bsd.rd" within the VM block
            # We need to be careful to only remove it from this VM's block
            vm_pattern = (
                rf'(vm "{re.escape(vm_name)}" \{{[^}}]*?)(\s*boot "[^"]+"\n)([^}}]*}})'
            )
            match = re.search(vm_pattern, content, re.DOTALL)
            if match:
                new_content = (
                    content[: match.start()]
                    + match.group(1)
                    + match.group(3)
                    + content[match.end() :]
                )
                with open(self.VM_CONF_PATH, "w", encoding="utf-8") as vm_conf_file:
                    vm_conf_file.write(new_content)
                self.logger.info(_("Removed boot device from VM '%s'"), vm_name)
                self._reload_vmd()
                return True

            # No boot line found, that's fine
            self.logger.info(_("No boot device to remove for VM '%s'"), vm_name)
            return True

        except Exception as error:
            self.logger.error(
                _("Error removing boot device from VM '%s': %s"), vm_name, error
            )
            return False

    def enable_vm(self, vm_name: str) -> bool:
        """
        Add 'enable' to an existing VM definition in /etc/vm.conf.

        This makes the VM auto-start when vmd starts at boot.

        Args:
            vm_name: Name of the VM to enable

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.VM_CONF_PATH.exists():
                self.logger.error(_("vm.conf does not exist"))
                return False

            with open(self.VM_CONF_PATH, "r", encoding="utf-8") as vm_conf_file:
                content = vm_conf_file.read()

            # Check if VM is defined
            if f'vm "{vm_name}"' not in content:
                self.logger.error(_("VM '%s' not found in /etc/vm.conf"), vm_name)
                return False

            # Check if already enabled
            # Look for the VM block and check if 'enable' is present
            vm_pattern = rf'(vm "{re.escape(vm_name)}" \{{[^}}]*)(}})'
            match = re.search(vm_pattern, content, re.DOTALL)
            if match:
                vm_block = match.group(1)
                if "enable" in vm_block:
                    self.logger.info(_("VM '%s' already enabled"), vm_name)
                    return True

                # Add 'enable' before the closing brace
                new_block = vm_block + "    enable\n}"
                new_content = (
                    content[: match.start()] + new_block + content[match.end() :]
                )

                with open(self.VM_CONF_PATH, "w", encoding="utf-8") as vm_conf_file:
                    vm_conf_file.write(new_content)

                self.logger.info(_("Enabled VM '%s' in /etc/vm.conf"), vm_name)
                self._reload_vmd()
                return True

            return False

        except Exception as error:
            self.logger.error(
                _("Error enabling VM '%s' in /etc/vm.conf: %s"), vm_name, error
            )
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
