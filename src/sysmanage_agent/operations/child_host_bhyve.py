"""
bhyve-specific child host operations for FreeBSD hosts.

Supports creating VMs using FreeBSD's bhyve hypervisor.
bhyve is FreeBSD's native hypervisor that supports running FreeBSD, Linux,
and other guests with near-native performance.

This module provides the main BhyveOperations class which coordinates:
- VM initialization (loading vmm.ko, installing UEFI firmware)
- VM creation (via BhyveCreationHelper)
- VM lifecycle management (via BhyveLifecycleHelper)
"""

import asyncio
import os
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.operations.child_host_bhyve_creation import (
    BHYVE_CLOUDINIT_DIR,
    BHYVE_IMAGES_DIR,
    BHYVE_VM_DIR,
    BhyveCreationHelper,
)
from src.sysmanage_agent.operations.child_host_bhyve_lifecycle import (
    BhyveLifecycleHelper,
)
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig


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

        # Initialize helper classes
        self._creation_helper = BhyveCreationHelper(logger)
        self._lifecycle_helper = BhyveLifecycleHelper(logger, self._creation_helper)

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
        - Installs UEFI firmware for Linux guest support

        Returns:
            Dict with success status and any required actions (like reboot)
        """
        try:
            self.logger.info(_("Initializing bhyve"))

            # Check current bhyve status
            bhyve_status = self.virtualization_checks.check_bhyve_support()
            if bhyve_status["enabled"] and bhyve_status["running"]:
                self.logger.info(_("bhyve is already initialized and running"))
                # Still check for UEFI firmware and qemu-img even if already initialized
                uefi_installed = await self._install_uefi_firmware()
                qemu_img_installed = await self._install_qemu_img()
                return {
                    "success": True,
                    "message": _("bhyve is already initialized and running"),
                    "already_initialized": True,
                    "uefi_installed": uefi_installed,
                    "qemu_img_installed": qemu_img_installed,
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

            # Step 3: Create VM directories
            for directory in [BHYVE_VM_DIR, BHYVE_IMAGES_DIR, BHYVE_CLOUDINIT_DIR]:
                os.makedirs(directory, mode=0o755, exist_ok=True)

            # Step 4: Install bhyve-firmware for UEFI support (needed for Linux guests)
            uefi_installed = await self._install_uefi_firmware()

            # Step 5: Install qemu-img for cloud image conversion (qcow2 -> raw)
            qemu_img_installed = await self._install_qemu_img()

            # Verify /dev/vmm directory exists (indicates CPU virtualization support)
            if not os.path.isdir("/dev/vmm"):
                self.logger.warning(
                    _(
                        "/dev/vmm not created - CPU virtualization may be disabled in BIOS"
                    )
                )
                return {
                    "success": False,
                    "error": _(
                        "/dev/vmm not created after loading vmm.ko. "
                        "Please enable VT-x/AMD-V in BIOS settings."
                    ),
                    "vmm_loaded": True,
                    "loader_conf_updated": True,
                    "uefi_installed": uefi_installed,
                    "qemu_img_installed": qemu_img_installed,
                }

            self.logger.info(_("bhyve initialized successfully"))
            return {
                "success": True,
                "message": _("bhyve has been initialized successfully"),
                "vmm_loaded": True,
                "loader_conf_updated": True,
                "uefi_installed": uefi_installed,
                "qemu_img_installed": qemu_img_installed,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Timeout initializing bhyve")}
        except Exception as error:
            self.logger.error(_("Error initializing bhyve: %s"), error)
            return {"success": False, "error": str(error)}

    async def disable_bhyve(self, _parameters: dict) -> dict:
        """
        Disable bhyve on FreeBSD: unload vmm.ko and remove from loader.conf.

        This is called when the user clicks "Disable bhyve" in the UI.

        Steps:
        - Unloads vmm.ko kernel module
        - Removes vmm_load="YES" from /boot/loader.conf

        Note: This will fail if any VMs are currently running.

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(_("Disabling bhyve"))

            # Step 1: Check if any VMs are running
            if os.path.isdir("/dev/vmm"):
                vm_entries = os.listdir("/dev/vmm")
                if vm_entries:
                    return {
                        "success": False,
                        "error": _("Cannot disable bhyve: VMs are running: %s")
                        % ", ".join(vm_entries),
                    }

            # Step 2: Unload vmm.ko kernel module
            self.logger.info(_("Unloading vmm.ko kernel module"))
            result = await self._run_subprocess(["kldunload", "vmm"], timeout=30)
            if result.returncode != 0:
                # Check if it's already unloaded
                if "not loaded" not in result.stderr.lower():
                    return {
                        "success": False,
                        "error": _("Failed to unload vmm.ko: %s")
                        % (result.stderr or result.stdout),
                    }
                self.logger.info(_("vmm.ko was already unloaded"))

            # Step 3: Remove vmm_load="YES" from /boot/loader.conf
            loader_conf = "/boot/loader.conf"
            vmm_load_line = 'vmm_load="YES"'

            try:
                if os.path.exists(loader_conf):
                    with open(loader_conf, "r", encoding="utf-8") as loader_file:
                        lines = loader_file.readlines()

                    # Filter out vmm_load and its comment
                    new_lines = []
                    skip_next = False
                    for line in lines:
                        if skip_next:
                            skip_next = False
                            continue
                        if "bhyve VMM support" in line:
                            skip_next = True  # Skip the vmm_load line after comment
                            continue
                        if vmm_load_line in line:
                            continue
                        new_lines.append(line)

                    with open(loader_conf, "w", encoding="utf-8") as loader_file:
                        loader_file.writelines(new_lines)

                    self.logger.info(_("Removed vmm.ko from %s"), loader_conf)

            except PermissionError:
                return {
                    "success": False,
                    "error": _("Permission denied writing to %s") % loader_conf,
                }

            self.logger.info(_("bhyve disabled successfully"))
            return {
                "success": True,
                "message": _("bhyve has been disabled successfully"),
                "vmm_unloaded": True,
                "loader_conf_updated": True,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Timeout disabling bhyve")}
        except Exception as error:
            self.logger.error(_("Error disabling bhyve: %s"), error)
            return {"success": False, "error": str(error)}

    async def _install_uefi_firmware(self) -> bool:
        """
        Install bhyve-firmware package for UEFI support.

        UEFI firmware is required to boot Linux guests on bhyve.
        FreeBSD guests can use bhyveload and don't require UEFI.

        Returns:
            True if UEFI firmware is available (already installed or newly installed),
            False if installation failed.
        """
        # Check if UEFI firmware is already available
        uefi_paths = [
            "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd",
            "/usr/local/share/bhyve-firmware/BHYVE_UEFI.fd",
        ]

        for path in uefi_paths:
            if os.path.exists(path):
                self.logger.info(_("UEFI firmware already available at %s"), path)
                return True

        # Try to install bhyve-firmware package
        self.logger.info(_("Installing bhyve-firmware package for UEFI support"))
        try:
            # Use pkg install with -y for non-interactive
            result = await self._run_subprocess(
                ["pkg", "install", "-y", "bhyve-firmware"],
                timeout=120,  # Package installation can take a while
            )

            if result.returncode == 0:
                self.logger.info(_("bhyve-firmware package installed successfully"))
                return True

            # Check if package is already installed (different exit code)
            if "already installed" in result.stdout.lower():
                self.logger.info(_("bhyve-firmware package is already installed"))
                return True

            self.logger.warning(
                _("Failed to install bhyve-firmware: %s"),
                result.stderr or result.stdout,
            )
            return False

        except subprocess.TimeoutExpired:
            self.logger.warning(_("Timeout installing bhyve-firmware package"))
            return False
        except Exception as error:
            self.logger.warning(_("Error installing bhyve-firmware: %s"), error)
            return False

    async def _install_qemu_img(self) -> bool:
        """
        Install qemu-img tool for cloud image conversion.

        bhyve requires raw disk images, but cloud images are often in qcow2 format.
        qemu-img is needed to convert qcow2 images to raw format.

        On FreeBSD, qemu-img is part of the qemu-nox11 package (or qemu for systems
        with X11).

        Returns:
            True if qemu-img is available (already installed or newly installed),
            False if installation failed.
        """
        # Check if qemu-img is already available
        try:
            result = await self._run_subprocess(
                ["which", "qemu-img"],
                timeout=10,
            )
            if result.returncode == 0:
                self.logger.info(_("qemu-img already available"))
                return True
        except Exception:
            pass

        # Try to install qemu-nox11 package (smaller, no X11 dependencies)
        self.logger.info(_("Installing qemu-nox11 package for qemu-img"))
        try:
            result = await self._run_subprocess(
                ["pkg", "install", "-y", "qemu-nox11"],
                timeout=300,  # QEMU package is large, may take a while
            )

            if result.returncode == 0:
                self.logger.info(_("qemu-nox11 package installed successfully"))
                return True

            # Check if package is already installed
            if "already installed" in result.stdout.lower():
                self.logger.info(_("qemu-nox11 package is already installed"))
                return True

            # If qemu-nox11 fails, try regular qemu as fallback
            self.logger.info(_("Trying qemu package as fallback"))
            result = await self._run_subprocess(
                ["pkg", "install", "-y", "qemu"],
                timeout=300,
            )

            if result.returncode == 0:
                self.logger.info(_("qemu package installed successfully"))
                return True

            if "already installed" in result.stdout.lower():
                self.logger.info(_("qemu package is already installed"))
                return True

            self.logger.warning(
                _("Failed to install qemu package: %s"),
                result.stderr or result.stdout,
            )
            return False

        except subprocess.TimeoutExpired:
            self.logger.warning(_("Timeout installing qemu package"))
            return False
        except Exception as error:
            self.logger.warning(_("Error installing qemu: %s"), error)
            return False

    async def create_bhyve_vm(self, config: BhyveVmConfig) -> Dict[str, Any]:
        """
        Create a new bhyve VM.

        Args:
            config: VM configuration

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(_("Creating bhyve VM: %s"), config.vm_name)

            # Check if VM already exists
            if self._creation_helper.vm_exists(config.vm_name):
                return {
                    "success": False,
                    "error": _("VM '%s' already exists") % config.vm_name,
                }

            # Prevent duplicate creations
            if config.vm_name in self._in_progress_vms:
                return {
                    "success": False,
                    "error": _("VM '%s' creation already in progress") % config.vm_name,
                }
            self._in_progress_vms.add(config.vm_name)

            try:
                # Create VM directory
                vm_dir = os.path.join(BHYVE_VM_DIR, config.vm_name)
                os.makedirs(vm_dir, mode=0o755, exist_ok=True)

                # Set up disk path
                disk_filename = f"{config.vm_name}.img"
                config.disk_path = os.path.join(vm_dir, disk_filename)

                # Download cloud image or create empty disk
                if config.cloud_image_url:
                    self.logger.info(_("Downloading cloud image"))
                    disk_result = self._creation_helper.download_cloud_image(
                        config.cloud_image_url,
                        config.disk_path,
                        config.get_disk_gb(),
                    )
                    if not disk_result.get("success"):
                        return disk_result
                else:
                    self.logger.info(_("Creating empty disk"))
                    disk_result = self._creation_helper.create_disk_image(
                        config.disk_path,
                        config.get_disk_gb(),
                        config.use_zvol,
                        config.zvol_parent,
                    )
                    if not disk_result.get("success"):
                        return disk_result
                    config.disk_path = disk_result["path"]

                # Create cloud-init ISO
                if config.use_cloud_init:
                    self.logger.info(_("Creating cloud-init ISO"))
                    cloudinit_result = self._creation_helper.create_cloud_init_iso(
                        config
                    )
                    if not cloudinit_result.get("success"):
                        return cloudinit_result

                # Set up networking
                bridge_result = self._creation_helper.create_bridge_if_needed()
                if not bridge_result.get("success"):
                    self.logger.warning(
                        _("Bridge setup warning: %s"), bridge_result.get("error")
                    )

                tap_result = self._creation_helper.create_tap_interface(config.vm_name)
                if not tap_result.get("success"):
                    return {
                        "success": False,
                        "error": _("Failed to create network interface: %s")
                        % tap_result.get("error"),
                    }
                tap_interface = tap_result["tap"]

                # Start the VM
                if self._creation_helper.is_linux_guest(config) or config.use_uefi:
                    start_result = self._creation_helper.start_vm_with_uefi(
                        config, tap_interface
                    )
                else:
                    start_result = self._creation_helper.start_vm_with_bhyveload(
                        config, tap_interface
                    )

                if not start_result.get("success"):
                    return start_result

                # Wait for VM to get IP
                vm_ip = await self._creation_helper.wait_for_vm_ip(
                    config.vm_name, tap_interface
                )
                # Get console device for user access
                console_device = self._creation_helper.get_console_device(
                    config.vm_name
                )

                if not vm_ip:
                    return {
                        "success": True,
                        "message": _("VM created but IP not yet available"),
                        "vm_name": config.vm_name,
                        "status": "running",
                        "ip_pending": True,
                        "child_name": config.vm_name,
                        "child_type": "bhyve",
                        "console_device": console_device,
                    }

                # Wait for SSH
                ssh_available = await self._creation_helper.wait_for_ssh(vm_ip)
                if not ssh_available:
                    return {
                        "success": True,
                        "message": _("VM created, cloud-init may still be running"),
                        "vm_name": config.vm_name,
                        "status": "running",
                        "ip_address": vm_ip,
                        "ssh_pending": True,
                        "child_name": config.vm_name,
                        "child_type": "bhyve",
                        "console_device": console_device,
                    }

                self.logger.info(
                    _("bhyve VM '%s' created successfully at %s"), config.vm_name, vm_ip
                )
                return {
                    "success": True,
                    "message": _("VM created successfully"),
                    "vm_name": config.vm_name,
                    "status": "running",
                    "ip_address": vm_ip,
                    "child_name": config.vm_name,
                    "child_type": "bhyve",
                    "console_device": console_device,
                }

            finally:
                self._in_progress_vms.discard(config.vm_name)

        except Exception as error:
            self.logger.error(_("Error creating bhyve VM: %s"), error)
            self._in_progress_vms.discard(config.vm_name)
            return {"success": False, "error": str(error)}

    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start a bhyve VM.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        return await self._lifecycle_helper.start_child_host(parameters)

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stop a bhyve VM.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        return await self._lifecycle_helper.stop_child_host(parameters)

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restart a bhyve VM.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        return await self._lifecycle_helper.restart_child_host(parameters)

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Delete a bhyve VM.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        return await self._lifecycle_helper.delete_child_host(parameters)
