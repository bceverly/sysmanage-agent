"""
VMM/vmd-specific child host operations for OpenBSD hosts.
"""

import asyncio
import os
import re
import subprocess  # nosec B404 # Required for system command execution
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from src.i18n import _
from src.sysmanage_agent.operations.child_host_types import VmmVmConfig
from src.sysmanage_agent.operations.child_host_vmm_lifecycle import (
    VmmLifecycleOperations,
)
from src.sysmanage_agent.operations.child_host_vmm_ssh import VmmSshOperations

# Default paths for VMM
VMM_DISK_DIR = "/var/vmm"
VMM_ISO_DIR = "/var/vmm/iso"


class VmmOperations:
    """VMM/vmd-specific operations for child host management on OpenBSD."""

    def __init__(self, agent_instance, logger, virtualization_checks):
        """
        Initialize VMM operations.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks
        self.ssh_ops = VmmSshOperations(logger)
        self.lifecycle = VmmLifecycleOperations(logger, virtualization_checks)

    async def initialize_vmd(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initialize VMM/vmd on OpenBSD: enable and start the vmd daemon.

        This is called when the user clicks "Enable VMM" in the UI.

        Returns:
            Dict with success status and any required actions (like reboot)
        """
        try:
            self.logger.info(_("Initializing VMM/vmd"))

            # Check current VMM status
            vmm_check = self.virtualization_checks.check_vmm_support()

            if not vmm_check.get("available"):
                return {
                    "success": False,
                    "error": _(
                        "VMM is not available on this system (requires OpenBSD)"
                    ),
                }

            # Check if kernel supports VMM
            if not vmm_check.get("kernel_supported"):
                return {
                    "success": False,
                    "error": _(
                        "VMM kernel support is not enabled. "
                        "Ensure your CPU supports hardware virtualization (VMX/SVM) "
                        "and the kernel has VMM support compiled in."
                    ),
                    "needs_reboot": True,
                }

            # If already running, nothing to do
            if vmm_check.get("running"):
                self.logger.info(_("vmd is already running"))
                return {
                    "success": True,
                    "message": _("VMM/vmd is already enabled and running"),
                    "already_enabled": True,
                }

            # Step 1: Enable vmd service using rcctl
            if not vmm_check.get("enabled"):
                self.logger.info(_("Enabling vmd service"))
                enable_result = subprocess.run(  # nosec B603 B607
                    ["rcctl", "enable", "vmd"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                if enable_result.returncode != 0:
                    error_msg = (
                        enable_result.stderr or enable_result.stdout or "Unknown error"
                    )
                    self.logger.error(_("Failed to enable vmd: %s"), error_msg)
                    return {
                        "success": False,
                        "error": _("Failed to enable vmd service: %s") % error_msg,
                    }

                self.logger.info(_("vmd service enabled"))

            # Step 2: Start vmd service using rcctl
            self.logger.info(_("Starting vmd service"))
            start_result = subprocess.run(  # nosec B603 B607
                ["rcctl", "start", "vmd"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if start_result.returncode != 0:
                error_msg = (
                    start_result.stderr or start_result.stdout or "Unknown error"
                )
                self.logger.error(_("Failed to start vmd: %s"), error_msg)
                return {
                    "success": False,
                    "error": _("Failed to start vmd service: %s") % error_msg,
                }

            self.logger.info(_("vmd service started"))

            # Verify vmd is now running
            verify_result = self.virtualization_checks.check_vmm_support()

            if verify_result.get("running"):
                self.logger.info(_("VMM/vmd is ready for use"))
                return {
                    "success": True,
                    "message": _("VMM/vmd has been enabled and started"),
                    "needs_reboot": False,
                }

            return {
                "success": False,
                "error": _("vmd was started but verification failed"),
            }

        except subprocess.TimeoutExpired:
            self.logger.error(_("Timeout while initializing vmd"))
            return {
                "success": False,
                "error": _("Timeout while initializing vmd service"),
            }
        except Exception as error:
            self.logger.error(_("Error initializing vmd: %s"), error)
            return {
                "success": False,
                "error": _("Error initializing vmd: %s") % str(error),
            }

    async def check_vmd_ready(self) -> Dict[str, Any]:
        """
        Check if vmd is operational and ready to create VMs.

        Returns:
            Dict with success status and vmd status info
        """
        return await self.lifecycle.check_vmd_ready()

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
        return await self.lifecycle.get_vm_status(vm_name)

    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start a stopped VMM virtual machine.

        Args:
            parameters: Dict containing:
                - child_name: Name of the VM to start
                - wait: If True, wait for VM to be running (default: True)

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        wait = parameters.get("wait", True)
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        return await self.lifecycle.start_vm(child_name, wait=wait)

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stop a running VMM virtual machine.

        Args:
            parameters: Dict containing:
                - child_name: Name of the VM to stop
                - force: If True, force stop the VM
                - wait: If True, wait for VM to be stopped (default: True)

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        force = parameters.get("force", False)
        wait = parameters.get("wait", True)

        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        return await self.lifecycle.stop_vm(child_name, force=force, wait=wait)

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restart a VMM virtual machine.

        Args:
            parameters: Dict containing:
                - child_name: Name of the VM to restart

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        return await self.lifecycle.restart_vm(child_name)

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Delete a VMM virtual machine.

        Args:
            parameters: Dict containing:
                - child_name: Name of the VM to delete
                - delete_disk: If True, also delete the disk image

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        delete_disk = parameters.get("delete_disk", False)
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        return await self.lifecycle.delete_vm(child_name, delete_disk=delete_disk)

    # =========================================================================
    # VM Creation Methods (Phase 5)
    # =========================================================================

    async def create_vmm_vm(self, config: VmmVmConfig) -> Dict[str, Any]:
        """
        Create a new VMM virtual machine with the full installation flow.

        This is a complex operation that:
        1. Creates a disk image
        2. Downloads the install ISO
        3. Launches the VM with the ISO
        4. Waits for installation (manual or autoinstall)
        5. Reboots without ISO
        6. Waits for VM to get IP
        7. Establishes SSH connection
        8. Configures hostname and user
        9. Installs and configures the sysmanage-agent

        Args:
            config: VmmVmConfig with all VM settings

        Returns:
            Dict with success status and details
        """
        try:
            # Validate inputs
            if not config.distribution:
                return {"success": False, "error": _("Distribution is required")}
            if not config.vm_name:
                return {"success": False, "error": _("VM name is required")}
            if not config.hostname:
                return {"success": False, "error": _("Hostname is required")}
            if not config.username:
                return {"success": False, "error": _("Username is required")}
            if not config.password:
                return {"success": False, "error": _("Password is required")}

            # Derive FQDN hostname if user didn't provide a domain
            fqdn_hostname = self._get_fqdn_hostname(config.hostname, config.server_url)
            if fqdn_hostname != config.hostname:
                self.logger.info(
                    "Using FQDN hostname '%s' (user provided '%s')",
                    fqdn_hostname,
                    config.hostname,
                )

            # Send progress update
            await self._send_progress("checking_vmm", _("Checking VMM status..."))

            # Step 1: Check VMM is available and running
            vmm_check = self.virtualization_checks.check_vmm_support()
            if not vmm_check.get("available"):
                return {
                    "success": False,
                    "error": _("VMM is not available on this system"),
                }

            if not vmm_check.get("running"):
                return {
                    "success": False,
                    "error": _("vmd is not running. Please enable VMM first."),
                }

            # Step 2: Check if VM already exists
            await self._send_progress(
                "checking_existing", _("Checking for existing VM...")
            )
            if self._vm_exists(config.vm_name):
                return {
                    "success": False,
                    "error": _("VM '%s' already exists") % config.vm_name,
                }

            # Step 3: Ensure directories exist
            self._ensure_vmm_directories()

            # Step 4: Create disk image
            await self._send_progress(
                "creating_disk",
                _("Creating %s disk image...") % config.disk_size,
            )
            disk_path = os.path.join(VMM_DISK_DIR, f"{config.vm_name}.qcow2")
            disk_result = self._create_disk_image(disk_path, config.disk_size)
            if not disk_result.get("success"):
                return disk_result

            # Step 5: Download install ISO if needed
            await self._send_progress(
                "downloading_iso", _("Downloading install ISO...")
            )
            iso_result = await self._get_install_iso(config.iso_url)
            if not iso_result.get("success"):
                return iso_result
            iso_path = iso_result.get("iso_path")

            # Step 6: Launch VM with install ISO
            await self._send_progress(
                "launching_vm",
                _("Launching VM %s with install media...") % config.vm_name,
            )
            launch_result = await self._launch_vm_with_iso(
                config.vm_name,
                disk_path,
                iso_path,
                config.memory,
                config.cpus,
            )
            if not launch_result.get("success"):
                return launch_result

            # Step 7: Wait for installation to complete
            # For now, we need manual installation via serial console
            # This can be enhanced with autoinstall support later
            await self._send_progress(
                "awaiting_installation",
                _(
                    "VM is running with install media. "
                    "Complete the installation via serial console "
                    "(vmctl console %s), then the setup will continue."
                )
                % config.vm_name,
            )

            # Step 8: Wait for VM to get an IP address (indicates OS is booted)
            await self._send_progress(
                "waiting_for_ip", _("Waiting for VM to obtain IP address...")
            )
            ip_result = await self._wait_for_vm_ip(config.vm_name, timeout=1800)
            if not ip_result.get("success"):
                return ip_result
            vm_ip = ip_result.get("ip")

            # Step 9: Wait for SSH to become available
            await self._send_progress(
                "waiting_for_ssh", _("Waiting for SSH to become available...")
            )
            ssh_result = await self.ssh_ops.wait_for_ssh(vm_ip, timeout=300)
            if not ssh_result.get("success"):
                return ssh_result

            # Step 10: Set hostname
            await self._send_progress(
                "setting_hostname", _("Setting hostname to %s...") % fqdn_hostname
            )
            hostname_result = await self.ssh_ops.run_ssh_command(
                vm_ip,
                config.username,
                config.password,
                f"hostname {fqdn_hostname}",
            )
            if not hostname_result.get("success"):
                self.logger.warning(
                    "Hostname configuration failed: %s", hostname_result.get("error")
                )

            # Step 11: Install sysmanage-agent
            if config.agent_install_commands:
                await self._send_progress(
                    "installing_agent", _("Installing sysmanage-agent...")
                )
                agent_result = await self.ssh_ops.install_agent_via_ssh(
                    vm_ip,
                    config.username,
                    config.password,
                    config.agent_install_commands,
                )
                if not agent_result.get("success"):
                    self.logger.warning(
                        "Agent installation failed: %s", agent_result.get("error")
                    )

            # Step 12: Configure agent
            if config.server_url:
                await self._send_progress(
                    "configuring_agent", _("Configuring sysmanage-agent...")
                )
                config_result = await self.ssh_ops.configure_agent_via_ssh(
                    vm_ip,
                    config.username,
                    config.password,
                    config.server_url,
                    fqdn_hostname,
                    config.server_port,
                    config.use_https,
                )
                if not config_result.get("success"):
                    self.logger.warning(
                        "Agent configuration failed: %s", config_result.get("error")
                    )

            # Step 13: Start agent service
            await self._send_progress("starting_agent", _("Starting agent service..."))
            start_result = await self.ssh_ops.start_agent_service_via_ssh(
                vm_ip,
                config.username,
                config.password,
            )
            if not start_result.get("success"):
                self.logger.warning(
                    "Agent service start failed: %s", start_result.get("error")
                )

            await self._send_progress("complete", _("VM creation complete"))

            return {
                "success": True,
                "child_name": config.vm_name,
                "child_type": "vmm",
                "hostname": fqdn_hostname,
                "username": config.username,
                "ip_address": vm_ip,
                "message": _("VMM virtual machine '%s' created successfully")
                % config.vm_name,
            }

        except Exception as error:
            self.logger.error(_("Error creating VMM VM: %s"), error)
            return {"success": False, "error": str(error)}

    async def _send_progress(self, step: str, message: str):
        """Send a progress update to the server."""
        try:
            if hasattr(self.agent, "send_message"):
                progress_message = self.agent.create_message(
                    "child_host_creation_progress",
                    {
                        "step": step,
                        "message": message,
                        "child_type": "vmm",
                    },
                )
                await self.agent.send_message(progress_message)
        except Exception as error:
            self.logger.debug("Failed to send progress update: %s", error)

    def _get_fqdn_hostname(self, hostname: str, server_url: str) -> str:
        """
        Derive FQDN hostname from server URL domain if not already FQDN.

        Args:
            hostname: User-provided hostname
            server_url: Server URL to derive domain from

        Returns:
            FQDN hostname
        """
        if "." in hostname:
            return hostname

        # Extract domain from server_url
        try:
            parsed = urlparse(server_url)
            server_host = parsed.hostname or ""
            if "." in server_host:
                parts = server_host.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                    return f"{hostname}.{domain}"
        except Exception:  # nosec B110 - returns original hostname on parse failure
            pass

        return hostname

    def _ensure_vmm_directories(self):
        """Ensure VMM directories exist."""
        for dir_path in [VMM_DISK_DIR, VMM_ISO_DIR]:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, mode=0o755)
                self.logger.info(_("Created VMM directory: %s"), dir_path)

    def _vm_exists(self, vm_name: str) -> bool:
        """Check if a VM with the given name already exists."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "status", vm_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            # vmctl status returns 0 if the VM exists (running or not)
            # and non-zero if it doesn't exist
            return result.returncode == 0
        except Exception:
            return False

    def _create_disk_image(self, disk_path: str, size: str) -> Dict[str, Any]:
        """
        Create a qcow2 disk image for the VM.

        Args:
            disk_path: Path for the disk image
            size: Disk size (e.g., "20G")

        Returns:
            Dict with success status
        """
        try:
            if os.path.exists(disk_path):
                return {
                    "success": False,
                    "error": _("Disk image already exists: %s") % disk_path,
                }

            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "create", "-s", size, disk_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info(_("Created disk image: %s (%s)"), disk_path, size)
                return {"success": True, "disk_path": disk_path}

            error_msg = result.stderr or result.stdout or "Unknown error"
            return {
                "success": False,
                "error": _("Failed to create disk image: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout creating disk image"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _get_install_iso(self, iso_url: str) -> Dict[str, Any]:
        """
        Get the install ISO, downloading if necessary.

        Args:
            iso_url: URL to download the ISO from

        Returns:
            Dict with success status and iso_path
        """
        if not iso_url:
            return {
                "success": False,
                "error": _("No ISO URL provided"),
            }

        try:
            # Extract filename from URL
            parsed = urlparse(iso_url)
            filename = os.path.basename(parsed.path)
            if not filename:
                filename = "install.iso"

            iso_path = os.path.join(VMM_ISO_DIR, filename)

            # Check if ISO already exists
            if os.path.exists(iso_path):
                self.logger.info(_("Using existing ISO: %s"), iso_path)
                return {"success": True, "iso_path": iso_path}

            # Download the ISO using ftp (OpenBSD's built-in downloader)
            self.logger.info(_("Downloading ISO from %s"), iso_url)
            result = subprocess.run(  # nosec B603 B607
                ["ftp", "-o", iso_path, iso_url],
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour timeout for large ISOs
                check=False,
            )

            if result.returncode == 0 and os.path.exists(iso_path):
                self.logger.info(_("Downloaded ISO: %s"), iso_path)
                return {"success": True, "iso_path": iso_path}

            error_msg = result.stderr or result.stdout or "Download failed"
            return {
                "success": False,
                "error": _("Failed to download ISO: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout downloading ISO"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _launch_vm_with_iso(
        self,
        vm_name: str,
        disk_path: str,
        iso_path: str,
        memory: str,
        _cpus: int,
    ) -> Dict[str, Any]:
        """
        Launch a VM with the install ISO attached.

        Uses vmd's built-in local networking (-L flag) for DHCP.

        Args:
            vm_name: Name for the VM
            disk_path: Path to the disk image
            iso_path: Path to the install ISO
            memory: Memory allocation (e.g., "1G")
            _cpus: Number of CPUs (reserved for future use with vm.conf)

        Returns:
            Dict with success status
        """
        try:
            # Build vmctl start command
            # -m: memory
            # -L: local network with DHCP
            # -i 1: one network interface
            # -r: boot from ISO (CDROM)
            # -d: disk image
            cmd = [
                "vmctl",
                "start",
                "-m",
                memory,
                "-L",
                "-i",
                "1",
                "-r",
                iso_path,
                "-d",
                disk_path,
                vm_name,
            ]

            self.logger.info(_("Launching VM: %s"), " ".join(cmd))

            result = subprocess.run(  # nosec B603 B607
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info(_("VM %s launched with install media"), vm_name)
                return {"success": True}

            error_msg = result.stderr or result.stdout or "Unknown error"
            return {
                "success": False,
                "error": _("Failed to launch VM: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout launching VM"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _wait_for_vm_ip(
        self, vm_name: str, timeout: int = 1800
    ) -> Dict[str, Any]:
        """
        Wait for the VM to obtain an IP address.

        Checks the vmd DHCP leases or ARP table.

        Args:
            vm_name: Name of the VM
            timeout: Maximum time to wait in seconds

        Returns:
            Dict with success status and IP address
        """
        start_time = time.time()
        last_status_log = 0

        while time.time() - start_time < timeout:
            try:
                # Try to get VM IP from vmd's DHCP leases
                vm_ip_addr = self._get_vm_ip_from_leases(vm_name)
                if vm_ip_addr:
                    self.logger.info(_("VM %s has IP: %s"), vm_name, vm_ip_addr)
                    return {"success": True, "ip": vm_ip_addr}

                # Log status every 60 seconds
                elapsed = int(time.time() - start_time)
                if elapsed - last_status_log >= 60:
                    self.logger.info(
                        _("Waiting for VM IP... (%d seconds elapsed)"), elapsed
                    )
                    last_status_log = elapsed

            except Exception as error:
                self.logger.debug("Error checking VM IP: %s", error)

            await asyncio.sleep(10)

        return {
            "success": False,
            "error": _("Timeout waiting for VM to obtain IP address"),
        }

    def _get_vm_ip_from_leases(self, vm_name: str) -> Optional[str]:
        """
        Get VM IP address from vmd DHCP leases.

        Args:
            vm_name: Name of the VM

        Returns:
            IP address string or None
        """
        try:
            # Check vmctl status for the VM's interface info
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "status", vm_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return None

            # Parse the VM ID from status output
            # vmctl status output format varies, but typically shows VM info
            # We need to find the local interface and check DHCP leases

            # Alternative: Check ARP table for MACs that might belong to VMs
            # vmd assigns MACs in the fe:e1:ba:d* range
            arp_result = subprocess.run(  # nosec B603 B607
                ["arp", "-an"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if arp_result.returncode == 0:
                # Look for vmd-assigned MAC addresses (fe:e1:ba:d*)
                # and extract the corresponding IP
                for line in arp_result.stdout.splitlines():
                    if "fe:e1:ba:d" in line.lower():
                        # Parse IP from ARP entry
                        # Format: host (ip) at mac on interface
                        match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
                        if match:
                            return match.group(1)

            return None

        except Exception:
            return None
