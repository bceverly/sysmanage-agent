"""
VMM/vmd-specific child host operations for OpenBSD hosts.
"""

import asyncio
import os
import re
import shutil
import subprocess  # nosec B404 # Required for system command execution
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from src.database.base import get_database_manager
from src.i18n import _
from src.sysmanage_agent.operations.child_host_types import VmmVmConfig
from src.sysmanage_agent.operations.child_host_vmm_autoinstall import (
    VmmAutoinstallOperations,
)
from src.sysmanage_agent.operations.child_host_vmm_bsd_embedder import BsdRdEmbedder
from src.sysmanage_agent.operations.child_host_vmm_github import GitHubVersionChecker
from src.sysmanage_agent.operations.child_host_vmm_httpd_autoinstall import (
    HttpdAutoinstallSetup,
)
from src.sysmanage_agent.operations.child_host_vmm_lifecycle import (
    VmmLifecycleOperations,
)
from src.sysmanage_agent.operations.child_host_vmm_site_builder import (
    SiteTarballBuilder,
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
        self.autoinstall = VmmAutoinstallOperations(logger)
        self.github_checker = GitHubVersionChecker(logger)
        self.site_builder = SiteTarballBuilder(
            logger, get_database_manager().get_session()
        )
        self.bsd_embedder = BsdRdEmbedder(logger)
        self.httpd_setup = HttpdAutoinstallSetup(logger)

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
        Create a new VMM virtual machine with PXE boot and offline installation.

        This new implementation:
        1. Extracts OpenBSD version from distribution parameter
        2. Checks GitHub for latest sysmanage-agent version
        3. Builds site.tgz with agent and dependencies (cached)
        4. Embeds site.tgz into bsd.rd for offline installation
        5. Sets up PXE infrastructure (DHCP + TFTP)
        6. Launches VM with PXE boot
        7. Waits for VM to shutdown (installation complete)
        8. Restarts VM without PXE boot
        9. VM self-registers with server (no SSH needed)

        Args:
            config: VmmVmConfig with all VM settings

        Returns:
            Dict with success status and details
        """
        autoinstall_state = None

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
            if not config.server_url:
                return {"success": False, "error": _("Server URL is required")}

            # Step 1: Extract OpenBSD version from distribution
            await self._send_progress(
                "parsing_version", _("Parsing OpenBSD version...")
            )
            openbsd_version = self._extract_openbsd_version(config.distribution)
            if not openbsd_version:
                return {
                    "success": False,
                    "error": _("Could not parse OpenBSD version from: %s")
                    % config.distribution,
                }

            self.logger.info(_("Creating OpenBSD %s VM"), openbsd_version)

            # Derive FQDN hostname
            fqdn_hostname = self._get_fqdn_hostname(config.hostname, config.server_url)
            if fqdn_hostname != config.hostname:
                self.logger.info(
                    _("Using FQDN hostname '%s' (user provided '%s')"),
                    fqdn_hostname,
                    config.hostname,
                )

            # Step 2: Check VMM is available and running
            await self._send_progress("checking_vmm", _("Checking VMM status..."))
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

            # Step 3: Check if VM already exists
            await self._send_progress(
                "checking_existing", _("Checking for existing VM...")
            )
            if self._vm_exists(config.vm_name):
                return {
                    "success": False,
                    "error": _("VM '%s' already exists") % config.vm_name,
                }

            # Step 4: Ensure directories exist
            self._ensure_vmm_directories()

            # Step 5: Get latest sysmanage-agent version from GitHub
            await self._send_progress(
                "checking_github",
                _("Checking GitHub for latest sysmanage-agent version..."),
            )
            version_result = self.github_checker.get_latest_version()
            if not version_result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to check GitHub version: %s")
                    % version_result.get("error"),
                }

            agent_version = version_result.get("version")
            tag_name = version_result.get("tag_name")
            self.logger.info(
                _("Latest sysmanage-agent version: %s (tag: %s)"),
                agent_version,
                tag_name,
            )

            # Step 6: Build or retrieve cached site.tgz
            await self._send_progress(
                "building_site_tarball",
                _("Building site tarball with sysmanage-agent %s...") % agent_version,
            )

            tarball_url = self.github_checker.get_port_tarball_url(agent_version)
            site_result = self.site_builder.get_or_build_site_tarball(
                openbsd_version=openbsd_version,
                agent_version=agent_version,
                agent_tarball_url=tarball_url,
                server_hostname=config.server_url,
                server_port=config.server_port,
                use_https=config.use_https,
            )

            if not site_result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to build site tarball: %s")
                    % site_result.get("error"),
                }

            site_tgz_path = site_result.get("site_tgz_path")
            self.logger.info(_("Site tarball ready: %s"), site_tgz_path)

            # Step 7: Get gateway IP from vether0 (already configured by vm.conf setup)
            # No PXE/TFTP/DHCP needed - using embedded bsd.rd with HTTP instead
            try:
                result = subprocess.run(  # nosec B603
                    ["ifconfig", "vether0"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                # Parse inet line: "inet 10.1.0.1 netmask 0xffffff00..."
                for line in result.stdout.split("\n"):
                    if "inet " in line and "netmask" in line:
                        gateway_ip = line.split()[1]
                        break
                else:
                    return {
                        "success": False,
                        "error": _("Could not determine gateway IP from vether0"),
                    }
            except Exception as error:
                return {
                    "success": False,
                    "error": _("Failed to get vether0 IP: %s") % str(error),
                }

            self.logger.info(_("Using gateway IP from vether0: %s"), gateway_ip)

            # Step 9: Setup httpd to serve OpenBSD sets (using detected gateway IP)
            await self._send_progress(
                "setting_up_httpd",
                _("Setting up httpd to serve OpenBSD installation sets..."),
            )
            httpd_result = self.httpd_setup.setup_httpd(gateway_ip)
            if not httpd_result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to setup httpd: %s") % httpd_result.get("error"),
                }

            # Download OpenBSD sets to /var/www/htdocs
            await self._send_progress(
                "downloading_sets",
                _("Downloading OpenBSD %s installation sets...") % openbsd_version,
            )
            sets_result = self.httpd_setup.download_openbsd_sets(openbsd_version)
            if not sets_result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to download OpenBSD sets: %s")
                    % sets_result.get("error"),
                }

            sets_dir = Path(sets_result.get("sets_dir"))
            self.logger.info(_("OpenBSD sets downloaded to: %s"), sets_dir)

            # Copy site.tgz to sets directory for HTTP serving
            version_nodot = openbsd_version.replace(".", "")
            site_filename = f"site{version_nodot}.tgz"
            site_dest = sets_dir / site_filename

            await self._send_progress(
                "copying_site_tarball",
                _("Copying site tarball to HTTP directory..."),
            )
            shutil.copy2(site_tgz_path, site_dest)
            self.logger.info(_("Copied site.tgz to: %s"), site_dest)

            # Create install.conf content (to be embedded in bsd.rd)
            install_conf_content = self.httpd_setup.create_install_conf_content(
                hostname=fqdn_hostname,
                username=config.username,
                _password=config.password,
                gateway_ip=gateway_ip,
                _openbsd_version=openbsd_version,
            )

            # Embed install.conf into bsd.rd
            await self._send_progress(
                "embedding_install_conf",
                _("Embedding install.conf into bsd.rd..."),
            )

            embed_result = self.httpd_setup.embed_install_conf_in_bsdrd(
                install_conf_content=install_conf_content,
                openbsd_version=openbsd_version,
                sets_dir=sets_dir,
            )

            if not embed_result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to embed install.conf: %s")
                    % embed_result.get("error"),
                }

            bsdrd_path = embed_result.get("bsdrd_path")
            self.logger.info(_("Modified bsd.rd ready: %s"), bsdrd_path)

            # Step 10: Create disk image
            await self._send_progress(
                "creating_disk",
                _("Creating %s disk image...") % config.disk_size,
            )
            disk_path = os.path.join(VMM_DISK_DIR, f"{config.vm_name}.qcow2")
            disk_result = self._create_disk_image(disk_path, config.disk_size)
            if not disk_result.get("success"):
                return disk_result

            # Step 11: Launch VM with embedded bsd.rd boot
            await self._send_progress(
                "launching_vm_http",
                _("Launching VM with embedded bsd.rd for HTTP installation..."),
            )
            launch_result = await self._launch_vm_with_bsdrd(
                config.vm_name,
                disk_path,
                bsdrd_path,
                config.memory,
                config.cpus,
            )
            if not launch_result.get("success"):
                return launch_result

            # Step 12: Wait for VM to shutdown (installation complete)
            await self._send_progress(
                "awaiting_shutdown",
                _(
                    "Waiting for VM to complete installation and shutdown. "
                    "The VM will install OpenBSD and sysmanage-agent offline, "
                    "then shutdown automatically. This may take 10-15 minutes."
                ),
            )
            shutdown_result = await self._wait_for_vm_shutdown(
                config.vm_name, timeout=1800
            )

            if not shutdown_result.get("success"):
                return shutdown_result

            self.logger.info(
                _("VM %s has shut down after installation"), config.vm_name
            )

            # Step 13: Restart VM to boot from installed disk
            await self._send_progress(
                "restarting_vm",
                _("Restarting VM to boot from installed system..."),
            )
            restart_result = await self._launch_vm_no_pxe(
                config.vm_name,
                disk_path,
                config.memory,
                config.cpus,
            )
            if not restart_result.get("success"):
                return restart_result

            # Step 14: Wait for VM to self-register with server
            await self._send_progress(
                "awaiting_registration",
                _(
                    "Waiting for VM to boot and register with server. "
                    "The sysmanage-agent will start automatically and connect."
                ),
            )

            await self._send_progress("complete", _("VM creation complete"))

            return {
                "success": True,
                "child_name": config.vm_name,
                "child_type": "vmm",
                "hostname": fqdn_hostname,
                "username": config.username,
                "openbsd_version": openbsd_version,
                "agent_version": agent_version,
                "message": _(
                    "VMM virtual machine '%s' created successfully. "
                    "VM will self-register when agent starts."
                )
                % config.vm_name,
            }

        except Exception as error:
            self.logger.error(_("Error creating VMM VM: %s"), error, exc_info=True)
            # Cleanup on error
            if autoinstall_state:
                try:
                    self.autoinstall.cleanup_install_conf()
                    self.autoinstall.cleanup_autoinstall_infrastructure(
                        autoinstall_state
                    )
                except Exception:  # nosec B110
                    pass
            return {"success": False, "error": str(error)}

    def _extract_openbsd_version(self, distribution: str) -> Optional[str]:
        """
        Extract OpenBSD version from distribution string.

        Args:
            distribution: Distribution string (e.g., "OpenBSD 7.7", "openbsd-7.6")

        Returns:
            Version string (e.g., "7.7") or None if not found
        """
        try:
            # Try to match version pattern like "7.7", "7.6", etc.
            match = re.search(r"(\d+\.\d+)", distribution)
            if match:
                return match.group(1)
            return None
        except Exception as error:
            self.logger.error(_("Error parsing OpenBSD version: %s"), error)
            return None

    async def _wait_for_vm_shutdown(
        self, vm_name: str, timeout: int = 1800
    ) -> Dict[str, Any]:
        """
        Wait for VM to shutdown by polling vmctl status.

        Args:
            vm_name: Name of the VM
            timeout: Maximum time to wait in seconds

        Returns:
            Dict with success status
        """
        start_time = time.time()
        last_status_log = 0

        self.logger.info(_("Waiting for VM %s to shutdown..."), vm_name)

        while time.time() - start_time < timeout:
            try:
                # Check if VM is still running
                result = subprocess.run(  # nosec B603 B607
                    ["vmctl", "status", vm_name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                # vmctl status returns non-zero if VM is not running
                if result.returncode != 0:
                    self.logger.info(_("VM %s has shut down"), vm_name)
                    return {"success": True}

                # Log status every 60 seconds
                elapsed = int(time.time() - start_time)
                if elapsed - last_status_log >= 60:
                    self.logger.info(
                        _("VM still running... (%d seconds elapsed)"), elapsed
                    )
                    last_status_log = elapsed

            except Exception as error:
                self.logger.debug("Error checking VM status: %s", error)

            await asyncio.sleep(10)

        return {
            "success": False,
            "error": _("Timeout waiting for VM to shutdown"),
        }

    async def _launch_vm_no_pxe(
        self,
        vm_name: str,
        disk_path: str,
        memory: str,
        _cpus: int,
    ) -> Dict[str, Any]:
        """
        Launch a VM without PXE boot (boot from disk).

        Args:
            vm_name: Name for the VM
            disk_path: Path to the disk image
            memory: Memory allocation (e.g., "1G")
            _cpus: Number of CPUs (reserved for future use with vm.conf)

        Returns:
            Dict with success status
        """
        try:
            # Build vmctl start command for disk boot
            # -m: memory
            # -n local: use the "local" switch defined in vm.conf
            # -i 1: one network interface
            # -d: disk image
            # No -B flag means boot from disk
            cmd = [
                "vmctl",
                "start",
                "-m",
                memory,
                "-n",
                "local",
                "-i",
                "1",
                "-d",
                disk_path,
                vm_name,
            ]

            self.logger.info(_("Launching VM from disk: %s"), " ".join(cmd))

            result = subprocess.run(  # nosec B603 B607
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info(_("VM %s launched from disk"), vm_name)
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

    async def _launch_vm_with_bsdrd(
        self,
        vm_name: str,
        disk_path: str,
        bsdrd_path: str,
        memory: str,
        _cpus: int,
    ) -> Dict[str, Any]:
        """
        Launch a VM with embedded bsd.rd boot for HTTP-based autoinstall.

        Args:
            vm_name: Name for the VM
            disk_path: Path to the disk image
            bsdrd_path: Path to the embedded bsd.rd file
            memory: Memory allocation (e.g., "1G")
            _cpus: Number of CPUs (reserved for future use with vm.conf)

        Returns:
            Dict with success status
        """
        try:
            # Build vmctl start command for embedded bsd.rd boot
            # -m: memory
            # -n local: use the "local" switch defined in vm.conf
            # -i 1: one network interface
            # -b bsdrd_path: boot from embedded bsd.rd kernel
            # -d: disk image
            cmd = [
                "vmctl",
                "start",
                "-m",
                memory,
                "-n",
                "local",
                "-i",
                "1",
                "-b",
                bsdrd_path,
                "-d",
                disk_path,
                vm_name,
            ]

            self.logger.info(_("Launching VM with embedded bsd.rd: %s"), " ".join(cmd))

            result = subprocess.run(  # nosec B603 B607
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info(_("VM %s launched with embedded bsd.rd"), vm_name)
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
