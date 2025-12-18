"""
VMM VM creation orchestration for OpenBSD.

This module handles the complete VM creation workflow including:
- OpenBSD version extraction and validation
- GitHub version checking for sysmanage-agent
- Site tarball building and caching
- HTTP-based autoinstall setup
- Disk image creation
- VM launch with embedded bsd.rd
- Installation monitoring and restart
"""

import asyncio
import json
import os
import re
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from src.i18n import _
from src.sysmanage_agent.operations.child_host_types import VmmVmConfig
from src.sysmanage_agent.operations.child_host_vmm_disk import VmmDiskOperations
from src.sysmanage_agent.operations.child_host_vmm_vmconf import VmConfManager

# VMM directories
VMM_DISK_DIR = "/var/vmm"
VMM_METADATA_DIR = "/var/vmm/metadata"


class VmmVmCreator:
    """Handles VMM VM creation workflow."""

    def __init__(
        self,
        agent_instance,
        logger,
        virtualization_checks,
        httpd_setup,
        github_checker,
        site_builder,
    ):
        """
        Initialize VM creator.

        Args:
            agent_instance: Reference to main SysManageAgent
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
            httpd_setup: HttpdAutoinstallSetup instance
            github_checker: GitHubVersionChecker instance
            site_builder: SiteTarballBuilder instance
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks
        self.httpd_setup = httpd_setup
        self.github_checker = github_checker
        self.site_builder = site_builder
        self.disk_ops = VmmDiskOperations(logger)
        self.vmconf_manager = VmConfManager(logger)

    async def create_vmm_vm(self, config: VmmVmConfig) -> Dict[str, Any]:
        """
        Create a new VMM virtual machine with HTTP-based autoinstall.

        Workflow:
        1. Extract OpenBSD version from distribution
        2. Check GitHub for latest sysmanage-agent version
        3. Build site.tgz with agent and dependencies (cached)
        4. Setup HTTP server for OpenBSD sets
        5. Embed install.conf into bsd.rd
        6. Create disk image
        7. Launch VM with embedded bsd.rd
        8. Wait for installation to complete
        9. Restart VM to boot from disk
        10. Wait for VM to self-register with server

        Args:
            config: VmmVmConfig with all VM settings

        Returns:
            Dict with success status and details
        """
        self.logger.info(
            "🚀 [VM_CREATE_START] Starting VM creation for: %s", config.vm_name
        )
        self.logger.info("🔍 [VM_CREATE_CONFIG] Distribution: %s", config.distribution)
        self.logger.info("🔍 [VM_CREATE_CONFIG] Hostname: %s", config.hostname)

        try:
            # Validate inputs
            self.logger.info("📋 [STEP_1] Validating configuration...")
            validation_result = self._validate_config(config)
            self.logger.info(
                "✅ [STEP_1] Validation result: %s", validation_result.get("success")
            )
            if not validation_result.get("success"):
                self.logger.error(
                    "❌ [STEP_1] Validation failed: %s", validation_result.get("error")
                )
                return validation_result
            self.logger.info("✅ [STEP_1] Configuration validated successfully")

            # Step 1: Extract OpenBSD version
            self.logger.info(
                "📋 [STEP_2] Extracting OpenBSD version from distribution..."
            )
            await self._send_progress(
                "parsing_version", _("Parsing OpenBSD version...")
            )
            openbsd_version = self._extract_openbsd_version(config.distribution)
            self.logger.info("🔍 [STEP_2] Extracted version: %s", openbsd_version)
            if not openbsd_version:
                self.logger.error(
                    "❌ [STEP_2] Failed to parse OpenBSD version from: %s",
                    config.distribution,
                )
                return {
                    "success": False,
                    "error": _("Could not parse OpenBSD version from: %s")
                    % config.distribution,
                }
            self.logger.info("✅ [STEP_2] OpenBSD version: %s", openbsd_version)

            self.logger.info(_("Creating OpenBSD %s VM"), openbsd_version)

            # Derive FQDN hostname
            self.logger.info("📋 [STEP_3] Deriving FQDN hostname...")
            fqdn_hostname = self._get_fqdn_hostname(
                config.hostname, config.server_config.server_url
            )
            self.logger.info("✅ [STEP_3] FQDN hostname: %s", fqdn_hostname)
            if fqdn_hostname != config.hostname:
                self.logger.info(
                    _("Using FQDN hostname '%s' (user provided '%s')"),
                    fqdn_hostname,
                    config.hostname,
                )

            # Step 2: Check VMM availability
            self.logger.info("📋 [STEP_4] Checking VMM availability...")
            vmm_result = await self._check_vmm_ready()
            self.logger.info("🔍 [STEP_4] VMM check result: %s", vmm_result)
            if not vmm_result.get("success"):
                self.logger.error(
                    "❌ [STEP_4] VMM not ready: %s", vmm_result.get("error")
                )
                return vmm_result
            self.logger.info("✅ [STEP_4] VMM is ready")

            # Step 3: Check if VM already exists
            self.logger.info("📋 [STEP_5] Checking if VM already exists...")
            await self._send_progress(
                "checking_existing", _("Checking for existing VM...")
            )
            vm_exists = self._vm_exists(config.vm_name)
            self.logger.info("🔍 [STEP_5] VM exists check: %s", vm_exists)
            if vm_exists:
                self.logger.error("❌ [STEP_5] VM '%s' already exists", config.vm_name)
                return {
                    "success": False,
                    "error": _("VM '%s' already exists") % config.vm_name,
                }
            self.logger.info("✅ [STEP_5] VM does not exist, proceeding...")

            # Step 4: Ensure directories exist
            self.logger.info("📋 [STEP_6] Ensuring VMM directories exist...")
            self._ensure_vmm_directories()
            self.logger.info("✅ [STEP_6] Directories ensured")

            # Step 5: Get latest sysmanage-agent version
            self.logger.info(
                "📋 [STEP_7] Getting latest sysmanage-agent version from GitHub..."
            )
            agent_version, tag_name = await self._get_agent_version()
            self.logger.info(
                "✅ [STEP_7] Latest sysmanage-agent version: %s (tag: %s)",
                agent_version,
                tag_name,
            )

            # Step 6: Build or retrieve site.tgz
            self.logger.info("📋 [STEP_8] Building/retrieving site.tgz...")
            site_tgz_path = await self._build_site_tarball(
                openbsd_version, agent_version, config
            )
            self.logger.info("✅ [STEP_8] Site tarball ready: %s", site_tgz_path)

            # Step 7: Get gateway IP
            self.logger.info("📋 [STEP_9] Getting gateway IP from vether0...")
            gateway_ip = self._get_gateway_ip()
            self.logger.info("🔍 [STEP_9] Gateway IP: %s", gateway_ip)
            if not gateway_ip:
                self.logger.error("❌ [STEP_9] Could not determine gateway IP")
                return {
                    "success": False,
                    "error": _("Could not determine gateway IP from vether0"),
                }
            self.logger.info("✅ [STEP_9] Using gateway IP: %s", gateway_ip)

            # Step 9a: Get next available VM IP
            vm_ip = self._get_next_vm_ip(gateway_ip)
            self.logger.info("✅ [STEP_9a] Using VM IP: %s", vm_ip)

            # Step 8: Setup HTTP server and download sets
            self.logger.info(
                "📋 [STEP_10] Setting up HTTP server and downloading OpenBSD sets..."
            )
            sets_dir = await self._setup_http_and_download_sets(
                openbsd_version, gateway_ip
            )
            self.logger.info("✅ [STEP_10] OpenBSD sets downloaded to: %s", sets_dir)

            # Step 9: Copy site.tgz to sets directory
            self.logger.info("📋 [STEP_11] Copying site.tgz to sets directory...")
            site_dest = await self._copy_site_tarball(
                site_tgz_path, sets_dir, openbsd_version
            )
            self.logger.info("✅ [STEP_11] Copied site.tgz to: %s", site_dest)

            # Step 10: Create and embed install.conf
            self.logger.info(
                "📋 [STEP_12] Creating and embedding install.conf into bsd.rd..."
            )
            bsdrd_path = await self._create_and_embed_install_conf(
                config, fqdn_hostname, gateway_ip, openbsd_version, sets_dir, vm_ip
            )
            self.logger.info("✅ [STEP_12] Modified bsd.rd ready: %s", bsdrd_path)

            # Step 11: Create disk image
            self.logger.info("📋 [STEP_13] Creating VM disk image...")
            disk_path = await self._create_vm_disk(config)
            self.logger.info("🔍 [STEP_13] Disk path: %s", disk_path)
            if not disk_path:
                self.logger.error("❌ [STEP_13] Failed to create disk image")
                return {
                    "success": False,
                    "error": _("Failed to create disk image"),
                }
            self.logger.info("✅ [STEP_13] Disk image created: %s", disk_path)

            # Step 12: Launch VM with embedded bsd.rd
            self.logger.info(
                "📋 [STEP_14] Launching VM with embedded bsd.rd for installation..."
            )
            launch_result = await self._launch_vm_for_install(
                config, disk_path, bsdrd_path
            )
            self.logger.info("🔍 [STEP_14] Launch result: %s", launch_result)
            if not launch_result.get("success"):
                self.logger.error(
                    "❌ [STEP_14] Failed to launch VM: %s", launch_result.get("error")
                )
                return launch_result
            self.logger.info("✅ [STEP_14] VM launched successfully")

            # Step 13: Wait for installation to complete
            self.logger.info("📋 [STEP_15] Waiting for installation to complete...")
            shutdown_result = await self._wait_for_installation_complete(config.vm_name)
            self.logger.info("🔍 [STEP_15] Shutdown result: %s", shutdown_result)
            if not shutdown_result.get("success"):
                self.logger.error(
                    "❌ [STEP_15] Installation did not complete: %s",
                    shutdown_result.get("error"),
                )
                return shutdown_result
            self.logger.info("✅ [STEP_15] Installation completed and VM shutdown")

            # Step 14: Restart VM to boot from disk
            self.logger.info("📋 [STEP_16] Restarting VM to boot from disk...")
            restart_result = await self._restart_vm_from_disk(config, disk_path)
            self.logger.info("🔍 [STEP_16] Restart result: %s", restart_result)
            if not restart_result.get("success"):
                self.logger.error(
                    "❌ [STEP_16] Failed to restart VM: %s", restart_result.get("error")
                )
                return restart_result
            self.logger.info("✅ [STEP_16] VM restarted and booting from disk")

            # Step 15: Wait for self-registration
            self.logger.info("📋 [STEP_17] Sending final progress update...")
            await self._send_progress(
                "awaiting_registration",
                _(
                    "Waiting for VM to boot and register with server. "
                    "The sysmanage-agent will start automatically and connect."
                ),
            )
            self.logger.info("✅ [STEP_17] Progress update sent")

            await self._send_progress("complete", _("VM creation complete"))
            self.logger.info("🎉 [STEP_17] VM creation complete progress sent")

            # Save metadata
            self.logger.info("📋 [STEP_18] Saving VM metadata...")
            self._save_vm_metadata(
                vm_name=config.vm_name,
                hostname=fqdn_hostname,
                distribution=config.distribution,
                openbsd_version=openbsd_version,
                vm_ip=vm_ip,
            )
            self.logger.info("✅ [STEP_18] Metadata saved")

            # Step 19: Add VM to /etc/vm.conf for boot persistence
            self.logger.info(
                "📋 [STEP_19] Adding VM to /etc/vm.conf for boot persistence..."
            )
            self.vmconf_manager.persist_vm(
                vm_name=config.vm_name,
                disk_path=disk_path,
                memory=config.memory or "1G",
            )
            self.logger.info("✅ [STEP_19] VM added to /etc/vm.conf")

            self.logger.info(
                "🎉 [VM_CREATE_SUCCESS] VM '%s' created successfully!", config.vm_name
            )
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
            self.logger.error(
                "💥 [VM_CREATE_ERROR] Exception caught in create_vmm_vm: %s",
                error,
                exc_info=True,
            )
            self.logger.error(
                "💥 [VM_CREATE_ERROR] Error type: %s", type(error).__name__
            )
            self.logger.error("💥 [VM_CREATE_ERROR] Error message: %s", str(error))
            return {"success": False, "error": str(error)}

    # =========================================================================
    # Validation Methods
    # =========================================================================

    def _validate_config(self, config: VmmVmConfig) -> Dict[str, Any]:
        """Validate VM configuration."""
        if not config.distribution:
            return {"success": False, "error": _("Distribution is required")}
        if not config.vm_name:
            return {"success": False, "error": _("VM name is required")}
        if not config.hostname:
            return {"success": False, "error": _("Hostname is required")}
        if not config.username:
            return {"success": False, "error": _("Username is required")}
        if not config.password_hash:
            return {"success": False, "error": _("Password hash is required")}
        if not config.server_config.server_url:
            return {"success": False, "error": _("Server URL is required")}
        return {"success": True}

    # =========================================================================
    # Setup and Preparation Methods
    # =========================================================================

    async def _check_vmm_ready(self) -> Dict[str, Any]:
        """Check if VMM is available and running."""
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
        return {"success": True}

    async def _get_agent_version(self) -> tuple:
        """Get latest sysmanage-agent version from GitHub."""
        await self._send_progress(
            "checking_github",
            _("Checking GitHub for latest sysmanage-agent version..."),
        )
        version_result = self.github_checker.get_latest_version()
        if not version_result.get("success"):
            raise RuntimeError(
                _("Failed to check GitHub version: %s") % version_result.get("error")
            )
        return version_result.get("version"), version_result.get("tag_name")

    async def _build_site_tarball(
        self, openbsd_version: str, agent_version: str, config: VmmVmConfig
    ) -> str:
        """Build or retrieve cached site.tgz."""
        await self._send_progress(
            "building_site_tarball",
            _("Building site tarball with sysmanage-agent %s...") % agent_version,
        )

        tarball_url = self.github_checker.get_port_tarball_url(agent_version)
        site_result = self.site_builder.get_or_build_site_tarball(
            openbsd_version=openbsd_version,
            agent_version=agent_version,
            agent_tarball_url=tarball_url,
            server_hostname=config.server_config.server_url,
            server_port=config.server_config.server_port,
            use_https=config.server_config.use_https,
        )

        if not site_result.get("success"):
            raise RuntimeError(
                _("Failed to build site tarball: %s") % site_result.get("error")
            )

        return site_result.get("site_tgz_path")

    def _get_gateway_ip(self) -> Optional[str]:
        """Get gateway IP from vether0 interface."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ifconfig", "vether0"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            # Parse inet line: "inet 10.1.0.1 netmask 0xffffff00..."
            for line in result.stdout.split("\n"):
                if "inet " in line and "netmask" in line:
                    return line.split()[1]
            return None
        except Exception as error:
            self.logger.error(_("Failed to get vether0 IP: %s"), error)
            return None

    def _get_next_vm_ip(self, gateway_ip: str) -> str:
        """
        Get the next available VM IP address.

        Checks both metadata and actual network usage (via ping) to find
        an unused IP in the subnet starting from .100.

        Args:
            gateway_ip: Gateway IP (e.g., "100.64.0.1") to derive subnet

        Returns:
            Next available IP (e.g., "100.64.0.100")
        """
        # Extract subnet prefix from gateway (e.g., "100.64.0" from "100.64.0.1")
        parts = gateway_ip.rsplit(".", 1)
        subnet_prefix = parts[0]

        # Find used IPs from metadata
        used_ips = set()
        metadata_dir = Path(VMM_METADATA_DIR)
        if metadata_dir.exists():
            for metadata_file in metadata_dir.glob("*.json"):
                try:
                    with open(metadata_file, "r", encoding="utf-8") as meta_file:
                        metadata = json.load(meta_file)
                        if "vm_ip" in metadata:
                            used_ips.add(metadata["vm_ip"])
                except Exception:
                    pass

        # Find next available IP starting from .100
        # Check both metadata AND ping to avoid collisions with VMs
        # that don't have vm_ip in metadata
        for i in range(100, 255):
            candidate_ip = f"{subnet_prefix}.{i}"
            if candidate_ip in used_ips:
                self.logger.debug(_("IP %s in use (metadata)"), candidate_ip)
                continue

            # Ping check - if IP responds, it's in use
            if self._is_ip_in_use(candidate_ip):
                self.logger.debug(_("IP %s in use (ping)"), candidate_ip)
                continue

            self.logger.info(_("Selected VM IP: %s"), candidate_ip)
            return candidate_ip

        # Fallback (shouldn't happen with 155 available IPs)
        return f"{subnet_prefix}.100"

    def _is_ip_in_use(self, ip: str) -> bool:
        """Check if an IP address is in use by checking ARP table."""
        try:
            # Check ARP table - more reliable than ping since VMs may block ICMP
            result = subprocess.run(  # nosec B603 B607
                ["arp", "-n", ip],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            # arp -n returns 0 and shows MAC if IP is in ARP cache
            # Returns non-zero or "no entry" if not found
            if result.returncode == 0 and "no entry" not in result.stdout.lower():
                self.logger.info(_("IP %s found in ARP table"), ip)
                return True
            return False
        except Exception:
            return False

    async def _setup_http_and_download_sets(
        self, openbsd_version: str, gateway_ip: str
    ) -> Path:
        """Setup HTTP server and download OpenBSD sets."""
        # Setup httpd
        await self._send_progress(
            "setting_up_httpd",
            _("Setting up httpd to serve OpenBSD installation sets..."),
        )
        httpd_result = self.httpd_setup.setup_httpd(gateway_ip)
        if not httpd_result.get("success"):
            raise RuntimeError(
                _("Failed to setup httpd: %s") % httpd_result.get("error")
            )

        # Download sets
        await self._send_progress(
            "downloading_sets",
            _("Downloading OpenBSD %s installation sets...") % openbsd_version,
        )
        sets_result = self.httpd_setup.download_openbsd_sets(openbsd_version)
        if not sets_result.get("success"):
            raise RuntimeError(
                _("Failed to download OpenBSD sets: %s") % sets_result.get("error")
            )

        return Path(sets_result.get("sets_dir"))

    async def _copy_site_tarball(
        self, site_tgz_path: str, sets_dir: Path, openbsd_version: str
    ) -> Path:
        """Copy site.tgz to HTTP sets directory."""
        version_nodot = openbsd_version.replace(".", "")
        site_filename = f"site{version_nodot}.tgz"
        site_dest = sets_dir / site_filename

        await self._send_progress(
            "copying_site_tarball",
            _("Copying site tarball to HTTP directory..."),
        )
        shutil.copy2(site_tgz_path, site_dest)
        return site_dest

    async def _create_and_embed_install_conf(
        self,
        config: VmmVmConfig,
        fqdn_hostname: str,
        gateway_ip: str,
        openbsd_version: str,
        sets_dir: Path,
        vm_ip: str,
    ) -> str:
        """Create install.conf and embed it into bsd.rd."""
        # Create install.conf content
        root_pwd_hash = config.root_password_hash or config.password_hash
        install_conf_content = self.httpd_setup.create_install_conf_content(
            hostname=fqdn_hostname,
            username=config.username,
            user_password_hash=config.password_hash,
            root_password_hash=root_pwd_hash,
            gateway_ip=gateway_ip,
            openbsd_version=openbsd_version,
            vm_ip=vm_ip,
        )

        # Embed into bsd.rd
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
            raise RuntimeError(
                _("Failed to embed install.conf: %s") % embed_result.get("error")
            )

        return embed_result.get("bsdrd_path")

    async def _create_vm_disk(self, config: VmmVmConfig) -> Optional[str]:
        """Create disk image for VM."""
        await self._send_progress(
            "creating_disk",
            _("Creating %s disk image...") % config.resource_config.disk_size,
        )
        disk_path = os.path.join(VMM_DISK_DIR, f"{config.vm_name}.qcow2")
        disk_result = self.disk_ops.create_disk_image(
            disk_path, config.resource_config.disk_size
        )
        if not disk_result.get("success"):
            self.logger.error(_("Failed to create disk: %s"), disk_result.get("error"))
            return None
        return disk_path

    # =========================================================================
    # VM Launch and Control Methods
    # =========================================================================

    async def _launch_vm_for_install(
        self, config: VmmVmConfig, disk_path: str, bsdrd_path: str
    ) -> Dict[str, Any]:
        """Launch VM with embedded bsd.rd for installation."""
        await self._send_progress(
            "launching_vm_http",
            _("Launching VM with embedded bsd.rd for HTTP installation..."),
        )
        return await self._launch_vm_with_bsdrd(
            config.vm_name,
            disk_path,
            bsdrd_path,
            config.resource_config.memory,
            config.resource_config.cpus,
        )

    async def _wait_for_installation_complete(self, vm_name: str) -> Dict[str, Any]:
        """Wait for VM to complete installation and shutdown."""
        await self._send_progress(
            "awaiting_shutdown",
            _(
                "Waiting for VM to complete installation and shutdown. "
                "The VM will install OpenBSD and sysmanage-agent offline, "
                "then shutdown automatically. This may take 10-15 minutes."
            ),
        )
        return await self._wait_for_vm_shutdown(vm_name, timeout=1800)

    async def _restart_vm_from_disk(
        self, config: VmmVmConfig, disk_path: str
    ) -> Dict[str, Any]:
        """Restart VM to boot from installed disk."""
        await self._send_progress(
            "restarting_vm",
            _("Restarting VM to boot from installed system..."),
        )
        return await self._launch_vm_no_pxe(
            config.vm_name,
            disk_path,
            config.resource_config.memory,
            config.resource_config.cpus,
        )

    # =========================================================================
    # Low-level VM Operations
    # =========================================================================

    async def _launch_vm_with_bsdrd(
        self,
        vm_name: str,
        disk_path: str,
        bsdrd_path: str,
        memory: str,
        _cpus: int,
    ) -> Dict[str, Any]:
        """Launch VM with embedded bsd.rd boot."""
        try:
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

    async def _launch_vm_no_pxe(
        self,
        vm_name: str,
        disk_path: str,
        memory: str,
        _cpus: int,
    ) -> Dict[str, Any]:
        """Launch VM from disk (no PXE boot)."""
        try:
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

    async def _wait_for_vm_shutdown(
        self, vm_name: str, timeout: int = 1800
    ) -> Dict[str, Any]:
        """Wait for VM to shutdown by polling vmctl status."""
        start_time = time.time()
        last_status_log = 0

        self.logger.info(_("Waiting for VM %s to shutdown..."), vm_name)

        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["vmctl", "status"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                # Check if VM name appears in output (vmctl status always returns 0)
                if vm_name not in result.stdout:
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

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def _vm_exists(self, vm_name: str) -> bool:
        """
        Check if a VM already exists.

        Checks:
        1. Metadata file exists
        2. VM.conf contains VM definition
        3. vmctl status shows the VM

        Args:
            vm_name: Name of the VM to check

        Returns:
            True if VM exists, False otherwise
        """
        self.logger.info("🔍 [VM_EXISTS_CHECK] Checking if VM '%s' exists...", vm_name)

        # Check metadata file
        metadata_path = Path(VMM_METADATA_DIR) / f"{vm_name}.json"
        self.logger.info(
            "🔍 [VM_EXISTS_CHECK] Checking metadata file: %s", metadata_path
        )
        if metadata_path.exists():
            self.logger.info(
                "✅ [VM_EXISTS_CHECK] VM '%s' exists (metadata file found)", vm_name
            )
            return True
        self.logger.info("❌ [VM_EXISTS_CHECK] Metadata file not found")

        # Check vm.conf
        self.logger.info("🔍 [VM_EXISTS_CHECK] Checking /etc/vm.conf...")
        try:
            with open("/etc/vm.conf", "r", encoding="utf-8") as file_handle:
                vm_conf_content = file_handle.read()
                # Look for 'vm "vm_name" {' pattern
                if f'vm "{vm_name}"' in vm_conf_content:
                    self.logger.info(
                        "✅ [VM_EXISTS_CHECK] VM '%s' exists (found in /etc/vm.conf)",
                        vm_name,
                    )
                    return True
            self.logger.info("❌ [VM_EXISTS_CHECK] VM not found in /etc/vm.conf")
        except FileNotFoundError:
            self.logger.info("❌ [VM_EXISTS_CHECK] /etc/vm.conf doesn't exist")
        except Exception as error:
            self.logger.warning(
                "⚠️ [VM_EXISTS_CHECK] Error reading /etc/vm.conf: %s", error
            )

        # Check vmctl status
        self.logger.info("🔍 [VM_EXISTS_CHECK] Checking vmctl status...")
        try:
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "status", vm_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            self.logger.info(
                "🔍 [VM_EXISTS_CHECK] vmctl returncode: %d", result.returncode
            )
            self.logger.info(
                "🔍 [VM_EXISTS_CHECK] vmctl stdout: %s", repr(result.stdout)
            )
            # vmctl status returns 0 even if VM doesn't exist (just shows empty list)
            # So we need to check if the output contains the VM name
            if result.returncode == 0 and vm_name in result.stdout:
                self.logger.info(
                    "✅ [VM_EXISTS_CHECK] VM '%s' exists (found in vmctl status)",
                    vm_name,
                )
                return True
            self.logger.info("❌ [VM_EXISTS_CHECK] VM not found in vmctl status")
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            self.logger.warning(
                "⚠️ [VM_EXISTS_CHECK] Error checking vmctl status: %s", error
            )

        self.logger.info("✅ [VM_EXISTS_CHECK] VM '%s' does NOT exist", vm_name)
        return False

    def _extract_openbsd_version(self, distribution: str) -> Optional[str]:
        """Extract OpenBSD version from distribution string."""
        try:
            match = re.search(r"(\d+\.\d+)", distribution)
            if match:
                return match.group(1)
            return None
        except Exception as error:
            self.logger.error(_("Error parsing OpenBSD version: %s"), error)
            return None

    def _get_fqdn_hostname(self, hostname: str, server_url: str) -> str:
        """Derive FQDN hostname from server URL if not already FQDN."""
        if "." in hostname:
            return hostname

        try:
            parsed = urlparse(server_url)
            server_host = parsed.hostname or ""
            if "." in server_host:
                parts = server_host.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                    return f"{hostname}.{domain}"
        except Exception:  # nosec B110
            pass

        return hostname

    def _ensure_vmm_directories(self):
        """Ensure VMM directories exist."""
        for dir_path in [VMM_DISK_DIR]:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, mode=0o755)
                self.logger.info(_("Created VMM directory: %s"), dir_path)

    def _save_vm_metadata(
        self,
        vm_name: str,
        hostname: str,
        distribution: str,
        openbsd_version: str,
        vm_ip: str,
    ) -> bool:
        """Save VM metadata to JSON file for listing."""
        try:
            metadata_dir = Path(VMM_METADATA_DIR)
            metadata_dir.mkdir(parents=True, exist_ok=True)

            metadata = {
                "vm_name": vm_name,
                "hostname": hostname,
                "vm_ip": vm_ip,
                "distribution": {
                    "distribution_name": "OpenBSD",
                    "distribution_version": openbsd_version,
                },
                "distribution_string": distribution,
            }

            metadata_file = metadata_dir / f"{vm_name}.json"
            with open(metadata_file, "w", encoding="utf-8") as metadata_fp:
                json.dump(metadata, metadata_fp, indent=2)

            self.logger.info(
                _("Saved VM metadata for '%s' to %s"), vm_name, metadata_file
            )
            return True

        except Exception as error:
            self.logger.error(
                _("Error saving VM metadata for '%s': %s"), vm_name, error
            )
            return False

    async def _send_progress(self, step: str, message: str):
        """Send progress update to server."""
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
