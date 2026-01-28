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
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import aiofiles

from src.i18n import _
from src.sysmanage_agent.operations.child_host_types import VmmVmConfig
from src.sysmanage_agent.operations.child_host_vmm_disk import VmmDiskOperations
from src.sysmanage_agent.operations.child_host_vmm_launcher import VmmLauncher
from src.sysmanage_agent.operations.child_host_vmm_utils import (
    VMM_DISK_DIR,
    VMM_METADATA_DIR,
    ensure_vmm_directories,
    extract_openbsd_version,
    get_fqdn_hostname,
    save_vm_metadata,
    vm_exists,
)
from src.sysmanage_agent.operations.child_host_vmm_vmconf import VmConfManager


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
        self.launcher = VmmLauncher(agent_instance, logger)

    async def _run_subprocess(
        self,
        cmd: list,
        timeout: int = 60,  # NOSONAR - timeout parameter is part of the established API
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
            await self.launcher.send_progress(
                "parsing_version", _("Parsing OpenBSD version...")
            )
            openbsd_version = extract_openbsd_version(config.distribution, self.logger)
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
            fqdn_hostname = get_fqdn_hostname(
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
            await self.launcher.send_progress(
                "checking_existing", _("Checking for existing VM...")
            )
            vm_already_exists = vm_exists(config.vm_name, self.logger)
            self.logger.info("🔍 [STEP_5] VM exists check: %s", vm_already_exists)
            if vm_already_exists:
                self.logger.error("❌ [STEP_5] VM '%s' already exists", config.vm_name)
                return {
                    "success": False,
                    "error": _("VM '%s' already exists") % config.vm_name,
                }
            self.logger.info("✅ [STEP_5] VM does not exist, proceeding...")

            # Step 4: Ensure directories exist
            self.logger.info("📋 [STEP_6] Ensuring VMM directories exist...")
            ensure_vmm_directories(self.logger)
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

            # NOTE: We do NOT add VM to vm.conf yet. Adding during install causes
            # an install loop because vmd auto-restarts the VM from bsd.rd on reboot.
            # We'll add to vm.conf only after the VM is fully provisioned.

            # Step 14: Launch VM with embedded bsd.rd
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

            # NOTE: No need to remove boot device from vm.conf since we never
            # added the VM to vm.conf during installation.

            # Step 16: Restart VM to boot from disk
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
            await self.launcher.send_progress(
                "awaiting_registration",
                _(
                    "Waiting for VM to boot and register with server. "
                    "The sysmanage-agent will start automatically and connect."
                ),
            )
            self.logger.info("✅ [STEP_17] Progress update sent")

            await self.launcher.send_progress("complete", _("VM creation complete"))
            self.logger.info("🎉 [STEP_17] VM creation complete progress sent")

            # Save metadata
            self.logger.info("📋 [STEP_18] Saving VM metadata...")
            save_vm_metadata(
                vm_name=config.vm_name,
                hostname=fqdn_hostname,
                distribution=config.distribution,
                openbsd_version=openbsd_version,
                vm_ip=vm_ip,
                logger=self.logger,
            )
            self.logger.info("✅ [STEP_18] Metadata saved")

            # Step 19: Add VM to /etc/vm.conf for persistence and auto-start
            # We only add to vm.conf now (after successful provisioning) to avoid
            # the install loop problem where vmd auto-restarts from bsd.rd
            self.logger.info(
                "📋 [STEP_19] Adding VM to /etc/vm.conf for persistence..."
            )
            persist_result = self.vmconf_manager.persist_vm(
                config.vm_name,
                disk_path,
                config.resource_config.memory,
                enable=True,  # Enable auto-start on boot
                boot_device=None,  # Boot from disk, not bsd.rd
            )
            if not persist_result:
                self.logger.warning(
                    "⚠️ [STEP_19] Failed to add VM to vm.conf - VM will work but "
                    "won't auto-start on host reboot"
                )
            else:
                self.logger.info("✅ [STEP_19] VM added to vm.conf for auto-start")

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
        await self.launcher.send_progress("checking_vmm", _("Checking VMM status..."))
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
        await self.launcher.send_progress(
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
        """Build or retrieve cached site.tgz.

        Uses asyncio.to_thread() to run the blocking site tarball build
        in a separate thread, preventing WebSocket keepalive timeouts.
        """
        await self.launcher.send_progress(
            "building_site_tarball",
            _("Building site tarball with sysmanage-agent %s...") % agent_version,
        )

        tarball_url = self.github_checker.get_port_tarball_url(agent_version)

        # Run blocking site tarball build in a separate thread to avoid
        # blocking the async event loop and causing WebSocket timeouts
        site_result = await asyncio.to_thread(
            self.site_builder.get_or_build_site_tarball,
            openbsd_version=openbsd_version,
            agent_version=agent_version,
            agent_tarball_url=tarball_url,
            server_hostname=config.server_config.server_url,
            server_port=config.server_config.server_port,
            use_https=config.server_config.use_https,
            auto_approve_token=config.auto_approve_token,
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
                except (OSError, json.JSONDecodeError) as err:
                    self.logger.debug(
                        _("Could not read metadata file %s: %s"), metadata_file, err
                    )

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
        """Setup HTTP server and download OpenBSD sets.

        Uses asyncio.to_thread() for blocking operations to prevent
        WebSocket keepalive timeouts during long downloads.
        """
        # Setup httpd (quick operation but still wrap for consistency)
        await self.launcher.send_progress(
            "setting_up_httpd",
            _("Setting up httpd to serve OpenBSD installation sets..."),
        )
        httpd_result = await asyncio.to_thread(self.httpd_setup.setup_httpd, gateway_ip)
        if not httpd_result.get("success"):
            raise RuntimeError(
                _("Failed to setup httpd: %s") % httpd_result.get("error")
            )

        # Download sets - this is a LONG operation (~10 minutes)
        # Must run in thread to avoid blocking WebSocket event loop
        await self.launcher.send_progress(
            "downloading_sets",
            _("Downloading OpenBSD %s installation sets...") % openbsd_version,
        )
        sets_result = await asyncio.to_thread(
            self.httpd_setup.download_openbsd_sets, openbsd_version
        )
        if not sets_result.get("success"):
            raise RuntimeError(
                _("Failed to download OpenBSD sets: %s") % sets_result.get("error")
            )

        return Path(sets_result.get("sets_dir"))

    async def _copy_site_tarball(
        self, site_tgz_path: str, sets_dir: Path, openbsd_version: str
    ) -> Path:
        """Copy site.tgz to HTTP sets directory and update index.txt."""
        version_nodot = openbsd_version.replace(".", "")
        site_filename = f"site{version_nodot}.tgz"
        site_dest = sets_dir / site_filename

        await self.launcher.send_progress(
            "copying_site_tarball",
            _("Copying site tarball to HTTP directory..."),
        )
        shutil.copy2(site_tgz_path, site_dest)

        # Update index.txt to include the site tarball
        # The OpenBSD installer uses index.txt to discover available sets
        index_txt_path = sets_dir / "index.txt"
        if index_txt_path.exists():
            # Check if site tarball is already in index.txt
            async with aiofiles.open(
                index_txt_path, "r", encoding="utf-8"
            ) as index_file:
                index_content = await index_file.read()
            if site_filename not in index_content:
                # Get file stats for the site tarball
                site_stat = site_dest.stat()
                site_size = site_stat.st_size
                # Append site tarball entry to index.txt (similar format to other entries)
                # Format: -rw-r--r--  1 1001  0  <size> <date> <filename>
                mtime = datetime.fromtimestamp(site_stat.st_mtime)
                date_str = mtime.strftime("%b %d %H:%M:%S %Y")
                site_entry = f"-rw-r--r--  1 1001  0  {site_size:>10} {date_str} {site_filename}\n"
                async with aiofiles.open(
                    index_txt_path, "a", encoding="utf-8"
                ) as index_file:
                    await index_file.write(site_entry)
                self.logger.info("Updated index.txt with %s", site_filename)

        # Update SHA256.sig to include the site tarball checksum
        # The OpenBSD installer uses SHA256.sig for checksum verification
        # Adding our checksum will invalidate the signature, but
        # "Continue without verification = yes" in install.conf handles that

        # Calculate SHA256 checksum
        sha256_hash = hashlib.sha256()
        async with aiofiles.open(site_dest, "rb") as site_file:
            while True:
                chunk = await site_file.read(8192)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        checksum = sha256_hash.hexdigest()
        # OpenBSD SHA256 format: SHA256 (filename) = checksum
        sha256_entry = f"SHA256 ({site_filename}) = {checksum}\n"

        # Update both SHA256 and SHA256.sig
        for sha_file in ["SHA256", "SHA256.sig"]:
            sha_path = sets_dir / sha_file
            if sha_path.exists():
                async with aiofiles.open(
                    sha_path, "r", encoding="utf-8"
                ) as sha_read_handle:
                    sha_content = await sha_read_handle.read()
                if site_filename not in sha_content:
                    async with aiofiles.open(
                        sha_path, "a", encoding="utf-8"
                    ) as sha_handle:
                        await sha_handle.write(sha256_entry)
                    self.logger.info(
                        "Updated %s with %s checksum", sha_file, site_filename
                    )

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
        await self.launcher.send_progress(
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
        await self.launcher.send_progress(
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
        await self.launcher.send_progress(
            "launching_vm_http",
            _("Launching VM with embedded bsd.rd for HTTP installation..."),
        )
        return await self.launcher.launch_vm_with_bsdrd(
            config.vm_name,
            disk_path,
            bsdrd_path,
            config.resource_config.memory,
        )

    async def _wait_for_installation_complete(self, vm_name: str) -> Dict[str, Any]:
        """Wait for VM to complete installation and shutdown."""
        await self.launcher.send_progress(
            "awaiting_shutdown",
            _(
                "Waiting for VM to complete installation and shutdown. "
                "The VM will install OpenBSD and sysmanage-agent offline, "
                "then shutdown automatically. This may take 10-15 minutes."
            ),
        )
        return await self.launcher.wait_for_vm_shutdown(vm_name, timeout=1800)

    async def _restart_vm_from_disk(
        self, config: VmmVmConfig, disk_path: str
    ) -> Dict[str, Any]:
        """Restart VM to boot from installed disk."""
        await self.launcher.send_progress(
            "restarting_vm",
            _("Restarting VM to boot from installed system..."),
        )
        return await self.launcher.launch_vm_from_disk(
            config.vm_name,
            disk_path,
            config.resource_config.memory,
        )
