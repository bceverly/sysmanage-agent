"""
Debian VMM VM creation orchestration.

This module handles the complete Debian VM creation workflow including:
- Debian version extraction and validation
- GitHub version checking for sysmanage-agent
- Preseed file generation
- ISO download and VM boot
- Boot parameter injection for serial console
- Automated installation via preseed
- Post-installation configuration
"""

import asyncio
import json
import os
import re
import subprocess  # nosec B404 # still needed for sync functions
import time
from pathlib import Path
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async
from src.sysmanage_agent.operations.child_host_debian_autoinstall import (
    DebianAutoinstallSetup,
)
from src.sysmanage_agent.operations.child_host_debian_console import (
    DebianConsoleAutomation,
)
from src.sysmanage_agent.operations.child_host_debian_packages import (
    SUPPORTED_DEBIAN_VERSIONS,
)
from src.sysmanage_agent.operations.child_host_types import VmmVmConfig
from src.sysmanage_agent.operations.child_host_vmm_disk import VmmDiskOperations
from src.sysmanage_agent.operations.child_host_vmm_launcher import VmmLauncher
from src.sysmanage_agent.operations.child_host_vmm_network_helpers import (
    get_host_dns_server,
)
from src.sysmanage_agent.operations.child_host_vmm_utils import (
    VMM_DISK_DIR,
    VMM_METADATA_DIR,
    ensure_vmm_directories,
    vm_exists,
)
from src.sysmanage_agent.operations.child_host_vmm_vmconf import VmConfManager


def extract_debian_version(distribution: str, logger) -> Optional[str]:
    """
    Extract Debian version from distribution string.

    Args:
        distribution: Distribution string (e.g., "Debian 12", "debian-12", "Bookworm")
        logger: Logger instance

    Returns:
        Version string (e.g., "12") or None if not found
    """
    # Map codenames to versions
    codename_map = {
        "bookworm": "12",
        "bullseye": "11",
        "buster": "10",
    }

    dist_lower = distribution.lower()

    # Check for codenames first
    for codename, version in codename_map.items():
        if codename in dist_lower and version in SUPPORTED_DEBIAN_VERSIONS:
            logger.info(_("Extracted Debian version %s from codename"), version)
            return version

    # Try various patterns for version numbers
    patterns = [
        r"Debian\s*(?:GNU/Linux)?\s*(\d+)",  # "Debian 12" or "Debian GNU/Linux 12"
        r"debian[_-]?(\d+)",  # "debian-12" or "debian_12"
        r"(\d+)",  # Just the version number
    ]

    for pattern in patterns:
        match = re.search(pattern, distribution, re.IGNORECASE)
        if match:
            version = match.group(1)
            if version in SUPPORTED_DEBIAN_VERSIONS:
                logger.info(_("Extracted Debian version: %s"), version)
                return version

    logger.warning(_("Could not extract Debian version from: %s"), distribution)
    return None


def get_fqdn_hostname(hostname: str, server_url: str) -> str:
    """
    Get fully qualified domain name for hostname.

    If hostname doesn't contain a domain, append the domain from server_url.

    Args:
        hostname: Hostname (may or may not be FQDN)
        server_url: Server URL to extract domain from

    Returns:
        FQDN hostname
    """
    if "." in hostname:
        return hostname

    # Extract domain from server URL
    match = re.search(
        r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", server_url
    )  # NOSONAR - regex operates on trusted internal data
    if match:
        domain_parts = match.group(0).split(".", 1)
        if len(domain_parts) > 1:
            return f"{hostname}.{domain_parts[1]}"

    return hostname


class DebianVmCreator:  # pylint: disable=too-many-instance-attributes
    """Handles Debian VMM VM creation workflow."""

    # Default resource configurations for Debian
    DEFAULT_DISK_SIZE = "20G"  # Debian needs more space than Alpine
    DEFAULT_MEMORY = "2G"  # Debian benefits from more memory

    def __init__(
        self,
        agent_instance,
        logger,
        virtualization_checks,
        github_checker,
        db_session,
    ):
        """
        Initialize Debian VM creator.

        Args:
            agent_instance: Reference to main SysManageAgent
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
            github_checker: GitHubVersionChecker instance
            db_session: Database session
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks
        self.github_checker = github_checker
        self.db_session = db_session

        # Initialize helpers
        self.disk_ops = VmmDiskOperations(logger)
        self.vmconf_manager = VmConfManager(logger)
        self.launcher = VmmLauncher(agent_instance, logger)
        self.autoinstall_setup = DebianAutoinstallSetup(logger)
        self.console_automation = DebianConsoleAutomation(logger)

    async def create_debian_vm(self, config: VmmVmConfig) -> Dict[str, Any]:
        """
        Create a new Debian VMM virtual machine.

        Workflow:
        1. Validate configuration
        2. Extract Debian version from distribution
        3. Derive FQDN hostname
        4. Check VMM availability
        5. Check if VM already exists
        6. Ensure directories exist
        7. Get latest sysmanage-agent version from GitHub
        8. Get gateway IP from vether0
        9. Get next available VM IP
        10. Download Debian ISO
        11. Create disk image
        12. Generate preseed file
        13. Create data directory with setup files
        14. Launch VM from ISO
        15. Inject boot parameters via console
        16. Wait for installation (20 min timeout)
        17. Restart VM from disk
        18. Save metadata
        19. Add to vm.conf for persistence

        Args:
            config: VmmVmConfig with all VM settings

        Returns:
            Dict with success status and details
        """
        self.logger.info(
            "🚀 [DEBIAN_CREATE_START] Starting Debian VM creation for: %s",
            config.vm_name,
        )
        self.logger.info(
            "🔍 [DEBIAN_CREATE_CONFIG] Distribution: %s", config.distribution
        )
        self.logger.info("🔍 [DEBIAN_CREATE_CONFIG] Hostname: %s", config.hostname)

        try:
            # Steps 1-9: Validate and prepare environment
            prep_result = await self._prepare_debian_vm(config)
            if not prep_result.get("success"):
                return prep_result

            debian_version = prep_result["debian_version"]
            fqdn_hostname = prep_result["fqdn_hostname"]
            agent_version = prep_result["agent_version"]
            gateway_ip = prep_result["gateway_ip"]
            vm_ip = prep_result["vm_ip"]

            # Steps 10-14: Download ISO, create disk, generate preseed, build serial ISO
            build_result = await self._build_debian_vm_artifacts(
                config, debian_version, fqdn_hostname, gateway_ip, vm_ip
            )
            if not build_result.get("success"):
                return build_result

            disk_path = build_result["disk_path"]
            serial_iso_path = build_result["serial_iso_path"]
            memory = config.resource_config.memory or self.DEFAULT_MEMORY

            # Steps 15-17: Launch, install, restart from disk
            boot_result = await self._launch_and_install_debian_vm(
                config, disk_path, serial_iso_path, memory
            )
            if not boot_result.get("success"):
                return boot_result

            # Steps 18-19: Save metadata, persist vm.conf
            self._finalize_debian_vm(
                config, fqdn_hostname, debian_version, vm_ip, disk_path, memory
            )

            await self.launcher.send_progress(
                "complete", _("Debian VM creation complete")
            )

            self.logger.info(
                "🎉 [DEBIAN_CREATE_SUCCESS] VM '%s' created successfully!",
                config.vm_name,
            )

            return {
                "success": True,
                "child_name": config.vm_name,
                "child_type": "vmm",
                "hostname": fqdn_hostname,
                "username": config.username,
                "debian_version": debian_version,
                "agent_version": agent_version,
                "message": _(
                    "Debian VM '%s' created successfully. "
                    "VM will self-register when agent starts on firstboot."
                )
                % config.vm_name,
            }

        except Exception as error:
            self.logger.error(
                "💥 [DEBIAN_CREATE_ERROR] Exception: %s", error, exc_info=True
            )
            return {"success": False, "error": str(error)}

    async def _prepare_debian_vm(self, config: VmmVmConfig) -> Dict[str, Any]:
        """Validate config and prepare environment (steps 1-9).

        Returns:
            Dict with success status and prepared values (debian_version,
            fqdn_hostname, agent_version, gateway_ip, vm_ip).
        """
        # Step 1: Validate configuration
        self.logger.info("📋 [STEP_1] Validating configuration...")
        validation_result = self._validate_config(config)
        if not validation_result.get("success"):
            return validation_result
        self.logger.info("✅ [STEP_1] Configuration validated")

        # Step 2: Extract Debian version
        self.logger.info("📋 [STEP_2] Extracting Debian version...")
        await self.launcher.send_progress(
            "parsing_version", _("Parsing Debian version...")
        )
        debian_version = extract_debian_version(config.distribution, self.logger)
        if not debian_version:
            return {
                "success": False,
                "error": _("Could not parse Debian version from: %s")
                % config.distribution,
            }
        self.logger.info("✅ [STEP_2] Debian version: %s", debian_version)

        # Step 3: Derive FQDN hostname
        self.logger.info("📋 [STEP_3] Deriving FQDN hostname...")
        fqdn_hostname = get_fqdn_hostname(
            config.hostname, config.server_config.server_url
        )
        self.logger.info("✅ [STEP_3] FQDN hostname: %s", fqdn_hostname)

        # Step 4: Check VMM availability
        self.logger.info("📋 [STEP_4] Checking VMM availability...")
        vmm_result = await self._check_vmm_ready()
        if not vmm_result.get("success"):
            return vmm_result
        self.logger.info("✅ [STEP_4] VMM is ready")

        # Step 5: Check if VM already exists
        self.logger.info("📋 [STEP_5] Checking if VM already exists...")
        await self.launcher.send_progress(
            "checking_existing", _("Checking for existing VM...")
        )
        if vm_exists(config.vm_name, self.logger):
            return {
                "success": False,
                "error": _("VM '%s' already exists") % config.vm_name,
            }
        self.logger.info("✅ [STEP_5] VM does not exist")

        # Step 6: Ensure directories exist
        self.logger.info("📋 [STEP_6] Ensuring VMM directories exist...")
        ensure_vmm_directories(self.logger)
        self.logger.info("✅ [STEP_6] Directories ensured")

        # Step 7: Get latest sysmanage-agent version
        self.logger.info("📋 [STEP_7] Getting latest sysmanage-agent version...")
        agent_version, _tag_name = await self._get_agent_version()
        self.logger.info("✅ [STEP_7] Agent version: %s", agent_version)

        # Step 8: Get gateway IP
        self.logger.info("📋 [STEP_8] Getting gateway IP...")
        gateway_ip = self._get_gateway_ip()
        if not gateway_ip:
            return {
                "success": False,
                "error": _("Could not determine gateway IP from vether0"),
            }
        self.logger.info("✅ [STEP_8] Gateway IP: %s", gateway_ip)

        # Step 9: Get next available VM IP
        self.logger.info("📋 [STEP_9] Getting next VM IP...")
        vm_ip = self._get_next_vm_ip(gateway_ip)
        self.logger.info("✅ [STEP_9] VM IP: %s", vm_ip)

        return {
            "success": True,
            "debian_version": debian_version,
            "fqdn_hostname": fqdn_hostname,
            "agent_version": agent_version,
            "gateway_ip": gateway_ip,
            "vm_ip": vm_ip,
        }

    async def _build_debian_vm_artifacts(
        self,
        config: VmmVmConfig,
        debian_version: str,
        fqdn_hostname: str,
        gateway_ip: str,
        vm_ip: str,
    ) -> Dict[str, Any]:
        """Download ISO, create disk, generate preseed, build serial ISO (steps 10-14).

        Returns:
            Dict with success status, disk_path, and serial_iso_path.
        """
        # Step 10: Download Debian ISO
        self.logger.info("📋 [STEP_10] Downloading Debian ISO...")
        await self.launcher.send_progress(
            "downloading_iso",
            _("Downloading Debian %s ISO (~600MB, this may take a while)...")
            % debian_version,
        )
        iso_result = await asyncio.to_thread(
            self.autoinstall_setup.download_debian_iso, debian_version
        )
        if not iso_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to download Debian ISO: %s")
                % iso_result.get("error"),
            }
        iso_path = iso_result.get("iso_path")
        self.logger.info("✅ [STEP_10] ISO ready: %s", iso_path)

        # Step 11: Create disk image
        self.logger.info("📋 [STEP_11] Creating disk image...")
        disk_size = config.resource_config.disk_size or self.DEFAULT_DISK_SIZE
        await self.launcher.send_progress(
            "creating_disk",
            _("Creating %s disk image...") % disk_size,
        )
        disk_path = os.path.join(VMM_DISK_DIR, f"{config.vm_name}.qcow2")
        disk_result = self.disk_ops.create_disk_image(disk_path, disk_size)
        if not disk_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to create disk: %s") % disk_result.get("error"),
            }
        self.logger.info("✅ [STEP_11] Disk created: %s", disk_path)

        # Step 12: Generate preseed file
        self.logger.info("📋 [STEP_12] Generating preseed file...")
        await self.launcher.send_progress(
            "generating_preseed",
            _("Generating Debian preseed configuration..."),
        )
        preseed_result = await self._generate_preseed(
            config,
            fqdn_hostname,
            gateway_ip,
            vm_ip,
            debian_version,
        )
        if not preseed_result.get("success"):
            return preseed_result
        preseed_content = preseed_result.get("preseed")
        self.logger.info("✅ [STEP_12] Preseed file generated")

        # Step 13: Create data directory with setup files
        self.logger.info("📋 [STEP_13] Creating data directory...")
        data_result = self.autoinstall_setup.create_debian_data_dir(
            vm_name=config.vm_name,
            preseed_content=preseed_content,
            server_hostname=config.server_config.server_url,
            server_port=config.server_config.server_port,
            use_https=config.server_config.use_https,
            auto_approve_token=config.auto_approve_token,
            debian_version=debian_version,
        )
        if not data_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to create data directory: %s")
                % data_result.get("error"),
            }
        self.logger.info(
            "✅ [STEP_13] Data directory created: %s", data_result.get("data_dir")
        )

        # Step 14: Create modified ISO with serial console boot
        self.logger.info("📋 [STEP_14] Creating serial console ISO...")
        await self.launcher.send_progress(
            "creating_serial_iso",
            _("Creating modified ISO for serial console installation..."),
        )
        dns_server = get_host_dns_server(self.logger)
        preseed_url = data_result.get("preseed_url")
        self.logger.info("📋 [STEP_14] Preseed URL: %s", preseed_url)

        serial_iso_result = await asyncio.to_thread(
            self.autoinstall_setup.create_serial_console_iso,
            iso_path,
            config.vm_name,
            preseed_url,
            vm_ip,
            gateway_ip,
            dns_server,
        )
        if not serial_iso_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to create serial console ISO: %s")
                % serial_iso_result.get("error"),
            }
        serial_iso_path = serial_iso_result.get("iso_path")
        self.logger.info("✅ [STEP_14] Serial console ISO created: %s", serial_iso_path)

        return {
            "success": True,
            "disk_path": disk_path,
            "serial_iso_path": serial_iso_path,
        }

    async def _launch_and_install_debian_vm(
        self,
        config: VmmVmConfig,
        disk_path: str,
        serial_iso_path: str,
        memory: str,
    ) -> Dict[str, Any]:
        """Launch VM from ISO, wait for install, restart from disk (steps 15-17).

        Returns:
            Dict with success status.
        """
        # Step 15: Launch VM from modified ISO
        self.logger.info("📋 [STEP_15] Launching VM from ISO...")
        await self.launcher.send_progress(
            "launching_vm",
            _("Launching Debian VM from ISO for installation..."),
        )
        launch_result = await self._launch_vm_from_iso(
            config, disk_path, serial_iso_path, memory
        )
        if not launch_result.get("success"):
            return launch_result
        self.logger.info("✅ [STEP_15] VM launched with serial console boot")

        # Step 16: Wait for installation to complete
        self.logger.info("📋 [STEP_16] Waiting for installation...")
        await self.launcher.send_progress(
            "awaiting_installation",
            _(
                "Debian installation in progress. "
                "This typically takes 15-20 minutes..."
            ),
        )
        shutdown_result = await self.console_automation.wait_for_installation_complete(
            config.vm_name, timeout=1200  # 20 minutes
        )
        if not shutdown_result.get("success"):
            self.logger.warning(
                "⚠️ Installation may still be running: %s",
                shutdown_result.get("error"),
            )
        else:
            self.logger.info("✅ [STEP_16] Installation complete")

        # Step 17: Stop VM and restart from disk only (no ISO)
        self.logger.info("📋 [STEP_17] Stopping VM to remove ISO from boot path...")
        await self.launcher.send_progress(
            "stopping_vm",
            _("Stopping VM to switch from ISO boot to disk boot..."),
        )

        # Force stop the VM to remove the ISO from the boot configuration
        stop_result = await self._stop_vm_for_restart(config.vm_name)
        if not stop_result.get("success"):
            self.logger.warning(
                "⚠️ Could not stop VM cleanly: %s", stop_result.get("error")
            )

        # Wait for VM to actually be stopped
        await asyncio.sleep(3)

        # Now start from disk only
        self.logger.info("📋 [STEP_17b] Starting VM from disk (no ISO)...")
        await self.launcher.send_progress(
            "restarting_vm",
            _("Starting Debian VM from installed system..."),
        )
        restart_result = await self.launcher.launch_vm_from_disk(
            config.vm_name,
            disk_path,
            memory,
        )
        if not restart_result.get("success"):
            return restart_result
        self.logger.info("✅ [STEP_17] VM restarted from disk")

        return {"success": True}

    def _finalize_debian_vm(
        self,
        config: VmmVmConfig,
        fqdn_hostname: str,
        debian_version: str,
        vm_ip: str,
        disk_path: str,
        memory: str,
    ) -> None:
        """Save metadata and persist vm.conf (steps 18-19)."""
        # Step 18: Save metadata
        self.logger.info("📋 [STEP_18] Saving VM metadata...")
        self._save_vm_metadata(
            config.vm_name,
            fqdn_hostname,
            config.distribution,
            debian_version,
            vm_ip,
        )
        self.logger.info("✅ [STEP_18] Metadata saved")

        # Step 19: Add to vm.conf for persistence
        self.logger.info("📋 [STEP_19] Adding VM to vm.conf...")
        persist_result = self.vmconf_manager.persist_vm(
            config.vm_name,
            disk_path,
            memory,
            enable=True,
            boot_device=None,
        )
        if persist_result:
            self.logger.info("✅ [STEP_19] VM added to vm.conf")
        else:
            self.logger.warning("⚠️ [STEP_19] Failed to add VM to vm.conf")

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
            return {"success": False, "error": _("Password is required")}
        if not config.server_config.server_url:
            return {"success": False, "error": _("Server URL is required")}
        return {"success": True}

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

    async def _stop_vm_for_restart(self, vm_name: str) -> Dict[str, Any]:
        """
        Stop VM to allow restart with different boot configuration.

        This is necessary when switching from ISO boot to disk boot.
        The VM must be fully stopped before it can be restarted with
        a different disk configuration.

        Args:
            vm_name: Name of the VM to stop

        Returns:
            Dict with success status
        """
        try:
            # First try graceful stop
            self.logger.info(_("Stopping VM '%s' for restart..."), vm_name)
            result = await run_command_async(
                ["vmctl", "stop", vm_name],
                timeout=30,
            )

            if result.returncode == 0:
                self.logger.info(_("VM '%s' stopped gracefully"), vm_name)
                return {"success": True}

            # If graceful stop failed, try force stop
            self.logger.warning(
                _("Graceful stop failed, trying force stop: %s"),
                result.stderr or result.stdout,
            )
            result = await run_command_async(
                ["vmctl", "stop", "-f", vm_name],
                timeout=30,
            )

            if result.returncode == 0:
                self.logger.info(_("VM '%s' force stopped"), vm_name)
                return {"success": True}

            # Check if VM is already stopped
            status_result = await run_command_async(
                ["vmctl", "status"],
                timeout=10,
            )
            if vm_name not in status_result.stdout or "stopped" in status_result.stdout:
                self.logger.info(_("VM '%s' is already stopped"), vm_name)
                return {"success": True}

            return {
                "success": False,
                "error": result.stderr or result.stdout or "Unknown error",
            }

        except asyncio.TimeoutError:
            return {"success": False, "error": _("Timeout stopping VM")}
        except Exception as error:
            return {"success": False, "error": str(error)}

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
            for line in result.stdout.split("\n"):
                if "inet " in line and "netmask" in line:
                    return line.split()[1]
            return None
        except Exception as error:
            self.logger.error(_("Failed to get vether0 IP: %s"), error)
            return None

    def _get_next_vm_ip(self, gateway_ip: str) -> str:
        """Get the next available VM IP address."""
        parts = gateway_ip.rsplit(".", 1)
        subnet_prefix = parts[0]

        # Find used IPs from metadata
        used_ips = set()
        metadata_dir = Path(VMM_METADATA_DIR)
        if metadata_dir.exists():
            for metadata_file in metadata_dir.glob("*.json"):
                try:
                    with open(metadata_file, "r", encoding="utf-8") as file_handle:
                        metadata = json.load(file_handle)
                        if "vm_ip" in metadata:
                            used_ips.add(metadata["vm_ip"])
                except (OSError, json.JSONDecodeError):
                    pass

        # Find next available IP starting from .100
        for i in range(100, 255):
            candidate_ip = f"{subnet_prefix}.{i}"
            if candidate_ip not in used_ips:
                return candidate_ip

        return f"{subnet_prefix}.100"

    async def _generate_preseed(  # NOSONAR - async required by caller interface
        self,
        config: VmmVmConfig,
        fqdn_hostname: str,
        gateway_ip: str,
        vm_ip: str,
        debian_version: str,
    ) -> Dict[str, Any]:
        """Generate enhanced preseed file with embedded agent config."""
        try:
            # Get host's DNS server
            dns_server = get_host_dns_server(self.logger)

            # Use password hashes directly from server
            # Server already sends SHA-512 format ($6$...) for Debian preseed
            user_password_hash = config.password_hash
            root_password_hash = config.root_password_hash or config.password_hash

            # Download latest sysmanage-agent .deb from GitHub
            agent_deb_url = None
            deb_result = self.autoinstall_setup.download_agent_deb(debian_version)
            if deb_result.get("success"):
                # Serve the .deb via httpd for the VM to download
                serve_result = self.autoinstall_setup.serve_agent_deb_via_httpd(
                    deb_result["deb_path"], config.vm_name
                )
                if serve_result.get("success"):
                    agent_deb_url = serve_result["deb_url"]
                    self.logger.info(
                        _("Agent .deb will be downloaded from: %s"), agent_deb_url
                    )
                else:
                    self.logger.warning(
                        _("Could not serve agent .deb via httpd: %s"),
                        serve_result.get("error"),
                    )
            else:
                self.logger.warning(
                    _("Could not download agent .deb: %s (will install via pip)"),
                    deb_result.get("error"),
                )

            # Generate enhanced preseed with embedded late_command
            result = self.autoinstall_setup.generate_enhanced_preseed(
                hostname=fqdn_hostname,
                username=config.username,
                user_password_hash=user_password_hash,
                root_password_hash=root_password_hash,
                gateway_ip=gateway_ip,
                vm_ip=vm_ip,
                debian_version=debian_version,
                server_hostname=config.server_config.server_url,
                server_port=config.server_config.server_port,
                use_https=config.server_config.use_https,
                auto_approve_token=config.auto_approve_token,
                dns_server=dns_server,
                disk="vdb",  # Second disk (first is ISO during install)
                timezone="UTC",
                agent_deb_url=agent_deb_url,
            )

            return result

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _launch_vm_from_iso(
        self, config: VmmVmConfig, disk_path: str, iso_path: str, memory: str
    ) -> Dict[str, Any]:
        """Launch VM from Debian ISO."""
        try:
            # vmctl start with ISO as first disk
            # OpenBSD VMM's SeaBIOS boots from the first disk, so we pass the ISO
            # as the first -d argument and the virtual disk as the second.
            # Using -b flag doesn't work for Debian as VMM expects a kernel
            # image with -b (like OpenBSD's bsd.rd), not a bootable ISO.
            # The ISO must be first so SeaBIOS's El Torito boot works.
            cmd = [
                "vmctl",
                "start",
                "-d",
                iso_path,  # ISO as first disk - SeaBIOS boots from first disk
                "-d",
                disk_path,  # Virtual disk as second disk
                "-m",
                memory,  # Memory
                "-n",
                "local",  # Network switch
                config.vm_name,
            ]

            self.logger.info(_("Launching Debian VM: %s"), " ".join(cmd))

            result = await run_command_async(cmd, timeout=30)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start VM: %s") % result.stderr,
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    def _save_vm_metadata(
        self,
        vm_name: str,
        hostname: str,
        distribution: str,
        debian_version: str,
        vm_ip: str,
    ) -> None:
        """Save VM metadata to JSON file."""
        metadata_dir = Path(VMM_METADATA_DIR)
        metadata_dir.mkdir(parents=True, exist_ok=True)

        metadata = {
            "vm_name": vm_name,
            "hostname": hostname,
            "vm_ip": vm_ip,
            "distribution": {
                "distribution_name": "Debian",
                "distribution_version": debian_version,
            },
            "distribution_string": distribution,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        metadata_path = metadata_dir / f"{vm_name}.json"
        with open(metadata_path, "w", encoding="utf-8") as metadata_file:
            json.dump(metadata, metadata_file, indent=2)

        self.logger.info(_("Saved VM metadata to %s"), metadata_path)
