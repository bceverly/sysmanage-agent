"""
Alpine Linux VMM VM creation orchestration.

This module handles the complete Alpine VM creation workflow including:
- Alpine version extraction and validation
- GitHub version checking for sysmanage-agent
- Site tarball building with configuration
- ISO download and VM boot
- Automated installation via serial console
- Post-installation configuration
"""

import asyncio
import json
import os
import re
import subprocess  # nosec B404
import time
from pathlib import Path
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.operations.child_host_alpine_autoinstall import (
    AlpineAutoinstallSetup,
)
from src.sysmanage_agent.operations.child_host_alpine_console import (
    AlpineConsoleAutomation,
)
from src.sysmanage_agent.operations.child_host_alpine_packages import (
    SUPPORTED_ALPINE_VERSIONS,
)
from src.sysmanage_agent.operations.child_host_alpine_site_builder import (
    AlpineSiteTarballBuilder,
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


def extract_alpine_version(distribution: str, logger) -> Optional[str]:
    """
    Extract Alpine Linux version from distribution string.

    Args:
        distribution: Distribution string (e.g., "Alpine Linux 3.20", "alpine-3.21")
        logger: Logger instance

    Returns:
        Version string (e.g., "3.20") or None if not found
    """
    # Try various patterns
    patterns = [
        r"Alpine\s*(?:Linux)?\s*(\d+\.\d+)",  # "Alpine Linux 3.20" or "Alpine 3.20"
        r"alpine[_-]?(\d+\.\d+)",  # "alpine-3.20" or "alpine_3.20"
        r"(\d+\.\d+)",  # Just the version number
    ]

    for pattern in patterns:
        match = re.search(pattern, distribution, re.IGNORECASE)
        if match:
            version = match.group(1)
            if version in SUPPORTED_ALPINE_VERSIONS:
                logger.info(_("Extracted Alpine version: %s"), version)
                return version

    logger.warning(_("Could not extract Alpine version from: %s"), distribution)
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
    match = re.search(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", server_url)
    if match:
        domain_parts = match.group(0).split(".", 1)
        if len(domain_parts) > 1:
            return f"{hostname}.{domain_parts[1]}"

    return hostname


class AlpineVmCreator:  # pylint: disable=too-many-instance-attributes
    """Handles Alpine Linux VMM VM creation workflow."""

    def __init__(
        self,
        agent_instance,
        logger,
        virtualization_checks,
        github_checker,
        db_session,
    ):
        """
        Initialize Alpine VM creator.

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
        self.autoinstall_setup = AlpineAutoinstallSetup(logger)
        self.site_builder = AlpineSiteTarballBuilder(logger, db_session)
        self.console_automation = AlpineConsoleAutomation(logger)

    async def create_alpine_vm(self, config: VmmVmConfig) -> Dict[str, Any]:
        """
        Create a new Alpine Linux VMM virtual machine.

        Workflow:
        1. Extract Alpine version from distribution
        2. Check GitHub for latest sysmanage-agent version
        3. Build site tarball with agent config
        4. Download Alpine ISO
        5. Create disk image
        6. Launch VM from ISO
        7. Wait for installation to complete (user assisted or automated)
        8. Configure first-boot scripts
        9. Restart VM to boot from disk

        Args:
            config: VmmVmConfig with all VM settings

        Returns:
            Dict with success status and details
        """
        self.logger.info(
            "🚀 [ALPINE_CREATE_START] Starting Alpine VM creation for: %s",
            config.vm_name,
        )
        self.logger.info(
            "🔍 [ALPINE_CREATE_CONFIG] Distribution: %s", config.distribution
        )
        self.logger.info("🔍 [ALPINE_CREATE_CONFIG] Hostname: %s", config.hostname)

        try:
            # Step 1: Validate configuration
            self.logger.info("📋 [STEP_1] Validating configuration...")
            validation_result = self._validate_config(config)
            if not validation_result.get("success"):
                return validation_result
            self.logger.info("✅ [STEP_1] Configuration validated")

            # Step 2: Extract Alpine version
            self.logger.info("📋 [STEP_2] Extracting Alpine version...")
            await self.launcher.send_progress(
                "parsing_version", _("Parsing Alpine Linux version...")
            )
            alpine_version = extract_alpine_version(config.distribution, self.logger)
            if not alpine_version:
                return {
                    "success": False,
                    "error": _("Could not parse Alpine version from: %s")
                    % config.distribution,
                }
            self.logger.info("✅ [STEP_2] Alpine version: %s", alpine_version)

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

            # Step 8: Build site tarball
            self.logger.info("📋 [STEP_8] Building Alpine site tarball...")
            site_result = await self._build_site_tarball(
                alpine_version, agent_version, config
            )
            if not site_result.get("success"):
                return site_result
            site_tgz_path = site_result.get("site_tgz_path")
            self.logger.info("✅ [STEP_8] Site tarball ready: %s", site_tgz_path)

            # Step 9: Get gateway IP
            self.logger.info("📋 [STEP_9] Getting gateway IP...")
            gateway_ip = self._get_gateway_ip()
            if not gateway_ip:
                return {
                    "success": False,
                    "error": _("Could not determine gateway IP from vether0"),
                }
            self.logger.info("✅ [STEP_9] Gateway IP: %s", gateway_ip)

            # Step 10: Get next available VM IP
            vm_ip = self._get_next_vm_ip(gateway_ip)
            self.logger.info("✅ [STEP_10] VM IP: %s", vm_ip)

            # Step 11: Download Alpine ISO
            self.logger.info("📋 [STEP_11] Downloading Alpine ISO...")
            await self.launcher.send_progress(
                "downloading_iso",
                _("Downloading Alpine Linux %s ISO...") % alpine_version,
            )
            iso_result = await asyncio.to_thread(
                self.autoinstall_setup.download_alpine_iso, alpine_version
            )
            if not iso_result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to download Alpine ISO: %s")
                    % iso_result.get("error"),
                }
            iso_path = iso_result.get("iso_path")
            self.logger.info("✅ [STEP_11] ISO ready: %s", iso_path)

            # Step 12: Create disk image
            self.logger.info("📋 [STEP_12] Creating disk image...")
            await self.launcher.send_progress(
                "creating_disk",
                _("Creating %s disk image...") % config.resource_config.disk_size,
            )
            disk_path = os.path.join(VMM_DISK_DIR, f"{config.vm_name}.qcow2")
            disk_result = self.disk_ops.create_disk_image(
                disk_path, config.resource_config.disk_size
            )
            if not disk_result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to create disk: %s") % disk_result.get("error"),
                }
            self.logger.info("✅ [STEP_12] Disk created: %s", disk_path)

            # Step 13: Create setup data directory
            self.logger.info("📋 [STEP_13] Creating setup data...")
            setup_result = await self._create_setup_data(
                config,
                fqdn_hostname,
                gateway_ip,
                vm_ip,
                alpine_version,
            )
            if not setup_result.get("success"):
                return setup_result
            self.logger.info("✅ [STEP_13] Setup data created")

            # Step 14: Launch VM from ISO
            self.logger.info("📋 [STEP_14] Launching VM from ISO...")
            await self.launcher.send_progress(
                "launching_vm",
                _("Launching Alpine VM from ISO for installation..."),
            )
            launch_result = await self._launch_vm_from_iso(config, disk_path, iso_path)
            if not launch_result.get("success"):
                return launch_result
            self.logger.info("✅ [STEP_14] VM launched")

            # Step 15: Wait for installation
            # Alpine installation requires more interaction than OpenBSD
            # We'll wait and provide instructions
            self.logger.info("📋 [STEP_15] Waiting for Alpine installation...")
            await self.launcher.send_progress(
                "awaiting_installation",
                _(
                    "Alpine VM is booting from ISO. Installation will proceed "
                    "automatically via serial console. This may take 5-10 minutes."
                ),
            )

            # Run the automated setup via serial console
            install_result = await self._run_automated_install(
                config.vm_name,
                fqdn_hostname,
                config.username,
                config.password_hash,  # Note: Alpine needs plain password
                config.root_password_hash,
                gateway_ip,
                vm_ip,
                alpine_version,
                server_hostname=config.server_config.server_url,
                server_port=config.server_config.server_port,
                use_https=config.server_config.use_https,
                auto_approve_token=config.auto_approve_token,
            )

            if not install_result.get("success"):
                self.logger.warning(
                    "⚠️ Automated install may need manual intervention: %s",
                    install_result.get("error"),
                )

            # Step 16: Wait for VM to shutdown after installation
            self.logger.info("📋 [STEP_16] Waiting for installation to complete...")
            await self.launcher.send_progress(
                "awaiting_shutdown",
                _("Waiting for Alpine installation to complete..."),
            )
            shutdown_result = await self._wait_for_vm_shutdown(
                config.vm_name, timeout=900
            )
            if not shutdown_result.get("success"):
                self.logger.warning(
                    "⚠️ VM may still be installing: %s", shutdown_result.get("error")
                )

            # Step 17: Restart VM to boot from disk
            self.logger.info("📋 [STEP_17] Restarting VM to boot from disk...")
            await self.launcher.send_progress(
                "restarting_vm",
                _("Restarting Alpine VM to boot from installed system..."),
            )
            restart_result = await self.launcher.launch_vm_from_disk(
                config.vm_name,
                disk_path,
                config.resource_config.memory,
            )
            if not restart_result.get("success"):
                return restart_result
            self.logger.info("✅ [STEP_17] VM restarted")

            # Step 18: Save metadata
            self.logger.info("📋 [STEP_18] Saving VM metadata...")
            self._save_vm_metadata(
                config.vm_name,
                fqdn_hostname,
                config.distribution,
                alpine_version,
                vm_ip,
            )
            self.logger.info("✅ [STEP_18] Metadata saved")

            # Step 19: Add to vm.conf for persistence
            self.logger.info("📋 [STEP_19] Adding VM to vm.conf...")
            persist_result = self.vmconf_manager.persist_vm(
                config.vm_name,
                disk_path,
                config.resource_config.memory,
                enable=True,
                boot_device=None,
            )
            if persist_result:
                self.logger.info("✅ [STEP_19] VM added to vm.conf")
            else:
                self.logger.warning("⚠️ [STEP_19] Failed to add VM to vm.conf")

            await self.launcher.send_progress(
                "complete", _("Alpine VM creation complete")
            )

            self.logger.info(
                "🎉 [ALPINE_CREATE_SUCCESS] VM '%s' created successfully!",
                config.vm_name,
            )

            return {
                "success": True,
                "child_name": config.vm_name,
                "child_type": "vmm",
                "hostname": fqdn_hostname,
                "username": config.username,
                "alpine_version": alpine_version,
                "agent_version": agent_version,
                "message": _(
                    "Alpine Linux VM '%s' created successfully. "
                    "VM will self-register when agent starts."
                )
                % config.vm_name,
            }

        except Exception as error:
            self.logger.error(
                "💥 [ALPINE_CREATE_ERROR] Exception: %s", error, exc_info=True
            )
            return {"success": False, "error": str(error)}

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
        self, alpine_version: str, agent_version: str, config: VmmVmConfig
    ) -> Dict[str, Any]:
        """Build Alpine site tarball."""
        await self.launcher.send_progress(
            "building_site_tarball",
            _("Building Alpine site tarball with sysmanage-agent %s...")
            % agent_version,
        )

        return await asyncio.to_thread(
            self.site_builder.get_or_build_site_tarball,
            alpine_version=alpine_version,
            agent_version=agent_version,
            server_hostname=config.server_config.server_url,
            server_port=config.server_config.server_port,
            use_https=config.server_config.use_https,
            auto_approve_token=config.auto_approve_token,
        )

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

    async def _create_setup_data(
        self,
        config: VmmVmConfig,
        fqdn_hostname: str,
        gateway_ip: str,
        vm_ip: str,
        alpine_version: str,
    ) -> Dict[str, Any]:
        """Create setup data for Alpine VM."""
        try:
            # Get host's DNS server for the VM to use
            dns_server = get_host_dns_server(self.logger)

            # Create the setup script with server config for agent installation
            setup_script = self.autoinstall_setup.create_setup_script(
                hostname=fqdn_hostname,
                username=config.username,
                user_password=config.password_hash,  # Need plain text for chpasswd
                root_password=config.root_password_hash or config.password_hash,
                gateway_ip=gateway_ip,
                vm_ip=vm_ip,
                alpine_version=alpine_version,
                dns_server=dns_server,
                server_hostname=config.server_config.server_url,
                server_port=config.server_config.server_port,
                use_https=config.server_config.use_https,
                auto_approve_token=config.auto_approve_token,
            )

            # Create agent config
            agent_config = self.autoinstall_setup.create_agent_config(
                server_hostname=config.server_config.server_url,
                server_port=config.server_config.server_port,
                use_https=config.server_config.use_https,
                auto_approve_token=config.auto_approve_token,
            )

            # Create firstboot script
            firstboot_script = self.autoinstall_setup.create_firstboot_setup(
                server_hostname=config.server_config.server_url,
                server_port=config.server_config.server_port,
                use_https=config.server_config.use_https,
                auto_approve_token=config.auto_approve_token,
            )

            # Save to data directory
            result = self.autoinstall_setup.create_alpine_data_disk(
                vm_name=config.vm_name,
                setup_script=setup_script,
                agent_config=agent_config,
                firstboot_script=firstboot_script,
            )

            return result

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _launch_vm_from_iso(
        self, config: VmmVmConfig, disk_path: str, iso_path: str
    ) -> Dict[str, Any]:
        """Launch VM from Alpine ISO."""
        try:
            # vmctl start with ISO as first disk
            # OpenBSD VMM's SeaBIOS boots from the first disk, so we pass the ISO
            # as the first -d argument and the virtual disk as the second.
            # Using -b flag doesn't work for Alpine as VMM BIOS can't load the
            # Alpine kernel directly (unlike OpenBSD's bsd.rd).
            # Note: Don't use -c flag as it blocks waiting for console input
            cmd = [
                "vmctl",
                "start",
                "-d",
                iso_path,  # ISO as first disk - SeaBIOS boots from first disk
                "-d",
                disk_path,  # Virtual disk as second disk
                "-m",
                config.resource_config.memory,  # Memory
                "-n",
                "local",  # Network switch
                config.vm_name,
            ]

            self.logger.info(_("Launching Alpine VM: %s"), " ".join(cmd))

            result = subprocess.run(  # nosec B603 B607
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start VM: %s") % result.stderr,
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _run_automated_install(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        vm_name: str,
        hostname: str,
        username: str,
        user_password: str,
        root_password: str,
        gateway_ip: str,
        vm_ip: str,
        alpine_version: str,
        server_hostname: str = None,
        server_port: int = None,
        use_https: bool = True,
        auto_approve_token: str = None,
    ) -> Dict[str, Any]:
        """
        Run automated installation via serial console.

        Uses the AlpineConsoleAutomation class to interact with the VM's
        serial console and run the setup-alpine process.
        """
        try:
            # Wait for VM to boot (Alpine boots quickly)
            self.logger.info(_("Waiting for Alpine VM to boot..."))
            await asyncio.sleep(15)

            # Get host's DNS server for the VM to use
            dns_server = get_host_dns_server(self.logger)
            if dns_server:
                self.logger.info(_("Using host DNS server: %s"), dns_server)
            else:
                self.logger.warning(
                    _("Could not detect host DNS, falling back to 8.8.8.8")
                )

            # Create the setup script with server config for agent installation
            setup_script = self.autoinstall_setup.create_setup_script(
                hostname=hostname,
                username=username,
                user_password=user_password,
                root_password=root_password or user_password,
                gateway_ip=gateway_ip,
                vm_ip=vm_ip,
                alpine_version=alpine_version,
                dns_server=dns_server,
                server_hostname=server_hostname,
                server_port=server_port,
                use_https=use_https,
                auto_approve_token=auto_approve_token,
            )

            # Write script to temp file for reference/debugging
            script_path = f"/tmp/alpine_setup_{vm_name}.sh"  # nosec B108
            with open(script_path, "w", encoding="utf-8") as script_file:
                script_file.write(setup_script)

            self.logger.info(
                _("Alpine setup script written to %s. Starting console automation..."),
                script_path,
            )

            # Run the automated console installation
            result = await self.console_automation.run_automated_setup(
                vm_name=vm_name,
                setup_script=setup_script,
                timeout=600,  # 10 minutes for installation
            )

            if not result.get("success"):
                self.logger.error(
                    _("Console automation failed: %s"), result.get("error")
                )
                self.logger.warning(
                    _(
                        "Manual intervention may be required. "
                        "Connect via: vmctl console %s"
                    ),
                    vm_name,
                )

            return result

        except Exception as error:
            self.logger.error(_("Automated install error: %s"), error, exc_info=True)
            return {"success": False, "error": str(error)}

    async def _wait_for_vm_shutdown(
        self, vm_name: str, timeout: int = 900
    ) -> Dict[str, Any]:
        """Wait for VM to shutdown after installation."""
        self.logger.info(_("Waiting for VM '%s' to shutdown..."), vm_name)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Run vmctl status (all VMs) and check if our VM has stopped
                # When a VM shuts down, it disappears from vmctl status entirely
                result = subprocess.run(  # nosec B603 B607
                    ["vmctl", "status"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                # Check for any indication VM has stopped:
                # 1. VM name not in output (disappeared from list)
                # 2. "stopped" appears in status
                # 3. Non-zero return code (error getting status)
                if (
                    vm_name not in result.stdout
                    or "stopped" in result.stdout.lower()
                    or result.returncode != 0
                ):
                    self.logger.info(_("VM '%s' has shutdown"), vm_name)
                    return {"success": True}

            except Exception:
                pass

            await asyncio.sleep(10)

        return {
            "success": False,
            "error": _("Timeout waiting for VM to shutdown"),
        }

    def _save_vm_metadata(
        self,
        vm_name: str,
        hostname: str,
        distribution: str,
        alpine_version: str,
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
                "distribution_name": "Alpine Linux",
                "distribution_version": alpine_version,
            },
            "distribution_string": distribution,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        metadata_path = metadata_dir / f"{vm_name}.json"
        with open(metadata_path, "w", encoding="utf-8") as metadata_file:
            json.dump(metadata, metadata_file, indent=2)

        self.logger.info(_("Saved VM metadata to %s"), metadata_path)
