"""
Ubuntu VMM VM creation orchestration.

This module handles the complete Ubuntu VM creation workflow including:
- Ubuntu version extraction and validation
- GitHub version checking for sysmanage-agent
- Autoinstall YAML file generation
- ISO download and modification for serial console
- VM boot with kernel ip= parameter for static networking
- Automated installation via autoinstall
- Post-installation configuration

Key differences from Debian:
- Uses Subiquity installer with autoinstall (YAML) instead of preseed
- Uses GRUB bootloader instead of ISOLINUX
- Requires kernel ip= parameter for static IP during autoinstall
- ISO is larger (~3.1GB vs ~650MB)
- Installation takes 15-20 minutes (kernel stage is slowest)
"""

import asyncio
import os
import time
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async
from src.sysmanage_agent.operations.child_host_types import VmmVmConfig
from src.sysmanage_agent.operations.child_host_ubuntu_autoinstall import (
    UbuntuAutoinstallSetup,
)
from src.sysmanage_agent.operations.child_host_ubuntu_packages import (
    extract_ubuntu_version,
)
from src.sysmanage_agent.operations.child_host_ubuntu_vm_helpers import (
    cleanup_installation_artifacts,
    get_disk_size,
    get_gateway_ip,
    get_next_vm_ip,
    parse_memory_gb,
    save_vm_metadata,
    validate_vm_config,
)
from src.sysmanage_agent.operations.child_host_vmm_disk import VmmDiskOperations
from src.sysmanage_agent.operations.child_host_vmm_launcher import VmmLauncher
from src.sysmanage_agent.operations.child_host_vmm_network_helpers import (
    get_host_dns_server,
)
from src.sysmanage_agent.operations.child_host_vmm_utils import (
    VMM_DISK_DIR,
    ensure_vmm_directories,
    get_fqdn_hostname,
    vm_exists,
)
from src.sysmanage_agent.operations.child_host_vmm_vmconf import VmConfManager


class UbuntuVmCreator:  # pylint: disable=too-many-instance-attributes
    """Handles Ubuntu VMM VM creation workflow."""

    # Default resource configurations for Ubuntu
    # Ubuntu Server needs more resources than minimal distros
    DEFAULT_DISK_SIZE = "20G"
    DEFAULT_MEMORY = "2G"  # Minimum recommended for installation

    def __init__(
        self,
        agent_instance,
        logger,
        virtualization_checks,
        github_checker,
        db_session,
    ):
        """
        Initialize Ubuntu VM creator.

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
        self.autoinstall_setup = UbuntuAutoinstallSetup(logger)

    async def _prepare_vm_environment(self, config: VmmVmConfig) -> Dict[str, Any]:
        """
        Prepare the VM environment (steps 1-10).

        Validates config, extracts version, checks VMM, gets network info.

        Args:
            config: VmmVmConfig with all VM settings

        Returns:
            Dict with success status and environment info or error
        """
        # Step 1: Validate configuration
        self.logger.info("Step 1: Validating configuration...")
        validation_result = validate_vm_config(config)
        if not validation_result.get("success"):
            return validation_result
        self.logger.info("Configuration validated")

        # Step 2: Extract Ubuntu version
        self.logger.info("Step 2: Extracting Ubuntu version...")
        await self.launcher.send_progress(
            "parsing_version", _("Parsing Ubuntu version...")
        )
        ubuntu_version = extract_ubuntu_version(config.distribution, self.logger)
        if not ubuntu_version:
            return {
                "success": False,
                "error": _("Could not parse Ubuntu version from: %s")
                % config.distribution,
            }
        self.logger.info("Ubuntu version: %s", ubuntu_version)

        # Step 3: Derive FQDN hostname
        self.logger.info("Step 3: Deriving FQDN hostname...")
        fqdn_hostname = get_fqdn_hostname(
            config.hostname, config.server_config.server_url
        )
        self.logger.info("FQDN hostname: %s", fqdn_hostname)

        # Step 4: Check VMM availability
        self.logger.info("Step 4: Checking VMM availability...")
        vmm_result = await self._check_vmm_ready()
        if not vmm_result.get("success"):
            return vmm_result
        self.logger.info("VMM is ready")

        # Step 5: Check if VM already exists
        self.logger.info("Step 5: Checking if VM already exists...")
        await self.launcher.send_progress(
            "checking_existing", _("Checking for existing VM...")
        )
        if vm_exists(config.vm_name, self.logger):
            return {
                "success": False,
                "error": _("VM '%s' already exists") % config.vm_name,
            }
        self.logger.info("VM does not exist")

        # Step 6: Ensure directories exist
        self.logger.info("Step 6: Ensuring VMM directories exist...")
        ensure_vmm_directories(self.logger)
        self.logger.info("Directories ensured")

        # Step 7: Get latest sysmanage-agent version
        self.logger.info("Step 7: Getting latest sysmanage-agent version...")
        agent_version, _tag_name = await self._get_agent_version()
        self.logger.info("Agent version: %s", agent_version)

        # Step 8: Get gateway IP
        self.logger.info("Step 8: Getting gateway IP...")
        gateway_ip = get_gateway_ip(self.logger)
        if not gateway_ip:
            return {
                "success": False,
                "error": _("Could not determine gateway IP from vether0"),
            }
        self.logger.info("Gateway IP: %s", gateway_ip)

        # Step 9: Get host DNS server (CRITICAL for Ubuntu!)
        self.logger.info("Step 9: Getting host DNS server...")
        dns_server = get_host_dns_server(self.logger)
        if not dns_server:
            return {
                "success": False,
                "error": _(
                    "Could not determine DNS server. "
                    "Ubuntu autoinstall requires actual DNS server, not gateway."
                ),
            }
        self.logger.info("DNS server: %s", dns_server)

        # Step 10: Get next available VM IP
        self.logger.info("Step 10: Getting next VM IP...")
        vm_ip = get_next_vm_ip(gateway_ip)
        self.logger.info("VM IP: %s", vm_ip)

        return {
            "success": True,
            "ubuntu_version": ubuntu_version,
            "fqdn_hostname": fqdn_hostname,
            "agent_version": agent_version,
            "gateway_ip": gateway_ip,
            "dns_server": dns_server,
            "vm_ip": vm_ip,
        }

    async def _prepare_installation_resources(
        self,
        config: VmmVmConfig,
        ubuntu_version: str,
        fqdn_hostname: str,
        gateway_ip: str,
        vm_ip: str,
        dns_server: str,
    ) -> Dict[str, Any]:
        """
        Prepare installation resources (steps 11-15).

        Downloads ISO, creates disk, generates autoinstall, creates ISOs.

        Args:
            config: VmmVmConfig with all VM settings
            ubuntu_version: Parsed Ubuntu version
            fqdn_hostname: Fully qualified domain name
            gateway_ip: Gateway IP address
            vm_ip: VM IP address
            dns_server: DNS server IP

        Returns:
            Dict with success status and resource paths or error
        """
        # Step 11: Download Ubuntu ISO
        self.logger.info("Step 11: Downloading Ubuntu ISO...")
        await self.launcher.send_progress(
            "downloading_iso",
            _("Downloading Ubuntu %s Server ISO (~3.1GB, this may take a while)...")
            % ubuntu_version,
        )
        iso_result = await asyncio.to_thread(
            self.autoinstall_setup.download_ubuntu_iso, ubuntu_version
        )
        if not iso_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to download Ubuntu ISO: %s")
                % iso_result.get("error"),
            }
        iso_path = iso_result.get("iso_path")
        self.logger.info("ISO ready: %s", iso_path)

        # Step 12: Create disk image
        self.logger.info("Step 12: Creating disk image...")
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
        self.logger.info("Disk created: %s", disk_path)

        # Step 13: Generate enhanced autoinstall with agent setup
        self.logger.info("Step 13: Generating autoinstall file...")
        await self.launcher.send_progress(
            "generating_autoinstall",
            _("Generating Ubuntu autoinstall configuration..."),
        )
        autoinstall_result = self.autoinstall_setup.generate_enhanced_autoinstall(
            hostname=fqdn_hostname,
            username=config.username,
            password_hash=config.password_hash,
            gateway_ip=gateway_ip,
            vm_ip=vm_ip,
            ubuntu_version=ubuntu_version,
            server_hostname=config.server_config.server_url,
            server_port=config.server_config.server_port,
            use_https=config.server_config.use_https,
            auto_approve_token=config.auto_approve_token,
            dns_server=dns_server,
        )
        if not autoinstall_result.get("success"):
            return autoinstall_result
        autoinstall_content = autoinstall_result.get("autoinstall")
        self.logger.info("Autoinstall file generated")

        # Step 14: Create data directory with setup files
        self.logger.info("Step 14: Creating data directory...")
        data_result = self.autoinstall_setup.create_ubuntu_data_dir(
            vm_name=config.vm_name,
            autoinstall_content=autoinstall_content,
            server_hostname=config.server_config.server_url,
            server_port=config.server_config.server_port,
            use_https=config.server_config.use_https,
            auto_approve_token=config.auto_approve_token,
            ubuntu_version=ubuntu_version,
        )
        if not data_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to create data directory: %s")
                % data_result.get("error"),
            }
        self.logger.info("Data directory created: %s", data_result.get("data_dir"))

        # Step 15: Create modified ISO with serial console
        self.logger.info("Step 15: Creating serial console ISO...")
        await self.launcher.send_progress(
            "creating_serial_iso",
            _("Creating modified ISO for serial console installation..."),
        )

        serial_iso_result = await asyncio.to_thread(
            self.autoinstall_setup.create_serial_console_iso,
            iso_path,
            config.vm_name,
            vm_ip,
            gateway_ip,
        )
        if not serial_iso_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to create serial console ISO: %s")
                % serial_iso_result.get("error"),
            }
        serial_iso_path = serial_iso_result.get("iso_path")
        self.logger.info("Serial console ISO created: %s", serial_iso_path)

        # Step 15b: Create cidata ISO with autoinstall configuration
        self.logger.info("Step 15b: Creating cidata ISO...")
        await self.launcher.send_progress(
            "creating_cidata_iso",
            _("Creating cidata ISO with autoinstall configuration..."),
        )
        cidata_result = await asyncio.to_thread(
            self.autoinstall_setup.create_cidata_iso,
            config.vm_name,
            autoinstall_content,
            "",  # Empty meta-data is fine
        )
        if not cidata_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to create cidata ISO: %s")
                % cidata_result.get("error"),
            }
        cidata_iso_path = cidata_result.get("cidata_iso_path")
        self.logger.info("Cidata ISO created: %s", cidata_iso_path)

        return {
            "success": True,
            "disk_path": disk_path,
            "serial_iso_path": serial_iso_path,
            "cidata_iso_path": cidata_iso_path,
        }

    async def _run_installation(
        self,
        config: VmmVmConfig,
        disk_path: str,
        serial_iso_path: str,
        cidata_iso_path: str,
    ) -> Dict[str, Any]:
        """
        Run the VM installation (steps 16-18).

        Launches VM, waits for installation, restarts from disk.

        Args:
            config: VmmVmConfig with all VM settings
            disk_path: Path to the disk image
            serial_iso_path: Path to the serial console ISO
            cidata_iso_path: Path to the cidata ISO

        Returns:
            Dict with success status and memory setting or error
        """
        # Step 16: Launch VM from modified ISO with cidata ISO
        self.logger.info("Step 16: Launching VM from ISO...")
        await self.launcher.send_progress(
            "launching_vm",
            _("Launching Ubuntu VM from ISO for installation..."),
        )
        # Ubuntu requires minimum 2G RAM for installation
        memory = config.resource_config.memory or self.DEFAULT_MEMORY
        if parse_memory_gb(memory) < 2:
            self.logger.info(
                _("Overriding memory %s to %s (Ubuntu minimum requirement)"),
                memory,
                self.DEFAULT_MEMORY,
            )
            memory = self.DEFAULT_MEMORY
        launch_result = await self._launch_vm_from_iso(
            config, disk_path, serial_iso_path, cidata_iso_path, memory
        )
        if not launch_result.get("success"):
            return launch_result
        self.logger.info("VM launched with serial console boot and cidata ISO")

        # Step 17: Wait for installation to complete
        self.logger.info("Step 17: Waiting for installation...")
        await self.launcher.send_progress(
            "awaiting_installation",
            _(
                "Ubuntu installation in progress. "
                "This typically takes 15-20 minutes..."
            ),
        )
        shutdown_result = await self._wait_for_installation_complete(
            config.vm_name, disk_path, timeout=1500  # 25 minutes
        )
        if not shutdown_result.get("success"):
            error_msg = shutdown_result.get("error", "Unknown error")
            # Check if this is a crash (disk too small) vs timeout
            if "crashed" in error_msg.lower() or "prematurely" in error_msg.lower():
                self.logger.error("Installation failed - VM crashed: %s", error_msg)
                return {
                    "success": False,
                    "error": _("Ubuntu installation failed: %s") % error_msg,
                }
            # Timeout - installation may still be running
            self.logger.warning("Installation may still be running: %s", error_msg)
        else:
            self.logger.info("Installation complete")

        # Step 18: Stop VM and restart from disk only (no ISO)
        self.logger.info("Step 18: Stopping VM to remove ISO from boot path...")
        await self.launcher.send_progress(
            "stopping_vm",
            _("Stopping VM to switch from ISO boot to disk boot..."),
        )

        stop_result = await self._stop_vm_for_restart(config.vm_name)
        if not stop_result.get("success"):
            self.logger.warning(
                "Could not stop VM cleanly: %s", stop_result.get("error")
            )

        # Wait for VM to actually be stopped
        await asyncio.sleep(3)

        # Now start from disk only
        self.logger.info("Step 18b: Starting VM from disk (no ISO)...")
        await self.launcher.send_progress(
            "restarting_vm",
            _("Starting Ubuntu VM from installed system..."),
        )
        restart_result = await self.launcher.launch_vm_from_disk(
            config.vm_name,
            disk_path,
            memory,
        )
        if not restart_result.get("success"):
            return restart_result
        self.logger.info("VM restarted from disk")

        return {"success": True, "memory": memory}

    async def create_ubuntu_vm(self, config: VmmVmConfig) -> Dict[str, Any]:
        """
        Create a new Ubuntu VMM virtual machine.

        Workflow:
        1. Validate configuration
        2. Extract Ubuntu version from distribution
        3. Derive FQDN hostname
        4. Check VMM availability
        5. Check if VM already exists
        6. Ensure directories exist
        7. Get latest sysmanage-agent version from GitHub
        8. Get gateway IP from vether0
        9. Get host DNS server (critical - must be actual DNS, not gateway)
        10. Get next available VM IP
        11. Download Ubuntu ISO (~3.1GB)
        12. Create disk image
        13. Generate enhanced autoinstall with agent setup
        14. Create data directory with setup files
        15. Create modified ISO with serial console and autoinstall params
        16. Launch VM from modified ISO
        17. Wait for installation (20-25 min timeout - Ubuntu is slower)
        18. Restart VM from disk
        19. Save metadata
        20. Add to vm.conf for persistence

        Args:
            config: VmmVmConfig with all VM settings

        Returns:
            Dict with success status and details
        """
        self.logger.info(
            "Starting Ubuntu VM creation for: %s",
            config.vm_name,
        )
        self.logger.info("Distribution: %s", config.distribution)
        self.logger.info("Hostname: %s", config.hostname)

        try:
            # Steps 1-10: Prepare VM environment
            env_result = await self._prepare_vm_environment(config)
            if not env_result.get("success"):
                return env_result

            ubuntu_version = env_result["ubuntu_version"]
            fqdn_hostname = env_result["fqdn_hostname"]
            agent_version = env_result["agent_version"]
            gateway_ip = env_result["gateway_ip"]
            dns_server = env_result["dns_server"]
            vm_ip = env_result["vm_ip"]

            # Steps 11-15: Prepare installation resources
            resources_result = await self._prepare_installation_resources(
                config, ubuntu_version, fqdn_hostname, gateway_ip, vm_ip, dns_server
            )
            if not resources_result.get("success"):
                return resources_result

            disk_path = resources_result["disk_path"]
            serial_iso_path = resources_result["serial_iso_path"]
            cidata_iso_path = resources_result["cidata_iso_path"]

            # Steps 16-18: Run installation
            install_result = await self._run_installation(
                config, disk_path, serial_iso_path, cidata_iso_path
            )
            if not install_result.get("success"):
                return install_result

            memory = install_result["memory"]

            # Step 19: Save metadata
            self.logger.info("Step 19: Saving VM metadata...")
            save_vm_metadata(
                config.vm_name,
                fqdn_hostname,
                config.distribution,
                ubuntu_version,
                vm_ip,
                self.logger,
            )
            self.logger.info("Metadata saved")

            # Step 20: Add to vm.conf for persistence
            self.logger.info("Step 20: Adding VM to vm.conf...")
            persist_result = self.vmconf_manager.persist_vm(
                config.vm_name,
                disk_path,
                memory,
                enable=True,
                boot_device=None,
            )
            if persist_result:
                self.logger.info("VM added to vm.conf")
            else:
                self.logger.warning("Failed to add VM to vm.conf")

            # Step 21: Clean up installation artifacts
            self.logger.info("Step 21: Cleaning up installation artifacts...")
            cleanup_installation_artifacts(serial_iso_path, config.vm_name, self.logger)

            await self.launcher.send_progress(
                "complete", _("Ubuntu VM creation complete")
            )

            self.logger.info(
                "VM '%s' created successfully!",
                config.vm_name,
            )

            return {
                "success": True,
                "child_name": config.vm_name,
                "child_type": "vmm",
                "hostname": fqdn_hostname,
                "username": config.username,
                "ubuntu_version": ubuntu_version,
                "agent_version": agent_version,
                "message": _(
                    "Ubuntu VM '%s' created successfully. "
                    "VM will self-register when agent starts on firstboot."
                )
                % config.vm_name,
            }

        except Exception as error:
            self.logger.error(
                "Exception during Ubuntu VM creation: %s", error, exc_info=True
            )
            return {"success": False, "error": str(error)}

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

    # Minimum disk size (in bytes) to consider installation successful
    # Ubuntu minimal install writes at least 2-3GB to disk
    MIN_INSTALLED_DISK_SIZE = 2 * 1024 * 1024 * 1024  # 2GB

    async def _wait_for_installation_complete(
        self,
        vm_name: str,
        disk_path: str,
        timeout: int = 1500,  # NOSONAR - timeout parameter is part of established API
    ) -> Dict[str, Any]:
        """
        Wait for Ubuntu installation to complete (VM shuts down).

        Args:
            vm_name: Name of the VM
            disk_path: Path to the VM's disk image
            timeout: Maximum time to wait in seconds (default 25 minutes)

        Returns:
            Dict with success status
        """
        self.logger.info(
            _("Waiting for Ubuntu installation to complete (timeout: %d seconds)..."),
            timeout,
        )

        start_time = time.time()
        check_interval = 30  # Check every 30 seconds

        while time.time() - start_time < timeout:
            # Check if VM is still running
            # Note: vmctl status returns exit code 1 when no VMs are running
            # (it still outputs the header row), so we check the output regardless
            result = await run_command_async(
                ["vmctl", "status"],
                timeout=10,
            )

            # Look for the VM in the output (check regardless of return code)
            # vmctl returns exit 1 with just header when no VMs exist
            vm_running = False
            for line in result.stdout.split("\n"):
                if vm_name in line and "running" in line.lower():
                    vm_running = True
                    break

            if not vm_running:
                # VM stopped - verify installation actually completed
                # by checking disk size (should be at least 2GB after install)
                disk_size = get_disk_size(disk_path, self.logger)
                elapsed = int(time.time() - start_time)

                if disk_size >= self.MIN_INSTALLED_DISK_SIZE:
                    self.logger.info(
                        _(
                            "VM '%s' shut down after %d seconds with disk size %d MB "
                            "- installation complete"
                        ),
                        vm_name,
                        elapsed,
                        disk_size // (1024 * 1024),
                    )
                    return {"success": True}
                # VM stopped but disk is too small - installation failed/crashed
                self.logger.error(
                    _(
                        "VM '%s' stopped after only %d seconds with disk size "
                        "%d KB - installation did NOT complete (VM likely crashed)"
                    ),
                    vm_name,
                    elapsed,
                    disk_size // 1024,
                )
                return {
                    "success": False,
                    "error": _(
                        "VM stopped prematurely after %d seconds. "
                        "Disk size is only %d KB (expected >2GB after installation). "
                        "The VM likely crashed during boot. "
                        "Check the VM console for boot errors."
                    )
                    % (elapsed, disk_size // 1024),
                }

            # Still running, wait and check again
            elapsed = int(time.time() - start_time)
            self.logger.info(
                _("Installation in progress... (%d seconds elapsed)"), elapsed
            )
            await asyncio.sleep(check_interval)

        return {
            "success": False,
            "error": _("Timeout waiting for installation to complete"),
        }

    async def _get_agent_version(self) -> tuple:
        """Get latest sysmanage-agent version from GitHub.

        Falls back to 'unknown' if GitHub is unreachable (e.g. private repo).
        The agent version is only used in the success result message for Ubuntu
        VMs, not in the autoinstall config itself, so this is non-critical.
        """
        await self.launcher.send_progress(
            "checking_github",
            _("Checking GitHub for latest sysmanage-agent version..."),
        )
        version_result = self.github_checker.get_latest_version()
        if not version_result.get("success"):
            self.logger.warning(
                _("Could not check GitHub version: %s. Continuing with 'unknown'."),
                version_result.get("error"),
            )
            return "unknown", "unknown"
        return version_result.get("version"), version_result.get("tag_name")

    async def _launch_vm_from_iso(
        self,
        config: VmmVmConfig,
        disk_path: str,
        iso_path: str,
        cidata_iso_path: str,
        memory: str,
    ) -> Dict[str, Any]:
        """
        Launch VM from Ubuntu ISO with cidata ISO attached.

        Attaches three disks:
        1. Ubuntu installer ISO (first disk - SeaBIOS boots from first disk)
        2. cidata ISO (second disk - cloud-init auto-detects by volume label)
        3. Virtual disk (third disk - installation target)

        Args:
            config: VM configuration
            disk_path: Path to the virtual disk image
            iso_path: Path to the Ubuntu installer ISO
            cidata_iso_path: Path to the cidata ISO with autoinstall config
            memory: Memory allocation string

        Returns:
            Dict with success status
        """
        try:
            # vmctl start with three disks:
            # 1. Ubuntu ISO (boot from first disk)
            # 2. cidata ISO (cloud-init finds it by 'cidata' volume label)
            # 3. Virtual disk (installation target)
            # Using -n local for static IP networking (not -L which uses DHCP)
            cmd = [
                "vmctl",
                "start",
                "-d",
                iso_path,  # Ubuntu ISO as first disk - SeaBIOS boots from first disk
                "-d",
                cidata_iso_path,  # cidata ISO as second disk - cloud-init detects it
                "-d",
                disk_path,  # Virtual disk as third disk - installation target
                "-m",
                memory,  # Memory
                "-n",
                "local",  # Network switch (not -L to avoid DHCP)
                config.vm_name,
            ]

            self.logger.info(_("Launching Ubuntu VM: %s"), " ".join(cmd))

            result = await run_command_async(
                cmd,
                timeout=30,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start VM: %s") % result.stderr,
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}
