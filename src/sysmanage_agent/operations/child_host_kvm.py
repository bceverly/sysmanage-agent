"""
KVM/libvirt-specific child host operations for Linux hosts.

This module handles KVM/QEMU virtual machine management via libvirt/virsh.
"""

import asyncio
import os
import platform
import pwd
import shutil
import subprocess  # nosec B404 # Required for sync functions
import time
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async
from src.sysmanage_agent.operations.child_host_kvm_creation import KvmCreation
from src.sysmanage_agent.operations.child_host_kvm_lifecycle import KvmLifecycle
from src.sysmanage_agent.operations.child_host_kvm_networking import KvmNetworking
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig

# Package installation commands by Linux distribution
# libguestfs-tools is needed for guest filesystem operations
# genisoimage is needed to create cloud-init ISOs
# Path to the KVM device node
DEV_KVM_PATH = "/dev/kvm"

LIBVIRT_PACKAGES = {
    "debian": [
        "qemu-kvm",
        "libvirt-daemon-system",
        "libvirt-clients",
        "virtinst",
        "bridge-utils",
        "libguestfs-tools",
        "genisoimage",
    ],
    "ubuntu": [
        "qemu-kvm",
        "libvirt-daemon-system",
        "libvirt-clients",
        "virtinst",
        "bridge-utils",
        "libguestfs-tools",
        "genisoimage",
    ],
    "fedora": ["@virtualization", "libguestfs-tools", "genisoimage"],
    "rhel": ["qemu-kvm", "libvirt", "virt-install", "libguestfs-tools", "genisoimage"],
    "centos": [
        "qemu-kvm",
        "libvirt",
        "virt-install",
        "libguestfs-tools",
        "genisoimage",
    ],
    "rocky": ["qemu-kvm", "libvirt", "virt-install", "libguestfs-tools", "genisoimage"],
    "alma": ["qemu-kvm", "libvirt", "virt-install", "libguestfs-tools", "genisoimage"],
    "alpine": ["qemu", "qemu-system-x86_64", "libvirt", "libvirt-daemon", "cdrkit"],
    "opensuse": [
        "patterns-server-kvm_server",
        "patterns-server-kvm_tools",
        "guestfs-tools",
        "genisoimage",
    ],
    "suse": [
        "patterns-server-kvm_server",
        "patterns-server-kvm_tools",
        "guestfs-tools",
        "genisoimage",
    ],
}


class KvmOperations:
    """KVM/libvirt-specific operations for child host management on Linux."""

    def __init__(self, agent_instance, logger, virtualization_checks):
        """
        Initialize KVM operations.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks
        self.networking = KvmNetworking(logger)
        self.lifecycle = KvmLifecycle(logger)
        self.creation = KvmCreation(logger)

    def _read_cpu_flags(self) -> Dict[str, Any]:
        """
        Read CPU flags from /proc/cpuinfo.

        Returns:
            Dict with success status and cpu_flags string
        """
        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8") as cpuinfo_file:
                for line in cpuinfo_file:
                    if line.startswith("flags"):
                        return {"success": True, "cpu_flags": line}
            return {"success": True, "cpu_flags": ""}
        except Exception as read_error:
            self.logger.warning(_("Could not read CPU flags: %s"), read_error)
            return {"success": False, "error": str(read_error)}

    def _detect_kvm_module(self, cpu_flags: str) -> Optional[str]:
        """
        Detect which KVM module to load based on CPU flags.

        Args:
            cpu_flags: CPU flags string from /proc/cpuinfo

        Returns:
            Module name ("kvm_intel" or "kvm_amd") or None if not supported
        """
        if "vmx" in cpu_flags:
            self.logger.info(_("Detected Intel CPU with VMX support"))
            return "kvm_intel"
        if "svm" in cpu_flags:
            self.logger.info(_("Detected AMD CPU with SVM support"))
            return "kvm_amd"

        self.logger.warning(
            _("No hardware virtualization support detected in CPU flags")
        )
        return None

    def _load_kvm_module_with_modprobe(self, module_name: str) -> Dict[str, Any]:
        """
        Load a KVM module using modprobe.

        Args:
            module_name: Name of the module to load

        Returns:
            Dict with success status
        """
        self.logger.info(
            _("Loading KVM module: %s with nested virtualization enabled"),
            module_name,
        )
        result = subprocess.run(  # nosec B603 B607
            ["modprobe", module_name, "nested=1"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            self.logger.error(_("Failed to load KVM module: %s"), error_msg)
            return {"success": False, "error": error_msg}

        return {"success": True}

    def _load_kvm_module(self) -> Dict[str, Any]:
        """
        Load the appropriate KVM kernel module based on CPU type.

        Returns:
            Dict with success status and loaded module name
        """
        try:
            if os.path.exists(DEV_KVM_PATH):
                self.logger.info(_("KVM device already exists"))
                return {"success": True, "message": "KVM already available"}

            flags_result = self._read_cpu_flags()
            if not flags_result.get("success"):
                return flags_result

            module_name = self._detect_kvm_module(flags_result.get("cpu_flags", ""))
            if not module_name:
                return {
                    "success": False,
                    "error": _(
                        "CPU does not support hardware virtualization (no vmx or svm flags)"
                    ),
                }

            load_result = self._load_kvm_module_with_modprobe(module_name)
            if not load_result.get("success"):
                return load_result

            time.sleep(0.5)

            if not os.path.exists(DEV_KVM_PATH):
                self.logger.warning(_("KVM module loaded but /dev/kvm not created"))
                return {
                    "success": False,
                    "error": _("Module loaded but /dev/kvm not created"),
                }

            self.logger.info(_("KVM module loaded successfully, /dev/kvm is available"))
            persistent_ok = self._configure_nested_virtualization_persistent(
                module_name
            )

            return {
                "success": True,
                "message": f"Loaded {module_name} module with nested virtualization",
                "module": module_name,
                "nested_enabled": True,
                "nested_persistent": persistent_ok,
            }

        except subprocess.TimeoutExpired:
            self.logger.error(_("Timeout loading KVM module"))
            return {"success": False, "error": _("Timeout loading KVM module")}
        except Exception as load_error:
            self.logger.error(_("Error loading KVM module: %s"), load_error)
            return {"success": False, "error": str(load_error)}

    def _configure_nested_virtualization_persistent(self, module_name: str) -> bool:
        """
        Make nested virtualization configuration persistent across reboots.

        Creates or updates /etc/modprobe.d/kvm.conf to enable nested virtualization
        for the specified KVM module (kvm_intel or kvm_amd).

        Args:
            module_name: The KVM module name (kvm_intel or kvm_amd)

        Returns:
            True if configuration was successfully written, False otherwise
        """
        config_file = "/etc/modprobe.d/kvm.conf"
        nested_option = f"options {module_name} nested=1"

        try:
            # Read existing config if it exists
            existing_content = ""
            if os.path.exists(config_file):
                try:
                    with open(config_file, "r", encoding="utf-8") as config:
                        existing_content = config.read()
                except PermissionError:
                    self.logger.warning(
                        _("Cannot read %s - will attempt to write anyway"), config_file
                    )

            # Check if nested option is already configured
            if nested_option in existing_content:
                self.logger.info(
                    _("Nested virtualization already configured in %s"), config_file
                )
                return True

            # Remove any existing nested= line for this module and add the new one
            lines = (
                existing_content.strip().split("\n") if existing_content.strip() else []
            )
            filtered_lines = [
                line
                for line in lines
                if not (line.startswith(f"options {module_name}") and "nested=" in line)
            ]
            filtered_lines.append(nested_option)

            # Write the configuration file
            new_content = "\n".join(filtered_lines) + "\n"

            # Use subprocess to write with sudo since /etc requires root
            write_result = subprocess.run(  # nosec B603 B607
                ["sudo", "tee", config_file],
                input=new_content,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if write_result.returncode == 0:
                self.logger.info(
                    _("Nested virtualization configuration saved to %s"), config_file
                )
                return True

            self.logger.warning(
                _("Failed to write nested virtualization config: %s"),
                write_result.stderr,
            )
            return False

        except Exception as config_error:
            self.logger.warning(
                _("Error configuring persistent nested virtualization: %s"),
                config_error,
            )
            return False

    async def enable_kvm_modules(  # NOSONAR - async required by caller interface
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enable KVM by loading the kernel modules via modprobe.

        This is called when the user clicks "Enable KVM" to load the kvm
        and kvm_intel/kvm_amd kernel modules.

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(_("Enabling KVM kernel modules"))

            # Use the existing _load_kvm_module method
            result = self._load_kvm_module()

            if result.get("success"):
                message = _(
                    "KVM kernel modules loaded with nested virtualization enabled"
                )
                if result.get("nested_persistent"):
                    message += _(
                        " - configuration saved to /etc/modprobe.d/kvm.conf for persistence"
                    )
                return {
                    "success": True,
                    "message": message,
                    "module": result.get("module"),
                    "nested_enabled": result.get("nested_enabled", False),
                    "nested_persistent": result.get("nested_persistent", False),
                }

            return result

        except Exception as error:
            self.logger.error(_("Error enabling KVM modules: %s"), error)
            return {"success": False, "error": str(error)}

    async def _check_running_vms(self) -> Optional[Dict[str, Any]]:
        """
        Check if any VMs are currently running.

        Returns:
            Error dict if VMs are running, None if no VMs running or check not possible
        """
        if not os.path.exists(DEV_KVM_PATH):
            return None

        virsh_path = shutil.which("virsh")
        if not virsh_path:
            return None

        result = await run_command_async(
            ["virsh", "list", "--state-running", "--name"],
            timeout=10,
        )
        if result.returncode != 0:
            return None

        running_vms = [
            vm.strip() for vm in result.stdout.strip().split("\n") if vm.strip()
        ]
        if not running_vms:
            return None

        return {
            "success": False,
            "error": _("Cannot disable KVM while VMs are running: %s")
            % ", ".join(running_vms),
        }

    async def _detect_loaded_vendor_module(self) -> Optional[str]:
        """
        Detect which KVM vendor module is currently loaded.

        Returns:
            Module name ("kvm_intel" or "kvm_amd") or None if neither loaded
        """
        lsmod_result = await run_command_async(["lsmod"], timeout=10)
        if lsmod_result.returncode != 0:
            return None

        if "kvm_intel" in lsmod_result.stdout:
            return "kvm_intel"
        if "kvm_amd" in lsmod_result.stdout:
            return "kvm_amd"
        return None

    async def _unload_module(self, module_name: str) -> Optional[Dict[str, Any]]:
        """
        Unload a kernel module using modprobe -r.

        Args:
            module_name: Name of the module to unload

        Returns:
            Error dict if unload failed, None on success
        """
        self.logger.info(_("Unloading %s module"), module_name)
        result = await run_command_async(
            ["modprobe", "-r", module_name],
            timeout=30,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            self.logger.error(_("Failed to unload %s: %s"), module_name, error_msg)
            return {"success": False, "error": error_msg}
        return None

    async def _verify_kvm_removed(self) -> Optional[Dict[str, Any]]:
        """
        Verify that /dev/kvm has been removed after module unload.

        Returns:
            Error dict if /dev/kvm still exists, None if successfully removed
        """
        await asyncio.sleep(0.5)
        if os.path.exists(DEV_KVM_PATH):
            return {
                "success": False,
                "error": _("Modules unloaded but /dev/kvm still exists"),
            }
        return None

    async def disable_kvm_modules(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Disable KVM by unloading the kernel modules via modprobe -r.

        This is called when the user clicks "Disable KVM" to unload the kvm
        kernel modules. Note: This will fail if any VMs are running.

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(_("Disabling KVM kernel modules"))

            # Check if any VMs are running
            running_vms_error = await self._check_running_vms()
            if running_vms_error:
                return running_vms_error

            # Unload vendor-specific module first (kvm_intel or kvm_amd)
            vendor_module = await self._detect_loaded_vendor_module()
            if vendor_module:
                unload_error = await self._unload_module(vendor_module)
                if unload_error:
                    return unload_error

            # Unload base kvm module
            unload_error = await self._unload_module("kvm")
            if unload_error:
                return unload_error

            # Verify /dev/kvm is gone
            verify_error = await self._verify_kvm_removed()
            if verify_error:
                return verify_error

            self.logger.info(_("KVM kernel modules unloaded successfully"))
            return {
                "success": True,
                "message": _("KVM kernel modules unloaded successfully"),
            }

        except asyncio.TimeoutError:
            self.logger.error(_("Timeout unloading KVM modules"))
            return {"success": False, "error": _("Timeout unloading KVM modules")}
        except Exception as error:
            self.logger.error(_("Error disabling KVM modules: %s"), error)
            return {"success": False, "error": str(error)}

    def _detect_package_manager(self) -> Dict[str, Any]:
        """
        Detect which package manager is available on this system.

        Returns:
            Dict with package manager info (name, packages, install_cmd)
        """
        # Try to detect distribution
        distro_id = ""
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as os_release:
                for line in os_release:
                    if line.startswith("ID="):
                        distro_id = line.strip().split("=")[1].strip('"').lower()
                        break
        except (
            Exception
        ):  # nosec B110 # Expected: continue to package manager detection
            pass

        # Detect package manager and get appropriate packages
        if shutil.which("apt-get"):
            packages = LIBVIRT_PACKAGES.get(distro_id, LIBVIRT_PACKAGES["debian"])
            return {
                "name": "apt",
                "packages": packages,
                "install_cmd": ["apt-get", "install", "-y"],
                "update_cmd": ["apt-get", "update"],
            }
        if shutil.which("dnf"):
            packages = LIBVIRT_PACKAGES.get(distro_id, LIBVIRT_PACKAGES["fedora"])
            return {
                "name": "dnf",
                "packages": packages,
                "install_cmd": ["dnf", "install", "-y"],
                "update_cmd": None,
            }
        if shutil.which("yum"):
            packages = LIBVIRT_PACKAGES.get(distro_id, LIBVIRT_PACKAGES["centos"])
            return {
                "name": "yum",
                "packages": packages,
                "install_cmd": ["yum", "install", "-y"],
                "update_cmd": None,
            }
        if shutil.which("zypper"):
            packages = LIBVIRT_PACKAGES.get(distro_id, LIBVIRT_PACKAGES["opensuse"])
            return {
                "name": "zypper",
                "packages": packages,
                "install_cmd": ["zypper", "install", "-y"],
                "update_cmd": ["zypper", "refresh"],
            }
        if shutil.which("apk"):
            packages = LIBVIRT_PACKAGES.get(distro_id, LIBVIRT_PACKAGES["alpine"])
            return {
                "name": "apk",
                "packages": packages,
                "install_cmd": ["apk", "add"],
                "update_cmd": ["apk", "update"],
            }
        return {"name": None, "packages": [], "install_cmd": None, "update_cmd": None}

    def _install_libvirt_packages(self, pkg_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Install libvirt packages using the detected package manager.

        Args:
            pkg_info: Dict with package manager info from _detect_package_manager

        Returns:
            Dict with success status and message
        """
        if not pkg_info.get("install_cmd"):
            return {
                "success": False,
                "error": _("No supported package manager found"),
            }

        try:
            # Run update command if available
            if pkg_info.get("update_cmd"):
                self.logger.info(_("Updating package lists"))
                subprocess.run(  # nosec B603 B607
                    ["sudo"] + pkg_info["update_cmd"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )

            # Install packages
            self.logger.info(_("Installing libvirt packages: %s"), pkg_info["packages"])
            install_cmd = ["sudo"] + pkg_info["install_cmd"] + pkg_info["packages"]

            result = subprocess.run(  # nosec B603 B607
                install_cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes timeout for package installation
                check=False,
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                self.logger.error(_("Failed to install libvirt: %s"), error_msg)
                return {"success": False, "error": error_msg}

            self.logger.info(_("Libvirt packages installed successfully"))
            return {"success": True, "message": _("Libvirt packages installed")}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Package installation timed out")}
        except Exception as install_error:
            self.logger.error(_("Error installing libvirt: %s"), install_error)
            return {"success": False, "error": str(install_error)}

    def _enable_libvirtd_service(self) -> Dict[str, Any]:
        """
        Enable and start the libvirtd service.

        Returns:
            Dict with success status and message
        """
        try:
            # Enable libvirtd
            self.logger.info(_("Enabling libvirtd service"))
            enable_result = subprocess.run(  # nosec B603 B607
                ["sudo", "systemctl", "enable", "libvirtd"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if enable_result.returncode != 0:
                self.logger.warning(
                    _("Could not enable libvirtd: %s"),
                    enable_result.stderr or enable_result.stdout,
                )

            # Start libvirtd
            self.logger.info(_("Starting libvirtd service"))
            start_result = subprocess.run(  # nosec B603 B607
                ["sudo", "systemctl", "start", "libvirtd"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if start_result.returncode != 0:
                error_msg = (
                    start_result.stderr or start_result.stdout or "Unknown error"
                )
                self.logger.error(_("Failed to start libvirtd: %s"), error_msg)
                return {"success": False, "error": error_msg}

            # Verify service is running
            status_result = subprocess.run(  # nosec B603 B607
                ["sudo", "systemctl", "is-active", "libvirtd"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if status_result.returncode == 0 and "active" in status_result.stdout:
                self.logger.info(_("libvirtd service is active"))
                return {"success": True, "message": _("libvirtd service started")}

            return {
                "success": False,
                "error": _("libvirtd service not active after start attempt"),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Service operation timed out")}
        except Exception as service_error:
            self.logger.error(_("Error with libvirtd service: %s"), service_error)
            return {"success": False, "error": str(service_error)}

    def _add_user_to_groups(self) -> Dict[str, Any]:
        """
        Add the current user to libvirt and kvm groups.

        Returns:
            Dict with success status and groups added
        """
        try:
            # Get current user
            current_user = pwd.getpwuid(os.getuid()).pw_name
            groups_to_add = ["libvirt", "kvm"]
            groups_added = []

            for group in groups_to_add:
                # Check if group exists
                try:
                    subprocess.run(  # nosec B603 B607
                        ["getent", "group", group],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=True,
                    )
                except subprocess.CalledProcessError:
                    # Group doesn't exist, skip
                    continue

                # Add user to group
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "usermod", "-aG", group, current_user],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                if result.returncode == 0:
                    groups_added.append(group)
                    self.logger.info(
                        _("Added user %s to group %s"), current_user, group
                    )

            return {
                "success": True,
                "groups_added": groups_added,
                "needs_relogin": len(groups_added) > 0,
            }

        except Exception as group_error:
            self.logger.warning(_("Error adding user to groups: %s"), group_error)
            return {"success": False, "error": str(group_error)}

    async def initialize_kvm(  # NOSONAR - async required by caller interface
        self, _parameters: dict
    ) -> dict:
        """
        Initialize KVM/libvirt on Linux: install packages, enable service, configure network.

        Args:
            _parameters: Optional parameters (unused)

        Returns:
            Dict with success status and details
        """
        try:
            self.logger.info(_("Initializing KVM/libvirt"))

            # Verify we're on Linux
            if platform.system() != "Linux":
                return {
                    "success": False,
                    "error": _("KVM is only supported on Linux systems"),
                }

            # Step 0: Load KVM kernel module if /dev/kvm doesn't exist
            # Do this first, before checking status, so hardware accel is available
            module_loaded = False
            if not os.path.exists(DEV_KVM_PATH):
                module_result = self._load_kvm_module()
                if module_result.get("success"):
                    module_loaded = True
                else:
                    self.logger.warning(
                        _("KVM module loading warning: %s"), module_result.get("error")
                    )
                    # Continue anyway - libvirt can still be installed

            # Check current KVM status
            kvm_check = self.virtualization_checks.check_kvm_support()

            # If already fully initialized (and we didn't just load the module), return success
            if kvm_check.get("initialized") and not module_loaded:
                self.logger.info(_("KVM is already initialized"))
                return {
                    "success": True,
                    "message": _("KVM is already initialized and ready to use"),
                    "already_initialized": True,
                }

            # If we just loaded the module and KVM is now fully initialized, return success
            if kvm_check.get("initialized") and module_loaded:
                self.logger.info(_("KVM module loaded and KVM is ready"))
                return {
                    "success": True,
                    "message": _(
                        "KVM kernel module loaded - hardware acceleration now available"
                    ),
                    "module_loaded": True,
                    "initialized": True,
                }

            # Step 1: Install libvirt packages if not installed
            if not kvm_check.get("installed"):
                pkg_info = self._detect_package_manager()
                install_result = self._install_libvirt_packages(pkg_info)
                if not install_result.get("success"):
                    return install_result

            # Step 2: Enable and start libvirtd service
            if not kvm_check.get("running"):
                service_result = self._enable_libvirtd_service()
                if not service_result.get("success"):
                    return service_result

            # Step 3: Add user to libvirt/kvm groups
            groups_result = self._add_user_to_groups()
            needs_relogin = groups_result.get("needs_relogin", False)

            # Step 4: Set up default network
            network_result = self.networking.setup_default_network()
            if not network_result.get("success"):
                self.logger.warning(
                    _("Network setup warning: %s"), network_result.get("error")
                )
                # Continue anyway - VMs may still work or user can fix manually

            # Verify KVM is now working
            verify_result = self.virtualization_checks.check_kvm_support()

            if verify_result.get("installed") and verify_result.get("running"):
                self.logger.info(_("KVM/libvirt is ready for use"))
                return {
                    "success": True,
                    "message": _("KVM/libvirt has been installed and configured"),
                    "user_needs_relogin": needs_relogin,
                    "network_configured": network_result.get("success", False),
                    "initialized": verify_result.get("initialized", False),
                }

            return {
                "success": False,
                "error": _("KVM initialization completed but verification failed"),
            }

        except subprocess.TimeoutExpired:
            self.logger.error(_("KVM initialization timed out"))
            return {
                "success": False,
                "error": _("KVM initialization timed out"),
            }
        except Exception as init_error:
            self.logger.error(_("Error initializing KVM: %s"), init_error)
            return {
                "success": False,
                "error": str(init_error),
            }

    # Delegate networking methods to KvmNetworking
    async def setup_kvm_networking(self, parameters: dict) -> dict:
        """Configure KVM networking based on the specified mode."""
        return await self.networking.setup_networking(parameters)

    async def list_kvm_networks(self, parameters: dict) -> dict:
        """List all configured KVM/libvirt networks."""
        return await self.networking.list_all_networks(parameters)

    # Delegate lifecycle methods to KvmLifecycle
    async def check_kvm_ready(  # NOSONAR - async required by caller interface
        self,
    ) -> Dict[str, Any]:
        """Check if KVM is fully operational and ready to create VMs."""
        return self.lifecycle.check_ready(self.virtualization_checks)

    async def start_child_host(self, parameters: dict) -> dict:
        """Start a stopped KVM virtual machine."""
        return await self.lifecycle.start_vm(parameters)

    async def stop_child_host(self, parameters: dict) -> dict:
        """Stop a running KVM virtual machine (graceful shutdown)."""
        return await self.lifecycle.stop_vm(parameters)

    async def restart_child_host(self, parameters: dict) -> dict:
        """Restart a KVM virtual machine."""
        return await self.lifecycle.restart_vm(parameters)

    async def delete_child_host(self, parameters: dict) -> dict:
        """Delete a KVM virtual machine and its storage."""
        return await self.lifecycle.delete_vm(parameters)

    async def create_vm(self, config: KvmVmConfig) -> Dict[str, Any]:
        """
        Create a KVM virtual machine with cloud-init.

        Args:
            config: KvmVmConfig instance with VM parameters

        Returns:
            Dict with success status and VM details
        """
        return await self.creation.create_vm(config)
