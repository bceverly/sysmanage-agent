"""
Linux virtualization support check methods.

This module provides mixin methods for checking Linux-specific
virtualization technologies: LXD (containers) and KVM/QEMU.
"""

import grp
import json
import os
import platform
import pwd
import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict


class LinuxVirtualizationMixin:
    """Mixin providing Linux virtualization check methods."""

    def _is_ubuntu_22_or_newer(self) -> bool:
        """
        Check if the system is running Ubuntu 22.04 or newer.

        Returns:
            True if Ubuntu 22.04+, False otherwise
        """
        try:
            # Read /etc/os-release to get distribution info
            if not os.path.exists("/etc/os-release"):
                return False

            with open("/etc/os-release", "r", encoding="utf-8") as os_release_file:
                os_release = {}
                for line in os_release_file:
                    line = line.strip()
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os_release[key] = value.strip('"')

            # Check if it's Ubuntu
            if os_release.get("ID", "").lower() != "ubuntu":
                return False

            # Check version (VERSION_ID is like "22.04" or "24.04")
            version_id = os_release.get("VERSION_ID", "")
            if not version_id:
                return False

            try:
                major_version = float(version_id)
                return major_version >= 22.04
            except ValueError:
                return False

        except Exception as error:
            self.logger.debug("Error checking Ubuntu version: %s", error)
            return False

    def _is_user_in_lxd_group(self) -> bool:
        """
        Check if the current user is in the lxd group.

        Returns:
            True if user is in lxd group, False otherwise
        """
        try:
            # Get current user
            username = pwd.getpwuid(os.getuid()).pw_name

            # Check if lxd group exists and user is a member
            try:
                lxd_group = grp.getgrnam("lxd")
                return username in lxd_group.gr_mem
            except KeyError:
                # lxd group doesn't exist
                return False

        except Exception as error:
            self.logger.debug("Error checking lxd group membership: %s", error)
            return False

    def check_lxd_support(self) -> Dict[str, Any]:
        """
        Check LXD/LXC container support on Linux (Ubuntu 22.04+ only).

        Returns:
            Dict with LXD availability info including:
            - available: True if LXD can potentially be used (Ubuntu 22.04+)
            - installed: True if LXD snap is installed
            - initialized: True if LXD has been initialized (has storage pool)
            - user_in_group: True if current user is in lxd group
            - needs_install: True if LXD needs to be installed
            - needs_init: True if LXD needs initialization
            - snap_available: True if snap is available for installation
        """
        result = {
            "available": False,
            "installed": False,
            "initialized": False,
            "user_in_group": False,
            "needs_install": False,
            "needs_init": False,
            "snap_available": False,
        }

        try:
            if platform.system().lower() != "linux":
                return result

            # Only support Ubuntu 22.04+
            if not self._is_ubuntu_22_or_newer():
                self.logger.debug("LXD support requires Ubuntu 22.04 or newer")
                return result

            # Ubuntu 22.04+ can use LXD
            result["available"] = True

            # Check if snap is available (for installation)
            snap_path = shutil.which("snap")
            result["snap_available"] = snap_path is not None

            # Check if LXD snap is installed
            if snap_path:
                snap_result = subprocess.run(  # nosec B603 B607
                    ["snap", "list", "lxd"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                result["installed"] = snap_result.returncode == 0

            # If not installed via snap, check if lxc command exists anyway
            if not result["installed"]:
                lxc_path = shutil.which("lxc")
                if lxc_path:
                    result["installed"] = True

            if not result["installed"]:
                result["needs_install"] = True
                self.logger.info("LXD is not installed")
                return result

            # Check if user is in lxd group
            result["user_in_group"] = self._is_user_in_lxd_group()

            # Check if LXD is initialized by checking for storage pools
            try:
                storage_result = subprocess.run(  # nosec B603 B607
                    ["lxc", "storage", "list", "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if storage_result.returncode == 0:
                    try:
                        storage_pools = json.loads(storage_result.stdout)
                        result["initialized"] = len(storage_pools) > 0
                    except json.JSONDecodeError:
                        result["initialized"] = False
                else:
                    result["initialized"] = False

            except Exception as storage_error:
                self.logger.debug("Error checking LXD storage: %s", storage_error)
                result["initialized"] = False

            if not result["initialized"]:
                result["needs_init"] = True
                self.logger.info("LXD is installed but not initialized")

            self.logger.info(
                "LXD support check: installed=%s, initialized=%s, user_in_group=%s",
                result["installed"],
                result["initialized"],
                result["user_in_group"],
            )

        except Exception as error:
            self.logger.debug("Error checking LXD support: %s", error)

        return result

    def _is_user_in_kvm_group(self) -> bool:
        """
        Check if the current user is in the kvm or libvirt groups.

        Returns:
            True if user is in kvm or libvirt group, False otherwise
        """
        try:
            username = pwd.getpwuid(os.getuid()).pw_name

            # Check kvm group
            try:
                kvm_group = grp.getgrnam("kvm")
                if username in kvm_group.gr_mem:
                    return True
            except KeyError:
                pass

            # Check libvirt group
            try:
                libvirt_group = grp.getgrnam("libvirt")
                if username in libvirt_group.gr_mem:
                    return True
            except KeyError:
                pass

            # Root always has access
            if os.getuid() == 0:
                return True

            return False
        except Exception as error:
            self.logger.debug("Error checking kvm/libvirt group membership: %s", error)
            return False

    def _check_cpu_virtualization_flags(self) -> bool:
        """
        Check if CPU has virtualization extensions (Intel VMX or AMD SVM).

        Returns:
            True if vmx or svm flags found in /proc/cpuinfo
        """
        try:
            if not os.path.exists("/proc/cpuinfo"):
                return False

            with open("/proc/cpuinfo", "r", encoding="utf-8") as cpuinfo_file:
                content = cpuinfo_file.read().lower()
                # Intel VT-x or AMD-V
                return "vmx" in content or "svm" in content

        except Exception as error:
            self.logger.debug("Error checking CPU virtualization flags: %s", error)
            return False

    def _get_cpu_vendor(self) -> str:
        """
        Determine CPU vendor (Intel or AMD) for KVM module selection.

        Returns:
            "intel", "amd", or None if unknown
        """
        try:
            if not os.path.exists("/proc/cpuinfo"):
                return None

            with open("/proc/cpuinfo", "r", encoding="utf-8") as cpuinfo_file:
                content = cpuinfo_file.read().lower()
                if "genuineintel" in content or "vmx" in content:
                    return "intel"
                if "authenticamd" in content or "svm" in content:
                    return "amd"
                return None

        except Exception as error:
            self.logger.debug("Error determining CPU vendor: %s", error)
            return None

    def _check_kvm_modules_loaded(self) -> Dict[str, bool]:
        """
        Check if KVM kernel modules are loaded or available.

        Returns:
            Dict with:
            - loaded: True if kvm modules are currently loaded
            - available: True if kvm modules exist in the kernel
        """
        result = {"loaded": False, "available": False}

        try:
            # Check if modules are loaded via lsmod
            lsmod_result = subprocess.run(  # nosec B603 B607
                ["lsmod"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if lsmod_result.returncode == 0:
                lsmod_output = lsmod_result.stdout.lower()
                # Check for kvm base module and vendor-specific module
                if "kvm" in lsmod_output:
                    result["loaded"] = True
                    result["available"] = True
                    return result

            # If not loaded, check if modules are available
            # Check via modinfo which works even if module isn't loaded
            modinfo_result = subprocess.run(  # nosec B603 B607
                ["modinfo", "kvm"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if modinfo_result.returncode == 0:
                result["available"] = True

        except FileNotFoundError:
            # lsmod or modinfo not found
            self.logger.debug("lsmod or modinfo not available")
        except Exception as error:
            self.logger.debug("Error checking KVM modules: %s", error)

        return result

    def _check_libvirtd_status(self) -> Dict[str, bool]:
        """
        Check libvirtd service status using systemctl.

        Returns:
            Dict with enabled and running status
        """
        result = {"enabled": False, "running": False}

        try:
            # Check if libvirtd is enabled
            enabled_result = subprocess.run(  # nosec B603 B607
                ["systemctl", "is-enabled", "libvirtd"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            result["enabled"] = enabled_result.returncode == 0

            # Check if libvirtd is active/running
            active_result = subprocess.run(  # nosec B603 B607
                ["systemctl", "is-active", "libvirtd"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            result["running"] = (
                active_result.returncode == 0
                and active_result.stdout.strip() == "active"
            )

        except Exception as error:
            self.logger.debug("Error checking libvirtd status: %s", error)

        return result

    def _check_default_network_exists(self) -> bool:
        """
        Check if libvirt default network exists and is active.

        Returns:
            True if default network exists and is active
        """
        try:
            virsh_path = shutil.which("virsh")
            if not virsh_path:
                return False

            # Check if default network exists and is active
            result = subprocess.run(  # nosec B603 B607
                ["virsh", "net-info", "default"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return False

            # Parse output for "Active: yes"
            return "active:" in result.stdout.lower() and "yes" in result.stdout.lower()

        except Exception as error:
            self.logger.debug("Error checking default network: %s", error)
            return False

    def check_kvm_support(self) -> Dict[str, Any]:
        """
        Check KVM/QEMU support on Linux.

        Returns:
            Dict with KVM availability info including:
            - available: True if /dev/kvm exists (hardware virtualization available)
            - installed: True if libvirt/virsh is installed
            - enabled: True if libvirtd service is enabled
            - running: True if libvirtd is currently running
            - initialized: True if ready to create VMs (network configured)
            - cpu_supported: True if CPU has VMX/SVM flags
            - kernel_supported: True if /dev/kvm exists
            - user_in_group: True if user is in kvm/libvirt group
            - management: "libvirt" or "qemu" or None
            - needs_install: True if libvirt needs to be installed
            - needs_enable: True if libvirtd needs to be enabled
            - needs_init: True if network needs to be initialized
            - modules_loaded: True if kvm kernel modules are currently loaded
            - modules_available: True if kvm modules exist but aren't loaded
            - needs_modprobe: True if modules need to be loaded via modprobe
            - cpu_vendor: "intel" or "amd" based on CPU type
        """
        result = {
            "available": False,
            "installed": False,
            "enabled": False,
            "running": False,
            "initialized": False,
            "cpu_supported": False,
            "kernel_supported": False,
            "user_in_group": False,
            "management": None,
            "needs_install": False,
            "needs_enable": False,
            "needs_init": False,
            "modules_loaded": False,
            "modules_available": False,
            "needs_modprobe": False,
            "cpu_vendor": None,
        }

        try:
            if platform.system().lower() != "linux":
                return result

            # Check CPU virtualization support (vmx/svm flags)
            result["cpu_supported"] = self._check_cpu_virtualization_flags()

            # Determine CPU vendor for kvm_intel vs kvm_amd
            result["cpu_vendor"] = self._get_cpu_vendor()

            # Check if KVM kernel modules are loaded
            modules_status = self._check_kvm_modules_loaded()
            result["modules_loaded"] = modules_status["loaded"]
            result["modules_available"] = modules_status["available"]

            # Check if KVM kernel module is loaded (/dev/kvm exists)
            if os.path.exists("/dev/kvm"):
                result["kernel_supported"] = True
                result["available"] = True
            elif result["modules_available"] and result["cpu_supported"]:
                # Modules exist but not loaded - can be enabled via modprobe
                result["available"] = True
                result["needs_modprobe"] = True
                self.logger.debug(
                    "KVM modules available but not loaded - can enable via modprobe"
                )
            else:
                # /dev/kvm not found - KVM hardware not available yet
                # but we still check if libvirt is installed so user can
                # install/configure it before enabling virtualization in BIOS
                self.logger.debug(
                    "/dev/kvm not found - hardware virtualization not available, "
                    "but checking libvirt installation status"
                )

            # Check if user has access to KVM
            result["user_in_group"] = self._is_user_in_kvm_group()

            # Check if libvirt/virsh is installed
            virsh_path = shutil.which("virsh")
            qemu_path = shutil.which("qemu-system-x86_64")

            if virsh_path:
                result["installed"] = True
                result["management"] = "libvirt"

                # Check libvirtd service status
                libvirtd_status = self._check_libvirtd_status()
                result["enabled"] = libvirtd_status["enabled"]
                result["running"] = libvirtd_status["running"]

                # Check if default network is configured
                if result["running"]:
                    result["initialized"] = self._check_default_network_exists()
                    if not result["initialized"]:
                        result["needs_init"] = True

                if not result["enabled"]:
                    result["needs_enable"] = True

            elif qemu_path:
                # QEMU is installed but not libvirt - can still use direct QEMU
                result["installed"] = True
                result["management"] = "qemu"
                result["enabled"] = True  # No service to enable for direct QEMU
                result["running"] = True
                result["initialized"] = True

            else:
                # Neither libvirt nor QEMU installed
                result["needs_install"] = True

            self.logger.info(
                "KVM support check: available=%s, installed=%s, enabled=%s, "
                "running=%s, initialized=%s, management=%s, cpu=%s",
                result["available"],
                result["installed"],
                result["enabled"],
                result["running"],
                result["initialized"],
                result["management"],
                result["cpu_supported"],
            )

        except Exception as error:
            self.logger.debug("Error checking KVM support: %s", error)

        return result
