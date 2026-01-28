"""
BSD virtualization support check methods.

This module provides mixin methods for checking BSD-specific
virtualization technologies: VMM/vmd (OpenBSD) and bhyve (FreeBSD).
"""

import os
import platform
import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict


class BsdVirtualizationMixin:
    """Mixin providing BSD virtualization check methods."""

    def _check_vmm_cpu_support(self) -> bool:
        """Check CPU virtualization support for VMM on OpenBSD.

        Returns:
            True if CPU vendor can be detected via sysctl
        """
        try:
            vmm_check = subprocess.run(  # nosec B603 B607
                ["sysctl", "hw.vendor"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return vmm_check.returncode == 0
        except Exception as cpu_error:
            self.logger.debug("Error checking CPU virtualization: %s", cpu_error)
            return False

    def _check_vmd_enabled(self) -> bool:
        """Check if vmd is enabled using rcctl on OpenBSD.

        Returns:
            True if vmd is enabled in rc.conf
        """
        try:
            rcctl_result = subprocess.run(  # nosec B603 B607
                ["rcctl", "get", "vmd", "flags"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if rcctl_result.returncode == 0:
                flags_output = rcctl_result.stdout.strip()
                return flags_output.upper() != "NO"
        except subprocess.TimeoutExpired:
            self.logger.debug("Timeout checking vmd enabled status")
        except Exception as rcctl_error:
            self.logger.debug("Error checking vmd enabled status: %s", rcctl_error)
        return False

    def _check_vmd_running(self, result: Dict[str, Any]) -> None:
        """Check if vmd is running using rcctl on OpenBSD.

        Args:
            result: Dict to update with running and initialized status
        """
        try:
            check_result = subprocess.run(  # nosec B603 B607
                ["rcctl", "check", "vmd"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if check_result.returncode == 0:
                result["running"] = True
                result["initialized"] = True
        except subprocess.TimeoutExpired:
            self.logger.debug("Timeout checking vmd running status")
        except Exception as check_error:
            self.logger.debug("Error checking vmd running status: %s", check_error)

    def check_vmm_support(self) -> Dict[str, Any]:
        """
        Check VMM/vmd support on OpenBSD.

        Returns:
            Dict with VMM availability info including:
            - available: True if VMM can potentially be used (OpenBSD with vmctl)
            - enabled: True if vmd is enabled in rc.conf
            - running: True if vmd daemon is currently running
            - initialized: True if vmd is ready to create VMs
            - kernel_supported: True if /dev/vmm device exists
            - needs_enable: True if vmd needs to be enabled
        """
        result = {
            "available": False,
            "enabled": False,
            "running": False,
            "initialized": False,
            "kernel_supported": False,
            "cpu_supported": False,
            "needs_enable": False,
        }

        try:
            if platform.system().lower() != "openbsd":
                return result

            vmctl_path = shutil.which("vmctl")
            if not vmctl_path:
                self.logger.debug("vmctl not found - VMM not available")
                return result

            result["available"] = True
            result["cpu_supported"] = self._check_vmm_cpu_support()

            if os.path.exists("/dev/vmm"):
                result["kernel_supported"] = True
            else:
                self.logger.debug("/dev/vmm not found - kernel VMM support not enabled")
                result["needs_enable"] = True
                return result

            result["enabled"] = self._check_vmd_enabled()
            self._check_vmd_running(result)

            if not result["enabled"] and not result["running"]:
                result["needs_enable"] = True

            self.logger.info(
                "VMM support check: available=%s, enabled=%s, running=%s, "
                "kernel_supported=%s, cpu_supported=%s",
                result["available"],
                result["enabled"],
                result["running"],
                result["kernel_supported"],
                result["cpu_supported"],
            )

        except Exception as error:
            self.logger.debug("Error checking VMM support: %s", error)

        return result

    def _check_bhyve_cpu_support(self) -> bool:
        """Check CPU virtualization support for bhyve on FreeBSD.

        Returns:
            True if Intel VT-x (VMX) or AMD-V (SVM) is initialized
        """
        try:
            vmx_result = subprocess.run(  # nosec B603 B607
                ["sysctl", "-n", "hw.vmm.vmx.initialized"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if vmx_result.returncode == 0 and vmx_result.stdout.strip() == "1":
                return True

            svm_result = subprocess.run(  # nosec B603 B607
                ["sysctl", "-n", "hw.vmm.svm.initialized"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return svm_result.returncode == 0 and svm_result.stdout.strip() == "1"
        except Exception as cpu_error:
            self.logger.debug("Error checking CPU virtualization: %s", cpu_error)
            return False

    def _check_vmm_kernel_module(self, result: Dict[str, Any]) -> None:
        """Check if vmm.ko kernel module is loaded on FreeBSD.

        Args:
            result: Dict to update with kernel module status
        """
        try:
            kldstat_result = subprocess.run(  # nosec B603 B607
                ["kldstat", "-q", "-m", "vmm"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if kldstat_result.returncode == 0:
                result["enabled"] = True
                result["kernel_supported"] = True
                result["running"] = True
                result["initialized"] = True
            else:
                if os.path.exists("/boot/kernel/vmm.ko"):
                    result["kernel_supported"] = True
                result["needs_enable"] = True
        except Exception as kld_error:
            self.logger.debug("Error checking vmm.ko status: %s", kld_error)
            result["needs_enable"] = True

    def check_bhyve_support(self) -> Dict[str, Any]:
        """
        Check bhyve support on FreeBSD.

        Returns:
            Dict with bhyve availability info including:
            - available: True if bhyve can potentially be used (FreeBSD with bhyvectl)
            - enabled: True if vmm.ko is loaded
            - running: True if bhyve is ready to create VMs
            - initialized: True if bhyve is fully configured
            - kernel_supported: True if vmm.ko can be loaded
            - cpu_supported: True if CPU has VT-x/AMD-V with EPT/RVI
            - uefi_available: True if UEFI firmware is installed
            - needs_enable: True if vmm.ko needs to be loaded
        """
        result = {
            "available": False,
            "enabled": False,
            "running": False,
            "initialized": False,
            "kernel_supported": False,
            "cpu_supported": False,
            "uefi_available": False,
            "needs_enable": False,
        }

        try:
            if platform.system().lower() != "freebsd":
                return result

            bhyvectl_path = shutil.which("bhyvectl")
            if not bhyvectl_path:
                self.logger.debug("bhyvectl not found - bhyve not available")
                return result

            result["available"] = True
            result["cpu_supported"] = self._check_bhyve_cpu_support()
            self._check_vmm_kernel_module(result)

            # Check if /dev/vmm directory exists (created when vmm.ko is loaded)
            if os.path.isdir("/dev/vmm"):
                result["enabled"] = True
                result["running"] = True

            # Check if UEFI firmware is available (required for non-FreeBSD guests)
            uefi_firmware_paths = [
                "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd",
                "/usr/local/share/bhyve-firmware/BHYVE_UEFI.fd",
            ]
            result["uefi_available"] = any(
                os.path.exists(p) for p in uefi_firmware_paths
            )

            self.logger.info(
                "bhyve support check: available=%s, enabled=%s, running=%s, "
                "kernel_supported=%s, cpu_supported=%s, uefi_available=%s",
                result["available"],
                result["enabled"],
                result["running"],
                result["kernel_supported"],
                result["cpu_supported"],
                result["uefi_available"],
            )

        except Exception as error:
            self.logger.debug("Error checking bhyve support: %s", error)

        return result
