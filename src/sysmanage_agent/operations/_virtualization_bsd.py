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

            # Check if vmctl is available
            vmctl_path = shutil.which("vmctl")
            if not vmctl_path:
                self.logger.debug("vmctl not found - VMM not available")
                return result

            result["available"] = True

            # Check CPU virtualization support (VMX for Intel, SVM for AMD)
            try:
                # On OpenBSD, the presence of /dev/vmm is the primary indicator
                # of CPU support since OpenBSD only creates it when VMX/SVM is available.
                # We also verify by checking if we can read the CPU vendor.
                vmm_check = subprocess.run(  # nosec B603 B607
                    ["sysctl", "hw.vendor"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if vmm_check.returncode == 0:
                    # CPU vendor detected, VMM support depends on /dev/vmm
                    result["cpu_supported"] = True
            except Exception as cpu_error:
                self.logger.debug("Error checking CPU virtualization: %s", cpu_error)

            # Check if kernel has VMM support (/dev/vmm exists)
            if os.path.exists("/dev/vmm"):
                result["kernel_supported"] = True
            else:
                self.logger.debug("/dev/vmm not found - kernel VMM support not enabled")
                result["needs_enable"] = True
                return result

            # Check if vmd is enabled using rcctl
            try:
                rcctl_result = subprocess.run(  # nosec B603 B607
                    ["rcctl", "get", "vmd", "flags"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                # If rcctl get vmd flags returns 0, vmd is enabled
                # If it returns non-zero or "NO", it's not enabled
                if rcctl_result.returncode == 0:
                    flags_output = rcctl_result.stdout.strip()
                    # "NO" means disabled, anything else means enabled
                    if flags_output.upper() != "NO":
                        result["enabled"] = True
            except subprocess.TimeoutExpired:
                self.logger.debug("Timeout checking vmd enabled status")
            except Exception as rcctl_error:
                self.logger.debug("Error checking vmd enabled status: %s", rcctl_error)

            # Check if vmd is running using rcctl check
            try:
                check_result = subprocess.run(  # nosec B603 B607
                    ["rcctl", "check", "vmd"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                # rcctl check returns 0 if service is running
                if check_result.returncode == 0:
                    result["running"] = True
                    result["initialized"] = True
            except subprocess.TimeoutExpired:
                self.logger.debug("Timeout checking vmd running status")
            except Exception as check_error:
                self.logger.debug("Error checking vmd running status: %s", check_error)

            # If not enabled and not running, it needs to be enabled
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

            # Check if bhyvectl is available
            bhyvectl_path = shutil.which("bhyvectl")
            if not bhyvectl_path:
                self.logger.debug("bhyvectl not found - bhyve not available")
                return result

            result["available"] = True

            # Check CPU virtualization support (VMX for Intel, SVM for AMD)
            try:
                # Check Intel VT-x with EPT
                vmx_result = subprocess.run(  # nosec B603 B607
                    ["sysctl", "-n", "hw.vmm.vmx.initialized"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if vmx_result.returncode == 0 and vmx_result.stdout.strip() == "1":
                    result["cpu_supported"] = True
                else:
                    # Check AMD-V with RVI
                    svm_result = subprocess.run(  # nosec B603 B607
                        ["sysctl", "-n", "hw.vmm.svm.initialized"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if svm_result.returncode == 0 and svm_result.stdout.strip() == "1":
                        result["cpu_supported"] = True
            except Exception as cpu_error:
                self.logger.debug("Error checking CPU virtualization: %s", cpu_error)

            # Check if vmm.ko kernel module is loaded
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
                    # vmm.ko not loaded, check if it can be loaded
                    # The module exists if the file is present
                    if os.path.exists("/boot/kernel/vmm.ko"):
                        result["kernel_supported"] = True
                    result["needs_enable"] = True
            except Exception as kld_error:
                self.logger.debug("Error checking vmm.ko status: %s", kld_error)
                result["needs_enable"] = True

            # Check if /dev/vmm directory exists (created when vmm.ko is loaded)
            if os.path.isdir("/dev/vmm"):
                result["enabled"] = True
                result["running"] = True

            # Check if UEFI firmware is available (required for non-FreeBSD guests)
            uefi_firmware_paths = [
                "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd",
                "/usr/local/share/bhyve-firmware/BHYVE_UEFI.fd",
            ]
            for uefi_path in uefi_firmware_paths:
                if os.path.exists(uefi_path):
                    result["uefi_available"] = True
                    break

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
