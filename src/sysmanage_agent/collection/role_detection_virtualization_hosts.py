"""
Virtualization host detection utilities for role detection.
"""

import logging
import os
import shutil
import subprocess  # nosec B404 # Required for virtualization host detection
from typing import Dict, Any, Optional

DEV_VMM_PATH = "/dev/vmm"


class VirtualizationHostDetector:
    """Handles detection of virtualization host roles (LXD, WSL, VMM, KVM, bhyve)."""

    def __init__(self, system: str, logger: logging.Logger, service_status_detector):
        self.system = system
        self.logger = logger
        self.service_status_detector = service_status_detector

    def detect_lxd_host_role(self) -> Optional[Dict[str, Any]]:
        """
        Detect if this host is a configured LXD host ready for containers.

        Returns role dict if LXD is installed AND initialized, None otherwise.
        """
        try:
            # Check if lxd command exists (snap or system)
            lxd_path = shutil.which("lxd") or "/snap/bin/lxd"
            lxc_path = shutil.which("lxc") or "/snap/bin/lxc"

            if not os.path.exists(lxd_path) and not os.path.exists(lxc_path):
                return None

            # Check if LXD is initialized by looking for lxdbr0 or running lxc info
            # lxc info will fail if LXD is not initialized
            result = subprocess.run(  # nosec B603 B607
                [lxc_path, "info"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                self.logger.debug("LXD installed but not initialized")
                return None

            # Get LXD version from snap or lxd --version
            version = "unknown"
            try:
                snap_result = subprocess.run(  # nosec B603 B607
                    ["snap", "list", "lxd"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if snap_result.returncode == 0:
                    # Parse: "lxd  5.21.4-8a3cf61  36579  5.21/stable  canonical**  -"
                    lines = snap_result.stdout.strip().split("\n")
                    if len(lines) >= 2:
                        parts = lines[1].split()
                        if len(parts) >= 2:
                            version = parts[1]
            except Exception:  # nosec B110 - version is optional, defaults to "unknown"
                pass

            # Check service status
            service_status = self.service_status_detector.get_service_status(
                "snap.lxd.daemon"
            )
            if service_status == "unknown":
                service_status = self.service_status_detector.get_service_status("lxd")

            self.logger.info(
                "Detected LXD Host role: v%s, status=%s", version, service_status
            )

            return {
                "role": "LXD Host",
                "package_name": "lxd",
                "package_version": version,
                "service_name": "snap.lxd.daemon",
                "service_status": service_status,
                "is_active": service_status == "running",
            }

        except Exception as error:
            self.logger.debug("Error detecting LXD host role: %s", error)
            return None

    def detect_wsl_host_role(self) -> Optional[Dict[str, Any]]:
        """
        Detect if this Windows host has WSL enabled and ready for instances.

        Returns role dict if WSL is enabled and functional, None otherwise.
        """
        try:
            # Check if wsl.exe exists and is functional
            result = subprocess.run(  # nosec B603 B607
                ["wsl.exe", "--status"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # --status returns 0 if WSL is properly configured
            if result.returncode != 0:
                self.logger.debug("WSL not enabled or not functional")
                return None

            # Get WSL version info
            version = "2"  # Default to WSL2
            version_result = subprocess.run(  # nosec B603 B607
                ["wsl.exe", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if version_result.returncode == 0:
                # Parse first line for version
                lines = version_result.stdout.strip().split("\n")
                if lines:
                    version = lines[0].replace("WSL version:", "").strip()
                    if not version:
                        version = "2"

            self.logger.info("Detected WSL Host role: v%s", version)

            return {
                "role": "WSL Host",
                "package_name": "wsl",
                "package_version": version,
                "service_name": None,  # WSL doesn't have a traditional service
                "service_status": "running",  # If --status works, it's running
                "is_active": True,
            }

        except FileNotFoundError:
            self.logger.debug("wsl.exe not found - WSL not installed")
            return None
        except Exception as error:
            self.logger.debug("Error detecting WSL host role: %s", error)
            return None

    def detect_vmm_host_role(self) -> Optional[Dict[str, Any]]:
        """
        Detect if this OpenBSD host has VMM/vmd enabled and ready for VMs.

        Returns role dict if VMM is available AND vmd is running, None otherwise.
        """
        try:
            # Check if vmctl command exists
            vmctl_path = shutil.which("vmctl")
            if not vmctl_path:
                return None

            # Check if /dev/vmm exists (kernel VMM support)
            if not os.path.exists(DEV_VMM_PATH):
                self.logger.debug("VMM kernel support not enabled (/dev/vmm missing)")
                return None

            # Check if vmd is running using rcctl check
            result = subprocess.run(  # nosec B603 B607
                ["rcctl", "check", "vmd"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                self.logger.debug("vmd is not running")
                return None

            # Get OpenBSD version for the package_version field
            obsd_version = "unknown"
            try:
                uname_result = subprocess.run(  # nosec B603 B607
                    ["uname", "-r"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if uname_result.returncode == 0:
                    obsd_version = uname_result.stdout.strip()
            except Exception:  # nosec B110 - version is optional
                pass

            # Get vmd version info from pkg_info if available
            vmd_version = obsd_version  # vmd version matches OpenBSD version
            vm_count = 0
            try:
                # Get count of running VMs
                vmctl_status = subprocess.run(  # nosec B603 B607
                    ["vmctl", "status"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if vmctl_status.returncode == 0:
                    # Count VMs (lines after header, excluding empty lines)
                    lines = vmctl_status.stdout.strip().split("\n")
                    if len(lines) > 1:
                        vm_count = len([ln for ln in lines[1:] if ln.strip()])
            except Exception:  # nosec B110 - VM count is optional
                pass

            self.logger.info(
                "Detected VMM Host role: OpenBSD %s, %d VMs",
                obsd_version,
                vm_count,
            )

            return {
                "role": "VMM Host",
                "package_name": "vmd",
                "package_version": vmd_version,
                "service_name": "vmd",
                "service_status": "running",
                "is_active": True,
                "vm_count": vm_count,
            }

        except Exception as error:
            self.logger.debug("Error detecting VMM host role: %s", error)
            return None

    def detect_kvm_host_role(self) -> Optional[Dict[str, Any]]:
        """
        Detect if this Linux host has KVM enabled and ready for VMs.

        Returns role dict if KVM is available AND libvirtd is running, None otherwise.
        """
        try:
            # Check if /dev/kvm exists (kernel KVM support)
            if not os.path.exists("/dev/kvm"):
                self.logger.debug("KVM kernel support not enabled (/dev/kvm missing)")
                return None

            # Check if virsh command exists (libvirt installed)
            virsh_path = shutil.which("virsh")
            if not virsh_path:
                self.logger.debug("libvirt/virsh not installed")
                return None

            # Check if libvirtd is running using systemctl
            result = subprocess.run(  # nosec B603 B607
                ["systemctl", "is-active", "libvirtd"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0 or result.stdout.strip() != "active":
                self.logger.debug("libvirtd is not running")
                return None

            # Get libvirt version
            version = "unknown"
            try:
                version_result = subprocess.run(  # nosec B603 B607
                    ["virsh", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if version_result.returncode == 0:
                    version = version_result.stdout.strip()
            except Exception:  # nosec B110 - version is optional
                pass

            # Get count of defined VMs
            vm_count = 0
            try:
                vmlist_result = subprocess.run(  # nosec B603 B607
                    ["virsh", "list", "--all", "--name"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if vmlist_result.returncode == 0:
                    # Count non-empty lines
                    vm_count = len(
                        [ln for ln in vmlist_result.stdout.strip().split("\n") if ln]
                    )
            except Exception:  # nosec B110 - VM count is optional
                pass

            self.logger.info(
                "Detected KVM Host role: libvirt v%s, %d VMs",
                version,
                vm_count,
            )

            return {
                "role": "KVM Host",
                "package_name": "libvirt",
                "package_version": version,
                "service_name": "libvirtd",
                "service_status": "running",
                "is_active": True,
                "vm_count": vm_count,
            }

        except Exception as error:
            self.logger.debug("Error detecting KVM host role: %s", error)
            return None

    def detect_bhyve_host_role(self) -> Optional[Dict[str, Any]]:
        """
        Detect if this FreeBSD host has bhyve enabled and ready for VMs.

        Returns role dict if bhyve is available AND vmm.ko is loaded, None otherwise.
        """
        try:
            # Check if bhyvectl command exists
            bhyvectl_path = shutil.which("bhyvectl")
            if not bhyvectl_path:
                return None

            # Check if vmm.ko is loaded by checking /dev/vmm directory
            if not os.path.isdir(DEV_VMM_PATH):
                self.logger.debug("bhyve vmm.ko not loaded (/dev/vmm missing)")
                return None

            # Get FreeBSD version for the package_version field
            freebsd_version = "unknown"
            try:
                uname_result = subprocess.run(  # nosec B603 B607
                    ["uname", "-r"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if uname_result.returncode == 0:
                    freebsd_version = uname_result.stdout.strip()
            except Exception:  # nosec B110 - version is optional
                pass

            # Get count of running VMs by listing /dev/vmm entries
            vm_count = 0
            try:
                if os.path.isdir(DEV_VMM_PATH):
                    vms = os.listdir(DEV_VMM_PATH)
                    vm_count = len(vms)
            except Exception:  # nosec B110 - VM count is optional
                pass

            # Check if UEFI firmware is available
            uefi_available = False
            uefi_paths = [
                "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd",
                "/usr/local/share/bhyve-firmware/BHYVE_UEFI.fd",
            ]
            for uefi_path in uefi_paths:
                if os.path.exists(uefi_path):
                    uefi_available = True
                    break

            self.logger.info(
                "Detected bhyve Host role: FreeBSD %s, %d VMs, UEFI=%s",
                freebsd_version,
                vm_count,
                uefi_available,
            )

            return {
                "role": "bhyve Host",
                "package_name": "bhyve",
                "package_version": freebsd_version,
                "service_name": None,  # bhyve doesn't have a service daemon
                "service_status": "running",  # If vmm.ko is loaded, it's ready
                "is_active": True,
                "vm_count": vm_count,
                "uefi_available": uefi_available,
            }

        except Exception as error:
            self.logger.debug("Error detecting bhyve host role: %s", error)
            return None
