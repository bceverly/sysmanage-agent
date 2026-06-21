"""
Virtualization-host role detection (post-cutover home).

Drop-in replacement for ``role_detection_virtualization_hosts``.  Same
public class name (``VirtualizationHostDetector``) and identical method
signatures so call sites can migrate by swapping a single import:

    # before (legacy):
    from .role_detection_virtualization_hosts import VirtualizationHostDetector

    # after (this module):
    from .virtualization_role_detector import VirtualizationHostDetector

The legacy module remains in place during the cutover; this module is
the destination so deletion of the legacy file doesn't lose the
periodic role-reporting flow.

Each ``detect_*_host_role`` method returns a role dict (with ``role``,
``package_name``, ``package_version``, ``service_name``,
``service_status``, ``is_active``, optional ``vm_count`` and
``uefi_available``) when the parent host is a configured + running
host of that hypervisor; returns None otherwise.
"""

import logging
import os
import shutil
import subprocess  # nosec B404 # required for hypervisor capability probes
from typing import Any, Dict, Optional

from src.i18n import _

DEV_VMM_PATH = "/dev/vmm"


class VirtualizationHostDetector:
    """Detect parent-host roles: LXD, WSL, VMM, KVM, bhyve.

    Mirrors the public surface of the legacy detector verbatim — the
    only intentional difference is the module path.  Behavior is
    identical so unit tests written against the legacy class also pass
    against this one (after the import swap).
    """

    def __init__(self, system: str, logger: logging.Logger, service_status_detector):
        self.system = system
        self.logger = logger
        self.service_status_detector = service_status_detector

    # ------------------------------------------------------------------
    # LXD
    # ------------------------------------------------------------------

    def detect_lxd_host_role(self) -> Optional[Dict[str, Any]]:
        """Detect a configured + initialized LXD host.

        Returns the role dict if ``lxc info`` succeeds (LXD initialized);
        returns None if LXD is missing or merely installed-but-not-init'd.
        """
        try:
            lxd_path = shutil.which("lxd") or "/snap/bin/lxd"
            lxc_path = shutil.which("lxc") or "/snap/bin/lxc"
            if not os.path.exists(lxd_path) and not os.path.exists(lxc_path):
                return None

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
                    lines = snap_result.stdout.strip().split("\n")
                    if len(lines) >= 2:
                        parts = lines[1].split()
                        if len(parts) >= 2:
                            version = parts[1]
            except Exception:  # nosec B110 # version is optional
                pass

            service_status = self.service_status_detector.get_service_status(
                "snap.lxd.daemon"
            )
            if service_status == "unknown":
                service_status = self.service_status_detector.get_service_status("lxd")

            self.logger.info(
                _("Detected LXD Host role: v%s, status=%s"), version, service_status
            )
            return {
                "role": "LXD Host",
                "package_name": "lxd",
                "package_version": version,
                "service_name": "snap.lxd.daemon",
                "service_status": service_status,
                "is_active": service_status == "running",
            }
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug("Error detecting LXD host role: %s", exc)
            return None

    # ------------------------------------------------------------------
    # WSL
    # ------------------------------------------------------------------

    def detect_wsl_host_role(self) -> Optional[Dict[str, Any]]:
        """Detect a Windows host with WSL enabled and functional."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["wsl.exe", "--status"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                self.logger.debug("WSL not enabled or not functional")
                return None

            version = "2"
            version_result = subprocess.run(  # nosec B603 B607
                ["wsl.exe", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if version_result.returncode == 0:
                lines = version_result.stdout.strip().split("\n")
                if lines:
                    version = lines[0].replace("WSL version:", "").strip()
                    if not version:
                        version = "2"

            self.logger.info(_("Detected WSL Host role: v%s"), version)
            return {
                "role": "WSL Host",
                "package_name": "wsl",
                "package_version": version,
                "service_name": None,
                "service_status": "running",
                "is_active": True,
            }
        except FileNotFoundError:
            self.logger.debug("wsl.exe not found - WSL not installed")
            return None
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug("Error detecting WSL host role: %s", exc)
            return None

    # ------------------------------------------------------------------
    # VMM (OpenBSD vmd)
    # ------------------------------------------------------------------

    def detect_vmm_host_role(self) -> Optional[Dict[str, Any]]:
        """Detect an OpenBSD host with vmd running."""
        try:
            vmctl_path = shutil.which("vmctl")
            if not vmctl_path:
                return None
            if not os.path.exists(DEV_VMM_PATH):
                self.logger.debug("VMM kernel support not enabled (/dev/vmm missing)")
                return None
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
            except Exception:  # nosec B110
                pass

            vm_count = 0
            try:
                vmctl_status = subprocess.run(  # nosec B603 B607
                    ["vmctl", "status"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if vmctl_status.returncode == 0:
                    lines = vmctl_status.stdout.strip().split("\n")
                    if len(lines) > 1:
                        vm_count = len([ln for ln in lines[1:] if ln.strip()])
            except Exception:  # nosec B110
                pass

            self.logger.info(
                _("Detected VMM Host role: OpenBSD %s, %d VMs"), obsd_version, vm_count
            )
            return {
                "role": "VMM Host",
                "package_name": "vmd",
                "package_version": obsd_version,
                "service_name": "vmd",
                "service_status": "running",
                "is_active": True,
                "vm_count": vm_count,
            }
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug("Error detecting VMM host role: %s", exc)
            return None

    # ------------------------------------------------------------------
    # KVM (Linux libvirt)
    # ------------------------------------------------------------------

    def detect_kvm_host_role(self) -> Optional[Dict[str, Any]]:
        """Detect a Linux host with libvirtd active and /dev/kvm present."""
        try:
            if not os.path.exists("/dev/kvm"):
                self.logger.debug("KVM kernel support not enabled (/dev/kvm missing)")
                return None
            virsh_path = shutil.which("virsh")
            if not virsh_path:
                self.logger.debug("libvirt/virsh not installed")
                return None
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
            except Exception:  # nosec B110
                pass

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
                    vm_count = len(
                        [ln for ln in vmlist_result.stdout.strip().split("\n") if ln]
                    )
            except Exception:  # nosec B110
                pass

            self.logger.info(
                _("Detected KVM Host role: libvirt v%s, %d VMs"), version, vm_count
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
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug("Error detecting KVM host role: %s", exc)
            return None

    # ------------------------------------------------------------------
    # bhyve (FreeBSD)
    # ------------------------------------------------------------------

    def detect_bhyve_host_role(self) -> Optional[Dict[str, Any]]:
        """Detect a FreeBSD host with bhyve vmm.ko loaded."""
        try:
            bhyvectl_path = shutil.which("bhyvectl")
            if not bhyvectl_path:
                return None
            if not os.path.isdir(DEV_VMM_PATH):
                self.logger.debug("bhyve vmm.ko not loaded (/dev/vmm missing)")
                return None

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
            except Exception:  # nosec B110
                pass

            vm_count = 0
            try:
                if os.path.isdir(DEV_VMM_PATH):
                    vms = os.listdir(DEV_VMM_PATH)
                    vm_count = len(vms)
            except Exception:  # nosec B110
                pass

            uefi_available = False
            for uefi_path in (
                "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd",
                "/usr/local/share/bhyve-firmware/BHYVE_UEFI.fd",
            ):
                if os.path.exists(uefi_path):
                    uefi_available = True
                    break

            self.logger.info(
                _("Detected bhyve Host role: FreeBSD %s, %d VMs, UEFI=%s"),
                freebsd_version,
                vm_count,
                uefi_available,
            )
            return {
                "role": "bhyve Host",
                "package_name": "bhyve",
                "package_version": freebsd_version,
                "service_name": None,
                "service_status": "running",
                "is_active": True,
                "vm_count": vm_count,
                "uefi_available": uefi_available,
            }
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug("Error detecting bhyve host role: %s", exc)
            return None
