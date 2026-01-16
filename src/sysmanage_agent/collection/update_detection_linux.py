#!/usr/bin/env python3
"""
Linux Update Detection Module

This module coordinates Linux update detection across package managers and system updates.
Implementation details are delegated to specialized helper modules.
"""

import logging
import subprocess  # nosec B404
from typing import Any, Dict, List, Optional

from src.i18n import _

from .linux_system_update_detectors import LinuxSystemUpdateDetector
from .linux_update_applicators import LinuxUpdateApplicator
from .linux_update_detectors import LinuxUpdateDetector as LinuxPkgDetector
from .update_detection_base import UpdateDetectorBase

logger = logging.getLogger(__name__)


class LinuxUpdateDetector(UpdateDetectorBase):
    """Linux-specific update detection with delegation to specialized helpers."""

    def __init__(self):
        super().__init__()
        # Initialize helper classes
        self.pkg_detector = LinuxPkgDetector(self._is_system_package_linux)
        self.sys_detector = LinuxSystemUpdateDetector()
        self.applicator = LinuxUpdateApplicator()

    # ========== Package Manager Update Detection (Delegated) ==========

    def _detect_apt_updates(self):
        """Detect updates from apt/dpkg (Debian/Ubuntu)."""
        updates = self.pkg_detector.detect_apt_updates()
        # Enhance with APT-specific metadata
        for update in updates:
            update["is_security_update"] = self._is_apt_security_update(
                update["package_name"]
            )
            update["update_size"] = self._get_apt_update_size(update["package_name"])
        self.available_updates.extend(updates)

    def _detect_snap_updates(self):
        """Detect updates from Snap."""
        self.available_updates.extend(self.pkg_detector.detect_snap_updates())

    def _detect_flatpak_updates(self):
        """Detect updates from Flatpak."""
        self.available_updates.extend(self.pkg_detector.detect_flatpak_updates())

    def _detect_dnf_updates(self):
        """Detect updates from DNF."""
        updates = self.pkg_detector.detect_dnf_updates()
        # Enhance with DNF-specific metadata
        for update in updates:
            update["is_security_update"] = self._is_dnf_security_update(
                update["package_name"]
            )
        self.available_updates.extend(updates)

    def _detect_zypper_updates(self):
        """Detect updates from Zypper (openSUSE)."""
        self.available_updates.extend(self.pkg_detector.detect_zypper_updates())

    def _detect_pacman_updates(self):
        """Detect updates from Pacman (Arch Linux)."""
        self.available_updates.extend(self.pkg_detector.detect_pacman_updates())

    def _detect_fwupd_updates(self):
        """Detect firmware updates from fwupd."""
        self.available_updates.extend(self.pkg_detector.detect_fwupd_updates())

    def _check_fwupd_daemon(self) -> bool:
        """Check if fwupd daemon is running and accessible."""
        return self.pkg_detector.check_fwupd_daemon()

    # ========== YUM Detection (Not Delegated - Simple Wrapper) ==========

    def _detect_yum_updates(self):
        """Detect updates from YUM (older Red Hat systems)."""
        # YUM uses same format as DNF
        self._detect_dnf_updates()

    # ========== APT-Specific Helper Methods ==========

    def _is_apt_security_update(self, package_name: str) -> bool:
        """Check if an APT package is a security update."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["apt-cache", "policy", package_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return (
                    "-security" in result.stdout or "security" in result.stdout.lower()
                )

            return False
        except Exception:
            return False

    def _get_apt_update_size(self, package_name: str) -> Optional[int]:
        """Get the download size for an APT package update."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["apt-cache", "show", package_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("Size:"):
                        return int(line.split(":")[1].strip())

            return None
        except Exception:
            return None

    # ========== DNF-Specific Helper Methods ==========

    def _is_dnf_security_update(self, package_name: str) -> bool:
        """Check if a DNF package is a security update."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["dnf", "updateinfo", "list", package_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return "security" in result.stdout.lower()

            return False
        except Exception:
            return False

    # ========== System Package Detection ==========

    def _is_system_package_linux(self, package_name: str) -> bool:
        """Determine if a Linux package is a system package."""
        system_prefixes = [
            "lib",
            "python3",
            "linux-",
            "systemd",
            "base-",
            "core",
            "essential",
            "kernel",
            "firmware",
            "driver",
        ]

        if "firmware" in package_name.lower():
            return True

        return any(package_name.startswith(prefix) for prefix in system_prefixes)

    # ========== System Update Detection (Delegated) ==========

    def _detect_debian_system_updates(self):
        """Detect Debian/Ubuntu system updates."""
        self.available_updates.extend(self.sys_detector.detect_debian_system_updates())

    def _detect_redhat_system_updates(self):
        """Detect Red Hat/Fedora system updates."""
        self.available_updates.extend(self.sys_detector.detect_redhat_system_updates())

    def _detect_arch_system_updates(self):
        """Detect Arch Linux system updates."""
        self.available_updates.extend(self.sys_detector.detect_arch_system_updates())

    def _detect_suse_system_updates(self):
        """Detect SUSE system updates."""
        self.available_updates.extend(self.sys_detector.detect_suse_system_updates())

    def _detect_ubuntu_release_upgrades(self):
        """Detect available Ubuntu release upgrades."""
        self.available_updates.extend(
            self.sys_detector.detect_ubuntu_release_upgrades()
        )

    def _detect_fedora_version_upgrades(self):
        """Detect available Fedora version upgrades."""
        self.available_updates.extend(
            self.sys_detector.detect_fedora_version_upgrades()
        )

    def _detect_opensuse_version_upgrades(self):
        """Detect available openSUSE version upgrades."""
        self.available_updates.extend(
            self.sys_detector.detect_opensuse_version_upgrades()
        )

    def _detect_linux_system_updates(self):
        """Detect Linux distribution-specific system updates."""
        try:
            # Detect distribution
            distro = None
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as file_handle:
                    for line in file_handle:
                        if line.startswith("ID="):
                            distro = line.split("=")[1].strip().strip('"').lower()
                            break
            except Exception:  # nosec B110
                pass

            # Call appropriate system update detection
            if distro in ["ubuntu", "debian", "linuxmint"]:
                self._detect_debian_system_updates()
            elif distro in ["fedora", "rhel", "centos", "rocky", "almalinux", "ol"]:
                self._detect_redhat_system_updates()
            elif distro == "arch":
                self._detect_arch_system_updates()
            elif distro in ["opensuse", "opensuse-leap", "opensuse-tumbleweed"]:
                self._detect_suse_system_updates()

        except Exception as error:
            logger.error(_("Failed to detect Linux system updates: %s"), str(error))

    def _detect_linux_version_upgrades(self):
        """Detect available Linux distribution version upgrades."""
        try:
            # Detect distribution
            distro = None
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as file_handle:
                    for line in file_handle:
                        if line.startswith("ID="):
                            distro = line.split("=")[1].strip().strip('"').lower()
                            break
            except Exception:  # nosec B110
                pass

            # Call appropriate version upgrade detection
            if distro == "ubuntu":
                self._detect_ubuntu_release_upgrades()
            elif distro == "fedora":
                self._detect_fedora_version_upgrades()
            elif distro in ["opensuse", "opensuse-leap", "opensuse-tumbleweed"]:
                self._detect_opensuse_version_upgrades()

        except Exception as error:
            logger.error(_("Failed to detect Linux version upgrades: %s"), str(error))

    # ========== Update Application (Delegated) ==========

    def _apply_apt_updates(self, packages: List[Dict], results: Dict):
        """Apply APT updates."""
        self.applicator.apply_apt_updates(packages, results)

    def _apply_snap_updates(self, packages: List[Dict], results: Dict):
        """Apply Snap updates."""
        self.applicator.apply_snap_updates(packages, results)

    def _apply_flatpak_updates(self, packages: List[Dict], results: Dict):
        """Apply Flatpak updates."""
        self.applicator.apply_flatpak_updates(packages, results)

    def _apply_dnf_updates(self, packages: List[Dict], results: Dict):
        """Apply DNF/YUM updates."""
        self.applicator.apply_dnf_updates(packages, results)

    def _apply_fwupd_updates(self, packages: List[Dict], results: Dict):
        """Apply firmware updates via fwupd."""
        self.applicator.apply_fwupd_updates(packages, results)

    def _apply_ubuntu_release_updates(self, packages: List[Dict], results: Dict):
        """Apply Ubuntu release upgrades."""
        self.applicator.apply_ubuntu_release_updates(packages, results)

    def _apply_fedora_release_updates(self, packages: List[Dict], results: Dict):
        """Apply Fedora release upgrades."""
        self.applicator.apply_fedora_release_updates(packages, results)

    def _apply_opensuse_release_updates(self, packages: List[Dict], results: Dict):
        """Apply openSUSE release upgrades."""
        self.applicator.apply_opensuse_release_updates(packages, results)

    # ========== Package Installation Methods ==========

    def _install_with_apt(self, package_name: str) -> Dict[str, Any]:
        """Install package using apt package manager."""
        try:
            subprocess.run(  # nosec B603, B607
                ["sudo", "apt", "update"], capture_output=True, check=True, timeout=120
            )

            result = subprocess.run(  # nosec B603, B607
                ["sudo", "apt", "install", "-y", package_name],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            version_result = subprocess.run(  # nosec B603, B607
                ["dpkg", "-s", package_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            version = "unknown"
            if version_result.returncode == 0:
                for line in version_result.stdout.split("\n"):
                    if line.startswith("Version:"):
                        version = line.split(":", 1)[1].strip()
                        break

            return {"success": True, "version": version, "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Installation of {package_name} timed out",
            }

    def _install_with_yum(self, package_name: str) -> Dict[str, Any]:
        """Install package using yum package manager."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["sudo", "yum", "install", "-y", package_name],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

    def _install_with_dnf(self, package_name: str) -> Dict[str, Any]:
        """Install package using dnf package manager."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["sudo", "dnf", "install", "-y", package_name],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

    def _install_with_pacman(self, package_name: str) -> Dict[str, Any]:
        """Install package using pacman package manager."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["sudo", "pacman", "-S", "--noconfirm", package_name],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

    def _install_with_zypper(self, package_name: str) -> Dict[str, Any]:
        """Install package using zypper package manager."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["sudo", "zypper", "install", "-y", package_name],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

    # ========== Update Orchestration ==========

    def detect_updates(self):
        """Detect all updates from Linux package managers and system updates."""
        # First detect OS-level system updates
        self._detect_linux_system_updates()

        # Detect OS version upgrades
        self._detect_linux_version_upgrades()

        # Then detect package manager updates
        managers = self._detect_package_managers()

        if "apt" in managers:
            self._detect_apt_updates()
        if "snap" in managers:
            self._detect_snap_updates()
        if "flatpak" in managers:
            self._detect_flatpak_updates()
        if "dnf" in managers:
            self._detect_dnf_updates()
        elif "yum" in managers:
            self._detect_yum_updates()
        if "pacman" in managers:
            self._detect_pacman_updates()
        if "zypper" in managers:
            self._detect_zypper_updates()
        if "fwupd" in managers:
            self._detect_fwupd_updates()
