#!/usr/bin/env python3
"""
Linux System Update Detection Helper Module

This module contains methods for detecting system-level updates and release upgrades
on Linux distributions.
"""

import logging
import re
import subprocess  # nosec B404

from src.i18n import _

logger = logging.getLogger(__name__)


class LinuxSystemUpdateDetector:
    """Helper class for detecting Linux system updates and release upgrades."""

    @staticmethod
    def _is_apt_security_update(package_name: str) -> bool:
        """Check if an apt package update is security-related."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["apt-cache", "policy", package_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return "security" in result.stdout.lower()
        except (subprocess.SubprocessError, OSError):
            pass
        return False

    @staticmethod
    def detect_debian_system_updates():
        """Detect Debian/Ubuntu system updates (kernel, systemd, etc.)."""
        updates = []
        try:
            logger.debug(_("Detecting Debian system updates"))

            result = subprocess.run(  # nosec B603, B607
                ["apt", "list", "--upgradable"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                system_packages = [
                    "linux-image",
                    "linux-headers",
                    "systemd",
                    "libc6",
                    "base-files",
                ]

                for line in result.stdout.strip().split("\n"):
                    if any(pkg in line for pkg in system_packages):
                        parts = line.split()
                        if len(parts) >= 2:
                            package_name = parts[0].split("/")[0]
                            available_version = parts[1]

                            # Check if it's a security update
                            is_security = (
                                LinuxSystemUpdateDetector._is_apt_security_update(
                                    package_name
                                )
                            )

                            update = {
                                "package_name": package_name,
                                "available_version": available_version,
                                "package_manager": "apt",
                                "is_system_update": True,
                                "is_security_update": is_security,
                            }
                            updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Debian system updates: %s"), str(error))

        return updates

    @staticmethod
    def detect_redhat_system_updates():
        """Detect Red Hat/Fedora system updates."""
        updates = []
        try:
            logger.debug(_("Detecting Red Hat system updates"))

            result = subprocess.run(  # nosec B603, B607
                ["dnf", "check-update", "--quiet"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.stdout.strip():
                system_packages = ["kernel", "systemd", "glibc", "basesystem"]

                for line in result.stdout.strip().split("\n"):
                    if any(pkg in line for pkg in system_packages):
                        parts = line.split()
                        if len(parts) >= 3:
                            update = {
                                "package_name": parts[0].split(".")[0],
                                "available_version": parts[1],
                                "package_manager": "dnf",
                                "is_system_update": True,
                            }
                            updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Red Hat system updates: %s"), str(error))

        return updates

    @staticmethod
    def detect_arch_system_updates():
        """Detect Arch Linux system updates."""
        updates = []
        try:
            logger.debug(_("Detecting Arch system updates"))

            result = subprocess.run(  # nosec B603, B607
                ["pacman", "-Qu"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                system_packages = ["linux", "systemd", "glibc", "base"]

                for line in result.stdout.strip().split("\n"):
                    if any(pkg in line for pkg in system_packages):
                        parts = line.split()
                        if len(parts) >= 4:
                            update = {
                                "package_name": parts[0],
                                "current_version": parts[1],
                                "available_version": parts[3],
                                "package_manager": "pacman",
                                "is_system_update": True,
                            }
                            updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Arch system updates: %s"), str(error))

        return updates

    @staticmethod
    def detect_suse_system_updates():
        """Detect SUSE system updates."""
        updates = []
        try:
            logger.debug(_("Detecting SUSE system updates"))

            result = subprocess.run(  # nosec B603, B607
                ["zypper", "list-updates"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                system_packages = ["kernel-default", "systemd", "glibc"]

                for line in result.stdout.strip().split("\n"):
                    if any(pkg in line for pkg in system_packages):
                        parts = line.split("|")
                        if len(parts) >= 5:
                            update = {
                                "package_name": parts[2].strip(),
                                "current_version": parts[3].strip(),
                                "available_version": parts[4].strip(),
                                "package_manager": "zypper",
                                "is_system_update": True,
                            }
                            updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect SUSE system updates: %s"), str(error))

        return updates

    @staticmethod
    def detect_ubuntu_release_upgrades():
        """Detect available Ubuntu release upgrades."""
        updates = []
        try:
            logger.debug(_("Detecting Ubuntu release upgrades"))

            result = subprocess.run(  # nosec B603, B607
                ["do-release-upgrade", "-c"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if "New release" in result.stdout:
                # Extract new version from output like "New release '25.10' available"
                version_match = re.search(
                    r"['\"](\d+\.\d+)['\"]", result.stdout
                )  # NOSONAR - regex on trusted system output
                if version_match:
                    new_version = version_match.group(1)

                    # Get current version
                    try:
                        current_result = subprocess.run(  # nosec B603, B607
                            ["lsb_release", "-rs"],
                            capture_output=True,
                            text=True,
                            timeout=10,
                            check=False,
                        )
                        current_version = (
                            current_result.stdout.strip()
                            if current_result.returncode == 0
                            else "Unknown"
                        )
                    except Exception:
                        current_version = "Unknown"

                    update = {
                        "package_name": "Ubuntu Release Upgrade",
                        "current_version": current_version,
                        "available_version": new_version,
                        "package_manager": "ubuntu-release",
                        "is_system_update": True,
                        "is_release_upgrade": True,
                        "requires_reboot": True,
                    }
                    updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Ubuntu release upgrades: %s"), str(error))

        return updates

    @staticmethod
    def detect_fedora_version_upgrades():
        """Detect available Fedora version upgrades."""
        updates = []
        try:
            logger.debug(_("Detecting Fedora version upgrades"))

            result = subprocess.run(  # nosec B603, B607
                ["dnf", "system-upgrade", "list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if "available" in result.stdout.lower():
                version_match = re.search(r"Fedora (\d+)", result.stdout)
                if version_match:
                    new_version = version_match.group(1)
                    update = {
                        "package_name": "Fedora Release Upgrade",
                        "current_version": "Current",
                        "available_version": f"Fedora {new_version}",
                        "package_manager": "fedora-release",
                        "is_system_update": True,
                        "is_release_upgrade": True,
                    }
                    updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Fedora version upgrades: %s"), str(error))

        return updates

    @staticmethod
    def detect_opensuse_version_upgrades():
        """Detect available openSUSE version upgrades."""
        updates = []
        try:
            logger.debug(_("Detecting openSUSE version upgrades"))

            result = subprocess.run(  # nosec B603, B607
                ["zypper", "repos"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Check if there's a newer release repository available
            if "update" in result.stdout.lower() or "upgrade" in result.stdout.lower():
                version_match = re.search(r"(\d+\.\d+)", result.stdout)
                if version_match:
                    new_version = version_match.group(1)
                    update = {
                        "package_name": "openSUSE Release Upgrade",
                        "current_version": "Current",
                        "available_version": f"openSUSE {new_version}",
                        "package_manager": "opensuse-release",
                        "is_system_update": True,
                        "is_release_upgrade": True,
                    }
                    updates.append(update)

        except Exception as error:
            logger.error(
                _("Failed to detect openSUSE version upgrades: %s"), str(error)
            )

        return updates
