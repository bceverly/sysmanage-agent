#!/usr/bin/env python3
"""
Linux Software Inventory Collection Module

Handles software inventory collection for Linux systems supporting multiple
package managers: apt/dpkg, snap, flatpak, yum, dnf, pacman, zypper, portage, apk.
"""

import logging
import subprocess  # nosec B404
from typing import List

from src.i18n import _
from src.sysmanage_agent.collection.software_inventory_base import (
    SoftwareInventoryCollectorBase,
)

logger = logging.getLogger(__name__)


class LinuxSoftwareInventoryCollector(SoftwareInventoryCollectorBase):
    """Collects software inventory from Linux package managers."""

    def __init__(self):  # pylint: disable=useless-parent-delegation
        super().__init__()

    def detect_package_managers(self) -> List[str]:
        """Detect available Linux package managers."""
        if self._package_managers is not None:
            return self._package_managers

        managers = []
        manager_executables = {
            "apt": ["apt", "apt-get", "dpkg"],
            "snap": ["snap"],
            "flatpak": ["flatpak"],
            "yum": ["yum"],
            "dnf": ["dnf"],
            "pacman": ["pacman"],
            "zypper": ["zypper"],
            "portage": ["emerge"],
            "apk": ["apk"],
        }

        for manager, executables in manager_executables.items():
            for executable in executables:
                if self._command_exists(executable):
                    managers.append(manager)
                    break

        self._package_managers = managers
        logger.debug(_("Detected package managers: %s"), ", ".join(managers))
        return managers

    def collect_packages(self):
        """Collect packages from all detected Linux package managers."""
        managers = self.detect_package_managers()

        if "apt" in managers:
            self._collect_apt_packages()
        if "snap" in managers:
            self._collect_snap_packages()
        if "flatpak" in managers:
            self._collect_flatpak_packages()
        if "yum" in managers:
            self._collect_yum_packages()
        if "dnf" in managers:
            self._collect_dnf_packages()
        if "pacman" in managers:
            self._collect_pacman_packages()
        if "zypper" in managers:
            self._collect_zypper_packages()
        if "portage" in managers:
            self._collect_portage_packages()
        if "apk" in managers:
            self._collect_apk_packages()

    def _collect_apt_packages(self):
        """Collect packages from apt/dpkg (Debian/Ubuntu)."""
        try:  # pylint: disable=too-many-nested-blocks
            logger.debug(_("Collecting apt packages"))

            # Use dpkg-query for detailed package information
            result = subprocess.run(
                [
                    "dpkg-query",
                    "-W",
                    "--showformat=${Package}\t${Version}\t${Architecture}\t${Description}\t${Installed-Size}\n",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split("\t")
                        if len(parts) >= 4:
                            package = {
                                "package_name": parts[0],
                                "version": parts[1],
                                "architecture": parts[2],
                                "description": parts[3],
                                "package_manager": "apt",
                                "source": "debian_repository",
                                "is_system_package": self._is_system_package_linux(
                                    parts[0]
                                ),
                                "is_user_installed": True,
                            }

                            # Convert size from KB to bytes if available
                            if len(parts) >= 5 and parts[4].isdigit():
                                package["size_bytes"] = int(parts[4]) * 1024

                            self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect apt packages: %s"), str(error))

    def _collect_snap_packages(self):
        """Collect packages from Snap."""
        try:
            logger.debug(_("Collecting snap packages"))

            result = subprocess.run(
                ["snap", "list", "--unicode=never"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        package = {
                            "package_name": parts[0],
                            "version": parts[1],
                            "package_manager": "snap",
                            "source": "snap_store",
                            "is_system_package": False,
                            "is_user_installed": True,
                        }

                        # Add channel info if available
                        if len(parts) >= 4:
                            package["source"] = f"snap_store/{parts[3]}"

                        self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect snap packages: %s"), str(error))

    def _collect_flatpak_packages(self):
        """Collect packages from Flatpak."""
        try:
            logger.debug(_("Collecting flatpak packages"))

            result = subprocess.run(
                [
                    "flatpak",
                    "list",
                    "--app",
                    "--columns=name,application,version,size,origin",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        package = {
                            "package_name": parts[0] if parts[0] else parts[1],
                            "bundle_id": parts[1],
                            "version": parts[2] if len(parts) > 2 else None,
                            "package_manager": "flatpak",
                            "source": "flathub",
                            "is_system_package": False,
                            "is_user_installed": True,
                        }

                        # Add size if available
                        if len(parts) > 3 and parts[3]:
                            package["size_bytes"] = self._parse_size_string(parts[3])

                        # Add origin if available
                        if len(parts) > 4 and parts[4]:
                            package["source"] = parts[4]

                        self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect flatpak packages: %s"), str(error))

    def _collect_yum_packages(self):
        """Collect packages from YUM (Red Hat/CentOS)."""
        # Implementation would use 'yum list installed' or 'rpm -qa'
        logger.debug(_("YUM package collection not implemented"))

    def _collect_dnf_packages(self):
        """Collect packages from DNF (Fedora)."""
        try:
            logger.debug(_("Collecting DNF packages"))

            result = subprocess.run(
                ["dnf", "list", "installed"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                in_packages = False

                for line in lines:
                    if line.startswith("Installed Packages"):
                        in_packages = True
                        continue

                    if in_packages and line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            package_name = parts[0].split(".")[0]  # Remove arch
                            version = parts[1]
                            repo = parts[2]

                            package = {
                                "package_name": package_name,
                                "version": version,
                                "package_manager": "dnf",
                                "source": repo,
                                "is_system_package": self._is_system_package_linux(
                                    package_name
                                ),
                                "is_user_installed": True,
                            }

                            self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect DNF packages: %s"), str(error))

    def _collect_pacman_packages(self):
        """Collect packages from Pacman (Arch Linux)."""
        try:
            logger.debug(_("Collecting Pacman packages"))

            result = subprocess.run(
                ["pacman", "-Q"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            package = {
                                "package_name": parts[0],
                                "version": parts[1],
                                "package_manager": "pacman",
                                "source": "arch_repository",
                                "is_system_package": self._is_system_package_linux(
                                    parts[0]
                                ),
                                "is_user_installed": True,
                            }

                            self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect Pacman packages: %s"), str(error))

    def _collect_zypper_packages(self):
        """Collect packages from Zypper (openSUSE)."""
        try:
            logger.debug(_("Collecting Zypper packages"))

            # Use rpm -qa for comprehensive package listing
            result = subprocess.run(
                [
                    "rpm",
                    "-qa",
                    "--queryformat",
                    "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\t%{SIZE}\n",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) < 4:
                    continue

                package = {
                    "package_name": parts[0],
                    "version": parts[1],
                    "architecture": parts[2],
                    "description": parts[3],
                    "package_manager": "zypper",
                    "source": "opensuse_repository",
                    "is_system_package": self._is_system_package_linux(parts[0]),
                    "is_user_installed": True,
                }

                # Add size if available
                if len(parts) >= 5 and parts[4].isdigit():
                    package["size_bytes"] = int(parts[4])

                self.collected_packages.append(package)

            zypper_count = len(
                [
                    p
                    for p in self.collected_packages
                    if p.get("package_manager") == "zypper"
                ]
            )
            logger.debug(_("Successfully collected %d Zypper packages"), zypper_count)

        except Exception as error:
            logger.error(_("Failed to collect Zypper packages: %s"), str(error))

    def _collect_portage_packages(self):
        """Collect packages from Portage (Gentoo)."""
        # Implementation would use 'equery list "*"'
        logger.debug(_("Portage package collection not implemented"))

    def _collect_apk_packages(self):
        """Collect packages from APK (Alpine Linux)."""
        try:
            logger.debug(_("Collecting APK packages"))

            # Use 'apk info -v' to get package names with versions
            result = subprocess.run(
                ["apk", "info", "-v"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue

                # Format is: package-name-version
                # e.g., "busybox-1.36.1-r0" -> name="busybox", version="1.36.1-r0"
                parts = line.rsplit("-", 2)
                if len(parts) < 2:
                    continue

                # Handle packages like "py3-foo-1.0-r0" correctly
                if len(parts) == 3 and parts[1][0].isdigit():
                    package_name = parts[0]
                    version = f"{parts[1]}-{parts[2]}"
                elif parts[-1][0].isdigit():
                    package_name = "-".join(parts[:-1])
                    version = parts[-1]
                else:
                    package_name = line
                    version = None

                package = {
                    "package_name": package_name,
                    "version": version,
                    "package_manager": "apk",
                    "source": "alpine_repository",
                    "is_system_package": self._is_system_package_linux(package_name),
                    "is_user_installed": True,
                }

                self.collected_packages.append(package)

            apk_count = len(
                [
                    p
                    for p in self.collected_packages
                    if p.get("package_manager") == "apk"
                ]
            )
            logger.debug(_("Successfully collected %d APK packages"), apk_count)

        except Exception as error:
            logger.error(_("Failed to collect APK packages: %s"), str(error))

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
        return any(package_name.startswith(prefix) for prefix in system_prefixes)
