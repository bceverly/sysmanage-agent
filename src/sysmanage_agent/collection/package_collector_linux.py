"""
Linux package collection module for SysManage Agent.

This module handles the collection of available packages from Linux package managers.
"""

import logging
import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _
from src.sysmanage_agent.collection.package_collector_base import BasePackageCollector

logger = logging.getLogger(__name__)


class LinuxPackageCollector(BasePackageCollector):
    """Collects available packages from Linux package managers."""

    def collect_packages(self) -> int:
        """Collect packages from Linux package managers."""
        total_collected = 0

        # Try different package managers
        managers = [
            ("apt", self._collect_apt_packages),
            ("yum", self._collect_yum_packages),
            ("dnf", self._collect_dnf_packages),
            ("zypper", self._collect_zypper_packages),
            ("pacman", self._collect_pacman_packages),
            ("snap", self._collect_snap_packages),
            ("flatpak", self._collect_flatpak_packages),
        ]

        for manager_name, collector_func in managers:
            if self._is_package_manager_available(manager_name):
                try:
                    count = collector_func()
                    total_collected += count
                    logger.info(_("Collected %d packages from %s"), count, manager_name)
                except Exception as error:
                    logger.error(
                        _("Failed to collect packages from %s: %s"), manager_name, error
                    )

        return total_collected

    def _collect_apt_packages(self) -> int:
        """Collect packages from APT (Ubuntu/Debian)."""
        try:
            # Update package lists first
            subprocess.run(  # nosec B603, B607
                ["apt", "update"], capture_output=True, timeout=300, check=False
            )

            # Get all available packages with descriptions using apt-cache dumpavail
            result = subprocess.run(  # nosec B603, B607
                ["apt-cache", "dumpavail"],
                capture_output=True,
                text=True,
                timeout=600,  # Increased timeout for larger output
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get APT package information"))
                return 0

            packages = self._parse_apt_dumpavail_output(result.stdout)
            return self._store_packages("apt", packages)

        except Exception as error:
            logger.error(_("Error collecting APT packages: %s"), error)
            return 0

    def _collect_yum_packages(self) -> int:
        """Collect packages from YUM (CentOS/RHEL 7)."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["yum", "list", "available"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get YUM package list"))
                return 0

            packages = self._parse_yum_output(result.stdout)
            return self._store_packages("yum", packages)

        except Exception as error:
            logger.error(_("Error collecting YUM packages: %s"), error)
            return 0

    def _collect_dnf_packages(self) -> int:
        """Collect packages from DNF (Fedora/RHEL 8+)."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["dnf", "list", "available"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get DNF package list"))
                return 0

            packages = self._parse_yum_output(
                result.stdout
            )  # DNF uses similar format to YUM
            return self._store_packages("dnf", packages)

        except Exception as error:
            logger.error(_("Error collecting DNF packages: %s"), error)
            return 0

    def _collect_zypper_packages(self) -> int:
        """Collect packages from Zypper (openSUSE/SLES)."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["zypper", "search", "-t", "package", "-s"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get Zypper package list"))
                return 0

            packages = self._parse_zypper_output(result.stdout)
            return self._store_packages("zypper", packages)

        except Exception as error:
            logger.error(_("Error collecting Zypper packages: %s"), error)
            return 0

    def _collect_pacman_packages(self) -> int:
        """Collect packages from Pacman (Arch Linux)."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["pacman", "-Ss"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get Pacman package list"))
                return 0

            packages = self._parse_pacman_output(result.stdout)
            return self._store_packages("pacman", packages)

        except Exception as error:
            logger.error(_("Error collecting Pacman packages: %s"), error)
            return 0

    def _collect_snap_packages(self) -> int:
        """Collect packages from Snap."""
        try:
            # Use % to get all available snaps with descriptions
            result = subprocess.run(  # nosec B603, B607
                ["snap", "find", "%"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get Snap package list"))
                return 0

            packages = self._parse_snap_output(result.stdout)
            return self._store_packages("snap", packages)

        except Exception as error:
            logger.error(_("Error collecting Snap packages: %s"), error)
            return 0

    def _collect_flatpak_packages(self) -> int:
        """Collect packages from Flatpak."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["flatpak", "remote-ls"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get Flatpak package list"))
                return 0

            packages = self._parse_flatpak_output(result.stdout)
            return self._store_packages("flatpak", packages)

        except Exception as error:
            logger.error(_("Error collecting Flatpak packages: %s"), error)
            return 0

    def _parse_apt_output(self, output: str) -> List[Dict[str, str]]:
        """Parse APT package list output."""
        packages = []
        for line in output.splitlines():
            if (
                line.startswith("WARNING")
                or line.startswith("Listing")
                or not line.strip()
            ):
                continue

            # APT format: "package/repository version architecture"
            parts = line.split()
            if len(parts) >= 3:
                name_repo = parts[0].split("/")[
                    0
                ]  # Extract package name without repository
                version = parts[1]
                _architecture = parts[2]  # Architecture info, not currently used

                # For now, description is empty - could be enhanced later with apt-cache show
                description = ""

                packages.append(
                    {"name": name_repo, "version": version, "description": description}
                )

        return packages

    def _parse_apt_dumpavail_output(self, output: str) -> List[Dict[str, str]]:
        """Parse apt-cache dumpavail output to extract package info with descriptions."""
        # pylint: disable=too-many-nested-blocks
        packages = []
        current_package = {}

        # Split output into lines and process each package block
        lines = output.splitlines()
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Skip empty lines at the start
            if not line:
                i += 1
                continue

            # Start of a new package block
            current_package = {}

            # Process all fields in this package block
            while i < len(lines) and lines[i].strip():
                line = lines[i].strip()

                if ":" in line:
                    field, value = line.split(":", 1)
                    field = field.strip().lower()
                    value = value.strip()

                    if field == "package":
                        current_package["name"] = value
                    elif field == "version":
                        current_package["version"] = value
                    elif field == "description":
                        # Description might span multiple lines
                        description_lines = [value]
                        i += 1

                        # Collect continuation lines (start with space)
                        while i < len(lines) and lines[i].startswith(" "):
                            desc_line = lines[i][1:]  # Remove leading space
                            if desc_line.strip():  # Skip empty description lines
                                description_lines.append(desc_line.strip())
                            i += 1

                        # Join description lines and clean up
                        current_package["description"] = " ".join(
                            description_lines
                        ).strip()
                        continue  # i already incremented in the while loop

                i += 1

            # Add package if we have minimum required fields
            if current_package.get("name") and current_package.get("version"):
                # Ensure description exists (empty string if missing)
                if "description" not in current_package:
                    current_package["description"] = ""

                packages.append(current_package)

            # Skip empty line after package block
            i += 1

        return packages

    def _parse_yum_output(self, output: str) -> List[Dict[str, str]]:
        """Parse YUM/DNF package list output."""
        packages = []
        parsing_packages = False

        for line in output.splitlines():
            if "Available Packages" in line:
                parsing_packages = True
                continue

            if not parsing_packages or not line.strip():
                continue

            # YUM format: "package.arch version repo"
            parts = line.split()
            if len(parts) >= 2:
                name_arch = parts[0].split(".")[0]
                version = parts[1]

                packages.append(
                    {"name": name_arch, "version": version, "description": ""}
                )

        return packages

    def _parse_zypper_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Zypper package list output."""
        packages = []
        for line in output.splitlines():
            if line.startswith("i") or line.startswith("v") or not line.strip():
                continue

            # Zypper format varies, try to extract name and version
            parts = line.split("|")
            if len(parts) >= 3:
                name = parts[1].strip()
                version = parts[2].strip()

                packages.append({"name": name, "version": version, "description": ""})

        return packages

    def _parse_pacman_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Pacman package list output."""
        packages = []
        current_package: Dict[str, str] = {}

        for line in output.splitlines():
            if line.startswith("    "):
                # Description line
                if current_package:
                    current_package["description"] = line.strip()
            else:
                # Package line: "repo/package version"
                if current_package:
                    packages.append(current_package)

                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].split("/")[-1]
                    version = parts[1]

                    current_package = {
                        "name": name,
                        "version": version,
                        "description": "",
                    }

        if current_package:
            packages.append(current_package)

        return packages

    def _parse_snap_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Snap package list output from 'snap find %'."""
        packages = []
        lines = output.splitlines()

        # Skip header line and empty lines
        for line in lines:
            if line.startswith("Name") or not line.strip():
                continue

            # Parse fixed-width columns based on 'snap find %' format
            # Name (25 chars), Version (28 chars), Publisher (21 chars), Notes (8 chars), Summary (rest)
            try:
                if len(line) < 30:  # Skip lines that are too short
                    continue

                # Extract name (first column, trim whitespace)
                name = line[:25].strip()
                if not name:
                    continue

                # Extract version (second column, starts around position 25)
                version_start = 25
                version_line = line[version_start:]
                version_match = version_line.split()[0] if version_line.split() else ""

                # Find summary - it's the last column after publisher and notes
                # Split the line and take everything after position 3 (name, version, publisher, notes)
                parts = line.split()
                if len(parts) >= 5:
                    # Summary is everything from the 5th element onwards
                    summary = " ".join(parts[4:])
                else:
                    summary = ""

                if name and version_match:
                    packages.append(
                        {"name": name, "version": version_match, "description": summary}
                    )

            except Exception:  # nosec B112
                # If parsing fails for a line, skip it and continue processing
                # This is safe because we're parsing text output that may have malformed lines
                continue

        return packages

    def _parse_flatpak_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Flatpak package list output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # Flatpak format: "Name Description Application ID Version Branch Origin"
            parts = line.split("\t")
            if len(parts) >= 4:
                name = parts[0]
                description = parts[1]
                version = parts[3]

                packages.append(
                    {"name": name, "version": version, "description": description}
                )

        return packages
