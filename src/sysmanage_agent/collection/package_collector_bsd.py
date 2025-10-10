"""
BSD package collection module for SysManage Agent.

This module handles the collection of available packages from BSD package managers.
"""

import logging
import platform
import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _
from src.sysmanage_agent.collection.package_collector_base import BasePackageCollector

logger = logging.getLogger(__name__)


class BSDPackageCollector(BasePackageCollector):
    """Collects available packages from BSD package managers."""

    def collect_packages(self) -> int:
        """Collect packages from BSD package managers."""
        total_collected = 0
        system = platform.system().lower()

        # Try pkg (FreeBSD) or pkg_info (OpenBSD)
        if system == "openbsd":
            # OpenBSD uses pkg_info command
            if self._is_package_manager_available("pkg_info"):
                try:
                    count = self._collect_pkg_packages()
                    total_collected += count
                    logger.info(_("Collected %d packages from pkg_info"), count)
                except Exception as error:
                    logger.error(_("Failed to collect pkg_info packages: %s"), error)
        elif system == "freebsd":
            # FreeBSD uses pkg command
            if self._is_package_manager_available("pkg"):
                try:
                    count = self._collect_pkg_packages()
                    total_collected += count
                    logger.info(_("Collected %d packages from pkg"), count)
                except Exception as error:
                    logger.error(_("Failed to collect pkg packages: %s"), error)

        # Try pkgin (NetBSD)
        if self._is_package_manager_available("pkgin"):
            try:
                count = self._collect_pkgin_packages()
                total_collected += count
                logger.info(_("Collected %d packages from pkgin"), count)
            except Exception as error:
                logger.error(_("Failed to collect pkgin packages: %s"), error)

        return total_collected

    def _collect_pkg_packages(self) -> int:
        """Collect packages from pkg (FreeBSD/OpenBSD)."""
        try:
            # Detect which BSD variant we're on
            system = platform.system().lower()

            if system == "openbsd":
                # OpenBSD uses pkg_info -Q to search all available packages
                result = subprocess.run(  # nosec B603, B607
                    ["pkg_info", "-Q", ""],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )

                if result.returncode != 0:
                    logger.error(_("Failed to get OpenBSD package list"))
                    return 0

                packages = self._parse_openbsd_pkg_info_output(result.stdout)
                return self._store_packages("pkg_add", packages)

            # FreeBSD uses pkg rquery
            result = subprocess.run(  # nosec B603, B607
                ["pkg", "rquery", "--all", "%n-%v %c"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get pkg package list"))
                return 0

            packages = self._parse_pkg_rquery_output(result.stdout)
            return self._store_packages("pkg", packages)

        except Exception as error:
            logger.error(_("Error collecting pkg packages: %s"), error)
            return 0

    def _collect_pkgin_packages(self) -> int:
        """Collect packages from pkgin (NetBSD)."""
        try:
            # Use pkgin avail to get all available packages from remote repositories
            result = subprocess.run(  # nosec B603, B607
                ["pkgin", "avail"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get pkgin package list"))
                return 0

            packages = self._parse_pkgin_output(result.stdout)
            return self._store_packages("pkgin", packages)

        except Exception as error:
            logger.error(_("Error collecting pkgin packages: %s"), error)
            return 0

    def _parse_pkg_output(self, output: str) -> List[Dict[str, str]]:
        """Parse pkg package list output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # pkg format: "name-version comment"
            parts = line.split(" ", 1)
            if len(parts) >= 1:
                name_version = parts[0]
                description = parts[1] if len(parts) > 1 else ""

                # Try to separate name and version
                if "-" in name_version:
                    last_dash = name_version.rfind("-")
                    name = name_version[:last_dash]
                    version = name_version[last_dash + 1 :]
                else:
                    name = name_version
                    version = "unknown"

                packages.append(
                    {"name": name, "version": version, "description": description}
                )

        return packages

    def _parse_pkg_rquery_output(self, output: str) -> List[Dict[str, str]]:
        """Parse pkg rquery --all output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # pkg rquery format: "name-version comment"
            parts = line.split(" ", 1)
            if len(parts) >= 1:
                name_version = parts[0]
                description = parts[1] if len(parts) > 1 else ""

                # Try to separate name and version
                if "-" in name_version:
                    last_dash = name_version.rfind("-")
                    name = name_version[:last_dash]
                    version = name_version[last_dash + 1 :]
                else:
                    name = name_version
                    version = "unknown"

                packages.append(
                    {"name": name, "version": version, "description": description}
                )

        return packages

    def _parse_pkgin_output(self, output: str) -> List[Dict[str, str]]:
        """Parse pkgin avail output."""
        packages = []
        for line in output.splitlines():
            if not line.strip() or line.startswith("pkg_summary"):
                continue

            # pkgin avail format: "package-version;comment"
            # Sometimes may be just "package-version" without comment
            if ";" in line:
                parts = line.split(";", 1)
                name_version = parts[0].strip()
                description = parts[1].strip()
            else:
                name_version = line.strip()
                description = ""

            # Try to separate name and version
            if "-" in name_version:
                # Find the last dash that separates name from version
                last_dash = name_version.rfind("-")
                name = name_version[:last_dash]
                version = name_version[last_dash + 1 :]
            else:
                name = name_version
                version = "unknown"

            packages.append(
                {"name": name, "version": version, "description": description}
            )

        return packages

    def _parse_openbsd_pkg_info_output(self, output: str) -> List[Dict[str, str]]:
        """Parse OpenBSD pkg_info -Q output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # pkg_info -Q format: "package-name-version"
            name_version = line.strip()

            # Try to separate name and version
            # OpenBSD package format: name-version where version starts with a digit
            if "-" in name_version:
                # Find the last dash followed by a digit (version number)
                parts = name_version.rsplit("-", 1)
                if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                    name = parts[0]
                    version = parts[1]
                else:
                    # If no digit after last dash, it's probably part of the name
                    name = name_version
                    version = "unknown"
            else:
                name = name_version
                version = "unknown"

            packages.append({"name": name, "version": version, "description": ""})

        return packages
