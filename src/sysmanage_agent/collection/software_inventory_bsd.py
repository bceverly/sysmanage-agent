#!/usr/bin/env python3
"""
BSD Software Inventory Collection Module

Handles software inventory collection for BSD systems including:
- FreeBSD: pkg (modern tool)
- OpenBSD/NetBSD: pkg_info
- FreeBSD ports (future enhancement)
"""

import logging
import platform
import re
import subprocess  # nosec B404
from typing import List

from src.i18n import _
from src.sysmanage_agent.collection.software_inventory_base import (
    SoftwareInventoryCollectorBase,
)

logger = logging.getLogger(__name__)


class BSDSoftwareInventoryCollector(SoftwareInventoryCollectorBase):
    """Collects software inventory from BSD package managers."""

    def __init__(self):  # pylint: disable=useless-parent-delegation
        super().__init__()

    def detect_package_managers(self) -> List[str]:
        """Detect available BSD package managers."""
        if self._package_managers is not None:
            return self._package_managers

        managers = []

        if self._command_exists("pkg"):
            managers.append("pkg")
        if self._command_exists("pkg_info"):
            managers.append("pkg_info")
        if self._command_exists("make"):
            managers.append("ports")

        self._package_managers = managers
        logger.debug(_("Detected package managers: %s"), ", ".join(managers))
        return managers

    def collect_packages(self):
        """Collect packages from all detected BSD package managers."""
        managers = self.detect_package_managers()

        if "pkg" in managers:
            self._collect_pkg_packages()
        if "pkg_info" in managers:
            self._collect_pkg_info_packages()
        if "ports" in managers:
            self._collect_ports_packages()

    def _collect_pkg_packages(self):
        """Collect packages from FreeBSD pkg (modern pkg tool)."""
        try:
            logger.debug(_("Collecting FreeBSD pkg packages"))

            # Use FreeBSD style: pkg info -a
            # Note: This is only for FreeBSD's modern pkg tool, not OpenBSD/NetBSD pkg_info
            result = subprocess.run(
                ["pkg", "info", "-a"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                source_name = "freebsd_packages"
                self._parse_pkg_output(result.stdout, source_name)
                logger.debug(_("Successfully collected FreeBSD pkg packages"))
            else:
                logger.debug(_("FreeBSD pkg tool not available or no packages found"))

        except Exception as error:
            logger.error(_("Failed to collect FreeBSD pkg packages: %s"), str(error))

    def _detect_bsd_platform_source(self):
        """Detect the BSD platform and return the appropriate source name.

        Returns:
            A tuple of (platform_name, source_name) where platform_name is the
            lowercased system name and source_name is the package source label.
        """
        platform_name = platform.system().lower()
        source_map = {
            "openbsd": "openbsd_packages",
            "netbsd": "netbsd_packages",
        }
        source_name = source_map.get(platform_name, "bsd_packages")
        return (platform_name, source_name)

    def _collect_pkg_info_packages(self):
        """Collect packages from OpenBSD/NetBSD pkg_info."""
        try:
            platform_name, source_name = self._detect_bsd_platform_source()
            logger.debug(_("Collecting %s pkg_info packages"), platform_name.upper())

            # Use pkg_info -a to list all installed packages
            result = subprocess.run(
                ["pkg_info", "-a"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                self._parse_pkg_output(result.stdout, source_name)
                logger.debug(
                    _("Successfully collected %s packages"), platform_name.upper()
                )
            else:
                logger.warning(
                    _("No pkg_info output found. Return code: %d"),
                    result.returncode,
                )
                if result.stderr:
                    logger.warning(_("pkg_info stderr: %s"), result.stderr)

        except Exception as error:
            logger.error(_("Failed to collect pkg_info packages: %s"), str(error))

    def _parse_pkg_output(self, output: str, source_name: str):
        """Parse output from BSD pkg commands (both FreeBSD and OpenBSD)."""
        for line in output.strip().split("\n"):
            if line:
                # Format: package-version comment
                # NOSONAR - regex operates on trusted internal data
                match = re.match(r"^([^-]+(?:-\D[^-]*)*)-(\d[^\s]*)\s+(.*)$", line)
                if match:
                    package_name = match.group(1)
                    version = match.group(2)
                    description = match.group(3)

                    package = {
                        "package_name": package_name,
                        "version": version,
                        "description": description,
                        "package_manager": "pkg",
                        "source": source_name,
                        "is_system_package": self._is_bsd_system_package(package_name),
                        "is_user_installed": True,
                    }

                    self.collected_packages.append(package)

    def _is_bsd_system_package(self, package_name: str) -> bool:
        """Determine if a BSD package is a system package."""
        system_prefixes = [
            "base-",
            "lib",
            "perl",
            "python",
            "ruby",
            "tcl",
            "tk",
            "gettext",
            "glib",
            "gtk",
            "qt",
            "mesa",
            "xorg",
            "freetype",
            "fontconfig",
            "expat",
            "libxml",
            "openssl",
            "curl",
            "wget",
            "automake",
            "autoconf",
            "libtool",
            "pkgconf",
            "cmake",
            "gmake",
            "gcc",
        ]
        package_lower = package_name.lower()
        return any(package_lower.startswith(prefix) for prefix in system_prefixes)

    def _collect_ports_packages(self):
        """Collect packages from FreeBSD ports."""
        # Implementation would parse /var/db/pkg
        logger.debug(_("FreeBSD ports collection not yet implemented"))
