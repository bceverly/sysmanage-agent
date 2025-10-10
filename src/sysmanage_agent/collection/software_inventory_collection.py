#!/usr/bin/env python3
"""
Software Inventory Collection Module for SysManage Agent

This module provides comprehensive software inventory collection across multiple platforms:
- Linux: apt/dpkg, snap, flatpak, yum/dnf, pacman, zypper
- macOS: Applications folder, Mac App Store, Homebrew, MacPorts
- Windows: Microsoft Store, winget, Chocolatey, MSI registry, Programs
- BSD: pkg (FreeBSD), ports system

Supports multiple package managers per platform and provides detailed metadata
including versions, installation paths, vendors, and package manager source.
"""

import logging
import platform
from datetime import datetime, timezone
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.collection.software_inventory_bsd import (
    BSDSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_linux import (
    LinuxSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_macos import (
    MacOSSoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.software_inventory_windows import (
    WindowsSoftwareInventoryCollector,
)

logger = logging.getLogger(__name__)


class SoftwareInventoryCollector:
    """
    Comprehensive software inventory collector supporting multiple platforms
    and package managers with detailed metadata collection.
    """

    def __init__(self):
        self.platform = platform.system().lower()
        self.collector = None

        # Initialize platform-specific collector
        if self.platform == "linux":
            self.collector = LinuxSoftwareInventoryCollector()
        elif self.platform == "darwin":
            self.collector = MacOSSoftwareInventoryCollector()
        elif self.platform == "windows":
            self.collector = WindowsSoftwareInventoryCollector()
        elif self.platform in ["freebsd", "openbsd", "netbsd"]:
            self.collector = BSDSoftwareInventoryCollector()
        else:
            logger.warning(
                _("Unsupported platform for software inventory: %s"), self.platform
            )

    def __getattr__(self, name):
        """Delegate attribute access to the platform-specific collector."""
        if self.collector is not None:
            return getattr(self.collector, name)
        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'"
        )

    # Explicit delegation methods for @patch.object compatibility
    def _collect_linux_packages(self):  # pylint: disable=inconsistent-return-statements
        """Delegate to platform collector."""
        if self.collector and hasattr(self.collector, "_collect_linux_packages"):
            return (
                self.collector._collect_linux_packages()  # pylint: disable=protected-access
            )

    def _collect_macos_packages(self):  # pylint: disable=inconsistent-return-statements
        """Delegate to platform collector."""
        if self.collector and hasattr(self.collector, "_collect_macos_packages"):
            return (
                self.collector._collect_macos_packages()  # pylint: disable=protected-access
            )

    def _collect_windows_packages(  # pylint: disable=inconsistent-return-statements
        self,
    ):
        """Delegate to platform collector."""
        if self.collector and hasattr(self.collector, "_collect_windows_packages"):
            return (
                self.collector._collect_windows_packages()  # pylint: disable=protected-access
            )

    def _collect_bsd_packages(self):  # pylint: disable=inconsistent-return-statements
        """Delegate to platform collector."""
        if self.collector and hasattr(self.collector, "_collect_bsd_packages"):
            return (
                self.collector._collect_bsd_packages()  # pylint: disable=protected-access
            )

    def _command_exists(self, command):
        """Delegate to platform collector."""
        if self.collector and hasattr(self.collector, "_command_exists"):
            return self.collector._command_exists(  # pylint: disable=protected-access
                command
            )
        return False

    def _detect_package_managers(self):
        """Delegate to platform collector."""
        if self.collector and hasattr(self.collector, "_detect_package_managers"):
            return (
                self.collector._detect_package_managers()  # pylint: disable=protected-access
            )
        return []

    def get_software_inventory(self) -> Dict[str, Any]:
        """
        Main entry point for software inventory collection.
        Returns comprehensive software inventory for the current platform.

        Returns:
            Dict containing software inventory data with timestamp and metadata
        """
        logger.info(_("Collecting software inventory"))

        if self.collector is None:
            return {
                "software_packages": [],
                "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": self.platform,
                "total_packages": 0,
                "error": "Unsupported platform",
            }

        try:
            self.collector.collect_packages()

            logger.info(
                _("Software inventory collection completed: %d packages found"),
                len(self.collector.collected_packages),
            )

            return {
                "software_packages": self.collector.collected_packages,
                "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": self.platform,
                "total_packages": len(self.collector.collected_packages),
            }

        except Exception as error:
            logger.error(_("Failed to collect software inventory: %s"), str(error))
            return {
                "software_packages": [],
                "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": self.platform,
                "total_packages": 0,
                "error": str(error),
            }
