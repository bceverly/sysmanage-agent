"""
Package collection module for SysManage Agent.

This module handles the collection of available packages from various package managers
and stores them in the local SQLite database for later transmission to the server.
"""

import logging
import platform

from src.database.base import get_database_manager
from src.i18n import _
from src.sysmanage_agent.collection.package_collector_bsd import BSDPackageCollector
from src.sysmanage_agent.collection.package_collector_linux import LinuxPackageCollector
from src.sysmanage_agent.collection.package_collector_macos import MacOSPackageCollector
from src.sysmanage_agent.collection.package_collector_windows import (
    WindowsPackageCollector,
)

logger = logging.getLogger(__name__)


class PackageCollector:
    """Collects available packages from various package managers."""

    def __init__(self):
        """Initialize the package collector."""
        self.db_manager = get_database_manager()
        self.system = platform.system().lower()
        self.collector = None

        # Initialize platform-specific collector
        if self.system == "linux":
            self.collector = LinuxPackageCollector()
        elif self.system == "darwin":
            self.collector = MacOSPackageCollector()
        elif self.system == "windows":
            self.collector = WindowsPackageCollector()
        elif self.system in ["freebsd", "openbsd", "netbsd"]:
            self.collector = BSDPackageCollector()
        else:
            logger.warning(_("Unsupported operating system: %s"), self.system)

    def __getattr__(self, name):
        """Delegate attribute access to the platform-specific collector."""
        if self.collector is not None:
            return getattr(self.collector, name)
        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'"
        )

    def collect_all_available_packages(self) -> bool:
        """
        Collect available packages from all supported package managers.

        Returns:
            bool: True if collection was successful, False otherwise
        """
        logger.info(_("Starting collection of available packages"))

        if self.collector is None:
            logger.warning(_("Unsupported operating system: %s"), self.system)
            return False

        try:
            collected_count = self.collector.collect_packages()

            logger.info(
                _("Package collection completed. Collected %d packages"),
                collected_count,
            )
            return True

        except Exception as error:
            logger.error(_("Failed to collect available packages: %s"), error)
            return False
