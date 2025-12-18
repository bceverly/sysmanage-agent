#!/usr/bin/env python3
"""
Windows Update Detection Module for SysManage Agent

This module provides comprehensive update detection for Windows systems:

OS-Level System Updates:
- Windows: Windows Updates via PowerShell/WU API (all updates from Windows Update)
- Windows version upgrades (feature updates)

Package Manager Updates:
- Microsoft Store
- winget (Windows Package Manager)
- Chocolatey
- Scoop

Detects available updates for both system components and installed packages,
providing detailed metadata including current version, available version,
security status, and update size.
"""

import logging

logger = logging.getLogger(__name__)

# pylint: disable=wrong-import-position
from .update_detection_base import UpdateDetectorBase
from .update_detection_windows_apply import WindowsUpdateApplierMixin
from .update_detection_windows_install import WindowsPackageInstallerMixin
from .update_detection_windows_packages import WindowsPackageDetectorMixin
from .update_detection_windows_system import WindowsSystemDetectorMixin


class WindowsUpdateDetector(
    WindowsPackageDetectorMixin,
    WindowsSystemDetectorMixin,
    WindowsUpdateApplierMixin,
    WindowsPackageInstallerMixin,
    UpdateDetectorBase,
):
    """Windows-specific update detection methods."""

    def detect_updates(self):
        """Detect all updates from Windows sources."""
        # First detect OS-level system updates
        self._detect_windows_system_updates()

        # Detect OS version upgrades
        self._detect_windows_version_upgrades()

        # Microsoft Store updates
        self._detect_microsoft_store_updates()

        # Package managers
        managers = self._detect_package_managers()
        if "winget" in managers:
            self._detect_winget_updates()
        if "chocolatey" in managers:
            self._detect_chocolatey_updates()
        if "scoop" in managers:
            self._detect_scoop_updates()
