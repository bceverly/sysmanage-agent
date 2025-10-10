#!/usr/bin/env python3
"""
Update Detection Module for SysManage Agent

This module provides comprehensive update detection across multiple platforms:

OS-Level System Updates:
- Linux: System/kernel updates via distribution-specific mechanisms
- macOS: System updates via Software Update (softwareupdate)
- Windows: Windows Updates via PowerShell/WU API (all updates from Windows Update)
- OpenBSD: System patches via syspatch

Package Manager Updates:
- Linux: apt, snap, flatpak, yum/dnf, pacman, zypper
- macOS: Mac App Store, Homebrew, MacPorts
- Windows: Microsoft Store, winget, Chocolatey
- BSD: pkg, ports

Detects available updates for both system components and installed packages,
providing detailed metadata including current version, available version,
security status, and update size.
"""

import logging
import platform
import subprocess  # nosec B404
from datetime import datetime, timezone
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.collection.update_detection_bsd import BSDUpdateDetector
from src.sysmanage_agent.collection.update_detection_linux import LinuxUpdateDetector
from src.sysmanage_agent.collection.update_detection_macos import MacOSUpdateDetector
from src.sysmanage_agent.collection.update_detection_windows import (
    WindowsUpdateDetector,
)

logger = logging.getLogger(__name__)


class UpdateDetector:
    """
    Comprehensive update detector supporting multiple platforms
    and package managers with detailed update metadata.
    """

    def __init__(self):
        self.platform = platform.system().lower()
        self.detector = None

        # Initialize platform-specific detector
        if self.platform == "linux":
            self.detector = LinuxUpdateDetector()
        elif self.platform == "darwin":
            self.detector = MacOSUpdateDetector()
        elif self.platform == "windows":
            self.detector = WindowsUpdateDetector()
        elif self.platform in ["freebsd", "openbsd", "netbsd"]:
            self.detector = BSDUpdateDetector()
        else:
            logger.warning(
                _("Unsupported platform for update detection: %s"), self.platform
            )

    def __getattr__(self, name):
        """Delegate attribute access to the platform-specific detector."""
        if self.detector is not None:
            return getattr(self.detector, name)
        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'"
        )

    def get_available_updates(self) -> Dict[str, Any]:
        """
        Main entry point for update detection.
        Returns comprehensive update information for the current platform.

        Returns:
            Dict containing available updates with metadata
        """
        logger.info(_("Detecting available updates"))

        if self.detector is None:
            return {
                "available_updates": [],
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": self.platform,
                "total_updates": 0,
                "error": "Unsupported platform",
            }

        try:
            # Delegate to platform-specific detector
            self.detector.detect_updates()

            # Categorize updates
            security_updates = [
                u
                for u in self.detector.available_updates
                if u.get("is_security_update")
            ]
            system_updates = [
                u for u in self.detector.available_updates if u.get("is_system_update")
            ]
            application_updates = [
                u
                for u in self.detector.available_updates
                if not u.get("is_security_update") and not u.get("is_system_update")
            ]

            logger.info(
                _(
                    "Update detection completed: %d updates found (%d security, %d system, %d application)"
                ),
                len(self.detector.available_updates),
                len(security_updates),
                len(system_updates),
                len(application_updates),
            )

            return {
                "available_updates": self.detector.available_updates,
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": self.platform,
                "total_updates": len(self.detector.available_updates),
                "security_updates": len(security_updates),
                "system_updates": len(system_updates),
                "application_updates": len(application_updates),
                "requires_reboot": self.detector.check_reboot_required(),
            }

        except Exception as error:
            logger.error(_("Failed to detect available updates: %s"), str(error))
            return {
                "available_updates": [],
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": self.platform,
                "total_updates": 0,
                "error": str(error),
            }

    def install_package(  # pylint: disable=too-many-return-statements
        self, package_name: str, package_manager: str = "auto"
    ) -> Dict[str, Any]:
        """
        Install a package using the specified or auto-detected package manager.

        Args:
            package_name: Name of the package to install
            package_manager: Package manager to use ("auto" for auto-detection)

        Returns:
            Dict containing success status, version, and output/error information
        """
        if self.detector is None:
            return {
                "success": False,
                "error": "Unsupported platform for package installation",
            }

        try:
            # Auto-detect package manager if needed
            if package_manager == "auto":
                package_manager = self._detect_best_package_manager()

            # Delegate to platform-specific detector's installation methods
            # These methods should exist in the platform-specific detectors
            install_method_name = f"_install_with_{package_manager}"
            if hasattr(self.detector, install_method_name):
                install_method = getattr(self.detector, install_method_name)
                return install_method(package_name)

            return {
                "success": False,
                "error": f"Unsupported package manager: {package_manager}",
            }

        except Exception as error:
            logger.error(
                _("Failed to install package %s: %s"), package_name, str(error)
            )
            return {"success": False, "error": str(error)}

    def _detect_best_package_manager(self) -> str:
        """Detect the best package manager for the current system."""
        # Platform-specific package manager preferences
        platform_managers = {
            "linux": ["apt", "dnf", "yum", "pacman", "zypper"],
            "darwin": ["brew"],
            "windows": ["winget", "choco"],
        }

        # Handle BSD platforms
        if self.platform in ["freebsd", "openbsd", "netbsd"]:
            return "pkg"

        # Get manager list for platform
        managers = platform_managers.get(self.platform, ["apt"])

        # Check for available managers in order of preference
        for manager in managers:
            if self._command_exists(manager):
                return manager

        # Return first manager as fallback
        return managers[0]

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system PATH."""
        try:
            # Use platform-appropriate command to check existence
            if self.platform == "windows":
                check_cmd = ["where", command]
            else:
                check_cmd = ["which", command]

            subprocess.run(  # nosec B603
                check_cmd, capture_output=True, check=True, timeout=5
            )
            return True
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            FileNotFoundError,
        ):
            return False
