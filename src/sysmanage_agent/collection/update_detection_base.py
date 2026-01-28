#!/usr/bin/env python3
"""
Base Update Detection Module for SysManage Agent

This module provides the base class and common functionality for update detection
across all platforms.
"""

import logging
import os
import platform
import subprocess  # nosec B404
from typing import (  # pylint: disable=unused-import  # Any used in child classes
    Any,
    List,
)

# Platform-specific imports
try:
    import pwd  # Unix/macOS only
except ImportError:
    pwd = None  # Windows

from src.i18n import _

logger = logging.getLogger(__name__)

HOMEBREW_ARM_PATH = "/opt/homebrew/bin/brew"
HOMEBREW_INTEL_PATH = "/usr/local/bin/brew"


class UpdateDetectorBase:
    """
    Base class for update detection with common functionality shared across platforms.
    """

    def __init__(self):
        self.platform = platform.system().lower()
        self.available_updates = []
        self._package_managers = None

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system PATH."""
        try:
            subprocess.run(  # nosec B603, B607
                [command, "--version"], capture_output=True, timeout=5, check=False
            )
            return True
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _format_size_mb(self, size_bytes):
        """Format size in bytes to MB."""
        if size_bytes is None:
            return None
        try:
            return round(size_bytes / (1024 * 1024), 2)
        except (TypeError, ValueError):
            return None

    def _detect_package_managers(self) -> List[str]:
        """
        Detect available package managers on the current system.
        """
        if self._package_managers is not None:
            return self._package_managers

        managers = []

        # Common package manager executables to check
        manager_executables = {
            # Linux package managers
            "apt": ["apt", "apt-get"],
            "snap": ["snap"],
            "flatpak": ["flatpak"],
            "yum": ["yum"],
            "dnf": ["dnf"],
            "pacman": ["pacman"],
            "zypper": ["zypper"],
            "portage": ["emerge"],
            "apk": ["apk"],
            "fwupd": ["fwupdmgr"],  # Firmware update manager
            # macOS package managers
            "homebrew": ["brew"],
            "macports": ["port"],
            # Windows package managers
            "winget": ["winget"],
            "chocolatey": ["choco"],
            "scoop": ["scoop"],
            # BSD package managers
            "pkg": ["pkg"],
            "pkgin": ["pkgin"],
        }

        for manager, executables in manager_executables.items():
            for executable in executables:
                # Special handling for Homebrew on macOS
                if manager == "homebrew" and executable == "brew":
                    if self._is_homebrew_available():
                        managers.append(manager)
                        break
                elif self._command_exists(executable):
                    managers.append(manager)
                    break

        self._package_managers = managers
        logger.info(
            _("Detected package managers: %s"),
            ", ".join(managers) if managers else "none",
        )
        return managers

    def _is_homebrew_available(self) -> bool:
        """Check if Homebrew is available on macOS with proper path detection."""
        homebrew_paths = [
            HOMEBREW_ARM_PATH,  # Apple Silicon (M1/M2)
            HOMEBREW_INTEL_PATH,  # Intel Macs
        ]

        for path in homebrew_paths:
            if not os.path.exists(path):
                continue
            try:
                result = subprocess.run(  # nosec B603, B607
                    [path, "--version"], capture_output=True, timeout=10, check=False
                )
                if result.returncode == 0:
                    return True
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return False

    def _get_homebrew_owner(self) -> str:
        """Get the owner of the Homebrew installation."""
        homebrew_paths = [
            HOMEBREW_ARM_PATH,  # Apple Silicon (M1/M2)
            HOMEBREW_INTEL_PATH,  # Intel Macs
        ]

        for path in homebrew_paths:
            try:
                if os.path.exists(path):
                    file_stat = os.stat(path)
                    owner_uid = file_stat.st_uid
                    if pwd is not None:
                        owner_info = pwd.getpwuid(owner_uid)
                        return owner_info.pw_name
                    # On Windows, return empty string since Homebrew doesn't exist
                    return ""
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return ""

    def _get_brew_command(self) -> str:
        """Get the correct brew command path, with sudo -u support when running privileged."""
        homebrew_paths = [
            HOMEBREW_ARM_PATH,  # Apple Silicon (M1/M2)
            HOMEBREW_INTEL_PATH,  # Intel Macs
            "brew",  # If in PATH
        ]

        for path in homebrew_paths:
            try:
                # Test if brew works directly first
                result = subprocess.run(  # nosec B603, B607
                    [path, "--version"], capture_output=True, timeout=10, check=False
                )
                if result.returncode == 0:
                    # Check if running as root and Homebrew owner is different
                    if os.geteuid() == 0:  # Running as root
                        homebrew_owner = self._get_homebrew_owner()
                        if homebrew_owner and homebrew_owner != "root":
                            # Return sudo command to run as homebrew owner
                            return f"sudo -u {homebrew_owner} {path}"

                    # Normal case
                    return path
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return "brew"  # Fallback

    def _detect_linux_reboot_required(self) -> bool:
        """Check if a Linux system reboot is required based on pending updates."""
        if os.path.exists("/var/run/reboot-required"):
            return True

        has_kernel_updates = any(
            "kernel" in u.get("package_name", "").lower()
            or "linux-image" in u.get("package_name", "").lower()
            for u in self.available_updates
        )
        if has_kernel_updates:
            return True

        has_firmware_updates = any(
            u.get("package_manager") == "fwupd" for u in self.available_updates
        )
        return has_firmware_updates

    def _detect_darwin_reboot_required(self) -> bool:
        """Check if a macOS system reboot is required based on pending updates."""
        return any(
            u.get("is_system_update") or "macOS" in u.get("package_name", "")
            for u in self.available_updates
        )

    def check_reboot_required(self) -> bool:
        """Check if a system reboot is required for updates."""
        if self.platform == "linux":
            return self._detect_linux_reboot_required()
        if self.platform == "darwin":
            return self._detect_darwin_reboot_required()
        if self.platform == "windows":
            return len(self.available_updates) > 0
        return False

    def _detect_best_package_manager(  # pylint: disable=too-many-return-statements
        self,
    ) -> str:
        """
        Detect the best/primary package manager for the current platform.

        Returns:
            str: The name of the best package manager
        """
        managers = self._detect_package_managers()

        if not managers:
            return ""

        # Platform-specific preferences
        if self.platform == "linux":
            # Prefer native system package managers
            for preferred in ["apt", "dnf", "yum", "pacman", "zypper"]:
                if preferred in managers:
                    return preferred
            # Fallback to universal package managers
            for fallback in ["snap", "flatpak"]:
                if fallback in managers:
                    return fallback

        elif self.platform == "darwin":
            # Prefer Homebrew on macOS
            if "homebrew" in managers:
                return "homebrew"
            if "macports" in managers:
                return "macports"

        elif self.platform == "windows":
            # Prefer winget on Windows
            for preferred in ["winget", "chocolatey", "scoop"]:
                if preferred in managers:
                    return preferred

        elif self.platform in ["freebsd", "openbsd", "netbsd"]:
            # BSD systems
            if "pkg" in managers:
                return "pkg"
            if "pkgin" in managers:
                return "pkgin"

        # Return first available if no preference matches
        return managers[0] if managers else ""
