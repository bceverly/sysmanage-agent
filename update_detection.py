#!/usr/bin/env python3
"""
Update Detection Module for SysManage Agent

This module provides comprehensive update detection across multiple platforms:
- Linux: apt, snap, flatpak, yum/dnf, pacman, zypper
- macOS: Mac App Store, Homebrew, MacPorts
- Windows: Microsoft Store, winget, Chocolatey
- BSD: pkg, ports

Detects available updates for installed packages and provides detailed metadata
including current version, available version, security status, and update size.
"""

import json
import logging
import os
import platform
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any

from i18n import _

logger = logging.getLogger(__name__)


class UpdateDetector:
    """
    Comprehensive update detector supporting multiple platforms
    and package managers with detailed update metadata.
    """

    def __init__(self):
        self.platform = platform.system().lower()
        self.available_updates = []
        self._package_managers = None

    def get_available_updates(self) -> Dict[str, Any]:
        """
        Main entry point for update detection.
        Returns comprehensive update information for the current platform.

        Returns:
            Dict containing available updates with metadata
        """
        logger.info(_("Detecting available updates"))

        try:
            self.available_updates = []

            if self.platform == "linux":
                self._detect_linux_updates()
            elif self.platform == "darwin":
                self._detect_macos_updates()
            elif self.platform == "windows":
                self._detect_windows_updates()
            elif self.platform in ["freebsd", "openbsd", "netbsd"]:
                self._detect_bsd_updates()
            else:
                logger.warning(
                    _("Unsupported platform for update detection: %s"), self.platform
                )

            # Categorize updates
            security_updates = [
                u for u in self.available_updates if u.get("is_security_update")
            ]
            system_updates = [
                u for u in self.available_updates if u.get("is_system_update")
            ]
            application_updates = [
                u
                for u in self.available_updates
                if not u.get("is_security_update") and not u.get("is_system_update")
            ]

            logger.info(
                _(
                    "Update detection completed: %d updates found (%d security, %d system, %d application)"
                ),
                len(self.available_updates),
                len(security_updates),
                len(system_updates),
                len(application_updates),
            )

            return {
                "available_updates": self.available_updates,
                "detection_timestamp": datetime.now().isoformat() + "Z",
                "platform": self.platform,
                "total_updates": len(self.available_updates),
                "security_updates": len(security_updates),
                "system_updates": len(system_updates),
                "application_updates": len(application_updates),
                "requires_reboot": self._check_reboot_required(),
            }

        except Exception as e:
            logger.error(_("Failed to detect available updates: %s"), str(e))
            return {
                "available_updates": [],
                "detection_timestamp": datetime.now().isoformat() + "Z",
                "platform": self.platform,
                "total_updates": 0,
                "error": str(e),
            }

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
            # macOS package managers
            "homebrew": ["brew"],
            "macports": ["port"],
            # Windows package managers
            "winget": ["winget"],
            "chocolatey": ["choco"],
            "scoop": ["scoop"],
            # BSD package managers
            "pkg": ["pkg"],
        }

        for manager, executables in manager_executables.items():
            for executable in executables:
                if self._command_exists(executable):
                    managers.append(manager)
                    break

        self._package_managers = managers
        logger.debug(_("Detected package managers: %s"), ", ".join(managers))
        return managers

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system PATH."""
        try:
            subprocess.run(
                [command, "--version"], capture_output=True, timeout=5, check=False
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _detect_linux_updates(self):
        """Detect updates from Linux package managers."""
        managers = self._detect_package_managers()

        if "apt" in managers:
            self._detect_apt_updates()
        if "snap" in managers:
            self._detect_snap_updates()
        if "flatpak" in managers:
            self._detect_flatpak_updates()
        if "dnf" in managers:
            self._detect_dnf_updates()
        elif "yum" in managers:
            self._detect_yum_updates()
        if "pacman" in managers:
            self._detect_pacman_updates()
        if "zypper" in managers:
            self._detect_zypper_updates()

    def _detect_macos_updates(self):
        """Detect updates from macOS sources."""
        # Mac App Store updates
        self._detect_macos_app_store_updates()

        # Package managers
        managers = self._detect_package_managers()
        if "homebrew" in managers:
            self._detect_homebrew_updates()
        if "macports" in managers:
            self._detect_macports_updates()

    def _detect_windows_updates(self):
        """Detect updates from Windows sources."""
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

    def _detect_bsd_updates(self):
        """Detect updates from BSD systems."""
        managers = self._detect_package_managers()

        if "pkg" in managers:
            self._detect_pkg_updates()

    # Linux Update Detection Implementations

    def _detect_apt_updates(self):
        """Detect updates from apt/dpkg (Debian/Ubuntu)."""
        try:
            logger.debug(_("Detecting apt updates"))

            # First, update the package list (simulate only)
            subprocess.run(
                ["apt-get", "update", "-qq"],
                capture_output=True,
                timeout=60,
                check=False,
            )

            # Get list of upgradable packages
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n")[1:]:  # Skip header
                    if line and "/" in line:
                        # Parse format: package/suite version arch [upgradable from: old_version]
                        match = re.match(
                            r"^([^/]+)/[^\s]+\s+([^\s]+)\s+[^\s]+\s+\[upgradable from:\s+([^\]]+)\]",
                            line,
                        )
                        if match:
                            package_name = match.group(1)
                            new_version = match.group(2)
                            current_version = match.group(3)

                            # Check if it's a security update
                            is_security = self._is_apt_security_update(package_name)

                            update = {
                                "package_name": package_name,
                                "current_version": current_version,
                                "available_version": new_version,
                                "package_manager": "apt",
                                "is_security_update": is_security,
                                "is_system_update": self._is_system_package_linux(
                                    package_name
                                ),
                                "update_size": self._get_apt_update_size(package_name),
                            }

                            self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect apt updates: %s"), str(e))

    def _is_apt_security_update(self, package_name: str) -> bool:
        """Check if an apt package update is security-related."""
        try:
            result = subprocess.run(
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

    def _get_apt_update_size(self, package_name: str) -> Optional[int]:
        """Get the download size for an apt package update."""
        try:
            result = subprocess.run(
                ["apt-cache", "show", package_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                match = re.search(r"Size:\s+(\d+)", result.stdout)
                if match:
                    return int(match.group(1))
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def _detect_snap_updates(self):
        """Detect updates from Snap."""
        try:
            logger.debug(_("Detecting snap updates"))

            result = subprocess.run(
                ["snap", "refresh", "--list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        update = {
                            "package_name": parts[0],
                            "current_version": parts[2],
                            "available_version": parts[3],
                            "package_manager": "snap",
                            "channel": parts[4] if len(parts) > 4 else "stable",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect snap updates: %s"), str(e))

    def _detect_flatpak_updates(self):
        """Detect updates from Flatpak."""
        try:
            logger.debug(_("Detecting flatpak updates"))

            result = subprocess.run(
                ["flatpak", "remote-ls", "--updates"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        update = {
                            "package_name": parts[0],
                            "bundle_id": parts[1],
                            "available_version": parts[2],
                            "package_manager": "flatpak",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect flatpak updates: %s"), str(e))

    def _detect_dnf_updates(self):
        """Detect updates from DNF (Fedora)."""
        try:
            logger.debug(_("Detecting DNF updates"))

            result = subprocess.run(
                ["dnf", "check-update", "--quiet"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            # DNF returns 100 when updates are available
            if result.returncode in [0, 100] and result.stdout.strip():
                lines = result.stdout.strip().split("\n")

                for line in lines:
                    if line and not line.startswith("Last metadata"):
                        parts = line.split()
                        if len(parts) >= 3:
                            package_name = parts[0].split(".")[0]  # Remove arch
                            available_version = parts[1]
                            repo = parts[2]

                            # Check if it's a security update
                            is_security = self._is_dnf_security_update(package_name)

                            update = {
                                "package_name": package_name,
                                "available_version": available_version,
                                "repository": repo,
                                "package_manager": "dnf",
                                "is_security_update": is_security,
                                "is_system_update": self._is_system_package_linux(
                                    package_name
                                ),
                            }
                            self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect DNF updates: %s"), str(e))

    def _is_dnf_security_update(self, package_name: str) -> bool:
        """Check if a DNF package update is security-related."""
        try:
            result = subprocess.run(
                ["dnf", "updateinfo", "list", "--security", package_name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return result.returncode == 0 and package_name in result.stdout
        except Exception:
            return False

    def _detect_yum_updates(self):
        """Detect updates from YUM (Red Hat/CentOS)."""
        # Similar to DNF but using yum commands
        logger.debug("YUM update detection not yet implemented")

    def _detect_pacman_updates(self):
        """Detect updates from Pacman (Arch Linux)."""
        try:
            logger.debug(_("Detecting Pacman updates"))

            # First sync the database
            subprocess.run(
                ["pacman", "-Sy"], capture_output=True, timeout=60, check=False
            )

            result = subprocess.run(
                ["pacman", "-Qu"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 4:  # package current -> available
                        update = {
                            "package_name": parts[0],
                            "current_version": parts[1],
                            "available_version": parts[3],
                            "package_manager": "pacman",
                            "is_security_update": False,
                            "is_system_update": self._is_system_package_linux(parts[0]),
                        }
                        self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect Pacman updates: %s"), str(e))

    def _detect_zypper_updates(self):
        """Detect updates from Zypper (openSUSE)."""
        try:
            logger.debug(_("Detecting Zypper updates"))

            result = subprocess.run(
                ["zypper", "list-updates"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                in_packages = False
                for line in result.stdout.strip().split("\n"):
                    if "---" in line:
                        in_packages = True
                        continue

                    if in_packages and line.strip():
                        parts = line.split("|")
                        if len(parts) >= 5:
                            update = {
                                "package_name": parts[2].strip(),
                                "current_version": parts[3].strip(),
                                "available_version": parts[4].strip(),
                                "package_manager": "zypper",
                                "repository": parts[1].strip(),
                                "is_security_update": "security" in parts[0].lower(),
                                "is_system_update": self._is_system_package_linux(
                                    parts[2].strip()
                                ),
                            }
                            self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect Zypper updates: %s"), str(e))

    # macOS Update Detection Implementations

    def _detect_homebrew_updates(self):
        """Detect updates from Homebrew (macOS)."""
        try:
            logger.debug(_("Detecting Homebrew updates"))

            # Get outdated formulas
            result = subprocess.run(
                ["brew", "outdated", "--json=v2"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)

                    # Process formulas
                    for formula in data.get("formulae", []):
                        update = {
                            "package_name": formula.get("name"),
                            "current_version": formula.get("installed_versions", [""])[
                                0
                            ],
                            "available_version": formula.get("current_version"),
                            "package_manager": "homebrew",
                            "source": "homebrew_core",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        self.available_updates.append(update)

                    # Process casks
                    for cask in data.get("casks", []):
                        update = {
                            "package_name": cask.get("name"),
                            "current_version": cask.get("installed_versions", [""])[0],
                            "available_version": cask.get("current_version"),
                            "package_manager": "homebrew",
                            "source": "homebrew_cask",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        self.available_updates.append(update)

                except json.JSONDecodeError:
                    logger.warning(_("Failed to parse Homebrew JSON output"))

        except Exception as e:
            logger.error(_("Failed to detect Homebrew updates: %s"), str(e))

    def _detect_macos_app_store_updates(self):
        """Detect Mac App Store updates."""
        try:
            logger.debug(_("Detecting Mac App Store updates"))

            result = subprocess.run(
                ["softwareupdate", "--list"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split("\n")
                i = 0
                while i < len(lines):
                    line = lines[i]
                    if "*" in line and "Label:" in line:  # Update lines start with * Label:
                        # Parse format: * Label: Name-VersionCode
                        label_match = re.match(r"\*\s+Label:\s+(.+)", line)
                        if label_match:
                            label = label_match.group(1).strip()
                            
                            # Look for the next line with Title and Version info
                            details_line = ""
                            if i + 1 < len(lines) and lines[i + 1].strip().startswith("Title:"):
                                details_line = lines[i + 1].strip()
                                i += 1  # Skip the details line in next iteration
                            
                            # Parse details: Title: Name, Version: X.Y.Z, Size: XXXKIB, ...
                            title = label  # Fallback to label
                            version = "unknown"
                            size_kb = None
                            is_recommended = False
                            requires_restart = False
                            
                            if details_line:
                                # Extract Title
                                title_match = re.search(r"Title:\s*([^,]+)", details_line)
                                if title_match:
                                    title = title_match.group(1).strip()
                                
                                # Extract Version
                                version_match = re.search(r"Version:\s*([^,]+)", details_line)
                                if version_match:
                                    version = version_match.group(1).strip()
                                
                                # Extract Size
                                size_match = re.search(r"Size:\s*(\d+)KiB", details_line)
                                if size_match:
                                    size_kb = int(size_match.group(1))
                                
                                # Check if recommended
                                is_recommended = "Recommended: YES" in details_line
                                
                                # Check if requires restart
                                requires_restart = "Action: restart" in details_line

                            update = {
                                "package_name": title,
                                "available_version": version,
                                "package_manager": "mac_app_store",
                                "label": label,
                                "size_kb": size_kb,
                                "is_security_update": "Security" in label,
                                "is_system_update": "macOS" in title or "Safari" in title,
                                "is_recommended": is_recommended,
                                "requires_restart": requires_restart,
                            }
                            self.available_updates.append(update)
                    
                    i += 1

        except Exception as e:
            logger.error(_("Failed to detect Mac App Store updates: %s"), str(e))

    def _detect_macports_updates(self):
        """Detect updates from MacPorts."""
        try:
            logger.debug(_("Detecting MacPorts updates"))

            result = subprocess.run(
                ["port", "outdated"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n")[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        update = {
                            "package_name": parts[0],
                            "current_version": parts[1],
                            "available_version": parts[3],
                            "package_manager": "macports",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect MacPorts updates: %s"), str(e))

    # Windows Update Detection Implementations

    def _detect_winget_updates(self):
        """Detect updates from Windows Package Manager."""
        try:
            logger.debug(_("Detecting winget updates"))

            result = subprocess.run(
                ["winget", "upgrade", "--include-unknown"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                in_packages = False

                for line in lines:
                    if "---" in line:
                        in_packages = True
                        continue

                    if in_packages and line.strip() and not line.startswith("No"):
                        parts = line.split()
                        if len(parts) >= 4:
                            update = {
                                "package_name": parts[0],
                                "bundle_id": parts[1],
                                "current_version": parts[2],
                                "available_version": parts[3],
                                "package_manager": "winget",
                                "is_security_update": False,
                                "is_system_update": False,
                            }
                            self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect winget updates: %s"), str(e))

    def _detect_microsoft_store_updates(self):
        """Detect Microsoft Store updates."""
        # This would require PowerShell commands to check Windows Store updates
        logger.debug("Microsoft Store update detection not yet implemented")

    def _detect_chocolatey_updates(self):
        """Detect updates from Chocolatey."""
        try:
            logger.debug(_("Detecting Chocolatey updates"))

            result = subprocess.run(
                ["choco", "outdated", "-r"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    parts = line.split("|")
                    if len(parts) >= 4:
                        update = {
                            "package_name": parts[0],
                            "current_version": parts[1],
                            "available_version": parts[2],
                            "package_manager": "chocolatey",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect Chocolatey updates: %s"), str(e))

    def _detect_scoop_updates(self):
        """Detect updates from Scoop."""
        try:
            logger.debug(_("Detecting Scoop updates"))

            result = subprocess.run(
                ["scoop", "status"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    if ":" in line and "Update" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            update = {
                                "package_name": parts[0],
                                "available_version": parts[-1],
                                "package_manager": "scoop",
                                "is_security_update": False,
                                "is_system_update": False,
                            }
                            self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect Scoop updates: %s"), str(e))

    # BSD Update Detection Implementations

    def _detect_pkg_updates(self):
        """Detect updates from FreeBSD/OpenBSD pkg."""
        try:
            logger.debug(_("Detecting pkg updates"))

            # Update the package repository
            subprocess.run(
                ["pkg", "update", "-q"], capture_output=True, timeout=60, check=False
            )

            result = subprocess.run(
                ["pkg", "version", "-vl", "<"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    # Parse format: package-version < needs updating (remote has version)
                    match = re.match(
                        r"^([^-]+(?:-[^0-9][^-]*)*)-([^\s]+)\s+<\s+.*remote has ([^\)]+)",
                        line,
                    )
                    if match:
                        update = {
                            "package_name": match.group(1),
                            "current_version": match.group(2),
                            "available_version": match.group(3),
                            "package_manager": "pkg",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        self.available_updates.append(update)

        except Exception as e:
            logger.error(_("Failed to detect pkg updates: %s"), str(e))

    # Helper methods

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

    def _check_reboot_required(self) -> bool:
        """Check if a system reboot is required for updates."""
        if self.platform == "linux":
            # Check for reboot-required file (Ubuntu/Debian)
            if os.path.exists("/var/run/reboot-required"):
                return True

            # Check for kernel updates in the pending updates
            kernel_updates = [
                u
                for u in self.available_updates
                if "kernel" in u.get("package_name", "").lower()
                or "linux-image" in u.get("package_name", "").lower()
            ]
            if kernel_updates:
                return True

        elif self.platform == "darwin":
            # Check for system updates that require reboot
            system_updates = [
                u
                for u in self.available_updates
                if u.get("is_system_update") or "macOS" in u.get("package_name", "")
            ]
            if system_updates:
                return True

        elif self.platform == "windows":
            # Windows updates typically require reboot
            return len(self.available_updates) > 0

        return False

    def apply_updates(
        self, package_names: List[str], package_managers: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Apply updates for specified packages.

        Args:
            package_names: List of package names to update
            package_managers: Optional list of package managers to use

        Returns:
            Dict containing update results and status
        """
        logger.info(_("Applying updates for %d packages"), len(package_names))

        if not package_names:
            return {
                "success": False,
                "error": "No packages specified for update",
                "updated_packages": [],
                "failed_packages": [],
                "update_timestamp": datetime.now().isoformat() + "Z",
                "requires_reboot": False,
            }

        results = {
            "updated_packages": [],
            "failed_packages": [],
            "update_timestamp": datetime.now().isoformat() + "Z",
            "requires_reboot": False,
        }

        # Group packages by package manager
        packages_by_manager = {}
        for update in self.available_updates:
            if update["package_name"] in package_names:
                manager = update["package_manager"]
                if package_managers and manager not in package_managers:
                    continue
                if manager not in packages_by_manager:
                    packages_by_manager[manager] = []
                packages_by_manager[manager].append(update)

        # Apply updates for each package manager
        for manager, packages in packages_by_manager.items():
            if manager == "apt":
                self._apply_apt_updates(packages, results)
            elif manager == "snap":
                self._apply_snap_updates(packages, results)
            elif manager == "flatpak":
                self._apply_flatpak_updates(packages, results)
            elif manager == "dnf":
                self._apply_dnf_updates(packages, results)
            elif manager == "homebrew":
                self._apply_homebrew_updates(packages, results)
            elif manager == "winget":
                self._apply_winget_updates(packages, results)
            elif manager == "pkg":
                self._apply_pkg_updates(packages, results)
            # Add more package manager implementations as needed

        # Check if reboot is required after updates
        results["requires_reboot"] = self._check_reboot_required()
        results["success"] = True

        return results

    def _apply_apt_updates(self, packages: List[Dict], results: Dict):
        """Apply apt updates."""
        package_names = [p["package_name"] for p in packages]

        try:
            # Run apt-get upgrade for specific packages
            result = subprocess.run(
                ["apt-get", "install", "--only-upgrade", "-y"] + package_names,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode == 0:
                for package in packages:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "apt",
                        }
                    )
            else:
                for package in packages:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "apt",
                            "error": result.stderr,
                        }
                    )

        except Exception as e:
            logger.error(_("Failed to apply apt updates: %s"), str(e))
            for package in packages:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "apt",
                        "error": str(e),
                    }
                )

    def _apply_snap_updates(self, packages: List[Dict], results: Dict):
        """Apply snap updates."""
        for package in packages:
            try:
                result = subprocess.run(
                    ["snap", "refresh", package["package_name"]],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )

                if result.returncode == 0:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "snap",
                        }
                    )
                else:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "snap",
                            "error": result.stderr,
                        }
                    )

            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "snap",
                        "error": str(e),
                    }
                )

    def _apply_flatpak_updates(self, packages: List[Dict], results: Dict):
        """Apply flatpak updates."""
        for package in packages:
            try:
                bundle_id = package.get("bundle_id", package["package_name"])
                result = subprocess.run(
                    ["flatpak", "update", "-y", bundle_id],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )

                if result.returncode == 0:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "flatpak",
                        }
                    )
                else:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "flatpak",
                            "error": result.stderr,
                        }
                    )

            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "flatpak",
                        "error": str(e),
                    }
                )

    def _apply_dnf_updates(self, packages: List[Dict], results: Dict):
        """Apply DNF updates."""
        package_names = [p["package_name"] for p in packages]

        try:
            result = subprocess.run(
                ["dnf", "upgrade", "-y"] + package_names,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode == 0:
                for package in packages:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "dnf",
                        }
                    )
            else:
                for package in packages:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "dnf",
                            "error": result.stderr,
                        }
                    )

        except Exception as e:
            logger.error(_("Failed to apply DNF updates: %s"), str(e))
            for package in packages:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "dnf",
                        "error": str(e),
                    }
                )

    def _apply_homebrew_updates(self, packages: List[Dict], results: Dict):
        """Apply Homebrew updates."""
        for package in packages:
            try:
                # Determine if it's a cask or formula
                source = package.get("source", "homebrew_core")
                if "cask" in source:
                    cmd = ["brew", "upgrade", "--cask", package["package_name"]]
                else:
                    cmd = ["brew", "upgrade", package["package_name"]]

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120, check=False
                )

                if result.returncode == 0:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "homebrew",
                        }
                    )
                else:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "homebrew",
                            "error": result.stderr,
                        }
                    )

            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "homebrew",
                        "error": str(e),
                    }
                )

    def _apply_winget_updates(self, packages: List[Dict], results: Dict):
        """Apply winget updates."""
        for package in packages:
            try:
                result = subprocess.run(
                    [
                        "winget",
                        "upgrade",
                        "--id",
                        package.get("bundle_id", package["package_name"]),
                        "--silent",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )

                if result.returncode == 0:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "winget",
                        }
                    )
                else:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "winget",
                            "error": result.stderr,
                        }
                    )

            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "winget",
                        "error": str(e),
                    }
                )

    def _apply_pkg_updates(self, packages: List[Dict], results: Dict):
        """Apply pkg updates (FreeBSD/OpenBSD)."""
        package_names = [p["package_name"] for p in packages]

        try:
            result = subprocess.run(
                ["pkg", "upgrade", "-y"] + package_names,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode == 0:
                for package in packages:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "pkg",
                        }
                    )
            else:
                for package in packages:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "pkg",
                            "error": result.stderr,
                        }
                    )

        except Exception as e:
            logger.error(_("Failed to apply pkg updates: %s"), str(e))
            for package in packages:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "pkg",
                        "error": str(e),
                    }
                )
