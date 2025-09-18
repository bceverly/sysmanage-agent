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

import json
import logging
import os
import platform
import re
import subprocess  # nosec B404
from datetime import datetime
from typing import Dict, List, Optional, Any

from src.i18n import _

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
                "requires_reboot": self.check_reboot_required(),
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
            subprocess.run(  # nosec B603, B607
                [command, "--version"], capture_output=True, timeout=5, check=False
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _detect_linux_updates(self):
        """Detect updates from Linux package managers."""
        # First detect OS-level system updates
        self._detect_linux_system_updates()

        # Detect OS version upgrades
        self._detect_linux_version_upgrades()

        # Then detect package manager updates
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
        if "fwupd" in managers:
            self._detect_fwupd_updates()

    def _detect_macos_updates(self):
        """Detect updates from macOS sources."""
        # First detect OS-level system updates
        self._detect_macos_system_updates()

        # Detect OS version upgrades
        self._detect_macos_version_upgrades()

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

    def _detect_bsd_updates(self):
        """Detect updates from BSD systems."""
        # First detect OS-level system updates (OpenBSD syspatch)
        if platform.system().lower() == "openbsd":
            self._detect_openbsd_system_updates()

        # Detect OS version upgrades
        self._detect_bsd_version_upgrades()

        # Then detect package manager updates
        managers = self._detect_package_managers()

        if "pkg" in managers:
            self._detect_pkg_updates()

    # Linux Update Detection Implementations

    def _detect_apt_updates(self):
        """Detect updates from apt/dpkg (Debian/Ubuntu)."""
        try:
            logger.debug(_("Detecting apt updates"))

            # First, update the package list (simulate only)
            subprocess.run(  # nosec B603, B607
                ["apt-get", "update", "-qq"],
                capture_output=True,
                timeout=60,
                check=False,
            )

            # Get list of upgradable packages
            result = subprocess.run(  # nosec B603, B607
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
            result = subprocess.run(  # nosec B603, B607
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
            result = subprocess.run(  # nosec B603, B607
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

            result = subprocess.run(  # nosec B603, B607
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

            result = subprocess.run(  # nosec B603, B607
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

            result = subprocess.run(  # nosec B603, B607
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
            result = subprocess.run(  # nosec B603, B607
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
        logger.debug(_("YUM update detection not yet implemented"))

    def _detect_pacman_updates(self):
        """Detect updates from Pacman (Arch Linux)."""
        try:
            logger.debug(_("Detecting Pacman updates"))

            # First sync the database
            subprocess.run(  # nosec B603, B607
                ["pacman", "-Sy"], capture_output=True, timeout=60, check=False
            )

            result = subprocess.run(  # nosec B603, B607
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

            result = subprocess.run(  # nosec B603, B607
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

    def _detect_fwupd_updates(self):
        """Detect firmware updates from fwupd."""
        try:  # pylint: disable=too-many-nested-blocks
            logger.debug(_("Detecting fwupd firmware updates"))

            # First, check if the daemon is running and we have permissions
            if not self._check_fwupd_daemon():
                logger.warning(_("fwupd daemon not running or no permissions"))
                return

            # Refresh metadata if allowed (requires privileges)
            try:
                refresh_result = subprocess.run(  # nosec B603, B607
                    ["fwupdmgr", "refresh", "--force"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if refresh_result.returncode != 0:
                    logger.debug(
                        _("fwupd refresh failed (may need privileges): %s"),
                        refresh_result.stderr,
                    )
            except Exception:
                logger.debug(
                    _("Could not refresh fwupd metadata (may need privileges)")
                )

            # Get updates that are available
            result = subprocess.run(  # nosec B603, B607
                ["fwupdmgr", "get-updates", "--json"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                try:
                    updates_data = json.loads(result.stdout)

                    if isinstance(updates_data, dict) and "Devices" in updates_data:
                        devices = updates_data["Devices"]
                    elif isinstance(updates_data, list):
                        devices = updates_data
                    else:
                        devices = []

                    for device in devices:
                        device_id = device.get("DeviceId", "unknown")
                        device_name = device.get(
                            "Name", device.get("DeviceName", _("Unknown Device"))
                        )

                        # Check for releases (available updates)
                        releases = device.get("Releases", [])
                        if not releases:
                            continue

                        # Get current version
                        current_version = device.get("Version", "unknown")

                        # Process each available release
                        for release in releases:
                            if not release:
                                continue

                            available_version = release.get("Version", "unknown")

                            # Skip if same version (shouldn't happen, but safety check)
                            if available_version == current_version:
                                continue

                            # Determine if this is a security update
                            is_security = self._is_fwupd_security_update(release)

                            # Get additional metadata
                            size = release.get("Size", 0)
                            vendor = device.get("Vendor", "Unknown")

                            # Create update record with unique package name that includes version
                            # This ensures React keys are unique when multiple firmware versions are available
                            unique_package_name = (
                                f"{vendor} {device_name} (→ {available_version})"
                            )

                            update = {
                                "package_name": unique_package_name,
                                "device_id": device_id,
                                "current_version": current_version,
                                "available_version": available_version,
                                "package_manager": "fwupd",
                                "is_security_update": is_security,
                                "is_system_update": True,  # Firmware updates are always system-level
                                "update_size": size,
                                "vendor": vendor,
                                "device_name": device_name,
                                "release_description": release.get("Description", ""),
                                "release_summary": release.get("Summary", ""),
                                "urgency": release.get("Urgency", "unknown"),
                                "requires_reboot": True,  # Most firmware updates require reboot
                            }

                            self.available_updates.append(update)

                except json.JSONDecodeError as e:
                    logger.error(_("Failed to parse fwupd JSON output: %s"), str(e))
                except Exception as e:
                    logger.error(_("Error processing fwupd updates: %s"), str(e))

            elif result.returncode == 2:
                # Exit code 2 typically means no updates available
                logger.debug(_("No firmware updates available"))
            else:
                logger.debug(_("fwupd get-updates failed: %s"), result.stderr.strip())

        except Exception as e:
            logger.error(_("Failed to detect fwupd updates: %s"), str(e))

    def _check_fwupd_daemon(self) -> bool:
        """Check if fwupd daemon is running and accessible."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["fwupdmgr", "get-devices", "--json"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _is_fwupd_security_update(self, release: dict) -> bool:
        """Determine if a firmware release is security-related."""
        # Check various indicators that this might be a security update
        description = (
            release.get("Description", "") + " " + release.get("Summary", "")
        ).lower()

        urgency = release.get("Urgency", "").lower()

        # Security keywords
        security_keywords = [
            "security",
            "cve",
            "vulnerability",
            "exploit",
            "patch",
            "fix",
            "critical",
            "urgent",
            "mitigation",
        ]

        # Check if urgency indicates security
        if urgency in ["critical", "high"]:
            return True

        # Check description for security keywords
        return any(keyword in description for keyword in security_keywords)

    # macOS Update Detection Implementations

    def _detect_homebrew_updates(self):
        """Detect updates from Homebrew (macOS)."""
        try:
            logger.debug(_("Detecting Homebrew updates"))

            # First update Homebrew to get the latest package information
            logger.debug(_("Updating Homebrew package information"))
            update_result = subprocess.run(  # nosec B603, B607
                ["brew", "update"],
                capture_output=True,
                text=True,
                timeout=60,  # Give more time for update
                check=False,
            )

            if update_result.returncode != 0:
                logger.warning(_("Homebrew update failed: %s"), update_result.stderr)
            else:
                logger.debug(_("Homebrew update completed successfully"))

            # Get outdated formulas
            result = subprocess.run(  # nosec B603, B607
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
        try:  # pylint: disable=too-many-nested-blocks
            logger.debug(_("Detecting Mac App Store updates"))

            result = subprocess.run(  # nosec B603, B607
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
                    if (
                        "*" in line and "Label:" in line
                    ):  # Update lines start with * Label:
                        # Parse format: * Label: Name-VersionCode
                        label_match = re.match(r"\*\s+Label:\s+(.+)", line)
                        if label_match:
                            label = label_match.group(1).strip()

                            # Look for the next line with Title and Version info
                            details_line = ""
                            if i + 1 < len(lines) and lines[i + 1].strip().startswith(
                                "Title:"
                            ):
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
                                title_match = re.search(
                                    r"Title:\s*([^,]+)", details_line
                                )
                                if title_match:
                                    title = title_match.group(1).strip()

                                # Extract Version
                                version_match = re.search(
                                    r"Version:\s*([^,]+)", details_line
                                )
                                if version_match:
                                    version = version_match.group(1).strip()

                                # Extract Size
                                size_match = re.search(
                                    r"Size:\s*(\d+)KiB", details_line
                                )
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
                                "is_system_update": "macOS" in title
                                or "Safari" in title,
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

            result = subprocess.run(  # nosec B603, B607
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
        try:  # pylint: disable=too-many-nested-blocks
            logger.debug(_("Detecting winget updates"))

            result = subprocess.run(  # nosec B603, B607
                ["winget", "upgrade", "--include-unknown"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                header_line = None
                data_start_idx = 0

                # Find header line to determine column positions
                for i, line in enumerate(lines):
                    if "Name" in line and "Id" in line and "Version" in line:
                        header_line = line
                        data_start_idx = i + 2  # Skip header and separator line
                        break

                if header_line and data_start_idx < len(lines):
                    # Parse column positions from header
                    name_start = header_line.find("Name")
                    id_start = header_line.find("Id")
                    version_start = header_line.find("Version")
                    available_start = header_line.find("Available")
                    source_start = header_line.find("Source")

                    # Process data lines
                    for line in lines[data_start_idx:]:
                        if (
                            line.strip()
                            and not line.startswith("No")
                            and not "upgrades available" in line
                        ):
                            try:
                                # Extract fields based on column positions
                                if id_start > name_start:
                                    package_name = line[name_start:id_start].strip()
                                    if version_start > id_start:
                                        bundle_id = line[id_start:version_start].strip()
                                        if available_start > version_start:
                                            current_version = line[
                                                version_start:available_start
                                            ].strip()
                                            if source_start > available_start:
                                                available_version = line[
                                                    available_start:source_start
                                                ].strip()
                                            else:
                                                available_version = (
                                                    line[available_start:]
                                                    .strip()
                                                    .split()[0]
                                                    if line[available_start:].strip()
                                                    else "unknown"
                                                )
                                        else:
                                            current_version = (
                                                line[version_start:].strip().split()[0]
                                                if line[version_start:].strip()
                                                else "unknown"
                                            )
                                            available_version = "unknown"
                                    else:
                                        bundle_id = (
                                            line[id_start:].strip().split()[0]
                                            if line[id_start:].strip()
                                            else package_name
                                        )
                                        current_version = "unknown"
                                        available_version = "unknown"
                                else:
                                    # Fallback to simple parsing
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        package_name = parts[0]
                                        bundle_id = parts[1]
                                        current_version = (
                                            parts[2] if len(parts) > 2 else "unknown"
                                        )
                                        available_version = (
                                            parts[3] if len(parts) > 3 else "unknown"
                                        )
                                    else:
                                        continue

                                # Clean up extracted values
                                package_name = package_name.strip()
                                bundle_id = bundle_id.strip()
                                current_version = current_version.strip()
                                available_version = available_version.strip()

                                # Skip if any critical field is empty
                                if not package_name or not bundle_id:
                                    continue

                                # Only add update if we have a valid available version
                                if (
                                    available_version
                                    and available_version != "unknown"
                                    and available_version != current_version
                                ):
                                    update = {
                                        "package_name": package_name,
                                        "bundle_id": bundle_id,
                                        "current_version": current_version,
                                        "available_version": available_version,
                                        "package_manager": "winget",
                                        "is_security_update": False,
                                        "is_system_update": False,
                                    }
                                    self.available_updates.append(update)

                            except Exception as e:
                                logger.debug(
                                    _("Failed to parse winget line '%s': %s"), line, e
                                )
                                continue

        except Exception as e:
            logger.error(_("Failed to detect winget updates: %s"), str(e))

    def _detect_microsoft_store_updates(self):
        """Detect Microsoft Store updates."""
        # This would require PowerShell commands to check Windows Store updates
        logger.debug(_("Microsoft Store update detection not yet implemented"))

    def _detect_chocolatey_updates(self):
        """Detect updates from Chocolatey."""
        try:
            logger.debug(_("Detecting Chocolatey updates"))

            result = subprocess.run(  # nosec B603, B607
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

            result = subprocess.run(  # nosec B603, B607
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
            subprocess.run(  # nosec B603, B607
                ["pkg", "update", "-q"], capture_output=True, timeout=60, check=False
            )

            result = subprocess.run(  # nosec B603, B607
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

        # All firmware packages are system packages
        if "firmware" in package_name.lower():
            return True

        return any(package_name.startswith(prefix) for prefix in system_prefixes)

    def check_reboot_required(self) -> bool:
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

            # Check for firmware updates in the pending updates
            firmware_updates = [
                u for u in self.available_updates if u.get("package_manager") == "fwupd"
            ]
            if firmware_updates:
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
                "error": _("No packages specified for update"),
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

        # Get fresh available updates for the apply operation
        logger.info(_("Refreshing update detection for apply operation"))
        fresh_update_data = self.get_available_updates()
        fresh_updates = fresh_update_data.get("available_updates", [])

        # Group packages by package manager
        packages_by_manager = {}
        logger.info(
            _("Filtering %d available updates for requested packages: %s"),
            len(fresh_updates),
            package_names,
        )
        logger.info(_("Requested package managers: %s"), package_managers)

        for update in fresh_updates:
            # Try exact match first, then partial match for better compatibility
            package_match = None
            for requested_name in package_names:
                if (
                    update["package_name"] == requested_name
                    or requested_name in update["package_name"]
                    or (
                        update.get("bundle_id", "")
                        and requested_name in update.get("bundle_id", "")
                    )
                ):
                    package_match = requested_name
                    break
            if package_match:
                manager = update["package_manager"]
                logger.info(
                    _(
                        "Found package '%s' (requested as '%s') with manager '%s', bundle_id='%s'"
                    ),
                    update["package_name"],
                    package_match,
                    manager,
                    update.get("bundle_id", "N/A"),
                )
                if package_managers and manager not in package_managers:
                    logger.warning(
                        _(
                            "Skipping package '%s' - manager '%s' not in requested managers %s"
                        ),
                        update["package_name"],
                        manager,
                        package_managers,
                    )
                    continue
                if manager not in packages_by_manager:
                    packages_by_manager[manager] = []
                packages_by_manager[manager].append(update)

        logger.info(
            _("Packages grouped by manager: %s"),
            {k: [p["package_name"] for p in v] for k, v in packages_by_manager.items()},
        )

        # Check if any packages were found for update
        if not packages_by_manager:
            logger.warning(
                _("No packages found for update among requested: %s"), package_names
            )
            for pkg_name in package_names:
                results["failed_packages"].append(
                    {
                        "package_name": pkg_name,
                        "package_manager": "unknown",
                        "error": _(
                            "Package not found in available updates (may already be up to date)"
                        ),
                    }
                )

        # Apply updates for each package manager
        for manager, packages in packages_by_manager.items():
            logger.info(
                _("Applying updates for %d packages with %s"), len(packages), manager
            )
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
            elif manager == "fwupd":
                self._apply_fwupd_updates(packages, results)
            # OS Version Upgrade Package Managers
            elif manager == "ubuntu-release":
                self._apply_ubuntu_release_updates(packages, results)
            elif manager == "fedora-release":
                self._apply_fedora_release_updates(packages, results)
            elif manager == "opensuse-release":
                self._apply_opensuse_release_updates(packages, results)
            elif manager == "macos-upgrade":
                self._apply_macos_upgrade_updates(packages, results)
            elif manager == "windows-upgrade":
                self._apply_windows_upgrade_updates(packages, results)
            elif manager == "openbsd-upgrade":
                self._apply_openbsd_upgrade_updates(packages, results)
            elif manager == "freebsd-upgrade":
                self._apply_freebsd_upgrade_updates(packages, results)
            # Add more package manager implementations as needed

        # Check if reboot is required after updates
        results["requires_reboot"] = self.check_reboot_required()
        results["success"] = True

        return results

    def _apply_apt_updates(self, packages: List[Dict], results: Dict):
        """Apply apt updates."""
        package_names = [p["package_name"] for p in packages]

        try:
            # Run apt-get upgrade for specific packages
            result = subprocess.run(  # nosec B603, B607
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
                result = subprocess.run(  # nosec B603, B607
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
                result = subprocess.run(  # nosec B603, B607
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
            result = subprocess.run(  # nosec B603, B607
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

                logger.info(_("Running homebrew command: %s"), " ".join(cmd))
                result = subprocess.run(  # nosec B603, B607
                    cmd, capture_output=True, text=True, timeout=120, check=False
                )

                logger.info(
                    _("Homebrew command completed. Return code: %d"), result.returncode
                )
                if result.stdout:
                    logger.info(_("Homebrew stdout: %s"), result.stdout.strip())
                if result.stderr:
                    logger.info(_("Homebrew stderr: %s"), result.stderr.strip())

                if result.returncode == 0:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "homebrew",
                        }
                    )
                    logger.info(
                        _("Successfully updated package %s"), package["package_name"]
                    )
                else:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "homebrew",
                            "error": result.stderr,
                        }
                    )
                    logger.error(
                        _("Failed to update package %s: %s"),
                        package["package_name"],
                        result.stderr,
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
                package_id = package.get("bundle_id", package["package_name"])
                logger.info(
                    _("Applying winget update for package '%s' (ID: %s)"),
                    package["package_name"],
                    package_id,
                )

                result = subprocess.run(  # nosec B603, B607
                    [
                        "winget",
                        "upgrade",
                        "--id",
                        package_id,
                        "--silent",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )

                logger.debug(
                    _("Winget command result: returncode=%d, stdout='%s', stderr='%s'"),
                    result.returncode,
                    result.stdout.strip(),
                    result.stderr.strip(),
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully updated package '%s'"), package["package_name"]
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "winget",
                        }
                    )
                else:
                    error_msg = (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or f"Command failed with exit code {result.returncode}"
                    )
                    logger.warning(
                        _("Failed to update package '%s': %s"),
                        package["package_name"],
                        error_msg,
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "winget",
                            "error": error_msg,
                        }
                    )

            except Exception as e:
                logger.error(
                    _("Exception updating package '%s': %s"),
                    package["package_name"],
                    str(e),
                )
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
            result = subprocess.run(  # nosec B603, B607
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

    def _apply_fwupd_updates(self, packages: List[Dict], results: Dict):
        """Apply firmware updates using fwupd."""
        for package in packages:
            device_id = package.get("device_id", "")
            package_name = package["package_name"]

            if not device_id:
                logger.error(
                    _("No device ID found for firmware package: %s"), package_name
                )
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "fwupd",
                        "error": _("No device ID available for firmware update"),
                    }
                )
                continue

            try:
                logger.info(_("Applying firmware update for device: %s"), device_id)

                # Check if system has privilege mode enabled
                # Firmware updates typically require root/admin privileges
                privilege_check = subprocess.run(  # nosec B603, B607
                    ["fwupdmgr", "get-devices", "--json"],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )

                if privilege_check.returncode != 0:
                    error_msg = _(
                        "fwupd not accessible - may require privileged mode or elevated permissions"
                    )
                    logger.warning(error_msg)
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "fwupd",
                            "error": error_msg,
                        }
                    )
                    continue

                # Apply the firmware update
                # We use --assume-yes to avoid interactive prompts
                update_cmd = ["fwupdmgr", "update", device_id, "--assume-yes"]

                logger.info(
                    _("Running firmware update command: %s"), " ".join(update_cmd)
                )

                result = subprocess.run(  # nosec B603, B607
                    update_cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,  # Firmware updates can take a long time
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully updated firmware for: %s"), package_name
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "fwupd",
                            "device_id": device_id,
                            "requires_reboot": True,  # Firmware updates typically require reboot
                        }
                    )
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("Firmware update failed")
                    )
                    logger.error(
                        _("Failed to update firmware for %s: %s"),
                        package_name,
                        error_msg,
                    )

                    # Check for common error conditions
                    if (
                        "not authorized" in error_msg.lower()
                        or "permission" in error_msg.lower()
                    ):
                        error_msg = _(
                            "Firmware update requires elevated privileges - agent may need to run in privileged mode"
                        )
                    elif "no updates" in error_msg.lower():
                        error_msg = _(
                            "No firmware updates available (may have been applied by another process)"
                        )
                    elif "device busy" in error_msg.lower():
                        error_msg = _(
                            "Device is busy - firmware update may be in progress or device is in use"
                        )

                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "fwupd",
                            "error": error_msg,
                            "device_id": device_id,
                        }
                    )

            except subprocess.TimeoutExpired:
                error_msg = _("Firmware update timed out after 10 minutes")
                logger.error(error_msg)
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "fwupd",
                        "error": error_msg,
                        "device_id": device_id,
                    }
                )
            except Exception as e:
                logger.error(
                    _("Exception applying firmware update for %s: %s"),
                    package_name,
                    str(e),
                )
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "fwupd",
                        "error": str(e),
                        "device_id": device_id,
                    }
                )

        return results

    # ===== OS VERSION UPGRADE APPLICATION METHODS =====

    def _apply_ubuntu_release_updates(self, packages: List[Dict], results: Dict):
        """Apply Ubuntu release upgrades using do-release-upgrade."""
        for package in packages:
            package_name = package.get("package_name")
            logger.info(_("Applying Ubuntu release upgrade: %s"), package_name)

            try:
                # First check if do-release-upgrade is available
                check_cmd = ["which", "do-release-upgrade"]
                result = subprocess.run(
                    check_cmd, capture_output=True, timeout=10, check=False
                )
                if result.returncode != 0:
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "ubuntu-release",
                            "error": _("do-release-upgrade not available"),
                        }
                    )
                    continue

                # Run the upgrade non-interactively
                upgrade_cmd = [
                    "do-release-upgrade",
                    "-f",
                    "DistUpgradeViewNonInteractive",
                ]
                logger.info(
                    _("Running Ubuntu release upgrade command: %s"),
                    " ".join(upgrade_cmd),
                )

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,  # 1 hour timeout for OS upgrades
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully applied Ubuntu release upgrade: %s"),
                        package_name,
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": package.get("available_version"),
                            "package_manager": "ubuntu-release",
                        }
                    )
                    results["requires_reboot"] = True
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("Ubuntu release upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "ubuntu-release",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "ubuntu-release",
                        "error": _("Ubuntu release upgrade timed out after 1 hour"),
                    }
                )
            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "ubuntu-release",
                        "error": str(e),
                    }
                )

    def _apply_fedora_release_updates(self, packages: List[Dict], results: Dict):
        """Apply Fedora release upgrades using dnf system-upgrade."""
        for package in packages:
            package_name = package.get("package_name")
            target_version = package.get("available_version")
            logger.info(
                _("Applying Fedora release upgrade: %s to %s"),
                package_name,
                target_version,
            )

            try:
                # Download the upgrade
                download_cmd = [
                    "dnf",
                    "system-upgrade",
                    "download",
                    "--refresh",
                    f"--releasever={target_version}",
                    "--allowerasing",
                    "-y",
                ]
                logger.info(
                    _("Downloading Fedora release upgrade: %s"), " ".join(download_cmd)
                )

                result = subprocess.run(  # nosec B603, B607
                    download_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 minutes for download
                    check=False,
                )

                if result.returncode == 0:
                    # Apply the upgrade (this will schedule a reboot)
                    apply_cmd = ["dnf", "system-upgrade", "reboot"]
                    logger.info(
                        _("Applying Fedora release upgrade: %s"), " ".join(apply_cmd)
                    )

                    apply_result = subprocess.run(  # nosec B603, B607
                        apply_cmd,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )

                    if apply_result.returncode == 0:
                        logger.info(
                            _("Successfully scheduled Fedora release upgrade: %s"),
                            package_name,
                        )
                        results["updated_packages"].append(
                            {
                                "package_name": package_name,
                                "old_version": package.get("current_version"),
                                "new_version": target_version,
                                "package_manager": "fedora-release",
                            }
                        )
                        results["requires_reboot"] = True
                    else:
                        error_msg = (
                            apply_result.stderr.strip()
                            if apply_result.stderr
                            else _("Fedora upgrade apply failed")
                        )
                        results["failed_packages"].append(
                            {
                                "package_name": package_name,
                                "package_manager": "fedora-release",
                                "error": error_msg,
                            }
                        )
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("Fedora upgrade download failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "fedora-release",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "fedora-release",
                        "error": _("Fedora release upgrade timed out"),
                    }
                )
            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "fedora-release",
                        "error": str(e),
                    }
                )

    def _apply_opensuse_release_updates(self, packages: List[Dict], results: Dict):
        """Apply openSUSE release upgrades using zypper dist-upgrade."""
        for package in packages:
            package_name = package.get("package_name")
            logger.info(_("Applying openSUSE release upgrade: %s"), package_name)

            try:
                upgrade_cmd = [
                    "zypper",
                    "dist-upgrade",
                    "--auto-agree-with-licenses",
                    "--no-confirm",
                ]
                logger.info(
                    _("Running openSUSE upgrade command: %s"), " ".join(upgrade_cmd)
                )

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,  # 1 hour timeout
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully applied openSUSE release upgrade: %s"),
                        package_name,
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": package.get("available_version"),
                            "package_manager": "opensuse-release",
                        }
                    )
                    results["requires_reboot"] = True
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("openSUSE release upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "opensuse-release",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "opensuse-release",
                        "error": _("openSUSE release upgrade timed out after 1 hour"),
                    }
                )
            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "opensuse-release",
                        "error": str(e),
                    }
                )

    def _apply_macos_upgrade_updates(self, packages: List[Dict], results: Dict):
        """Apply macOS version upgrades using softwareupdate."""
        for package in packages:
            package_name = package.get("package_name")
            available_version = package.get("available_version")
            logger.info(_("Applying macOS upgrade: %s"), available_version)

            try:
                # Install the macOS upgrade
                upgrade_cmd = [
                    "softwareupdate",
                    "--install",
                    available_version,
                    "--restart",
                ]
                logger.info(
                    _("Running macOS upgrade command: %s"), " ".join(upgrade_cmd)
                )

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=7200,  # 2 hours timeout for macOS upgrades
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully applied macOS upgrade: %s"), available_version
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": available_version,
                            "package_manager": "macos-upgrade",
                        }
                    )
                    results["requires_reboot"] = True
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("macOS upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "macos-upgrade",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "macos-upgrade",
                        "error": _("macOS upgrade timed out after 2 hours"),
                    }
                )
            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "macos-upgrade",
                        "error": str(e),
                    }
                )

    def _apply_windows_upgrade_updates(self, packages: List[Dict], results: Dict):
        """Apply Windows version upgrades using PowerShell."""
        for package in packages:
            package_name = package.get("package_name")
            available_version = package.get("available_version")
            logger.info(_("Applying Windows upgrade: %s"), available_version)

            try:
                # PowerShell command to install Windows feature updates
                powershell_cmd = f"""
                Install-WindowsUpdate -Title "{available_version}" -AcceptAll -AutoReboot
                """

                upgrade_cmd = ["powershell", "-Command", powershell_cmd]
                logger.info(_("Running Windows upgrade command"))

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=7200,  # 2 hours timeout for Windows upgrades
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully applied Windows upgrade: %s"), available_version
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": available_version,
                            "package_manager": "windows-upgrade",
                        }
                    )
                    results["requires_reboot"] = True
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("Windows upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "windows-upgrade",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "windows-upgrade",
                        "error": _("Windows upgrade timed out after 2 hours"),
                    }
                )
            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "windows-upgrade",
                        "error": str(e),
                    }
                )

    def _apply_openbsd_upgrade_updates(self, packages: List[Dict], results: Dict):
        """Apply OpenBSD version upgrades using sysupgrade."""
        for package in packages:
            package_name = package.get("package_name")
            logger.info(_("Applying OpenBSD upgrade: %s"), package_name)

            try:
                # Run sysupgrade
                upgrade_cmd = ["sysupgrade"]
                logger.info(
                    _("Running OpenBSD sysupgrade command: %s"), " ".join(upgrade_cmd)
                )

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 minutes timeout
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully applied OpenBSD upgrade: %s"), package_name
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": package.get("available_version"),
                            "package_manager": "openbsd-upgrade",
                        }
                    )
                    results["requires_reboot"] = True
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("OpenBSD upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "openbsd-upgrade",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "openbsd-upgrade",
                        "error": _("OpenBSD upgrade timed out after 30 minutes"),
                    }
                )
            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "openbsd-upgrade",
                        "error": str(e),
                    }
                )

    def _apply_freebsd_upgrade_updates(self, packages: List[Dict], results: Dict):
        """Apply FreeBSD version upgrades using freebsd-update."""
        for package in packages:
            package_name = package.get("package_name")
            logger.info(_("Applying FreeBSD upgrade: %s"), package_name)

            try:
                # Run freebsd-update upgrade and install
                upgrade_cmd = ["freebsd-update", "upgrade", "-r", "RELEASE"]
                logger.info(
                    _("Running FreeBSD upgrade command: %s"), " ".join(upgrade_cmd)
                )

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 minutes for upgrade
                    check=False,
                )

                if result.returncode == 0:
                    # Install the upgrade
                    install_cmd = ["freebsd-update", "install"]
                    install_result = subprocess.run(  # nosec B603, B607
                        install_cmd,
                        capture_output=True,
                        text=True,
                        timeout=1800,  # 30 minutes for install
                        check=False,
                    )

                    if install_result.returncode == 0:
                        logger.info(
                            _("Successfully applied FreeBSD upgrade: %s"), package_name
                        )
                        results["updated_packages"].append(
                            {
                                "package_name": package_name,
                                "old_version": package.get("current_version"),
                                "new_version": package.get("available_version"),
                                "package_manager": "freebsd-upgrade",
                            }
                        )
                        results["requires_reboot"] = True
                    else:
                        error_msg = (
                            install_result.stderr.strip()
                            if install_result.stderr
                            else _("FreeBSD upgrade install failed")
                        )
                        results["failed_packages"].append(
                            {
                                "package_name": package_name,
                                "package_manager": "freebsd-upgrade",
                                "error": error_msg,
                            }
                        )
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("FreeBSD upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "freebsd-upgrade",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "freebsd-upgrade",
                        "error": _("FreeBSD upgrade timed out"),
                    }
                )
            except Exception as e:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "freebsd-upgrade",
                        "error": str(e),
                    }
                )

    # OS-Level System Update Detection Methods

    def _detect_windows_system_updates(self):
        """Detect Windows system updates from Windows Update using PowerShell."""
        try:
            logger.debug(_("Detecting Windows system updates"))

            # PowerShell command to get Windows Updates
            # This is more reliable than wuauclt which is deprecated
            powershell_cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                """
                try {
                    # Import the module for Windows Update
                    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
                        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
                        $updates = Get-WUList -MicrosoftUpdate
                    } else {
                        # Fallback to WUApiLib COM object
                        $session = New-Object -ComObject Microsoft.Update.Session
                        $searcher = $session.CreateUpdateSearcher()
                        $searchResult = $searcher.Search("IsInstalled=0")
                        $updates = $searchResult.Updates
                    }

                    $updateList = @()
                    foreach($update in $updates) {
                        $categories = @()
                        if ($update.Categories) {
                            foreach($cat in $update.Categories) {
                                $categories += @{ Name = $cat.Name }
                            }
                        }

                        $updateInfo = @{
                            Title = $update.Title
                            Description = $update.Description
                            Categories = $categories
                            IsDownloaded = $update.IsDownloaded
                            SizeInBytes = $update.MaxDownloadSize
                            SeverityText = if($update.MsrcSeverity) { $update.MsrcSeverity } else { "Unknown" }
                            UpdateID = $update.Identity.UpdateID
                            RevisionNumber = $update.Identity.RevisionNumber
                        }
                        $updateList += $updateInfo
                    }

                    $updateList | ConvertTo-Json -Depth 3
                } catch {
                    Write-Output "ERROR: $($_.Exception.Message)"
                }
                """,
            ]

            result = subprocess.run(  # nosec B603, B607
                powershell_cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
                ),
            )

            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()

                if output.startswith("ERROR:"):
                    logger.warning(_("Windows Update detection failed: %s"), output[6:])
                    return

                try:
                    updates_data = json.loads(output) if output != "null" else []
                    if not isinstance(updates_data, list):
                        updates_data = [updates_data] if updates_data else []

                    for update in updates_data:
                        # Determine if this is a security update
                        categories = update.get("Categories", [])
                        severity = update.get("SeverityText", "").lower()
                        title = update.get("Title", "").lower()

                        # Handle both string and list formats for categories
                        if isinstance(categories, list):
                            category_text = " ".join(
                                [
                                    (
                                        cat.get("Name", "")
                                        if isinstance(cat, dict)
                                        else str(cat)
                                    )
                                    for cat in categories
                                ]
                            ).lower()
                        else:
                            category_text = str(categories).lower()

                        is_security = (
                            "security" in category_text
                            or "critical" in severity
                            or "important" in severity
                            or "security" in title
                            or "cumulative" in title
                            or "kb" in title
                        )

                        # Default to security if we can't determine (as requested)
                        update_type = "security" if is_security else "regular"

                        self.available_updates.append(
                            {
                                "package_name": update.get("Title", "Unknown Update"),
                                "current_version": "installed",
                                "available_version": f"Rev.{update.get('RevisionNumber', 'unknown')}",
                                "package_manager": "Windows Update",
                                "update_type": update_type,
                                "description": update.get("Description", ""),
                                "size": self._format_size_mb(
                                    update.get("SizeInBytes", 0)
                                ),
                                "categories": update.get("Categories", ""),
                                "severity": update.get("SeverityText", "Unknown"),
                                "is_downloaded": update.get("IsDownloaded", False),
                                "update_id": update.get("UpdateID", ""),
                            }
                        )

                    logger.debug(
                        _("Found %d Windows system updates"), len(updates_data)
                    )

                except json.JSONDecodeError as e:
                    logger.warning(
                        _("Failed to parse Windows Update output: %s"), str(e)
                    )

        except subprocess.TimeoutExpired:
            logger.warning(_("Windows Update detection timed out"))
        except Exception as e:
            logger.error(_("Failed to detect Windows system updates: %s"), str(e))

    def _detect_macos_system_updates(self):
        """Detect macOS system updates from Software Update."""
        try:
            logger.debug(_("Detecting macOS system updates"))

            # Use softwareupdate command to list available updates
            result = subprocess.run(  # nosec B603, B607
                ["softwareupdate", "--list", "--no-scan"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                output = result.stdout

                # Parse the output to extract update information
                lines = output.split("\n")

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Look for update entries (usually start with *)
                    if line.startswith("*"):
                        # Extract update name and details
                        parts = line[1:].strip().split("-", 1)
                        if len(parts) >= 2:
                            update_name = parts[0].strip()
                            description = parts[1].strip()

                            # Determine if this is a security update
                            name_lower = update_name.lower()
                            desc_lower = description.lower()

                            is_security = (
                                "security" in name_lower
                                or "security" in desc_lower
                                or "safari"
                                in name_lower  # Safari updates often security-related
                                or "xprotect"
                                in name_lower  # XProtect is security software
                                or "malware" in desc_lower
                                or "vulnerability" in desc_lower
                            )

                            # Default to security as requested
                            update_type = "security" if is_security else "security"

                            self.available_updates.append(
                                {
                                    "package_name": update_name,
                                    "current_version": "installed",
                                    "available_version": "latest",
                                    "package_manager": "macOS Update",
                                    "update_type": update_type,
                                    "description": description,
                                    "size": 0,  # Size not available from softwareupdate --list
                                }
                            )

                logger.debug(
                    _("Found %d macOS system updates"),
                    len(
                        [
                            u
                            for u in self.available_updates
                            if u.get("package_manager") == "macOS Update"
                        ]
                    ),
                )

            else:
                logger.warning(
                    _("softwareupdate command failed with exit code %d"),
                    result.returncode,
                )
                if result.stderr:
                    logger.warning(_("softwareupdate stderr: %s"), result.stderr)

        except subprocess.TimeoutExpired:
            logger.warning(_("macOS system update detection timed out"))
        except Exception as e:
            logger.error(_("Failed to detect macOS system updates: %s"), str(e))

    def _detect_openbsd_system_updates(self):
        """Detect OpenBSD system updates using syspatch."""
        try:
            logger.debug(_("Detecting OpenBSD system updates"))

            # Check available syspatches
            result = subprocess.run(  # nosec B603, B607
                ["syspatch", "-c"],  # -c for check only
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )

            if result.returncode == 0:
                patches = result.stdout.strip().split("\n")

                for patch in patches:
                    patch = patch.strip()
                    if not patch:
                        continue

                    # syspatch -c lists available patches, one per line
                    # All syspatch updates are security/system updates by nature
                    self.available_updates.append(
                        {
                            "package_name": f"syspatch-{patch}",
                            "current_version": "not installed",
                            "available_version": patch,
                            "package_manager": "syspatch",
                            "is_security_update": True,  # All syspatches are security updates
                            "is_system_update": True,  # All syspatches are also system updates
                            "requires_reboot": True,  # Most syspatches require reboot
                            "update_size_bytes": None,  # Size not available from syspatch -c
                            "source": "OpenBSD base system",
                            "repository": "syspatch",
                        }
                    )

                logger.debug(
                    _("Found %d OpenBSD system patches"),
                    len(
                        [
                            u
                            for u in self.available_updates
                            if u.get("package_manager") == "syspatch"
                        ]
                    ),
                )

            elif result.returncode == 1:
                # syspatch returns 1 when no patches are available
                logger.debug(_("No OpenBSD system patches available"))
            else:
                logger.warning(
                    _("syspatch command failed with exit code %d"), result.returncode
                )
                if result.stderr:
                    logger.warning(_("syspatch stderr: %s"), result.stderr)

        except subprocess.TimeoutExpired:
            logger.warning(_("OpenBSD system update detection timed out"))
        except FileNotFoundError:
            logger.debug(_("syspatch not available on this system"))
        except Exception as e:
            logger.error(_("Failed to detect OpenBSD system updates: %s"), str(e))

    def _detect_linux_system_updates(self):
        """Detect Linux distribution system updates (separate from package updates)."""
        try:
            logger.debug(_("Detecting Linux system/kernel updates"))

            # Check if we're on a Debian/Ubuntu system
            if os.path.exists("/etc/debian_version"):
                self._detect_debian_system_updates()
            elif os.path.exists("/etc/redhat-release") or os.path.exists(
                "/etc/fedora-release"
            ):
                self._detect_redhat_system_updates()
            elif os.path.exists("/etc/arch-release"):
                self._detect_arch_system_updates()
            elif os.path.exists("/etc/SUSE-brand") or os.path.exists(
                "/etc/SuSE-release"
            ):
                self._detect_suse_system_updates()

        except Exception as e:
            logger.error(_("Failed to detect Linux system updates: %s"), str(e))

    def _detect_debian_system_updates(self):
        """Detect Debian/Ubuntu system-level updates."""
        try:
            # Look for kernel and system updates specifically
            result = subprocess.run(  # nosec B603, B607
                ["apt", "list", "--upgradable"],
                capture_output=True,
                check=False,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")[1:]  # Skip header

                for line in lines:
                    if not line.strip():
                        continue

                    parts = line.split("/")
                    if len(parts) >= 2:
                        package_name = parts[0]

                        # Filter for system-level packages
                        if any(
                            keyword in package_name
                            for keyword in [
                                "linux-image",
                                "linux-headers",
                                "linux-generic",
                                "ubuntu-release-upgrader",
                                "update-manager",
                                "systemd",
                                "udev",
                                "dbus",
                                "init",
                            ]
                        ):
                            # This is a system update
                            version_info = parts[1].split(" ")
                            available_version = (
                                version_info[0] if version_info else "unknown"
                            )

                            # Check if it's security-related
                            is_security = self._is_apt_security_update(package_name)
                            update_type = "security" if is_security else "system"

                            self.available_updates.append(
                                {
                                    "package_name": package_name,
                                    "current_version": "installed",
                                    "available_version": available_version,
                                    "package_manager": "Linux System Update",
                                    "update_type": update_type,
                                    "description": f"Linux system package update: {package_name}",
                                    "size": 0,
                                }
                            )

        except Exception as e:
            logger.debug(_("Failed to detect Debian system updates: %s"), str(e))

    def _detect_redhat_system_updates(self):
        """Detect RedHat/Fedora system-level updates."""
        try:
            # Use dnf if available, otherwise yum
            cmd = "dnf" if self._command_exists("dnf") else "yum"

            result = subprocess.run(  # nosec B603, B607
                [cmd, "check-update", "--security"],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )

            # yum/dnf returns 100 when updates are available
            if result.returncode in (100, 0):
                lines = result.stdout.split("\n")

                for line in lines:
                    if not line.strip() or line.startswith("Last metadata"):
                        continue

                    parts = line.split()
                    if len(parts) >= 3:
                        package_name = parts[0]
                        available_version = parts[1]

                        # Filter for system packages
                        if any(
                            keyword in package_name
                            for keyword in [
                                "kernel",
                                "systemd",
                                "glibc",
                                "rpm",
                                "yum",
                                "dnf",
                            ]
                        ):
                            self.available_updates.append(
                                {
                                    "package_name": package_name,
                                    "current_version": "installed",
                                    "available_version": available_version,
                                    "package_manager": "Linux System Update",
                                    "update_type": "security",  # From --security flag
                                    "description": f"Linux system package update: {package_name}",
                                    "size": 0,
                                }
                            )

        except Exception as e:
            logger.debug(_("Failed to detect RedHat system updates: %s"), str(e))

    def _detect_arch_system_updates(self):
        """Detect Arch Linux system-level updates."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["pacman", "-Sup", "--print-format", "%n %v"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")

                for line in lines:
                    if not line.strip():
                        continue

                    parts = line.split()
                    if len(parts) >= 2:
                        package_name = parts[0]
                        available_version = parts[1]

                        # Filter for system packages
                        if any(
                            keyword in package_name
                            for keyword in [
                                "linux",
                                "kernel",
                                "systemd",
                                "glibc",
                                "pacman",
                            ]
                        ):
                            self.available_updates.append(
                                {
                                    "package_name": package_name,
                                    "current_version": "installed",
                                    "available_version": available_version,
                                    "package_manager": "Linux System Update",
                                    "update_type": "system",
                                    "description": f"Linux system package update: {package_name}",
                                    "size": 0,
                                }
                            )

        except Exception as e:
            logger.debug(_("Failed to detect Arch system updates: %s"), str(e))

    def _detect_suse_system_updates(self):
        """Detect SUSE system-level updates."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["zypper", "list-updates", "--type", "package"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")

                for line in lines:
                    if not line.strip() or line.startswith("S |"):
                        continue

                    parts = line.split("|")
                    if len(parts) >= 4:
                        package_name = parts[2].strip()
                        available_version = parts[4].strip()

                        # Filter for system packages
                        if any(
                            keyword in package_name
                            for keyword in [
                                "kernel",
                                "systemd",
                                "glibc",
                                "zypper",
                                "rpm",
                            ]
                        ):
                            self.available_updates.append(
                                {
                                    "package_name": package_name,
                                    "current_version": "installed",
                                    "available_version": available_version,
                                    "package_manager": "Linux System Update",
                                    "update_type": "system",
                                    "description": f"Linux system package update: {package_name}",
                                    "size": 0,
                                }
                            )

        except Exception as e:
            logger.debug(_("Failed to detect SUSE system updates: %s"), str(e))

    def _format_size_mb(self, size_bytes):
        """Format size in bytes to MB string."""
        if size_bytes == 0:
            return "0.0 MB"
        size_mb = size_bytes / 1024 / 1024
        return f"{size_mb:.1f} MB"

    # ===== OS VERSION UPGRADE DETECTION =====

    def _detect_os_version_upgrades(self):
        """
        Detect available OS version upgrades across all platforms.
        All OS upgrades are classified as security updates.
        """
        logger.debug(_("Detecting OS version upgrades"))

        if self.platform == "linux":
            self._detect_linux_version_upgrades()
        elif self.platform == "darwin":
            self._detect_macos_version_upgrades()
        elif self.platform == "windows":
            self._detect_windows_version_upgrades()
        elif self.platform in ["freebsd", "openbsd", "netbsd"]:
            self._detect_bsd_version_upgrades()

    def _detect_linux_version_upgrades(self):
        """Detect Linux distribution version upgrades."""
        try:
            # Check for Ubuntu release upgrades
            if os.path.exists("/etc/debian_version"):
                self._detect_ubuntu_release_upgrades()

            # Check for Fedora version upgrades
            elif os.path.exists("/etc/fedora-release"):
                self._detect_fedora_version_upgrades()

            # Check for openSUSE version upgrades
            elif os.path.exists("/etc/SUSE-brand"):
                self._detect_opensuse_version_upgrades()

            # Check for Arch Linux upgrades (rolling release)
            elif os.path.exists("/etc/arch-release"):
                # Arch is rolling release, no major version upgrades
                pass

        except Exception as e:
            logger.error(_("Failed to detect Linux version upgrades: %s"), str(e))

    def _detect_ubuntu_release_upgrades(self):
        """Detect Ubuntu release upgrades using do-release-upgrade."""
        try:
            # Check if do-release-upgrade is available
            result = subprocess.run(
                ["which", "do-release-upgrade"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                return

            # Check for available release upgrades
            result = subprocess.run(
                ["do-release-upgrade", "--check-dist-upgrade-only", "--quiet"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                # Parse current version
                with open("/etc/lsb-release", "r", encoding="utf-8") as f:
                    content = f.read()
                    current_version = None
                    for line in content.split("\n"):
                        if line.startswith("DISTRIB_RELEASE="):
                            current_version = line.split("=")[1].strip('"')
                            break

                if current_version:
                    # Extract available version from output
                    # do-release-upgrade output format varies, so we'll create a generic upgrade
                    available_version = "Next LTS"  # Generic for now

                    self.available_updates.append(
                        {
                            "package_name": "ubuntu-release",
                            "current_version": current_version,
                            "available_version": available_version,
                            "package_manager": "ubuntu-release",
                            "is_security_update": True,  # Always security for OS upgrades
                            "is_system_update": True,
                            "update_size": 2000000000,  # ~2GB estimate
                            "repository": "ubuntu-release",
                            "requires_reboot": True,
                        }
                    )

        except Exception as e:
            logger.error(_("Failed to detect Ubuntu release upgrades: %s"), str(e))

    def _detect_fedora_version_upgrades(self):
        """Detect Fedora version upgrades using dnf system-upgrade."""
        try:
            # Check if dnf system-upgrade plugin is available
            result = subprocess.run(
                ["dnf", "system-upgrade", "--help"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                return

            # Get current Fedora version
            with open("/etc/fedora-release", "r", encoding="utf-8") as f:
                content = f.read()
                match = re.search(r"Fedora (\d+)", content)
                if not match:
                    return
                current_version = match.group(1)

            # Check for newer Fedora releases (simple check for next version)
            next_version = str(int(current_version) + 1)

            # Check if the next version exists (this is a simplified check)
            result = subprocess.run(
                [
                    "dnf",
                    "system-upgrade",
                    "download",
                    "--refresh",
                    "--releasever=" + next_version,
                    "--assumeno",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # If the command doesn't immediately fail, there might be an upgrade available
            if (
                "No such file or directory" not in result.stderr
                and "Not found" not in result.stderr
            ):
                self.available_updates.append(
                    {
                        "package_name": "fedora-release",
                        "current_version": current_version,
                        "available_version": next_version,
                        "package_manager": "fedora-release",
                        "is_security_update": True,  # Always security for OS upgrades
                        "is_system_update": True,
                        "update_size": 1500000000,  # ~1.5GB estimate
                        "repository": "fedora-release",
                        "requires_reboot": True,
                    }
                )

        except Exception as e:
            logger.error(_("Failed to detect Fedora version upgrades: %s"), str(e))

    def _detect_opensuse_version_upgrades(self):
        """Detect openSUSE version upgrades."""
        try:
            # Get current openSUSE version
            result = subprocess.run(
                ["zypper", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                return

            # Check for distribution upgrades
            result = subprocess.run(
                ["zypper", "dist-upgrade", "--dry-run", "--no-confirm"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if (
                "upgrade" in result.stdout.lower()
                and "packages" in result.stdout.lower()
            ):
                # Parse version info (simplified)
                current_version = "Current"
                available_version = "Latest"

                self.available_updates.append(
                    {
                        "package_name": "opensuse-release",
                        "current_version": current_version,
                        "available_version": available_version,
                        "package_manager": "opensuse-release",
                        "is_security_update": True,  # Always security for OS upgrades
                        "is_system_update": True,
                        "update_size": 1000000000,  # ~1GB estimate
                        "repository": "opensuse-release",
                        "requires_reboot": True,
                    }
                )

        except Exception as e:
            logger.error(_("Failed to detect openSUSE version upgrades: %s"), str(e))

    def _detect_macos_version_upgrades(self):
        """Detect macOS version upgrades using softwareupdate."""
        try:
            # Check for major macOS upgrades
            result = subprocess.run(
                ["softwareupdate", "--list", "--include-config-data"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines:
                    # Look for macOS installer packages
                    if "macOS" in line and ("Installer" in line or "Upgrade" in line):
                        # Parse the line to extract version info
                        # Format is usually: "* macOS Something-Version"
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            package_name = "macos-upgrade"
                            available_version = " ".join(
                                parts[1:]
                            )  # Everything after the *

                            # Get current macOS version
                            current_result = subprocess.run(
                                ["sw_vers", "-productVersion"],
                                capture_output=True,
                                text=True,
                                timeout=10,
                                check=False,
                            )
                            current_version = (
                                current_result.stdout.strip()
                                if current_result.returncode == 0
                                else "Unknown"
                            )

                            self.available_updates.append(
                                {
                                    "package_name": package_name,
                                    "current_version": current_version,
                                    "available_version": available_version,
                                    "package_manager": "macos-upgrade",
                                    "is_security_update": True,  # Always security for OS upgrades
                                    "is_system_update": True,
                                    "update_size": 8000000000,  # ~8GB estimate for macOS
                                    "repository": "apple-software-update",
                                    "requires_reboot": True,
                                }
                            )

        except Exception as e:
            logger.error(_("Failed to detect macOS version upgrades: %s"), str(e))

    def _detect_windows_version_upgrades(self):
        """Detect Windows version upgrades using Windows Update."""
        try:
            # PowerShell command to check for feature updates (major version upgrades)
            powershell_cmd = """
            Get-WUList -MicrosoftUpdate | Where-Object {
                $_.Title -match "Feature update|Version upgrade|Windows 11|Windows 10" -and
                $_.Size -gt 1GB
            } | Select-Object Title, Size | ConvertTo-Json
            """

            result = subprocess.run(
                ["powershell", "-Command", powershell_cmd],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                try:
                    updates = json.loads(result.stdout)
                    if not isinstance(updates, list):
                        updates = [updates]

                    for update in updates:
                        title = update.get("Title", "")
                        size = update.get("Size", 0)

                        # Get current Windows version
                        version_result = subprocess.run(
                            [
                                "powershell",
                                "-Command",
                                "(Get-ComputerInfo).WindowsVersion",
                            ],
                            capture_output=True,
                            text=True,
                            timeout=10,
                            check=False,
                        )
                        current_version = (
                            version_result.stdout.strip()
                            if version_result.returncode == 0
                            else "Unknown"
                        )

                        self.available_updates.append(
                            {
                                "package_name": "windows-feature-update",
                                "current_version": current_version,
                                "available_version": title,
                                "package_manager": "windows-upgrade",
                                "is_security_update": True,  # Always security for OS upgrades
                                "is_system_update": True,
                                "update_size": size,
                                "repository": "windows-update",
                                "requires_reboot": True,
                            }
                        )

                except json.JSONDecodeError:
                    logger.debug(_("Could not parse Windows upgrade JSON output"))

        except Exception as e:
            logger.error(_("Failed to detect Windows version upgrades: %s"), str(e))

    def _detect_bsd_version_upgrades(self):
        """Detect BSD version upgrades."""
        try:
            if self.platform == "openbsd":
                self._detect_openbsd_version_upgrades()
            elif self.platform == "freebsd":
                self._detect_freebsd_version_upgrades()

        except Exception as e:
            logger.error(_("Failed to detect BSD version upgrades: %s"), str(e))

    def _detect_openbsd_version_upgrades(self):
        """Detect OpenBSD version upgrades using sysupgrade."""
        try:
            # Check if sysupgrade is available
            result = subprocess.run(
                ["which", "sysupgrade"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                return

            # Check for available upgrades
            result = subprocess.run(
                ["sysupgrade", "-n"],  # -n for dry run
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and "upgrade" in result.stdout.lower():
                # Get current version
                version_result = subprocess.run(
                    ["uname", "-r"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                current_version = (
                    version_result.stdout.strip()
                    if version_result.returncode == 0
                    else "Unknown"
                )

                self.available_updates.append(
                    {
                        "package_name": "openbsd-release",
                        "current_version": current_version,
                        "available_version": "Next Release",
                        "package_manager": "openbsd-upgrade",
                        "is_security_update": True,  # Always security for OS upgrades
                        "is_system_update": True,
                        "update_size": 500000000,  # ~500MB estimate
                        "repository": "openbsd-release",
                        "requires_reboot": True,
                    }
                )

        except Exception as e:
            logger.error(_("Failed to detect OpenBSD version upgrades: %s"), str(e))

    def _detect_freebsd_version_upgrades(self):
        """Detect FreeBSD version upgrades using freebsd-update."""
        try:
            # Check for available upgrades
            result = subprocess.run(
                ["freebsd-update", "upgrade", "-r", "RELEASE"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if (
                "upgrade" in result.stdout.lower()
                or "available" in result.stdout.lower()
            ):
                # Get current version
                version_result = subprocess.run(
                    ["uname", "-r"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                current_version = (
                    version_result.stdout.strip()
                    if version_result.returncode == 0
                    else "Unknown"
                )

                self.available_updates.append(
                    {
                        "package_name": "freebsd-release",
                        "current_version": current_version,
                        "available_version": "Next Release",
                        "package_manager": "freebsd-upgrade",
                        "is_security_update": True,  # Always security for OS upgrades
                        "is_system_update": True,
                        "update_size": 800000000,  # ~800MB estimate
                        "repository": "freebsd-release",
                        "requires_reboot": True,
                    }
                )

        except Exception as e:
            logger.error(_("Failed to detect FreeBSD version upgrades: %s"), str(e))
