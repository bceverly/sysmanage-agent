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

from __future__ import annotations

import json
import logging
import re
import subprocess  # nosec B404
from typing import (  # pylint: disable=unused-import  # Optional used in child classes
    Any,
    Dict,
    List,
    Optional,
)

# Platform-specific imports
try:
    import pwd  # Unix/macOS only  # pylint: disable=unused-import  # pwd used in other platform modules
except ImportError:
    pwd = None  # Windows

from src.i18n import _

logger = logging.getLogger(__name__)

from .update_detection_base import (  # pylint: disable=wrong-import-position
    UpdateDetectorBase,
)

logger = logging.getLogger(__name__)


class MacOSUpdateDetector(UpdateDetectorBase):
    """macOS-specific update detection methods."""

    def _is_macos_major_upgrade(self, title, version):
        """
        Determine if a macOS update is a major version upgrade vs a patch update.

        Args:
            title: The update title (e.g., "macOS Sequoia 15.7", "macOS Tahoe 26")
            version: The version string (e.g., "15.7", "26.0")

        Returns:
            bool: True if this is a major version upgrade, False if it's a patch update
        """
        try:
            # Get current macOS version
            result = subprocess.run(  # nosec B603, B607
                ["sw_vers", "-productVersion"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                # If we can't determine current version, default to treating as patch update
                return False

            current_version = result.stdout.strip()

            # Extract major version numbers
            try:
                current_major = int(current_version.split(".")[0])

                # Try to extract major version from the available version
                if "." in version:
                    available_major = int(version.split(".")[0])
                else:
                    # Handle cases like "26" or "26.0"
                    available_major = int(float(version))

                # If major versions differ significantly, it's a major upgrade
                # For macOS: 15.x -> 15.y is patch, 15.x -> 16.x+ is major upgrade
                return available_major > current_major

            except (ValueError, IndexError):
                # If we can't parse versions, check the title for known patterns
                # Major upgrades typically have different codenames
                current_codename = (
                    self._get_macos_codename(current_major)
                    if "current_major" in locals()
                    else ""
                )

                # Known major version transitions (approximate)
                major_upgrade_patterns = [
                    "Tahoe",  # macOS 26
                    "Ventura",  # macOS 13
                    "Monterey",  # macOS 12
                    "Big Sur",  # macOS 11
                    "Catalina",  # macOS 10.15
                ]

                # If title contains a different major codename, it's likely a major upgrade
                for pattern in major_upgrade_patterns:
                    if pattern in title and pattern not in current_codename:
                        return True

                return False

        except Exception:
            # Default to treating as patch update if anything goes wrong
            return False

    def _get_macos_codename(self, major_version):
        """Get the codename for a macOS major version."""
        codenames = {
            15: "Sequoia",
            14: "Sonoma",
            13: "Ventura",
            12: "Monterey",
            11: "Big Sur",
            26: "Tahoe",  # Future version
        }
        return codenames.get(major_version, "")

    def _detect_homebrew_updates(self):
        """Detect updates from Homebrew (macOS)."""
        try:
            logger.debug(_("Detecting Homebrew updates"))

            # Find the correct brew path
            brew_cmd = self._get_brew_command()

            # First update Homebrew to get the latest package information
            logger.debug(_("Updating Homebrew package information"))
            # Split brew_cmd in case it contains sudo -u
            brew_args = brew_cmd.split() + ["update"]
            update_result = subprocess.run(  # nosec B603, B607
                brew_args,
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
            # Split brew_cmd in case it contains sudo -u
            brew_args = brew_cmd.split() + ["outdated", "--json=v2"]
            result = subprocess.run(  # nosec B603, B607
                brew_args,
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

        except Exception as error:
            logger.error(_("Failed to detect Homebrew updates: %s"), str(error))

    def _parse_softwareupdate_details(self, details_line):
        """Parse the details line from softwareupdate output.

        Args:
            details_line: A line like 'Title: Name, Version: X.Y.Z, Size: XXXKIB, ...'.

        Returns:
            dict: Parsed fields with keys title, version, size_kb, is_recommended, requires_restart.
        """
        parsed = {
            "title": None,
            "version": "unknown",
            "size_kb": None,
            "is_recommended": False,
            "requires_restart": False,
        }

        if not details_line:
            return parsed

        title_match = re.search(r"Title:\s*([^,]+)", details_line)
        if title_match:
            parsed["title"] = title_match.group(1).strip()

        version_match = re.search(r"Version:\s*([^,]+)", details_line)
        if version_match:
            parsed["version"] = version_match.group(1).strip()

        size_match = re.search(r"Size:\s*(\d+)KiB", details_line)
        if size_match:
            parsed["size_kb"] = int(size_match.group(1))

        parsed["is_recommended"] = "Recommended: YES" in details_line
        parsed["requires_restart"] = "Action: restart" in details_line

        return parsed

    def _collect_current_macos_version(self):
        """Retrieve the current macOS product version string.

        Returns:
            str: The macOS version (e.g. '15.3') or 'unknown' on failure.
        """
        try:
            result = subprocess.run(  # nosec B603, B607
                ["sw_vers", "-productVersion"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:  # nosec B110 # Fallback to unknown on any error
            pass
        return "unknown"

    def _process_softwareupdate_entry(self, label, details_line):
        """Build an update dict from a softwareupdate label and its details line.

        Args:
            label: The label string from the '* Label:' line.
            details_line: The subsequent details line, or empty string if absent.

        Returns:
            dict: An update dict ready to append to available_updates.
        """
        details = self._parse_softwareupdate_details(details_line)

        title = details["title"] if details["title"] else label
        version = details["version"]

        is_major_upgrade = self._is_macos_major_upgrade(title, version)
        current_version = self._collect_current_macos_version()

        return {
            "package_name": title,
            "current_version": current_version,
            "available_version": version,
            "package_manager": (
                "mac_app_store" if not is_major_upgrade else "macos-upgrade"
            ),
            "label": label,
            "size_kb": details["size_kb"],
            "is_security_update": "Security" in label,
            "is_system_update": ("macOS" in title or "Safari" in title)
            and not is_major_upgrade,
            "is_recommended": details["is_recommended"],
            "requires_restart": details["requires_restart"],
        }

    def _detect_macos_app_store_updates(self):
        """Detect Mac App Store updates."""
        try:
            logger.debug(_("Detecting Mac App Store updates"))

            result = subprocess.run(  # nosec B603, B607
                ["softwareupdate", "--list"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0 or not result.stdout.strip():
                return

            lines = result.stdout.strip().split("\n")
            i = 0
            while i < len(lines):
                line = lines[i]
                i += 1
                if "*" not in line or "Label:" not in line:
                    continue
                label_match = re.match(r"\s*\*\s+Label:\s+(.+)", line)
                if not label_match:
                    continue
                label = label_match.group(1).strip()
                details_line = ""
                if i < len(lines) and lines[i].strip().startswith("Title:"):
                    details_line = lines[i].strip()
                    i += 1
                update = self._process_softwareupdate_entry(label, details_line)
                self.available_updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Mac App Store updates: %s"), str(error))

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

        except Exception as error:
            logger.error(_("Failed to detect MacPorts updates: %s"), str(error))

    # Windows Update Detection Implementations

    def _apply_homebrew_updates(self, packages: List[Dict], results: Dict):
        """Apply Homebrew updates."""
        # Get the correct brew command with sudo -u support if needed
        brew_cmd = self._get_brew_command()

        for package in packages:
            try:
                # Determine if it's a cask or formula
                source = package.get("source", "homebrew_core")
                if "cask" in source:
                    cmd_args = ["upgrade", "--cask", package["package_name"]]
                else:
                    cmd_args = ["upgrade", package["package_name"]]

                # Split brew_cmd in case it contains sudo -u
                cmd = brew_cmd.split() + cmd_args

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

            except Exception as error:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "homebrew",
                        "error": str(error),
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
            except Exception as error:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "macos-upgrade",
                        "error": str(error),
                    }
                )

    def _is_macos_upgrade_line(self, line: str) -> bool:
        """Check if a softwareupdate output line is a macOS upgrade.

        Args:
            line: A line from softwareupdate --list output.

        Returns:
            True if line represents a macOS upgrade, False otherwise.
        """
        return "macOS" in line and ("Installer" in line or "Upgrade" in line)

    def _get_current_macos_version(self) -> str:
        """Get the current macOS version using sw_vers.

        Returns:
            Current macOS version string, or "Unknown" if unavailable.
        """
        current_result = subprocess.run(  # nosec B603, B607
            ["sw_vers", "-productVersion"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if current_result.returncode == 0:
            return current_result.stdout.strip()
        return "Unknown"

    def _parse_macos_upgrade_line(self, line: str) -> str | None:
        """Parse a macOS upgrade line to extract version info.

        Args:
            line: A line from softwareupdate output.

        Returns:
            Available version string, or None if unparseable.
        """
        parts = line.strip().split()
        if len(parts) < 2:
            return None
        # Everything after the * is the version info
        return " ".join(parts[1:])

    def _add_macos_upgrade_update(self, available_version: str):
        """Add a macOS upgrade to available_updates.

        Args:
            available_version: The available macOS version string.
        """
        current_version = self._get_current_macos_version()
        self.available_updates.append(
            {
                "package_name": "macos-upgrade",
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

    def _detect_macos_version_upgrades(self):
        """Detect macOS version upgrades using softwareupdate."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["softwareupdate", "--list", "--include-config-data"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return

            for line in result.stdout.split("\n"):
                if not self._is_macos_upgrade_line(line):
                    continue

                available_version = self._parse_macos_upgrade_line(line)
                if available_version:
                    self._add_macos_upgrade_update(available_version)

        except Exception as error:
            logger.error(_("Failed to detect macOS version upgrades: %s"), str(error))

    def _install_with_brew(self, package_name: str) -> Dict[str, Any]:
        """Install package using Homebrew package manager."""
        try:
            # Get the correct brew command with sudo -u support if needed
            brew_cmd = self._get_brew_command()
            # Split brew_cmd in case it contains sudo -u
            cmd = brew_cmd.split() + ["install", package_name]

            result = subprocess.run(  # nosec B603, B607
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            # Link the package to create symlinks in /opt/homebrew/bin or /usr/local/bin
            link_cmd = brew_cmd.split() + ["link", package_name]
            subprocess.run(  # nosec B603, B607
                link_cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

    def detect_updates(self):
        """Detect all updates from macOS sources."""
        # Mac App Store updates (includes both system updates and OS upgrades with proper categorization)
        self._detect_macos_app_store_updates()

        # Package managers
        managers = self._detect_package_managers()
        if "homebrew" in managers:
            self._detect_homebrew_updates()
        if "macports" in managers:
            self._detect_macports_updates()
