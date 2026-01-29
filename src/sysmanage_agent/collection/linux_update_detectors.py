#!/usr/bin/env python3
"""
Linux Update Detection Helper Module

This module contains methods for detecting updates on Linux systems
across different package managers.
"""

import json
import logging
import subprocess  # nosec B404
from typing import Optional

from src.i18n import _

logger = logging.getLogger(__name__)


class LinuxUpdateDetector:
    """Helper class for detecting Linux updates across different package managers."""

    def __init__(self, is_system_package_callback):
        """
        Initialize the detector.

        Args:
            is_system_package_callback: Callback function to determine if a package is a system package
        """
        self.is_system_package_linux = is_system_package_callback

    def detect_apt_updates(self):
        """Detect updates from APT."""
        updates = []
        try:
            logger.debug(_("Detecting APT updates"))

            # Update package list
            subprocess.run(  # nosec B603, B607
                ["apt-get", "update"],
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
                updates = self._parse_apt_upgradable_output(result.stdout)

        except Exception as error:
            logger.error(_("Failed to detect APT updates: %s"), str(error))

        return updates

    def _parse_apt_upgradable_output(self, stdout: str) -> list:
        """Parse the output of 'apt list --upgradable' into update records."""
        updates = []
        for line in stdout.strip().split("\n"):
            if "/" not in line or "[upgradable" not in line.lower():
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            package_name = parts[0].split("/")[0]
            available_version = parts[1]
            current_version = parts[5].rstrip("]") if len(parts) > 5 else "unknown"

            updates.append(
                {
                    "package_name": package_name,
                    "current_version": current_version,
                    "available_version": available_version,
                    "package_manager": "apt",
                    "is_security_update": "-security" in line,
                    "is_system_update": self.is_system_package_linux(package_name),
                }
            )

        return updates

    def detect_snap_updates(self):
        """Detect updates from Snap."""
        updates = []
        try:
            logger.debug(_("Detecting Snap updates"))

            result = subprocess.run(  # nosec B603, B607
                ["snap", "refresh", "--list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        update = {
                            "package_name": parts[0],
                            "current_version": parts[1],
                            "available_version": parts[3],
                            "package_manager": "snap",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Snap updates: %s"), str(error))

        return updates

    def detect_flatpak_updates(self):
        """Detect updates from Flatpak."""
        updates = []
        try:
            logger.debug(_("Detecting Flatpak updates"))

            result = subprocess.run(  # nosec B603, B607
                ["flatpak", "update", "--appstream"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

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
                            "current_version": "unknown",
                            "available_version": parts[2],
                            "package_manager": "flatpak",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Flatpak updates: %s"), str(error))

        return updates

    def detect_dnf_updates(self):
        """Detect updates from DNF."""
        updates = []
        try:
            logger.debug(_("Detecting DNF updates"))

            result = subprocess.run(  # nosec B603, B607
                ["dnf", "check-update", "--quiet"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 3 and not line.startswith("Last"):
                        package_name = parts[0].split(".")[0]
                        available_version = parts[1]
                        repository = parts[2]

                        update = {
                            "package_name": package_name,
                            "current_version": "unknown",
                            "available_version": available_version,
                            "package_manager": "dnf",
                            "repository": repository,
                            "is_security_update": "security" in repository.lower(),
                            "is_system_update": self.is_system_package_linux(
                                package_name
                            ),
                        }
                        updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect DNF updates: %s"), str(error))

        return updates

    def detect_zypper_updates(self):
        """Detect updates from Zypper (openSUSE)."""
        updates = []
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
                updates = self._parse_zypper_output(result.stdout)

        except Exception as error:
            logger.error(_("Failed to detect Zypper updates: %s"), str(error))

        return updates

    def _parse_zypper_output(self, stdout: str) -> list:
        """Parse zypper list-updates output into update records."""
        updates = []
        in_packages = False
        for line in stdout.strip().split("\n"):
            if "---" in line:
                in_packages = True
                continue

            if not in_packages or not line.strip():
                continue

            parts = line.split("|")
            if len(parts) >= 5:
                package_name = parts[2].strip()
                updates.append(
                    {
                        "package_name": package_name,
                        "current_version": parts[3].strip(),
                        "available_version": parts[4].strip(),
                        "package_manager": "zypper",
                        "repository": parts[1].strip(),
                        "is_security_update": "security" in parts[0].lower(),
                        "is_system_update": self.is_system_package_linux(package_name),
                    }
                )

        return updates

    def detect_pacman_updates(self):
        """Detect updates from Pacman (Arch Linux)."""
        updates = []
        try:
            logger.debug(_("Detecting Pacman updates"))

            # Sync package database
            subprocess.run(  # nosec B603, B607
                ["pacman", "-Sy"],
                capture_output=True,
                timeout=60,
                check=False,
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
                    if len(parts) >= 4:
                        update = {
                            "package_name": parts[0],
                            "current_version": parts[1],
                            "available_version": parts[3],
                            "package_manager": "pacman",
                            "is_security_update": False,
                            "is_system_update": self.is_system_package_linux(parts[0]),
                        }
                        updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect Pacman updates: %s"), str(error))

        return updates

    @staticmethod
    def check_fwupd_daemon():
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

    def detect_fwupd_updates(self):
        """Detect firmware updates from fwupd."""
        updates = []
        try:
            logger.debug(_("Detecting fwupd firmware updates"))

            # First, check if the daemon is running and we have permissions
            if not self.check_fwupd_daemon():
                logger.warning(_("fwupd daemon not running or no permissions"))
                return updates

            self._refresh_fwupd_metadata()

            # Get updates that are available
            result = subprocess.run(  # nosec B603, B607
                ["fwupdmgr", "get-updates", "--json"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                updates = self._parse_fwupd_updates_output(result.stdout)
            elif result.returncode == 2:
                logger.debug(_("No firmware updates available"))
            else:
                logger.debug(_("fwupd get-updates failed: %s"), result.stderr.strip())

        except Exception as error:
            logger.error(_("Failed to detect fwupd updates: %s"), str(error))

        return updates

    def _refresh_fwupd_metadata(self):
        """Refresh fwupd metadata if allowed (requires privileges)."""
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
            logger.debug(_("Could not refresh fwupd metadata (may need privileges)"))

    def _parse_fwupd_updates_output(self, stdout: str) -> list:
        """Parse the JSON output from fwupdmgr get-updates."""
        updates = []
        try:
            updates_data = json.loads(stdout)
            devices = self._extract_fwupd_devices(updates_data)

            for device in devices:
                device_updates = self._process_fwupd_device(device)
                updates.extend(device_updates)

        except json.JSONDecodeError as error:
            logger.error(_("Failed to parse fwupd JSON output: %s"), str(error))
        except Exception as error:
            logger.error(_("Error processing fwupd updates: %s"), str(error))

        return updates

    @staticmethod
    def _extract_fwupd_devices(updates_data) -> list:
        """Extract the devices list from fwupd JSON output."""
        if isinstance(updates_data, dict) and "Devices" in updates_data:
            return updates_data["Devices"]
        if isinstance(updates_data, list):
            return updates_data
        return []

    def _process_fwupd_device(self, device: dict) -> list:
        """Process a single fwupd device and return its available updates."""
        updates = []
        device_id = device.get("DeviceId", "unknown")
        device_name = device.get("Name", device.get("DeviceName", _("Unknown Device")))

        releases = device.get("Releases", [])
        if not releases:
            return updates

        current_version = device.get("Version", "unknown")

        for release in releases:
            update = self._process_fwupd_release(
                release, device_id, device_name, current_version, device
            )
            if update:
                updates.append(update)

        return updates

    def _process_fwupd_release(
        self,
        release: dict,
        device_id: str,
        device_name: str,
        current_version: str,
        device: dict,
    ) -> Optional[dict]:
        """Process a single fwupd release and return an update record if applicable."""
        if not release:
            return None

        available_version = release.get("Version", "unknown")
        if available_version == current_version:
            return None

        vendor = device.get("Vendor", "Unknown")
        unique_package_name = f"{vendor} {device_name} (→ {available_version})"

        return {
            "package_name": unique_package_name,
            "device_id": device_id,
            "current_version": current_version,
            "available_version": available_version,
            "package_manager": "fwupd",
            "is_security_update": self._is_fwupd_security_update(release),
            "is_system_update": True,
            "update_size": release.get("Size", 0),
            "vendor": vendor,
            "device_name": device_name,
            "release_description": release.get("Description", ""),
            "release_summary": release.get("Summary", ""),
            "urgency": release.get("Urgency", "unknown"),
            "requires_reboot": True,
        }

    @staticmethod
    def _is_fwupd_security_update(release: dict) -> bool:
        """Determine if a firmware release is security-related."""
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
