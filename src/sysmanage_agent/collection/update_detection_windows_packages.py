#!/usr/bin/env python3
"""
Windows Package Manager Detection Module for SysManage Agent

This module handles detection of updates from Windows package managers:
- winget (Windows Package Manager)
- Chocolatey
- Scoop
- Microsoft Store
"""

import logging
import subprocess  # nosec B404

from src.i18n import _

logger = logging.getLogger(__name__)


class WindowsPackageDetectorMixin:
    """Mixin class for Windows package manager update detection."""

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

                            except Exception as error:
                                logger.debug(
                                    _("Failed to parse winget line '%s': %s"),
                                    line,
                                    error,
                                )
                                continue

        except Exception as error:
            logger.error(_("Failed to detect winget updates: %s"), str(error))

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

        except Exception as error:
            logger.error(_("Failed to detect Chocolatey updates: %s"), str(error))

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

        except Exception as error:
            logger.error(_("Failed to detect Scoop updates: %s"), str(error))
