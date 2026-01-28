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

    def _parse_winget_header(self, lines):
        """Find and parse the winget output header to determine column positions.

        Args:
            lines: List of output lines from winget upgrade.

        Returns:
            tuple: (column_positions dict, data_start_idx) or (None, 0) if no header found.
                   column_positions has keys: name_start, id_start, version_start,
                   available_start, source_start.
        """
        for i, line in enumerate(lines):
            if "Name" in line and "Id" in line and "Version" in line:
                return {
                    "name_start": line.find("Name"),
                    "id_start": line.find("Id"),
                    "version_start": line.find("Version"),
                    "available_start": line.find("Available"),
                    "source_start": line.find("Source"),
                }, i + 2  # Skip header and separator line
        return None, 0

    def _parse_winget_line_by_columns(self, line, cols):
        """Extract package fields from a winget output line using column positions.

        Args:
            line: A single data line from winget upgrade output.
            cols: Column position dict with keys name_start, id_start, version_start,
                  available_start, source_start.

        Returns:
            dict or None: A dict with package_name, bundle_id, current_version,
                          available_version if parseable, or None on failure.
        """
        name_start = cols["name_start"]
        id_start = cols["id_start"]
        version_start = cols["version_start"]
        available_start = cols["available_start"]
        source_start = cols["source_start"]

        if id_start > name_start:
            package_name = line[name_start:id_start].strip()
            if version_start > id_start:
                bundle_id = line[id_start:version_start].strip()
                if available_start > version_start:
                    current_version = line[version_start:available_start].strip()
                    if source_start > available_start:
                        available_version = line[available_start:source_start].strip()
                    else:
                        available_version = (
                            line[available_start:].strip().split()[0]
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
            return self._parse_winget_line_fallback(line)

        return {
            "package_name": package_name.strip(),
            "bundle_id": bundle_id.strip(),
            "current_version": current_version.strip(),
            "available_version": available_version.strip(),
        }

    def _parse_winget_line_fallback(self, line):
        """Parse a winget output line using simple whitespace splitting.

        Args:
            line: A single data line from winget upgrade output.

        Returns:
            dict or None: A dict with package fields if parseable, or None on failure.
        """
        parts = line.split()
        if len(parts) >= 2:
            return {
                "package_name": parts[0],
                "bundle_id": parts[1],
                "current_version": parts[2] if len(parts) > 2 else "unknown",
                "available_version": parts[3] if len(parts) > 3 else "unknown",
            }
        return None

    def _process_winget_update_line(self, line: str, cols: dict) -> None:
        """Process a single winget update line and append to available_updates if valid."""
        parsed = self._parse_winget_line_by_columns(line, cols)
        if parsed is None:
            return
        if not parsed["package_name"] or not parsed["bundle_id"]:
            return
        avail_ver = parsed["available_version"]
        if (
            not avail_ver
            or avail_ver == "unknown"
            or avail_ver == parsed["current_version"]
        ):
            return
        update = {
            "package_name": parsed["package_name"],
            "bundle_id": parsed["bundle_id"],
            "current_version": parsed["current_version"],
            "available_version": avail_ver,
            "package_manager": "winget",
            "is_security_update": False,
            "is_system_update": False,
        }
        self.available_updates.append(update)

    def _detect_winget_updates(self):
        """Detect updates from Windows Package Manager."""
        try:
            logger.debug(_("Detecting winget updates"))

            result = subprocess.run(  # nosec B603, B607
                ["winget", "upgrade", "--include-unknown"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return

            lines = result.stdout.strip().split("\n")
            cols, data_start_idx = self._parse_winget_header(lines)
            if not cols or data_start_idx >= len(lines):
                return

            for line in lines[data_start_idx:]:
                if (
                    not line.strip()
                    or line.startswith("No")
                    or "upgrades available" in line
                ):
                    continue
                try:
                    self._process_winget_update_line(line, cols)
                except Exception as error:
                    logger.debug(_("Failed to parse winget line '%s': %s"), line, error)

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
