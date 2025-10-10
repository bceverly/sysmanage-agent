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
import platform
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


class WindowsUpdateDetector(UpdateDetectorBase):
    """Windows-specific update detection methods."""

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

    # BSD Update Detection Implementations

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

            except Exception as error:
                logger.error(
                    _("Exception updating package '%s': %s"),
                    package["package_name"],
                    str(error),
                )
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "winget",
                        "error": str(error),
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
            except Exception as error:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "windows-upgrade",
                        "error": str(error),
                    }
                )

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

                except json.JSONDecodeError as error:
                    logger.warning(
                        _("Failed to parse Windows Update output: %s"), str(error)
                    )

        except subprocess.TimeoutExpired:
            logger.warning(_("Windows Update detection timed out"))
        except Exception as error:
            logger.error(_("Failed to detect Windows system updates: %s"), str(error))

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

            result = subprocess.run(  # nosec B603, B607
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
                        version_result = subprocess.run(  # nosec B603, B607
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

        except Exception as error:
            logger.error(_("Failed to detect Windows version upgrades: %s"), str(error))

    def _install_with_winget(self, package_name: str) -> Dict[str, Any]:
        """Install package using winget package manager."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["winget", "install", "--id", package_name, "--silent"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

    def _install_with_choco(self, package_name: str) -> Dict[str, Any]:
        """Install package using Chocolatey package manager."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["choco", "install", package_name, "-y"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

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
