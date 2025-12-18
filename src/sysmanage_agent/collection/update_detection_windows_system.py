#!/usr/bin/env python3
"""
Windows System Update Detection Module for SysManage Agent

This module handles detection of Windows system updates:
- Windows Update (OS patches, security updates, cumulative updates)
- Windows version upgrades (feature updates)
"""

import json
import logging
import platform
import subprocess  # nosec B404

from src.i18n import _

logger = logging.getLogger(__name__)


class WindowsSystemDetectorMixin:
    """Mixin class for Windows system update detection."""

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

                        update_entry = {
                            "package_name": update.get("Title", "Unknown Update"),
                            "current_version": "installed",
                            "available_version": f"Rev.{update.get('RevisionNumber', 'unknown')}",
                            "package_manager": "Windows Update",
                            "update_type": update_type,
                            "description": update.get("Description", ""),
                            "size": self._format_size_mb(update.get("SizeInBytes", 0)),
                            "categories": update.get("Categories", ""),
                            "severity": update.get("SeverityText", "Unknown"),
                            "is_downloaded": update.get("IsDownloaded", False),
                            "update_id": update.get("UpdateID", ""),
                        }

                        # Log the update_id for debugging
                        logger.info(
                            _("Windows Update detected: '%s' with UpdateID='%s'"),
                            update_entry["package_name"],
                            update_entry["update_id"],
                        )

                        self.available_updates.append(update_entry)

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
