#!/usr/bin/env python3
"""
Windows Software Inventory Collection Module

Handles software inventory collection for Windows systems including:
- Windows Registry (Programs and Features)
- Microsoft Store apps
- winget
- Chocolatey
- Scoop
"""

import json
import logging
import subprocess  # nosec B404
from typing import List

from src.i18n import _
from src.sysmanage_agent.collection.software_inventory_base import (
    SoftwareInventoryCollectorBase,
)

logger = logging.getLogger(__name__)


class WindowsSoftwareInventoryCollector(SoftwareInventoryCollectorBase):
    """Collects software inventory from Windows sources."""

    def __init__(self):  # pylint: disable=useless-parent-delegation
        super().__init__()

    def detect_package_managers(self) -> List[str]:
        """Detect available Windows package managers."""
        if self._package_managers is not None:
            return self._package_managers

        managers = []
        manager_executables = {
            "winget": ["winget"],
            "chocolatey": ["choco"],
            "scoop": ["scoop"],
        }

        for manager, executables in manager_executables.items():
            for executable in executables:
                if self._command_exists(executable):
                    managers.append(manager)
                    break

        self._package_managers = managers
        logger.debug(_("Detected package managers: %s"), ", ".join(managers))
        return managers

    def collect_packages(self):
        """Collect packages from all Windows sources."""
        # Windows Registry (Programs and Features)
        self._collect_windows_registry_programs()

        # Microsoft Store apps
        self._collect_microsoft_store_apps()

        # Package managers
        managers = self.detect_package_managers()
        if "winget" in managers:
            self._collect_winget_packages()
        if "chocolatey" in managers:
            self._collect_chocolatey_packages()
        if "scoop" in managers:
            self._collect_scoop_packages()

    def _collect_windows_registry_programs(self):
        """Collect programs from Windows Registry."""
        try:
            import winreg  # pylint: disable=import-outside-toplevel

            logger.debug(_("Collecting Windows Registry programs"))

            # Registry keys where installed programs are listed
            registry_keys = [
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                ),
                (
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                ),
            ]

            seen_programs = set()

            for hkey, subkey_path in registry_keys:
                try:
                    with winreg.OpenKey(hkey, subkey_path) as key:
                        subkey_count = winreg.QueryInfoKey(key)[0]

                        for i in range(subkey_count):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    try:
                                        display_name = winreg.QueryValueEx(
                                            subkey, "DisplayName"
                                        )[0]
                                        # Skip if no display name or empty
                                        if not display_name or not display_name.strip():
                                            continue

                                        # Get version if available
                                        try:
                                            version = winreg.QueryValueEx(
                                                subkey, "DisplayVersion"
                                            )[0]
                                        except FileNotFoundError:
                                            version = "Unknown"

                                        # Get publisher if available
                                        try:
                                            publisher = winreg.QueryValueEx(
                                                subkey, "Publisher"
                                            )[0]
                                        except FileNotFoundError:
                                            publisher = None

                                        # Create unique identifier to avoid duplicates
                                        program_id = f"{display_name}_{version}"
                                        if program_id in seen_programs:
                                            continue

                                        seen_programs.add(program_id)

                                        package = {
                                            "package_name": display_name,
                                            "version": (
                                                version if version else "Unknown"
                                            ),
                                            "bundle_id": subkey_name,
                                            "package_manager": "windows_registry",
                                            "source": "windows_installer",
                                            "is_system_package": False,
                                            "is_user_installed": True,
                                        }

                                        if publisher:
                                            package["publisher"] = publisher

                                        self.collected_packages.append(package)

                                    except FileNotFoundError:
                                        # No DisplayName - skip this entry
                                        continue
                            except OSError:
                                # Error opening subkey - skip
                                continue
                except FileNotFoundError:
                    # Registry key doesn't exist - skip
                    continue
                except PermissionError:
                    # No permission to access this key - skip
                    logger.debug(
                        _("No permission to access registry key: %s"), subkey_path
                    )
                    continue

            logger.info(
                _("Collected %d programs from Windows Registry"),
                len(
                    [
                        p
                        for p in self.collected_packages
                        if p.get("package_manager") == "windows_registry"
                    ]
                ),
            )

        except ImportError:
            logger.debug(_("winreg module not available (not on Windows)"))
        except Exception as error:
            logger.error(
                _("Failed to collect Windows Registry programs: %s"), str(error)
            )

    def _collect_microsoft_store_apps(self):
        """Collect Microsoft Store applications."""
        try:
            logger.debug(_("Collecting Microsoft Store applications"))

            # Use PowerShell to get AppxPackage information
            powershell_cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-AppxPackage | Select-Object Name, Version, Publisher, PackageFullName | ConvertTo-Json",
            ]

            result = subprocess.run(
                powershell_cmd,  # nosec B603
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                try:
                    apps_data = json.loads(result.stdout)

                    # Handle both single app (dict) and multiple apps (list)
                    if isinstance(apps_data, dict):
                        apps_data = [apps_data]

                    for app in apps_data:
                        # Skip if no name
                        if not app.get("Name"):
                            continue

                        package = {
                            "package_name": app.get("Name", "Unknown"),
                            "version": app.get("Version", "Unknown"),
                            "bundle_id": app.get("PackageFullName", app.get("Name")),
                            "package_manager": "microsoft_store",
                            "source": "microsoft_store",
                            "is_system_package": False,
                            "is_user_installed": True,
                        }

                        if app.get("Publisher"):
                            package["publisher"] = app.get("Publisher")

                        self.collected_packages.append(package)

                    logger.info(
                        _("Collected %d apps from Microsoft Store"),
                        len(
                            [
                                p
                                for p in self.collected_packages
                                if p.get("package_manager") == "microsoft_store"
                            ]
                        ),
                    )

                except json.JSONDecodeError as error:
                    logger.error(
                        _("Failed to parse Microsoft Store apps JSON: %s"), str(error)
                    )
            else:
                logger.debug(_("No Microsoft Store apps found or command failed"))

        except FileNotFoundError:
            logger.debug(
                _("PowerShell not found (not on Windows or PowerShell not installed)")
            )
        except Exception as error:
            logger.error(_("Failed to collect Microsoft Store apps: %s"), str(error))

    def _collect_winget_packages(self):
        """Collect packages from Windows Package Manager."""
        try:  # pylint: disable=too-many-nested-blocks
            logger.debug(_("Collecting winget packages"))

            result = subprocess.run(
                ["winget", "list"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                # Find the header line to understand column positions
                header_line = None
                data_start_idx = 0
                for i, line in enumerate(lines):
                    if "Name" in line and "Id" in line and "Version" in line:
                        header_line = line
                        # Skip the header and separator line
                        data_start_idx = i + 2
                        break

                if header_line:
                    # Extract column positions from header
                    name_pos = header_line.find("Name")
                    id_pos = header_line.find("Id")
                    version_pos = header_line.find("Version")

                    for line in lines[data_start_idx:]:
                        if line.strip() and not line.startswith("-"):
                            # Parse using column positions for more reliable parsing
                            if len(line) > version_pos:
                                package_name = (
                                    line[name_pos:id_pos].strip()
                                    if id_pos > name_pos
                                    else line[name_pos:].strip()
                                )
                                package_id = (
                                    line[id_pos:version_pos].strip()
                                    if version_pos > id_pos
                                    else line[id_pos:].strip()
                                )
                                version_part = (
                                    line[version_pos:].split()
                                    if len(line) > version_pos
                                    else []
                                )
                                version = (
                                    version_part[0]
                                    if version_part and version_part[0] != ""
                                    else "Unknown"
                                )

                                if package_name and package_id:
                                    package = {
                                        "package_name": package_name,
                                        "version": version,
                                        "bundle_id": package_id,
                                        "package_manager": "winget",
                                        "source": (
                                            "microsoft_store"
                                            if "msstore" in package_id.lower()
                                            else "winget_repository"
                                        ),
                                        "is_system_package": False,
                                        "is_user_installed": True,
                                    }

                                    self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect winget packages: %s"), str(error))

    def _collect_chocolatey_packages(self):
        """Collect packages from Chocolatey."""
        # Implementation would use 'choco list --local-only'
        logger.debug(_("Chocolatey package collection not yet implemented"))

    def _collect_scoop_packages(self):
        """Collect packages from Scoop."""
        # Implementation would use 'scoop list'
        logger.debug(_("Scoop package collection not yet implemented"))
