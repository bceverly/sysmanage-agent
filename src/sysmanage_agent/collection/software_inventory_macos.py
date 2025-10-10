#!/usr/bin/env python3
"""
macOS Software Inventory Collection Module

Handles software inventory collection for macOS systems including:
- Applications folder
- Mac App Store
- Homebrew
- MacPorts
"""

import json
import logging
import os
import re
import subprocess  # nosec B404
from typing import List

from src.i18n import _
from src.sysmanage_agent.collection.software_inventory_base import (
    SoftwareInventoryCollectorBase,
)

logger = logging.getLogger(__name__)


class MacOSSoftwareInventoryCollector(SoftwareInventoryCollectorBase):
    """Collects software inventory from macOS sources."""

    def __init__(self):  # pylint: disable=useless-parent-delegation
        super().__init__()

    def detect_package_managers(self) -> List[str]:
        """Detect available macOS package managers."""
        if self._package_managers is not None:
            return self._package_managers

        managers = []

        if self._is_homebrew_available():
            managers.append("homebrew")

        if self._command_exists("port"):
            managers.append("macports")

        self._package_managers = managers
        logger.debug(_("Detected package managers: %s"), ", ".join(managers))
        return managers

    def collect_packages(self):
        """Collect packages from all macOS sources."""
        # Applications folder
        self._collect_macos_applications()

        # Mac App Store applications
        self._collect_macos_app_store()

        # Package managers
        managers = self.detect_package_managers()
        if "homebrew" in managers:
            self._collect_homebrew_packages()
        if "macports" in managers:
            self._collect_macports_packages()

    def _is_homebrew_available(self) -> bool:
        """Check if Homebrew is available on macOS with proper path detection."""
        homebrew_paths = [
            "/opt/homebrew/bin/brew",  # Apple Silicon (M1/M2)
            "/usr/local/bin/brew",  # Intel Macs
        ]

        for path in homebrew_paths:
            try:
                result = subprocess.run(  # nosec B603, B607
                    [path, "--version"], capture_output=True, timeout=10, check=False
                )
                if result.returncode == 0:
                    return True
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return False

    def _get_brew_command(self) -> str:
        """Get the correct brew command path."""
        homebrew_paths = [
            "/opt/homebrew/bin/brew",  # Apple Silicon (M1/M2)
            "/usr/local/bin/brew",  # Intel Macs
            "brew",  # If in PATH
        ]

        for path in homebrew_paths:
            try:
                result = subprocess.run(  # nosec B603, B607
                    [path, "--version"], capture_output=True, timeout=10, check=False
                )
                if result.returncode == 0:
                    return path
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return "brew"  # Fallback

    def _collect_homebrew_packages(self):
        """Collect packages from Homebrew (macOS)."""
        try:
            logger.debug(_("Collecting Homebrew packages"))

            # Find the correct brew path
            brew_cmd = self._get_brew_command()

            # Get list of installed packages
            result = subprocess.run(
                [brew_cmd, "list", "--formula", "--versions"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            package = {
                                "package_name": parts[0],
                                "version": parts[1],
                                "package_manager": "homebrew",
                                "source": "homebrew_core",
                                "is_system_package": False,
                                "is_user_installed": True,
                            }
                            self.collected_packages.append(package)

            # Also collect casks
            result = subprocess.run(
                [brew_cmd, "list", "--cask", "--versions"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            package = {
                                "package_name": parts[0],
                                "version": parts[1],
                                "package_manager": "homebrew",
                                "source": "homebrew_cask",
                                "category": "application",
                                "is_system_package": False,
                                "is_user_installed": True,
                            }
                            self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect Homebrew packages: %s"), str(error))

    def _collect_macos_applications(self):
        """Collect applications from macOS Applications folder."""
        try:  # pylint: disable=too-many-nested-blocks
            logger.debug(_("Collecting macOS Applications"))

            apps_dirs = ["/Applications", os.path.expanduser("~/Applications")]

            for apps_dir in apps_dirs:
                if os.path.exists(apps_dir):
                    for item in os.listdir(apps_dir):
                        if item.endswith(".app"):
                            app_path = os.path.join(apps_dir, item)
                            app_name = item[:-4]  # Remove .app extension

                            package = {
                                "package_name": app_name,
                                "package_manager": "macos_applications",
                                "source": "local_install",
                                "category": "application",
                                "installation_path": app_path,
                                "is_system_package": apps_dir == "/Applications",
                                "is_user_installed": apps_dir != "/Applications",
                            }

                            # Try to get bundle info
                            info_plist_path = os.path.join(
                                app_path, "Contents", "Info.plist"
                            )
                            if os.path.exists(info_plist_path):
                                try:
                                    # Use system_profiler or plutil to read plist
                                    result = subprocess.run(
                                        [
                                            "plutil",
                                            "-p",
                                            info_plist_path,
                                        ],  # nosec B603, B607
                                        capture_output=True,
                                        text=True,
                                        timeout=5,
                                        check=False,
                                    )

                                    if result.returncode == 0:
                                        # Parse basic info from plist output
                                        output = result.stdout
                                        if "CFBundleIdentifier" in output:
                                            match = re.search(
                                                r'"CFBundleIdentifier" => "([^"]+)"',
                                                output,
                                            )
                                            if match:
                                                package["bundle_id"] = match.group(1)

                                        if "CFBundleShortVersionString" in output:
                                            match = re.search(
                                                r'"CFBundleShortVersionString" => "([^"]+)"',
                                                output,
                                            )
                                            if match:
                                                package["version"] = match.group(1)

                                except subprocess.TimeoutExpired:
                                    pass

                            self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect macOS applications: %s"), str(error))

    def _collect_macos_app_store(self):
        """Collect Mac App Store applications."""
        try:  # pylint: disable=too-many-nested-blocks
            logger.debug(_("Collecting Mac App Store applications"))

            result = subprocess.run(
                [
                    "system_profiler",
                    "SPApplicationsDataType",
                    "-json",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    applications = data.get("SPApplicationsDataType", [])

                    for app in applications:
                        # Check if it's from Mac App Store
                        source_kind = app.get("source_kind", "")
                        if (
                            "App Store" in source_kind
                            or app.get("obtained_from") == "mac_app_store"
                        ):
                            package = {
                                "package_name": app.get("_name", "Unknown"),
                                "version": app.get("version", "Unknown"),
                                "bundle_id": app.get("info", "Unknown"),
                                "package_manager": "mac_app_store",
                                "source": "app_store",
                                "category": "application",
                                "vendor": (
                                    app.get("info", {})
                                    .get("CFBundleIdentifier", "")
                                    .split(".")[0]
                                    if isinstance(app.get("info"), dict)
                                    else ""
                                ),
                                "is_system_package": False,
                                "is_user_installed": True,
                            }

                            # Get size if available
                            if "kind" in app and "bytes" in str(app["kind"]):
                                size_match = re.search(
                                    r"(\d+(?:\.\d+)?)\s*([KMGT]?B)", str(app["kind"])
                                )
                                if size_match:
                                    package["size_bytes"] = self._parse_size_string(
                                        f"{size_match.group(1)} {size_match.group(2)}"
                                    )

                            self.collected_packages.append(package)

                except json.JSONDecodeError:
                    logger.warning(_("Failed to parse system_profiler JSON output"))

        except Exception as error:
            logger.error(
                _("Failed to collect Mac App Store applications: %s"), str(error)
            )

    def _collect_macports_packages(self):
        """Collect packages from MacPorts."""
        # Implementation would use 'port installed'
        logger.debug(_("MacPorts package collection not implemented"))
