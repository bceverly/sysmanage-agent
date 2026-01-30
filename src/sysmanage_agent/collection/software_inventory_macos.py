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

APPLICATIONS_DIR = "/Applications"


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
            except Exception:  # nosec B112 # Continue trying other homebrew paths
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
            except Exception:  # nosec B112 # Continue trying other homebrew paths
                continue
        return "brew"  # Fallback

    def _collect_homebrew_list(self, brew_cmd, list_type, source):
        """Collect packages from a specific Homebrew list type.

        Args:
            brew_cmd: Path to the brew executable.
            list_type: Either '--formula' or '--cask'.
            source: Source label for the packages (e.g. 'homebrew_core', 'homebrew_cask').
        """
        result = subprocess.run(
            [brew_cmd, "list", list_type, "--versions"],  # nosec B603, B607
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            return

        is_cask = list_type == "--cask"
        for line in result.stdout.strip().split("\n"):
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    package = {
                        "package_name": parts[0],
                        "version": parts[1],
                        "package_manager": "homebrew",
                        "source": source,
                        "is_system_package": False,
                        "is_user_installed": True,
                    }
                    if is_cask:
                        package["category"] = "application"
                    self.collected_packages.append(package)

    def _collect_homebrew_packages(self):
        """Collect packages from Homebrew (macOS)."""
        try:
            logger.debug(_("Collecting Homebrew packages"))

            brew_cmd = self._get_brew_command()

            self._collect_homebrew_list(brew_cmd, "--formula", "homebrew_core")
            self._collect_homebrew_list(brew_cmd, "--cask", "homebrew_cask")

        except Exception as error:
            logger.error(_("Failed to collect Homebrew packages: %s"), str(error))

    def _parse_plist_field(self, output, field_name):
        """Extract a single field value from plutil -p output.

        Args:
            output: The text output from 'plutil -p'.
            field_name: The plist key to extract (e.g. 'CFBundleIdentifier').

        Returns:
            The field value as a string, or None if not found.
        """
        if field_name not in output:
            return None
        match = re.search(rf'"{field_name}" => "([^"]+)"', output)
        return match.group(1) if match else None

    def _detect_plist_metadata(self, info_plist_path):
        """Read bundle_id and version from a macOS Info.plist file.

        Args:
            info_plist_path: Absolute path to the Info.plist file.

        Returns:
            A dict with 'bundle_id' and/or 'version' keys if found,
            or an empty dict on failure.
        """
        if not os.path.exists(info_plist_path):
            return {}

        try:
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

            if result.returncode != 0:
                return {}

            metadata = {}
            output = result.stdout

            bundle_id = self._parse_plist_field(output, "CFBundleIdentifier")
            if bundle_id:
                metadata["bundle_id"] = bundle_id

            version = self._parse_plist_field(output, "CFBundleShortVersionString")
            if version:
                metadata["version"] = version

            return metadata

        except subprocess.TimeoutExpired:
            return {}

    def _collect_macos_applications(self):
        """Collect applications from macOS Applications folder."""
        try:
            logger.debug(_("Collecting macOS Applications"))

            apps_dirs = [APPLICATIONS_DIR, os.path.expanduser("~/Applications")]

            for apps_dir in apps_dirs:
                if not os.path.exists(apps_dir):
                    continue

                for item in os.listdir(apps_dir):
                    if not item.endswith(".app"):
                        continue

                    app_path = os.path.join(apps_dir, item)
                    app_name = item[:-4]  # Remove .app extension

                    package = {
                        "package_name": app_name,
                        "package_manager": "macos_applications",
                        "source": "local_install",
                        "category": "application",
                        "installation_path": app_path,
                        "is_system_package": apps_dir == APPLICATIONS_DIR,
                        "is_user_installed": apps_dir != APPLICATIONS_DIR,
                    }

                    # Try to get bundle info from Info.plist
                    info_plist_path = os.path.join(app_path, "Contents", "Info.plist")
                    plist_metadata = self._detect_plist_metadata(info_plist_path)
                    package.update(plist_metadata)

                    self.collected_packages.append(package)

        except Exception as error:
            logger.error(_("Failed to collect macOS applications: %s"), str(error))

    def _process_app_store_entry(self, app):
        """Process a single application entry from system_profiler output.

        Args:
            app: A dict representing one application from SPApplicationsDataType.

        Returns:
            A package dict if the app is from the Mac App Store, or None otherwise.
        """
        source_kind = app.get("source_kind", "")
        if (
            "App Store" not in source_kind
            and app.get("obtained_from") != "mac_app_store"
        ):
            return None

        package = {
            "package_name": app.get("_name", "Unknown"),
            "version": app.get("version", "Unknown"),
            "bundle_id": app.get("info", "Unknown"),
            "package_manager": "mac_app_store",
            "source": "app_store",
            "category": "application",
            "vendor": (
                app.get("info", {}).get("CFBundleIdentifier", "").split(".")[0]
                if isinstance(app.get("info"), dict)
                else ""
            ),
            "is_system_package": False,
            "is_user_installed": True,
        }

        self._detect_app_store_size(app, package)
        return package

    def _detect_app_store_size(self, app, package):
        """Detect and set size_bytes on a Mac App Store package if available.

        Args:
            app: The raw application dict from system_profiler.
            package: The package dict to update with size_bytes.
        """
        if "kind" not in app or "bytes" not in str(app["kind"]):
            return

        # NOSONAR - regex operates on trusted internal data
        size_match = re.search(r"(\d+(?:\.\d+)?)\s*([KMGT]?B)", str(app["kind"]))
        if size_match:
            package["size_bytes"] = self._parse_size_string(
                f"{size_match.group(1)} {size_match.group(2)}"
            )

    def _collect_macos_app_store(self):
        """Collect Mac App Store applications."""
        try:
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
                        package = self._process_app_store_entry(app)
                        if package:
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
