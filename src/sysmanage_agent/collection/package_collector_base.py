"""
Base package collection module for SysManage Agent.

This module provides the base class and common functionality for package collectors.
"""

import glob
import logging
import os
import platform
import subprocess  # nosec B404
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Platform-specific imports
try:
    import pwd  # Unix/macOS only
except ImportError:
    pwd = None  # Windows

from src.database.base import get_database_manager
from src.database.models import AvailablePackage
from src.i18n import _

logger = logging.getLogger(__name__)

HOMEBREW_ARM_PATH = "/opt/homebrew/bin/brew"
HOMEBREW_INTEL_PATH = "/usr/local/bin/brew"


class BasePackageCollector:
    """Base class for package collectors with common functionality."""

    def __init__(self):
        """Initialize the package collector."""
        self.db_manager = get_database_manager()

    def _is_package_manager_available(self, manager: str) -> bool:
        """Check if a package manager is available on the system."""
        try:
            # For Homebrew on macOS, use dedicated checker
            if manager == "brew":
                return self._check_homebrew_available()

            # For winget on Windows, use dedicated checker
            if manager == "winget" and platform.system().lower() == "windows":
                return self._check_winget_available()

            # For other package managers, use which (Unix) or where (Windows)
            return self._detect_manager_via_which(manager)
        except Exception:
            return False

    def _detect_manager_via_which(self, manager: str) -> bool:
        """Detect whether a package manager is on PATH using 'which' or 'where'.

        Uses 'where' on Windows and 'which' on Unix-like systems.
        Returns True if the manager is found on the system PATH.
        """
        system = platform.system().lower()
        lookup_cmd = "where" if system == "windows" else "which"
        result = subprocess.run(  # nosec B603, B607
            [lookup_cmd, manager], capture_output=True, timeout=10, check=False
        )
        return result.returncode == 0

    def _check_homebrew_available(self) -> bool:
        """Check if Homebrew is available."""
        homebrew_paths = [
            HOMEBREW_ARM_PATH,  # Apple Silicon (M1/M2)
            HOMEBREW_INTEL_PATH,  # Intel Macs
        ]
        for path in homebrew_paths:
            try:
                result = subprocess.run(  # nosec B603, B607
                    [path, "--version"],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode == 0:
                    return True
            except Exception:  # nosec B112
                continue
        return False

    def _check_winget_available(self) -> bool:
        """Check if winget is available on Windows."""
        winget_paths = [
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe"),
            r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe",
        ]
        for path in winget_paths:
            resolved_path = self._resolve_glob_path(path)
            if resolved_path is None:
                continue

            if os.path.exists(resolved_path) and self._detect_command_available(
                resolved_path
            ):
                return True
        return False

    def _resolve_glob_path(self, path: str) -> Optional[str]:
        """Resolve a path that may contain glob wildcards.

        Returns the first matching path, or the original path if no wildcards.
        Returns None if the wildcard matched nothing.
        """
        if "*" not in path:
            return path
        matching_paths = glob.glob(path)
        if matching_paths:
            return matching_paths[0]
        return None

    def _detect_command_available(self, command_path: str) -> bool:
        """Detect whether a command is available by running it with --version.

        Returns True if the command executes successfully, False otherwise.
        """
        try:
            result = subprocess.run(  # nosec B603, B607
                [command_path, "--version"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            return result.returncode == 0
        except Exception:  # nosec B112
            return False

    def _get_homebrew_owner(self) -> str:
        """Get the owner of the Homebrew installation."""

        homebrew_paths = [
            HOMEBREW_ARM_PATH,  # Apple Silicon (M1/M2)
            HOMEBREW_INTEL_PATH,  # Intel Macs
        ]

        for path in homebrew_paths:
            try:
                if os.path.exists(path):
                    file_stat = os.stat(path)
                    owner_uid = file_stat.st_uid
                    if pwd is not None:
                        owner_info = pwd.getpwuid(owner_uid)
                        return owner_info.pw_name
                    # On Windows, return empty string since Homebrew doesn't exist
                    return ""
            except Exception:  # nosec B112 # Continue trying other homebrew paths
                continue
        return ""

    def _get_brew_command(self) -> str:
        """Get the correct brew command path, with sudo -u support when running privileged."""
        homebrew_paths = [
            HOMEBREW_ARM_PATH,  # Apple Silicon (M1/M2)
            HOMEBREW_INTEL_PATH,  # Intel Macs
            "brew",  # If in PATH
        ]

        for path in homebrew_paths:
            if self._detect_command_available(path):
                return self._process_brew_path_for_privilege(path)
        return ""

    def _process_brew_path_for_privilege(self, path: str) -> str:
        """Process a brew path to handle privilege escalation when running as root.

        If running as root and the Homebrew installation is owned by a non-root user,
        returns a sudo -u command to run as the Homebrew owner. Otherwise returns
        the path as-is.
        """
        if os.geteuid() == 0:  # Running as root
            homebrew_owner = self._get_homebrew_owner()
            if homebrew_owner and homebrew_owner != "root":
                return f"sudo -u {homebrew_owner} {path}"
        return path

    def _get_winget_command(self) -> str:
        """Get the correct winget command path."""
        winget_paths = self._collect_winget_search_paths()

        for path in winget_paths:
            resolved = self._resolve_glob_path(path)
            if resolved is None:
                continue

            found = self._detect_winget_at_path(resolved)
            if found:
                return resolved

        logger.warning(_("winget not found in any common location"))
        return ""

    def _collect_winget_search_paths(self) -> List[str]:
        """Collect all candidate paths where winget might be installed.

        Checks the standard install location, WindowsApps wildcard path,
        per-user profile locations, and the PATH fallback.
        """
        winget_paths = [
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe"),
            r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe",
        ]

        # Also check common user profile locations
        users_dir = r"C:\Users"
        if os.path.exists(users_dir):
            for user_dir in os.listdir(users_dir):
                user_winget = os.path.join(
                    users_dir,
                    user_dir,
                    r"AppData\Local\Microsoft\WindowsApps\winget.exe",
                )
                winget_paths.append(user_winget)

        # Add PATH fallback
        winget_paths.append("winget")
        return winget_paths

    def _detect_winget_at_path(self, path: str) -> bool:
        """Detect whether winget is usable at the given path.

        For the bare 'winget' name, tries it directly from PATH.
        For absolute paths, checks existence first, then verifies it runs.
        Returns True if the command at the path is working.
        """
        if path == "winget":
            return self._detect_command_available(path)

        if os.path.exists(path) and self._detect_command_available(path):
            logger.info(_("Found winget at: %s"), path)
            return True

        return False

    def _store_packages(self, manager: str, packages: List[Dict[str, str]]) -> int:
        """Store packages in the local database."""
        if not packages:
            return 0

        collection_date = datetime.now(timezone.utc)
        stored_count = 0

        try:
            with self.db_manager.get_session() as session:
                # Delete existing packages for this manager
                session.query(AvailablePackage).filter(
                    AvailablePackage.package_manager == manager
                ).delete()

                # Insert new packages
                for package in packages:
                    db_package = AvailablePackage(
                        package_manager=manager,
                        package_name=package["name"],
                        package_version=package["version"],
                        package_description=package.get("description", ""),
                        collection_date=collection_date,
                        created_at=collection_date,
                    )
                    session.add(db_package)
                    stored_count += 1

                session.commit()

        except Exception as error:
            logger.error(_("Failed to store packages for %s: %s"), manager, error)
            return 0

        return stored_count

    def get_packages_for_manager(self, manager: str) -> List[AvailablePackage]:
        """Get all packages for a specific package manager."""
        try:
            with self.db_manager.get_session() as session:
                packages = (
                    session.query(AvailablePackage)
                    .filter(AvailablePackage.package_manager == manager)
                    .all()
                )

                # Detach from session
                return [
                    AvailablePackage(
                        id=pkg.id,
                        package_manager=pkg.package_manager,
                        package_name=pkg.package_name,
                        package_version=pkg.package_version,
                        package_description=pkg.package_description,
                        collection_date=pkg.collection_date,
                        created_at=pkg.created_at,
                    )
                    for pkg in packages
                ]

        except Exception as error:
            logger.error(_("Failed to get packages for %s: %s"), manager, error)
            return []

    def get_all_packages(self) -> List[AvailablePackage]:
        """Get all available packages from the database."""
        try:
            with self.db_manager.get_session() as session:
                packages = session.query(AvailablePackage).all()

                # Detach from session
                return [
                    AvailablePackage(
                        id=pkg.id,
                        package_manager=pkg.package_manager,
                        package_name=pkg.package_name,
                        package_version=pkg.package_version,
                        package_description=pkg.package_description,
                        collection_date=pkg.collection_date,
                        created_at=pkg.created_at,
                    )
                    for pkg in packages
                ]

        except Exception as error:
            logger.error(_("Failed to get all packages: %s"), error)
            return []

    def get_package_managers(self) -> List[str]:
        """Get list of package managers that have packages stored."""
        try:
            with self.db_manager.get_session() as session:
                managers = (
                    session.query(AvailablePackage.package_manager).distinct().all()
                )
                return [manager[0] for manager in managers]

        except Exception as error:
            logger.error(_("Failed to get package managers: %s"), error)
            return []

    def get_packages_for_transmission(self) -> Dict[str, any]:
        """Get all packages organized by package manager for transmission to server.

        Note: This method only returns package data. The OS name and version
        should be determined by the caller using the registration system's
        get_system_info() to ensure consistency with host registration.
        """
        try:
            with self.db_manager.get_session() as session:
                packages = session.query(AvailablePackage).all()

                # Organize packages by manager
                packages_by_manager = {}
                for package in packages:
                    manager = package.package_manager
                    if manager not in packages_by_manager:
                        packages_by_manager[manager] = []

                    packages_by_manager[manager].append(
                        {
                            "name": package.package_name,
                            "version": package.package_version,
                            "description": package.package_description or "",
                        }
                    )

                # Return only package manager data
                # OS info should be added by caller from registration system
                return {
                    "package_managers": packages_by_manager,
                }

        except Exception as error:
            logger.error(_("Failed to get packages for transmission: %s"), error)
            return {}
