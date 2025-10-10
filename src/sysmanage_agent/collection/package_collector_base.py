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
from typing import Dict, List

# Platform-specific imports
try:
    import pwd  # Unix/macOS only
except ImportError:
    pwd = None  # Windows

from src.database.base import get_database_manager
from src.database.models import AvailablePackage
from src.i18n import _

logger = logging.getLogger(__name__)


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
            system = platform.system().lower()
            if system == "windows":
                # Windows uses 'where' command
                result = subprocess.run(  # nosec B603, B607
                    ["where", manager], capture_output=True, timeout=10, check=False
                )
            else:
                # Unix/Linux/BSD/macOS use 'which' command
                result = subprocess.run(  # nosec B603, B607
                    ["which", manager], capture_output=True, timeout=10, check=False
                )
            return result.returncode == 0
        except Exception:
            return False

    def _check_homebrew_available(self) -> bool:
        """Check if Homebrew is available."""
        homebrew_paths = [
            "/opt/homebrew/bin/brew",  # Apple Silicon (M1/M2)
            "/usr/local/bin/brew",  # Intel Macs
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
            # Handle wildcards in path
            if "*" in path:
                matching_paths = glob.glob(path)
                if matching_paths:
                    path = matching_paths[0]
                else:
                    continue

            if os.path.exists(path):
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

    def _get_homebrew_owner(self) -> str:
        """Get the owner of the Homebrew installation."""

        homebrew_paths = [
            "/opt/homebrew/bin/brew",  # Apple Silicon (M1/M2)
            "/usr/local/bin/brew",  # Intel Macs
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
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return ""

    def _get_brew_command(self) -> str:
        """Get the correct brew command path, with sudo -u support when running privileged."""
        homebrew_paths = [
            "/opt/homebrew/bin/brew",  # Apple Silicon (M1/M2)
            "/usr/local/bin/brew",  # Intel Macs
            "brew",  # If in PATH
        ]

        for path in homebrew_paths:
            try:
                # Test if brew works directly first
                result = subprocess.run(  # nosec B603, B607
                    [path, "--version"], capture_output=True, timeout=10, check=False
                )
                if result.returncode == 0:
                    # Check if running as root and Homebrew owner is different
                    if os.geteuid() == 0:  # Running as root
                        homebrew_owner = self._get_homebrew_owner()
                        if homebrew_owner and homebrew_owner != "root":
                            # Return sudo command to run as homebrew owner
                            return f"sudo -u {homebrew_owner} {path}"

                    # Normal case
                    return path
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return ""

    def _get_winget_command(self) -> str:
        """Get the correct winget command path."""
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

        for path in winget_paths:
            # Handle wildcards in path
            if "*" in path:
                matching_paths = glob.glob(path)
                if matching_paths:
                    path = matching_paths[0]
                else:
                    continue

            if path == "winget":
                # Try using it from PATH
                try:
                    result = subprocess.run(  # nosec B603, B607
                        [path, "--version"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode == 0:
                        return path
                except Exception:  # nosec B112
                    continue
            elif os.path.exists(path):
                # Verify it works before returning
                try:
                    result = subprocess.run(  # nosec B603, B607
                        [path, "--version"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode == 0:
                        logger.info(_("Found winget at: %s"), path)
                        return path
                except Exception:  # nosec B112
                    continue

        logger.warning(_("winget not found in any common location"))
        return ""

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
