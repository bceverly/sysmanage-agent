"""
Package manager detection utilities for role detection.
"""

import logging
import os
import re
import shutil
import subprocess  # nosec B404 # Required for system package management
from typing import Dict, Optional


def is_valid_unix_username(username: str) -> bool:
    """
    Validate that a string is a valid Unix username.

    Valid usernames:
    - Start with a lowercase letter or underscore
    - Contain only lowercase letters, digits, underscores, and hyphens
    - Are 1-32 characters long

    Args:
        username: The username to validate

    Returns:
        True if valid, False otherwise
    """
    if not username:
        return False
    # POSIX portable username: starts with letter/underscore, alphanumeric/underscore/hyphen
    pattern = r"^[a-z_][a-z0-9_-]{0,31}$"
    return bool(re.match(pattern, username))


class PackageManagerDetector:
    """Handles package detection across different operating systems and package managers."""

    def __init__(self, system: str, logger: logging.Logger):
        self.system = system
        self.logger = logger

    def get_installed_packages(self) -> Dict[str, str]:
        """Get list of installed packages with versions."""
        packages = {}

        try:
            if self.system == "linux":
                packages.update(self._collect_linux_packages())
            elif self.system == "darwin":
                packages.update(self._collect_darwin_packages())
            elif self.system in ["netbsd", "freebsd", "openbsd"]:
                packages.update(self._collect_bsd_packages())
            elif self.system == "windows":
                packages.update(self._get_windows_packages())

        except Exception as error:
            self.logger.error("Error getting installed packages: %s", error)

        return packages

    def _collect_linux_packages(self) -> Dict[str, str]:
        """Collect packages from Linux package managers."""
        packages = {}

        # Try different package managers
        if self._command_exists("dpkg"):
            packages.update(self._get_dpkg_packages())
        elif self._command_exists("rpm"):
            packages.update(self._get_rpm_packages())
        elif self._command_exists("pacman"):
            packages.update(self._get_pacman_packages())

        # Also check snap packages (can coexist with other package managers)
        if self._command_exists("snap"):
            packages.update(self._get_snap_packages())

        return packages

    def _collect_darwin_packages(self) -> Dict[str, str]:
        """Collect packages from macOS package managers."""
        packages = {}
        if self._command_exists("brew"):
            packages.update(self._get_homebrew_packages())
        return packages

    def _collect_bsd_packages(self) -> Dict[str, str]:
        """Collect packages from BSD package managers."""
        packages = {}
        if self._command_exists("pkgin"):  # NetBSD
            packages.update(self._get_pkgin_packages())
        elif self._command_exists("pkg"):  # FreeBSD/OpenBSD
            packages.update(self._get_pkg_packages())
        return packages

    def _get_dpkg_packages(self) -> Dict[str, str]:
        """Get packages from dpkg (Debian/Ubuntu)."""
        packages = {}
        dpkg_path = self._get_command_path("dpkg-query")
        if not dpkg_path:
            return packages

        try:
            result = (
                subprocess.run(  # nosec B603 B607 # dpkg-query with controlled args
                    [dpkg_path, "-W", "-f=${Package}\\t${Version}\\n"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line and "\t" in line:
                        package, version = line.split("\t", 1)
                        packages[package] = version

        except Exception as error:
            self.logger.debug("Error getting dpkg packages: %s", error)

        return packages

    def _get_rpm_packages(self) -> Dict[str, str]:
        """Get packages from RPM (RHEL/CentOS/Fedora)."""
        packages = {}
        rpm_path = self._get_command_path("rpm")
        if not rpm_path:
            return packages

        try:
            result = subprocess.run(  # nosec B603 B607 # rpm with controlled args
                [rpm_path, "-qa", "--queryformat", "%{NAME}\\t%{VERSION}\\n"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line and "\t" in line:
                        package, version = line.split("\t", 1)
                        packages[package] = version

        except Exception as error:
            self.logger.debug("Error getting RPM packages: %s", error)

        return packages

    def _get_pacman_packages(self) -> Dict[str, str]:
        """Get packages from pacman (Arch Linux)."""
        packages = {}
        pacman_path = self._get_command_path("pacman")
        if not pacman_path:
            return packages

        try:
            result = subprocess.run(  # nosec B603 B607 # pacman with controlled args
                [pacman_path, "-Q"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line and " " in line:
                        package, version = line.split(" ", 1)
                        packages[package] = version

        except Exception as error:
            self.logger.debug("Error getting pacman packages: %s", error)

        return packages

    def _get_snap_packages(self) -> Dict[str, str]:
        """Get packages from snap."""
        packages = {}
        snap_path = self._get_command_path("snap")
        if not snap_path:
            return packages

        try:
            result = subprocess.run(  # nosec B603 B607 # snap with controlled args
                [snap_path, "list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                # Skip the header line (Name  Version  Rev  Tracking  Publisher  Notes)
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            package_name = parts[0]
                            version = parts[1]
                            packages[package_name] = version

        except Exception as error:
            self.logger.debug("Error getting snap packages: %s", error)

        return packages

    def _get_homebrew_packages(self) -> Dict[str, str]:
        """Get packages from Homebrew (macOS)."""
        packages = {}
        brew_path = self._get_command_path("brew")
        if not brew_path:
            return packages

        try:
            cmd = self._build_homebrew_command(brew_path)

            # Get formula packages (command-line tools and libraries)
            result = subprocess.run(  # nosec B603 B607
                cmd,  # nosemgrep: dangerous-subprocess-use-tainted-env-args
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                packages = self._parse_homebrew_output(result.stdout)

        except Exception as error:
            self.logger.debug("Error getting Homebrew packages: %s", error)

        return packages

    def _build_homebrew_command(self, brew_path: str) -> list:
        """Build the Homebrew list command, handling root user case."""
        cmd = [brew_path, "list", "--formula", "--versions"]
        if os.getuid() == 0:  # Running as root
            original_user = os.environ.get("SUDO_USER")
            if original_user and is_valid_unix_username(original_user):
                cmd = ["sudo", "-u", original_user] + cmd
        return cmd

    @staticmethod
    def _parse_homebrew_output(stdout: str) -> Dict[str, str]:
        """Parse Homebrew list output into a package name-version dict."""
        packages = {}
        for line in stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                packages[parts[0]] = parts[1]
        return packages

    def _get_pkgin_packages(self) -> Dict[str, str]:
        """Get packages from pkgin (NetBSD)."""
        packages = {}
        pkgin_path = self._get_command_path("pkgin")
        if not pkgin_path:
            return packages

        try:
            result = subprocess.run(  # nosec B603 B607 # pkgin with controlled args
                [pkgin_path, "list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return packages

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                # pkgin list format: "package-version description"
                parts = line.split(None, 1)
                if not parts:
                    continue
                # Extract package name and version from "package-version"
                pkg_full = parts[0]
                if "-" not in pkg_full:
                    continue
                # Split on last dash to separate name from version
                pkg_name = "-".join(pkg_full.split("-")[:-1])
                pkg_version = pkg_full.split("-")[-1]
                packages[pkg_name] = pkg_version
        except Exception as error:
            self.logger.error("Error getting pkgin packages: %s", error)
        return packages

    def _get_pkg_packages(self) -> Dict[str, str]:
        """Get packages from pkg (FreeBSD/OpenBSD)."""
        packages = {}
        pkg_path = self._get_command_path("pkg")
        if not pkg_path:
            return packages

        try:
            result = subprocess.run(  # nosec B603 B607 # pkg with controlled args
                [pkg_path, "info"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return packages

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                # pkg info format: "package-version description"
                parts = line.split(None, 1)
                if not parts:
                    continue
                # Extract package name and version from "package-version"
                pkg_full = parts[0]
                if "-" not in pkg_full:
                    continue
                # Split on last dash to separate name from version
                pkg_name = "-".join(pkg_full.split("-")[:-1])
                pkg_version = pkg_full.split("-")[-1]
                packages[pkg_name] = pkg_version
        except Exception as error:
            self.logger.error("Error getting pkg packages: %s", error)
        return packages

    def _get_windows_packages(self) -> Dict[str, str]:
        """Get packages from Windows (check multiple sources)."""
        packages = {}

        # Check for databases in common installation paths
        packages.update(self._get_windows_installed_programs())

        # Check for Python's SQLite
        packages.update(self._get_python_packages())

        # Check for winget packages
        if self._command_exists("winget"):
            packages.update(self._get_winget_packages())

        return packages

    def _get_windows_installed_programs(self) -> Dict[str, str]:
        """Check for databases installed in standard Windows locations."""
        packages = {}

        self._detect_windows_postgresql(packages)
        self._detect_windows_mysql(packages)

        return packages

    def _detect_windows_postgresql(self, packages: Dict[str, str]) -> None:
        """Detect PostgreSQL installations in standard Windows paths."""
        postgres_paths = [
            r"C:\Program Files\PostgreSQL",
            r"C:\Program Files (x86)\PostgreSQL",
        ]

        for base_path in postgres_paths:
            if not os.path.exists(base_path):
                continue
            try:
                for version_dir in os.listdir(base_path):
                    version_path = os.path.join(base_path, version_dir)
                    if os.path.isdir(version_path):
                        packages["postgresql"] = version_dir
                        self.logger.info(
                            "Found PostgreSQL %s in %s", version_dir, base_path
                        )
                        return  # Take first version found
            except Exception as error:
                self.logger.debug(
                    "Error checking PostgreSQL path %s: %s", base_path, error
                )

    def _detect_windows_mysql(self, packages: Dict[str, str]) -> None:
        """Detect MySQL installations in standard Windows paths."""
        mysql_paths = [r"C:\Program Files\MySQL", r"C:\Program Files (x86)\MySQL"]

        for base_path in mysql_paths:
            if not os.path.exists(base_path):
                continue
            try:
                for server_dir in os.listdir(base_path):
                    if "Server" in server_dir:
                        version = server_dir.replace("MySQL Server ", "")
                        packages["mysql-server"] = version
                        self.logger.info(
                            "Found MySQL Server %s in %s", version, base_path
                        )
                        return  # Take first version found
            except Exception as error:
                self.logger.debug("Error checking MySQL path %s: %s", base_path, error)

    def _get_python_packages(self) -> Dict[str, str]:
        """Check for Python's built-in SQLite."""
        packages = {}

        try:
            # Check if Python has SQLite support
            result = subprocess.run(
                [
                    "python",
                    "-c",
                    "import sqlite3; print(sqlite3.sqlite_version)",
                ],  # nosec B603, B607 # Safe: no user input
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                packages["sqlite3"] = version
                self.logger.info("Found SQLite %s via Python", version)
        except Exception as error:
            self.logger.debug("Error checking Python SQLite: %s", error)

        return packages

    def _get_winget_packages(self) -> Dict[str, str]:
        """Get packages from winget (Windows Package Manager)."""
        packages = {}
        winget_path = self._get_command_path("winget")
        if not winget_path:
            return packages

        try:
            result = subprocess.run(
                [
                    winget_path,
                    "list",
                    "--disable-interactivity",
                ],  # nosec B603 # winget_path from _get_command_path
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                packages = self._parse_winget_output(result.stdout)

        except Exception as error:
            self.logger.debug("Error getting winget packages: %s", error)

        return packages

    def _parse_winget_output(self, stdout: str) -> Dict[str, str]:
        """Parse winget list output for database-related packages."""
        packages = {}
        db_keywords = [
            "postgresql",
            "mysql",
            "mariadb",
            "sqlite",
            "mongodb",
            "redis",
        ]

        lines = stdout.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or "-" * 5 in line or line.startswith("Name"):
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            name_lower = line.lower()
            if any(db in name_lower for db in db_keywords):
                name = parts[0]
                version = parts[2] if len(parts) > 2 else "unknown"
                packages[name.lower()] = version

        return packages

    def find_package_version(
        self, package_pattern: str, packages: Dict[str, str]
    ) -> Optional[str]:
        """Find package version by name or pattern."""
        # First try exact match
        if package_pattern in packages:
            return packages[package_pattern]

        # Try pattern matching for partial names
        # Note: Substring matching is intentionally simple to catch variations
        # like postgresql-server, postgresql14-server, etc.
        for package_name, version in packages.items():
            if package_pattern in package_name.lower():
                return version

        return None

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system."""
        return shutil.which(command) is not None

    def _get_command_path(self, command: str) -> Optional[str]:
        """Get the full path to a command."""
        return shutil.which(command)
