"""
Role detection collection module for detecting server roles based on installed packages and services.
"""

import fnmatch
import os
import platform
import shutil
import subprocess  # nosec B404 # Required for system package and service management
from typing import Dict, List, Optional, Any
import logging


class RoleDetector:
    """Detects server roles based on installed packages and running services."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system = platform.system().lower()

        # Define role mappings: package patterns -> role information
        self.role_mappings = {
            "web_server": {
                "role": "Web Server",
                "packages": {
                    "apache2": {"service_names": ["apache2", "httpd"]},
                    "nginx": {"service_names": ["nginx"]},
                    "httpd": {"service_names": ["httpd", "apache2"]},
                    "lighttpd": {"service_names": ["lighttpd"]},
                    "caddy": {"service_names": ["caddy"]},
                    "traefik": {"service_names": ["traefik"]},
                },
            },
            "database_server": {
                "role": "Database Server",
                "packages": {
                    # PostgreSQL - use version-specific server packages to avoid duplicates
                    "postgresql": {
                        "service_names": ["postgresql", "postgres"]
                    },  # Windows/Generic without -server suffix
                    "postgresql14-server": {
                        "service_names": ["postgresql", "postgres"]
                    },  # NetBSD/BSD
                    "postgresql15-server": {
                        "service_names": ["postgresql", "postgres"]
                    },
                    "postgresql16-server": {
                        "service_names": ["postgresql", "postgres"]
                    },
                    # macOS Homebrew PostgreSQL packages
                    "postgresql@14": {
                        "service_names": ["postgresql", "postgres"]
                    },  # Homebrew versioned PostgreSQL
                    "postgresql@15": {"service_names": ["postgresql", "postgres"]},
                    "postgresql@16": {"service_names": ["postgresql", "postgres"]},
                    "postgresql-homebrew": {
                        "service_names": ["postgresql", "postgres"]
                    },  # Homebrew generic PostgreSQL
                    # MySQL/MariaDB
                    "mysql-server": {"service_names": ["mysql", "mysqld"]},
                    "mariadb-server": {"service_names": ["mariadb", "mysqld"]},
                    "mysql": {"service_names": ["mysql", "mysqld"]},  # Homebrew MySQL
                    "mariadb": {
                        "service_names": ["mariadb", "mysqld"]
                    },  # Homebrew MariaDB
                    # Other databases
                    "mongodb": {"service_names": ["mongod", "mongodb"]},
                    "redis": {"service_names": ["redis", "redis-server"]},
                    "sqlite3": {"service_names": []},  # No service for SQLite
                    "sqlite": {"service_names": []},  # macOS Homebrew SQLite
                    "percona-server": {"service_names": ["mysql", "mysqld"]},
                    "cassandra": {"service_names": ["cassandra"]},
                    "influxdb": {"service_names": ["influxdb"]},
                    "elasticsearch": {"service_names": ["elasticsearch"]},
                },
            },
            "monitoring_server": {
                "role": "Monitoring Server",
                "packages": {
                    "grafana": {"service_names": ["grafana-server", "grafana"]},
                    "grafana-enterprise": {
                        "service_names": ["grafana-server", "grafana"]
                    },
                    "grafana-oss": {"service_names": ["grafana-server", "grafana"]},
                    "otelcol": {"service_names": ["otelcol", "otelcol-contrib"]},
                    "otelcol-contrib": {
                        "service_names": ["otelcol-contrib", "otelcol"]
                    },
                    "opentelemetry-collector": {
                        "service_names": ["otelcol", "otelcol-contrib"]
                    },
                    "prometheus": {"service_names": ["prometheus"]},
                    "prometheus2": {"service_names": ["prometheus"]},
                },
            },
            "log_aggregation_server": {
                "role": "Log Aggregation Server",
                "packages": {
                    "graylog-server": {"service_names": ["graylog-server", "graylog"]},
                    "graylog": {"service_names": ["graylog-server", "graylog"]},
                },
            },
        }

    def detect_roles(self) -> List[Dict[str, Any]]:
        """
        Detect server roles based on installed packages and services.

        Returns:
            List of role dictionaries with role, package, version, service, and status info.
        """
        roles = []

        try:
            # Get installed packages
            installed_packages = self._get_installed_packages()
            if not installed_packages:
                self.logger.warning(
                    "No packages detected or unsupported package manager"
                )
                return roles

            # Check each role category
            for role_info in self.role_mappings.values():
                role_name = role_info["role"]
                self._check_role_packages(
                    role_name, role_info["packages"], installed_packages, roles
                )

        except Exception as error:
            self.logger.error("Error detecting roles: %s", error)

        return roles

    def _check_role_packages(
        self,
        role_name: str,
        packages_config: Dict[str, Any],
        installed_packages: Dict[str, str],
        roles: List[Dict[str, Any]],
    ) -> None:
        """Check packages for a specific role and add found roles to the list."""
        for package_pattern, service_info in packages_config.items():
            # Check if package is installed
            package_version = self._find_package_version(
                package_pattern, installed_packages
            )
            if package_version:
                self.logger.info(
                    "Found %s package: %s v%s",
                    role_name,
                    package_pattern,
                    package_version,
                )

                # Check service status for packages that have services
                service_status = "unknown"
                active_service = None

                if service_info["service_names"]:
                    for service_name in service_info["service_names"]:
                        status = self._get_service_status(service_name)
                        if status == "running":
                            service_status = status
                            active_service = service_name
                            break
                        if status == "stopped" and service_status == "unknown":
                            service_status = status
                            active_service = service_name
                else:
                    # For packages without services (like SQLite), mark as "installed"
                    service_status = "installed"

                # Check for duplicates based on role + service_name combination
                role_service_key = (role_name, active_service)
                self.logger.debug(
                    "Checking for duplicate: role=%s, service=%s, existing_roles_count=%d",
                    role_name,
                    active_service,
                    len(roles),
                )

                existing_role = next(
                    (
                        r
                        for r in roles
                        if (r["role"], r["service_name"]) == role_service_key
                    ),
                    None,
                )

                if existing_role:
                    # Skip this duplicate - we already have this role+service combination
                    self.logger.info(
                        "Skipping duplicate role: %s with service %s (already have package %s)",
                        role_name,
                        active_service,
                        existing_role["package_name"],
                    )
                else:
                    self.logger.debug(
                        "Adding new role: %s with service %s, package %s",
                        role_name,
                        active_service,
                        package_pattern,
                    )
                    roles.append(
                        {
                            "role": role_name,
                            "package_name": package_pattern,
                            "package_version": package_version,
                            "service_name": active_service,
                            "service_status": service_status,
                            "is_active": service_status == "running",
                        }
                    )

    def _get_installed_packages(self) -> Dict[str, str]:
        """Get list of installed packages with versions."""
        packages = {}

        try:
            if self.system == "linux":
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

            elif self.system == "darwin":  # macOS
                # macOS package managers
                if self._command_exists("brew"):
                    packages.update(self._get_homebrew_packages())
                # Could also add MacPorts support here in the future
                # if self._command_exists("port"):
                #     packages.update(self._get_macports_packages())

            elif self.system in ["netbsd", "freebsd", "openbsd"]:
                # BSD package managers
                if self._command_exists("pkgin"):  # NetBSD
                    packages.update(self._get_pkgin_packages())
                elif self._command_exists("pkg"):  # FreeBSD/OpenBSD
                    packages.update(self._get_pkg_packages())

            elif self.system == "windows":
                # Windows package managers and direct detection
                packages.update(self._get_windows_packages())

        except Exception as error:
            self.logger.error("Error getting installed packages: %s", error)

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
            # If running as root (like via sudo), we need to run brew as the original user
            # because Homebrew refuses to run as root for security reasons
            cmd = [brew_path, "list", "--formula", "--versions"]
            if os.getuid() == 0:  # Running as root
                # Get the original user from SUDO_USER environment variable
                original_user = os.environ.get("SUDO_USER")
                if original_user:
                    cmd = ["sudo", "-u", original_user] + cmd

            # Get formula packages (command-line tools and libraries)
            result = subprocess.run(  # nosec B603 B607 # brew with controlled args
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            package_name = parts[0]
                            # Take the first version if multiple versions are listed
                            version = parts[1]
                            packages[package_name] = version

        except Exception as error:
            self.logger.debug("Error getting Homebrew packages: %s", error)

        return packages

    def _find_package_version(
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

    def _get_service_status(self, service_name: str) -> str:
        """Get the status of a service."""
        try:
            if self.system == "linux":
                return self._get_linux_service_status(service_name)
            if self.system == "darwin":  # macOS
                return self._get_macos_service_status(service_name)
            if self.system in ["netbsd", "freebsd", "openbsd"]:
                return self._get_bsd_service_status(service_name)
            if self.system == "windows":
                return self._get_windows_service_status(service_name)
        except Exception as error:
            self.logger.debug("Error checking service %s: %s", service_name, error)

        return "unknown"

    def _get_linux_service_status(self, service_name: str) -> str:
        """Get the status of a service on Linux."""
        # Try snap services first (for snap packages)
        if self._command_exists("snap"):
            snap_status = self._get_snap_service_status(service_name)
            if snap_status != "unknown":
                return snap_status

        # Try systemctl
        systemctl_path = self._get_command_path("systemctl")
        if systemctl_path:
            result = subprocess.run(  # nosec B603 B607 # systemctl with controlled args
                [systemctl_path, "is-active", service_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip() == "active":
                return "running"
            if result.stdout.strip() in ["inactive", "failed"]:
                return "stopped"

        # Try service command as fallback
        service_path = self._get_command_path("service")
        if service_path:
            result = subprocess.run(  # nosec B603 B607 # service with controlled args
                [service_path, service_name, "status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return "running" if result.returncode == 0 else "stopped"

        return "unknown"

    def _get_macos_service_status(self, service_name: str) -> str:
        """Get the status of a service on macOS."""
        # Try brew services first
        brew_status = self._check_brew_services(service_name)
        if brew_status != "unknown":
            return brew_status

        # Try checking running processes as fallback
        return self._check_process_status(service_name)

    def _check_brew_services(self, service_name: str) -> str:
        """Check service status using brew services."""
        brew_path = self._get_command_path("brew")
        if not brew_path:
            return "unknown"

        try:
            cmd = self._build_brew_command(brew_path)
            result = subprocess.run(  # nosec B603 B607 # brew with controlled args
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return self._parse_brew_services_output(result.stdout, service_name)

        except Exception as error:
            self.logger.debug(
                "Error checking brew services for %s: %s", service_name, error
            )

        return "unknown"

    def _build_brew_command(self, brew_path: str) -> list:
        """Build the brew services command, handling root user case."""
        cmd = [brew_path, "services", "list"]
        if os.getuid() == 0:  # Running as root
            original_user = os.environ.get("SUDO_USER")
            if original_user:
                cmd = ["sudo", "-u", original_user] + cmd
        return cmd

    def _parse_brew_services_output(self, output: str, service_name: str) -> str:
        """Parse brew services output to find service status."""
        for line in output.strip().split("\n"):
            if not line.strip() or line.startswith("Name"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            name = parts[0]
            status = parts[1]

            # Check if this service matches our target
            if (
                service_name in name.lower()
                or name.lower() in service_name
                or service_name == name
            ):
                if status == "started":
                    return "running"
                if status == "stopped":
                    return "stopped"

        return "unknown"

    def _check_process_status(self, service_name: str) -> str:
        """Check if service is running by examining processes."""
        try:
            result = subprocess.run(  # nosec B603 B607 # ps with controlled args
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                # Look for the service process in the output
                for line in result.stdout.lower().split("\n"):
                    if service_name.lower() in line and "grep" not in line:
                        return "running"
                    # Also check for common process name variations
                    if (
                        service_name in ["postgresql", "postgres"]
                        and "postgres:" in line
                        and "grep" not in line
                    ):
                        return "running"
                # If we checked processes and didn't find it, it's stopped
                return "stopped"
        except Exception as error:
            self.logger.debug(
                "Error checking processes for %s: %s", service_name, error
            )

        return "unknown"

    def _get_bsd_service_status(self, service_name: str) -> str:
        """Get the status of a service on BSD systems."""
        # BSD systems - check if process is running
        result = subprocess.run(  # nosec B603 B607 # ps with controlled args
            ["ps", "aux"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            # Look for the service process in the output
            for line in result.stdout.lower().split("\n"):
                if service_name.lower() in line and "grep" not in line:
                    return "running"
                # Also check for common process name variations
                if (
                    service_name in ["postgresql", "postgres"]
                    and "postgres:" in line
                    and "grep" not in line
                ):
                    return "running"
            # If we checked processes and didn't find it, it's stopped
            return "stopped"

        # Try service command as fallback for BSD
        service_path = self._get_command_path("service")
        if service_path:
            result = subprocess.run(  # nosec B603 B607 # service with controlled args
                [service_path, service_name, "onestatus"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return "running" if result.returncode == 0 else "stopped"

        return "unknown"

    def _get_snap_service_status(self, service_name: str) -> str:
        """Check the status of a snap service."""
        snap_path = self._get_command_path("snap")
        if not snap_path:
            return "unknown"

        try:
            result = subprocess.run(  # nosec B603 B607 # snap with controlled args
                [snap_path, "services"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return "unknown"

            return self._parse_snap_services_output(result.stdout, service_name)

        except Exception as error:
            self.logger.debug(
                "Error checking snap services for %s: %s", service_name, error
            )

        return "unknown"

    def _parse_snap_services_output(self, output: str, service_name: str) -> str:
        """Parse snap services output to find service status."""
        lines = output.strip().split("\n")
        # Skip the header line
        for line in lines[1:]:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            snap_service_name = parts[0]
            status = parts[2]

            # Check for service name match
            if self._is_snap_service_match(snap_service_name, service_name):
                if status == "active":
                    return "running"
                if status in ["inactive", "disabled"]:
                    return "stopped"

        return "unknown"

    def _is_snap_service_match(self, snap_service_name: str, service_name: str) -> bool:
        """Check if snap service name matches the target service name."""
        return (
            snap_service_name == service_name
            or service_name in snap_service_name
            or snap_service_name.endswith(f".{service_name}")
        )

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

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system."""
        return shutil.which(command) is not None

    def _get_command_path(self, command: str) -> Optional[str]:
        """Get the full path to a command."""
        return shutil.which(command)

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

        # Check for PostgreSQL in Program Files
        postgres_paths = [
            r"C:\Program Files\PostgreSQL",
            r"C:\Program Files (x86)\PostgreSQL",
        ]

        for base_path in postgres_paths:
            if os.path.exists(base_path):
                # Check for version subdirectories
                try:
                    for version_dir in os.listdir(base_path):
                        version_path = os.path.join(base_path, version_dir)
                        if os.path.isdir(version_path):
                            # Found PostgreSQL installation
                            packages["postgresql"] = version_dir
                            self.logger.info(
                                "Found PostgreSQL %s in %s", version_dir, base_path
                            )
                            break  # Take first version found
                except Exception as error:
                    self.logger.debug(
                        "Error checking PostgreSQL path %s: %s", base_path, error
                    )

        # Check for MySQL in Program Files
        mysql_paths = [r"C:\Program Files\MySQL", r"C:\Program Files (x86)\MySQL"]

        for base_path in mysql_paths:
            if os.path.exists(base_path):
                try:
                    for server_dir in os.listdir(base_path):
                        if "Server" in server_dir:
                            version = server_dir.replace("MySQL Server ", "")
                            packages["mysql-server"] = version
                            self.logger.info(
                                "Found MySQL Server %s in %s", version, base_path
                            )
                            break
                except Exception as error:
                    self.logger.debug(
                        "Error checking MySQL path %s: %s", base_path, error
                    )

        return packages

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
                lines = result.stdout.strip().split("\n")
                # Skip header lines
                for line in lines:
                    line = line.strip()
                    if not line or "-" * 5 in line or line.startswith("Name"):
                        continue

                    # Parse winget output (Name, Id, Version, Available, Source)
                    parts = line.split()
                    if len(parts) >= 3:
                        # Look for database-related packages
                        name_lower = line.lower()
                        if any(
                            db in name_lower
                            for db in [
                                "postgresql",
                                "mysql",
                                "mariadb",
                                "sqlite",
                                "mongodb",
                                "redis",
                            ]
                        ):
                            # Extract package name and version
                            # This is approximate due to winget's variable output format
                            name = parts[0]
                            # Version is typically 3rd column
                            version = parts[2] if len(parts) > 2 else "unknown"
                            packages[name.lower()] = version

        except Exception as error:
            self.logger.debug("Error getting winget packages: %s", error)

        return packages

    def _get_windows_service_status(self, service_name: str) -> str:
        """Get the status of a service on Windows."""
        # Windows services can have different names
        service_mappings = {
            "postgresql": ["postgresql-x64-*", "postgresql*"],
            "postgres": ["postgresql-x64-*", "postgresql*"],
            "mysql": ["MySQL*", "MySQL", "MySQL80", "MySQL57"],
            "mysqld": ["MySQL*", "MySQL", "MySQL80", "MySQL57"],
            "mongodb": ["MongoDB"],
            "mongod": ["MongoDB"],
            "redis": ["Redis"],
        }

        # Get actual service names to check
        services_to_check = service_mappings.get(service_name, [service_name])

        for svc_pattern in services_to_check:
            status = self._check_single_service_pattern(svc_pattern)
            if status != "unknown":
                return status

        return "unknown"

    def _check_single_service_pattern(self, svc_pattern: str) -> str:
        """Check a single service pattern and return its status."""
        try:
            # Use sc query to list services
            result = subprocess.run(
                [
                    "sc",
                    "query",
                    "state=",
                    "all",
                ],  # nosec B603, B607 # Safe: no user input
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return self._parse_service_output(result.stdout, svc_pattern)

        except Exception as error:
            self.logger.debug(
                "Error checking Windows service %s: %s", svc_pattern, error
            )

        return "unknown"

    def _parse_service_output(self, output: str, svc_pattern: str) -> str:
        """Parse sc query output for a specific service pattern."""
        lines = output.split("\n")
        current_service = None

        for line in lines:
            if "SERVICE_NAME:" in line:
                current_service = line.split("SERVICE_NAME:")[1].strip()
            elif "STATE" in line and current_service:
                # Check if this service matches our pattern
                if self._matches_service_pattern(current_service, svc_pattern):
                    if "RUNNING" in line:
                        self.logger.info(
                            "Found running Windows service: %s", current_service
                        )
                        return "running"
                    if "STOPPED" in line:
                        self.logger.info(
                            "Found stopped Windows service: %s", current_service
                        )
                        return "stopped"

        return "unknown"

    def _matches_service_pattern(self, service_name: str, pattern: str) -> bool:
        """Check if a Windows service name matches a pattern."""
        # Case-insensitive matching
        service_lower = service_name.lower()
        pattern_lower = pattern.lower()

        # Try exact match first
        if service_lower == pattern_lower:
            return True

        # Try wildcard match
        if "*" in pattern:
            return fnmatch.fnmatch(service_lower, pattern_lower)

        # Try substring match
        return pattern_lower in service_lower
