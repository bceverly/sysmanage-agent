"""
Role detection collection module for detecting server roles based on installed packages and services.
"""

import platform
import subprocess
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
                    "postgresql": {"service_names": ["postgresql", "postgres"]},
                    "mysql-server": {"service_names": ["mysql", "mysqld"]},
                    "mariadb-server": {"service_names": ["mariadb", "mysqld"]},
                    "mongodb": {"service_names": ["mongod", "mongodb"]},
                    "redis": {"service_names": ["redis", "redis-server"]},
                    "sqlite3": {"service_names": []},  # No service for SQLite
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

        except Exception as e:
            self.logger.error("Error detecting roles: %s", e)

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
                        if status in ["running", "stopped"]:
                            service_status = status
                            active_service = service_name
                            break
                else:
                    # For packages without services (like SQLite), mark as "installed"
                    service_status = "installed"

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

        except Exception as e:
            self.logger.error("Error getting installed packages: %s", e)

        return packages

    def _get_dpkg_packages(self) -> Dict[str, str]:
        """Get packages from dpkg (Debian/Ubuntu)."""
        packages = {}
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"],
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

        except Exception as e:
            self.logger.debug("Error getting dpkg packages: %s", e)

        return packages

    def _get_rpm_packages(self) -> Dict[str, str]:
        """Get packages from RPM (RHEL/CentOS/Fedora)."""
        packages = {}
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}\\n"],
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

        except Exception as e:
            self.logger.debug("Error getting RPM packages: %s", e)

        return packages

    def _get_pacman_packages(self) -> Dict[str, str]:
        """Get packages from pacman (Arch Linux)."""
        packages = {}
        try:
            result = subprocess.run(
                ["pacman", "-Q"],
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

        except Exception as e:
            self.logger.debug("Error getting pacman packages: %s", e)

        return packages

    def _get_snap_packages(self) -> Dict[str, str]:
        """Get packages from snap."""
        packages = {}
        try:
            result = subprocess.run(
                ["snap", "list"],
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

        except Exception as e:
            self.logger.debug("Error getting snap packages: %s", e)

        return packages

    def _find_package_version(
        self, package_pattern: str, packages: Dict[str, str]
    ) -> Optional[str]:
        """Find package version by name or pattern."""
        # First try exact match
        if package_pattern in packages:
            return packages[package_pattern]

        # Try pattern matching for partial names
        for package_name, version in packages.items():
            if package_pattern in package_name.lower():
                return version

        return None

    def _get_service_status(self, service_name: str) -> str:
        """Get the status of a service."""
        try:
            if self.system == "linux":
                # Try snap services first (for snap packages)
                if self._command_exists("snap"):
                    snap_status = self._get_snap_service_status(service_name)
                    if snap_status != "unknown":
                        return snap_status

                # Try systemctl
                if self._command_exists("systemctl"):
                    result = subprocess.run(
                        ["systemctl", "is-active", service_name],
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
                if self._command_exists("service"):
                    result = subprocess.run(
                        ["service", service_name, "status"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        return "running"
                    return "stopped"

        except Exception as e:
            self.logger.debug("Error checking service %s: %s", service_name, e)

        return "unknown"

    def _get_snap_service_status(self, service_name: str) -> str:
        """Check the status of a snap service."""
        try:
            result = subprocess.run(
                ["snap", "services"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return "unknown"

            return self._parse_snap_services_output(result.stdout, service_name)

        except Exception as e:
            self.logger.debug(
                "Error checking snap services for %s: %s", service_name, e
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

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system."""
        try:
            result = subprocess.run(
                ["which", command], capture_output=True, timeout=5, check=False
            )
            return result.returncode == 0
        except Exception:
            return False
