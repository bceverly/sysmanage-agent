"""
Role detection collection module for detecting server roles based on installed packages and services.
"""

import platform
from typing import Dict, List, Any
import logging

from .role_detection_package_managers import PackageManagerDetector
from .role_detection_service_status import ServiceStatusDetector
from .role_detection_virtualization_hosts import VirtualizationHostDetector


class RoleDetector:
    """Detects server roles based on installed packages and running services."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system = platform.system().lower()

        # Initialize helper modules
        self.package_detector = PackageManagerDetector(self.system, self.logger)
        self.service_detector = ServiceStatusDetector(self.system, self.logger)
        self.virt_detector = VirtualizationHostDetector(
            self.system, self.logger, self.service_detector
        )

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
            # Virtualization host roles - these require special detection
            # to verify the host is actually configured and ready for child hosts
            "lxd_host": {
                "role": "LXD Host",
                "packages": {
                    "lxd": {"service_names": ["snap.lxd.daemon", "lxd"]},
                },
                "special_detection": "lxd",  # Flag for special handling
            },
            "wsl_host": {
                "role": "WSL Host",
                "packages": {},  # WSL is a Windows feature, not a package
                "special_detection": "wsl",  # Flag for special handling
            },
            "vmm_host": {
                "role": "VMM Host",
                "packages": {},  # VMM is an OpenBSD kernel feature
                "special_detection": "vmm",  # Flag for special handling
            },
            "kvm_host": {
                "role": "KVM Host",
                "packages": {},  # KVM is a Linux kernel feature + libvirt
                "special_detection": "kvm",  # Flag for special handling
            },
            "bhyve_host": {
                "role": "bhyve Host",
                "packages": {},  # bhyve is a FreeBSD kernel feature
                "special_detection": "bhyve",  # Flag for special handling
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
            installed_packages = self.package_detector.get_installed_packages()
            if not installed_packages:
                self.logger.warning(
                    "No packages detected or unsupported package manager"
                )
                # Still check special detection roles even without packages
                self._detect_virtualization_host_roles(roles)
                return roles

            # Check each role category
            for _, role_info in self.role_mappings.items():
                role_name = role_info["role"]

                # Handle special detection for virtualization hosts
                if role_info.get("special_detection"):
                    # These are handled separately below
                    continue

                self._check_role_packages(
                    role_name, role_info["packages"], installed_packages, roles
                )

            # Detect virtualization host roles (LXD, WSL, VMM)
            self._detect_virtualization_host_roles(roles)

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
            package_version = self.package_detector.find_package_version(
                package_pattern, installed_packages
            )
            if not package_version:
                continue

            self.logger.info(
                "Found %s package: %s v%s",
                role_name,
                package_pattern,
                package_version,
            )

            service_status, active_service = self._detect_service_status(
                service_info["service_names"]
            )

            self._add_role_if_unique(
                roles,
                role_name,
                package_pattern,
                package_version,
                active_service,
                service_status,
            )

    def _detect_service_status(self, service_names: List[str]) -> tuple:
        """Detect the status of services and return the best match.

        Returns:
            Tuple of (service_status, active_service_name)
        """
        if not service_names:
            return ("installed", None)

        service_status = "unknown"
        active_service = None

        for service_name in service_names:
            status = self.service_detector.get_service_status(service_name)
            if status == "running":
                return (status, service_name)
            if status == "stopped" and service_status == "unknown":
                service_status = status
                active_service = service_name

        return (service_status, active_service)

    def _add_role_if_unique(
        self,
        roles: List[Dict[str, Any]],
        role_name: str,
        package_pattern: str,
        package_version: str,
        active_service: str,
        service_status: str,
    ) -> None:
        """Add a role to the list if no duplicate role+service combination exists."""
        role_service_key = (role_name, active_service)
        self.logger.debug(
            "Checking for duplicate: role=%s, service=%s, existing_roles_count=%d",
            role_name,
            active_service,
            len(roles),
        )

        existing_role = next(
            (r for r in roles if (r["role"], r["service_name"]) == role_service_key),
            None,
        )

        if existing_role:
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

    def _detect_virtualization_host_roles(self, roles: List[Dict[str, Any]]) -> None:
        """
        Detect virtualization host roles (LXD Host, WSL Host, VMM Host, KVM Host).

        These roles require special detection beyond package checking because
        the host must be properly configured and ready to create child hosts,
        not just have the software installed.
        """
        # Detect LXD Host on Linux
        if self.system == "linux":
            lxd_role = self.virt_detector.detect_lxd_host_role()
            if lxd_role:
                roles.append(lxd_role)

            # Detect KVM Host on Linux
            kvm_role = self.virt_detector.detect_kvm_host_role()
            if kvm_role:
                roles.append(kvm_role)

        # Detect WSL Host on Windows
        if self.system == "windows":
            wsl_role = self.virt_detector.detect_wsl_host_role()
            if wsl_role:
                roles.append(wsl_role)

        # Detect VMM Host on OpenBSD
        if self.system == "openbsd":
            vmm_role = self.virt_detector.detect_vmm_host_role()
            if vmm_role:
                roles.append(vmm_role)

        # Detect bhyve Host on FreeBSD
        if self.system == "freebsd":
            bhyve_role = self.virt_detector.detect_bhyve_host_role()
            if bhyve_role:
                roles.append(bhyve_role)
