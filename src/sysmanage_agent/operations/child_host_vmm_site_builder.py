"""
OpenBSD site77.tgz builder for VMM autoinstall.

This module handles building the site77.tgz file that contains:
- sysmanage-agent package
- All Python dependencies (for offline installation)
- Configuration files
- First-boot setup scripts
"""

import hashlib
import logging
import os
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from sqlalchemy.orm import Session

from src.database.models import VmmBuildCache
from src.i18n import _
from src.sysmanage_agent.operations.child_host_vmm_package_builder import (
    PackageBuilder,
)


class SiteTarballBuilder:
    """Builds site77.tgz with sysmanage-agent and dependencies."""

    # OpenBSD package mirror
    PKG_URL_TEMPLATE = "https://ftp.openbsd.org/pub/OpenBSD/{version}/packages/amd64/"

    # Python packages required for sysmanage-agent (OpenBSD 7.7 amd64)
    REQUIRED_PACKAGES = [
        "python-3.12.9",
        "sqlite3-3.49.1p1",
        "gettext-runtime-0.23.1",
        "libiconv-1.17",
        "bzip2-1.0.8p0",
        "libffi-3.4.7p1",
        "libb2-0.98.1v0",
        "xz-5.6.4p0",
        "libcares-1.34.3p0",
        "gmp-6.3.0",
        "py3-websockets-13.1p0",
        "py3-yaml-6.0.2p0",
        "py3-aiohttp-3.11.14",
        "py3-cryptography-44.0.2",
        "py3-cryptodome-3.22.0",
        "py3-sqlalchemy-2.0.40",
        "py3-alembic-1.15.1",
        "py3-propcache-0.3.0",
        "py3-aiosignal-1.3.2",
        "py3-frozenlist-1.5.0",
        "py3-aiodns-3.2.0p0",
        "py3-aiohappyeyeballs-2.6.1",
        "py3-multidict-6.1.0p0",
        "py3-yarl-1.18.0p0",
        "py3-brotli-1.1.0p0",
        "py3-attrs-25.3.0",
        "py3-cffi-1.17.1p0",
        "py3-greenlet-3.1.1p0",
        "py3-typing_extensions-4.12.2p1",
        "py3-mako-1.3.9",
        "libyaml-0.2.5",
        "py3-cares-4.5.0",
        "py3-idna-3.10p1",
        "py3-cparser-2.22p0",
        "py3-MarkupSafe-2.1.5p0",
        "py3-beaker-1.13.0p0",
    ]

    def __init__(self, logger: logging.Logger, db_session: Session):
        """
        Initialize site tarball builder.

        Args:
            logger: Logger instance
            db_session: Database session for cache operations
        """
        self.logger = logger
        self.db_session = db_session

    def build_site_tarball(
        self,
        openbsd_version: str,
        agent_version: str,
        agent_tarball_url: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
    ) -> Dict[str, Any]:
        """
        Build site77.tgz with sysmanage-agent and dependencies.

        Args:
            openbsd_version: OpenBSD version (e.g., "7.7")
            agent_version: sysmanage-agent version (e.g., "0.9.9.8")
            agent_tarball_url: URL to download agent port tarball
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS for server connection

        Returns:
            Dict containing:
                - success: bool
                - site_tgz_path: str if successful
                - site_tgz_checksum: str if successful
                - agent_package_path: str if successful
                - error: str if failed
        """
        try:
            self.logger.info(
                _("Building site tarball for OpenBSD %s with agent version %s"),
                openbsd_version,
                agent_version,
            )

            # Create temporary build directory
            with tempfile.TemporaryDirectory(
                prefix="sysmanage-site-build-"
            ) as build_dir:
                build_path = Path(build_dir)

                # Step 1: Download and extract agent port tarball
                self.logger.info(_("Downloading agent port tarball"))
                self.logger.info(
                    _("About to call _download_port_tarball with URL: %s"),
                    agent_tarball_url,
                )
                port_result = self._download_port_tarball(agent_tarball_url, build_path)
                self.logger.info(_("Returned from _download_port_tarball"))
                self.logger.info(_("port_result: %s"), port_result)
                if not port_result["success"]:
                    self.logger.error(
                        _("Download failed: %s"), port_result.get("error")
                    )
                    return port_result
                port_dir = port_result["port_dir"]
                self.logger.info(_("port_dir: %s"), port_dir)

                # Step 2: Build sysmanage-agent package
                self.logger.info(_("Building sysmanage-agent package"))
                pkg_result = self._build_agent_package(port_dir, agent_version)
                if not pkg_result["success"]:
                    return pkg_result
                agent_pkg_path = pkg_result["package_path"]

                # Step 3: Download Python dependencies
                self.logger.info(_("Downloading Python dependencies"))
                deps_result = self._download_dependencies(openbsd_version, build_path)
                if not deps_result["success"]:
                    return deps_result
                packages_dir = deps_result["packages_dir"]

                # Step 4: Create site tarball structure
                self.logger.info(_("Creating site tarball structure"))
                site_result = self._create_site_structure(
                    build_path,
                    agent_pkg_path,
                    packages_dir,
                    server_hostname,
                    server_port,
                    use_https,
                )
                if not site_result["success"]:
                    return site_result

                # Step 5: Create site77.tgz
                self.logger.info(_("Creating site77.tgz"))
                tarball_result = self._create_tarball(
                    build_path,
                    openbsd_version,
                )
                if not tarball_result["success"]:
                    return tarball_result

                site_tgz_path = tarball_result["tarball_path"]
                checksum = self._calculate_checksum(site_tgz_path)

                # Step 6: Copy agent package to permanent location
                agent_dest = self._get_agent_package_path(
                    openbsd_version, agent_version
                )
                os.makedirs(os.path.dirname(agent_dest), exist_ok=True)
                shutil.copy2(agent_pkg_path, agent_dest)

                self.logger.info(
                    _("Site tarball built successfully: %s (checksum: %s)"),
                    site_tgz_path,
                    checksum[:16],
                )

                return {
                    "success": True,
                    "site_tgz_path": site_tgz_path,
                    "site_tgz_checksum": checksum,
                    "agent_package_path": agent_dest,
                    "error": None,
                }

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                _("Failed to build site tarball: %s"), error, exc_info=True
            )
            return {
                "success": False,
                "site_tgz_path": None,
                "site_tgz_checksum": None,
                "agent_package_path": None,
                "error": str(error),
            }

    def _download_port_tarball(self, url: str, build_path: Path) -> Dict[str, Any]:
        """Download and extract OpenBSD port tarball."""
        self.logger.info(_("ENTERED _download_port_tarball method"))
        try:
            self.logger.info(_("Inside try block, about to create tarball_path"))
            tarball_path = build_path / "port.tar.gz"
            self.logger.info(_("Created tarball_path: %s"), tarball_path)

            # Download using urllib
            self.logger.info(_("About to download with urllib"))
            self.logger.debug(_("Downloading from %s"), url)

            with urllib.request.urlopen(url, timeout=300) as response:  # nosec B310
                with open(tarball_path, "wb") as file:
                    shutil.copyfileobj(response, file)

            self.logger.info(_("Download completed"))

            self.logger.info(_("Checking if tarball exists: %s"), tarball_path)
            if not tarball_path.exists():
                self.logger.error(_("Downloaded file not found at %s"), tarball_path)
                return {
                    "success": False,
                    "port_dir": None,
                    "error": _("Downloaded file not found"),
                }

            self.logger.info(
                _("Tarball exists, size: %d bytes"), tarball_path.stat().st_size
            )

            # Extract - the tarball extracts port files directly into build_path
            self.logger.info(_("Extracting tarball to %s"), build_path)
            with tarfile.open(tarball_path, "r:gz") as tar:
                tar.extractall(path=build_path, filter="data")  # type: ignore
            self.logger.info(_("Extraction complete"))

            # Verify extraction by checking for Makefile
            port_makefile = build_path / "Makefile"
            self.logger.info(_("Checking for port Makefile: %s"), port_makefile)
            if not port_makefile.exists():
                self.logger.error(_("Port Makefile not found after extraction"))
                self.logger.error(
                    _("Contents of build_path: %s"), list(build_path.iterdir())
                )
                return {
                    "success": False,
                    "port_dir": None,
                    "error": _("Port Makefile not found after extraction"),
                }

            # The port directory is the build_path itself
            port_dir = build_path

            self.logger.info(_("Returning success, port_dir: %s"), port_dir)
            return {"success": True, "port_dir": port_dir, "error": None}

        except urllib.error.HTTPError as error:
            self.logger.error(_("HTTP error during download: %s"), error)
            return {
                "success": False,
                "port_dir": None,
                "error": f"HTTP error: {error}",
            }
        except urllib.error.URLError as error:
            self.logger.error(_("URL error during download: %s"), error)
            return {
                "success": False,
                "port_dir": None,
                "error": f"Network error: {error}",
            }
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(_("Unexpected error during download: %s"), error)
            return {
                "success": False,
                "port_dir": None,
                "error": f"Download failed: {error}",
            }

    def _build_agent_package(
        self, port_dir: Path, agent_version: str
    ) -> Dict[str, Any]:
        """Build sysmanage-agent package from port."""
        package_builder = PackageBuilder(self.logger)
        return package_builder.build_agent_package(port_dir, agent_version)

    def _download_dependencies(
        self, openbsd_version: str, build_path: Path
    ) -> Dict[str, Any]:
        """Download Python dependencies from OpenBSD mirror."""
        try:
            packages_dir = build_path / "packages"
            packages_dir.mkdir(exist_ok=True)

            pkg_url_base = self.PKG_URL_TEMPLATE.format(version=openbsd_version)

            for package in self.REQUIRED_PACKAGES:
                pkg_file = f"{package}.tgz"
                pkg_url = f"{pkg_url_base}{pkg_file}"
                dest_path = packages_dir / pkg_file

                self.logger.debug(_("Downloading %s"), package)

                try:
                    with urllib.request.urlopen(  # nosec B310
                        pkg_url, timeout=120
                    ) as response:
                        with open(dest_path, "wb") as file:
                            shutil.copyfileobj(response, file)
                except Exception as error:  # pylint: disable=broad-except
                    self.logger.warning(_("Failed to download %s: %s"), package, error)
                    # Continue with other packages

            # Verify we got at least some packages
            downloaded = list(packages_dir.glob("*.tgz"))
            if len(downloaded) < len(self.REQUIRED_PACKAGES) // 2:
                return {
                    "success": False,
                    "packages_dir": None,
                    "error": _("Too few packages downloaded (%d/%d)")
                    % (len(downloaded), len(self.REQUIRED_PACKAGES)),
                }

            return {
                "success": True,
                "packages_dir": packages_dir,
                "error": None,
            }

        except Exception as error:  # pylint: disable=broad-except
            return {
                "success": False,
                "packages_dir": None,
                "error": f"Dependency download failed: {error}",
            }

    def _create_site_structure(
        self,
        build_path: Path,
        agent_pkg_path: str,
        packages_dir: Path,
        server_hostname: str,
        server_port: int,
        use_https: bool,
    ) -> Dict[str, Any]:
        """Create the site77 directory structure."""
        try:
            site_dir = build_path / "site77"
            site_dir.mkdir(exist_ok=True)

            # Create root subdirectory for first-boot files
            root_dir = site_dir / "root"
            root_dir.mkdir(exist_ok=True)

            # Create etc subdirectory for config files
            etc_dir = site_dir / "etc"
            etc_dir.mkdir(exist_ok=True)

            # Copy sysmanage-agent package
            shutil.copy2(agent_pkg_path, root_dir)

            # Copy packages directory
            dest_packages = root_dir / "packages"
            shutil.copytree(packages_dir, dest_packages)

            # Create sysmanage-agent.yaml configuration in /etc
            # Note: Agent expects /etc/sysmanage-agent.yaml (not sysmanage-agent-system.yaml)
            config_content = self._generate_agent_config(
                server_hostname, server_port, use_https
            )
            config_path = etc_dir / "sysmanage-agent.yaml"
            config_path.write_text(config_content)

            # Create rc.firsttime script for first boot
            firsttime_script = self._generate_firsttime_script()
            firsttime_path = etc_dir / "rc.firsttime"
            firsttime_path.write_text(firsttime_script)
            firsttime_path.chmod(0o755)

            # Create install.site script (runs during installation)
            install_site = self._generate_install_site_script()
            install_site_path = site_dir / "install.site"
            install_site_path.write_text(install_site)
            install_site_path.chmod(0o755)

            return {"success": True, "error": None}

        except Exception as error:  # pylint: disable=broad-except
            return {
                "success": False,
                "error": f"Site structure creation failed: {error}",
            }

    def _generate_agent_config(self, hostname: str, port: int, use_https: bool) -> str:
        """Generate sysmanage-agent.yaml configuration."""
        return f"""# SysManage Agent Configuration
# Auto-generated by VMM autoinstall

# Server connection settings
server:
  hostname: "{hostname}"
  port: {port}
  use_https: {str(use_https).lower()}
  verify_ssl: false

# Client identification settings
client:
  registration_retry_interval: 30
  max_registration_retries: 10
  update_check_interval: 3600

# Internationalization settings
i18n:
  language: "en"

# Logging configuration
logging:
  level: "INFO"
  file: "/var/log/sysmanage-agent/agent.log"
  format: "[%(asctime)s UTC] %(name)s - %(levelname)s - %(message)s"

# WebSocket connection settings
websocket:
  auto_reconnect: true
  reconnect_interval: 5
  ping_interval: 60

# Database configuration
database:
  path: "agent.db"
  auto_migrate: true

# Script execution configuration
script_execution:
  enabled: true
  timeout: 300
  max_concurrent: 3
  allowed_shells:
    - "sh"
    - "ksh"
    - "csh"
  user_restrictions:
    allow_user_switching: false
    allowed_users: []
  security:
    restricted_paths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/etc/ssh/"
      - "/home/*/.ssh/"
      - "/root/.ssh/"
      - "*.key"
      - "*.pem"
    audit_logging: true
    require_approval: false
"""

    @staticmethod
    def _generate_firsttime_script() -> str:
        """Generate rc.firsttime script for first boot setup."""
        return """#!/bin/sh
# First boot setup - install sysmanage-agent and dependencies

echo "==> Installing Python dependencies (offline)..."
PKG_COUNT=$(ls -1 /root/packages/*.tgz 2>/dev/null | wc -l)
if [ ${PKG_COUNT} -gt 0 ]; then
    PKG_PATH="file:///root/packages/" pkg_add -D unsigned /root/packages/*.tgz
    echo "Installed ${PKG_COUNT} dependency packages"
fi

echo "==> Installing sysmanage-agent..."
AGENT_PKG=$(ls /root/sysmanage-agent-*.tgz 2>/dev/null | head -1)
if [ -n "$AGENT_PKG" ]; then
    PKG_PATH="file:///root/packages/" pkg_add -D unsigned "$AGENT_PKG"

    # Copy configuration
    if [ -f /root/sysmanage-agent.yaml ]; then
        mkdir -p /etc/sysmanage-agent
        cp /root/sysmanage-agent.yaml /etc/sysmanage-agent/
    fi

    # Enable and start service
    rcctl enable sysmanage_agent
    rcctl start sysmanage_agent
fi

echo "==> Running syspatch..."
syspatch

echo "==> Setup complete, shutting down..."
shutdown -p now
"""

    @staticmethod
    def _generate_install_site_script() -> str:
        """Generate install.site script (runs during installation)."""
        return """#!/bin/sh
# Post-installation script - runs during install

# Fix installurl to use official mirror
echo "https://cdn.openbsd.org/pub/OpenBSD" > /etc/installurl

exit 0
"""

    def _create_tarball(self, build_path: Path, openbsd_version: str) -> Dict[str, Any]:
        """Create site77.tgz from site directory."""
        try:
            site_dir = build_path / "site77"
            if not site_dir.exists():
                return {
                    "success": False,
                    "tarball_path": None,
                    "error": _("Site directory not found"),
                }

            # Create output directory
            output_dir = Path("/var/vmm/site-tarballs")
            output_dir.mkdir(parents=True, exist_ok=True)

            # Create tarball filename with version
            tarball_name = f"site{openbsd_version.replace('.', '')}.tgz"
            tarball_path = output_dir / tarball_name

            # Create tarball
            with tarfile.open(tarball_path, "w:gz") as tar:
                tar.add(site_dir, arcname=".")

            return {
                "success": True,
                "tarball_path": str(tarball_path),
                "error": None,
            }

        except Exception as error:  # pylint: disable=broad-except
            return {
                "success": False,
                "tarball_path": None,
                "error": f"Tarball creation failed: {error}",
            }

    @staticmethod
    def _calculate_checksum(file_path: str) -> str:
        """Calculate SHA256 checksum of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def _get_agent_package_path(openbsd_version: str, agent_version: str) -> str:
        """Get permanent storage path for agent package."""
        cache_dir = Path("/var/vmm/agent-packages")
        cache_dir.mkdir(parents=True, exist_ok=True)
        return str(
            cache_dir / f"sysmanage-agent-{agent_version}-obsd{openbsd_version}.tgz"
        )

    def get_or_build_site_tarball(
        self,
        openbsd_version: str,
        agent_version: str,
        agent_tarball_url: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
    ) -> Dict[str, Any]:
        """
        Get cached site tarball or build new one if not cached.

        Args:
            openbsd_version: OpenBSD version (e.g., "7.7")
            agent_version: sysmanage-agent version
            agent_tarball_url: URL to download agent port tarball
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS

        Returns:
            Dict with success status and paths
        """
        try:
            # Check cache
            cached = (
                self.db_session.query(VmmBuildCache)
                .filter_by(
                    openbsd_version=openbsd_version,
                    agent_version=agent_version,
                    build_status="success",
                )
                .first()
            )

            if cached:
                # Verify cached file exists
                if os.path.exists(cached.site_tgz_path):
                    self.logger.info(
                        _("Using cached site tarball: %s (built: %s)"),
                        cached.site_tgz_path,
                        cached.built_at,
                    )

                    # Update last_used_at
                    cached.last_used_at = datetime.now(timezone.utc)
                    self.db_session.commit()

                    return {
                        "success": True,
                        "site_tgz_path": cached.site_tgz_path,
                        "site_tgz_checksum": cached.site_tgz_checksum,
                        "agent_package_path": cached.agent_package_path,
                        "from_cache": True,
                        "error": None,
                    }

                # Cached entry exists but file is missing - delete cache entry
                self.logger.warning(
                    _("Cached file missing, rebuilding: %s"),
                    cached.site_tgz_path,
                )
                self.db_session.delete(cached)
                self.db_session.commit()

            # Build new tarball
            self.logger.info(_("Building new site tarball (not in cache)"))
            result = self.build_site_tarball(
                openbsd_version,
                agent_version,
                agent_tarball_url,
                server_hostname,
                server_port,
                use_https,
            )

            if not result["success"]:
                return result

            # Store in cache
            cache_entry = VmmBuildCache(
                openbsd_version=openbsd_version,
                agent_version=agent_version,
                site_tgz_path=result["site_tgz_path"],
                agent_package_path=result["agent_package_path"],
                site_tgz_checksum=result["site_tgz_checksum"],
                built_at=datetime.now(timezone.utc),
                last_used_at=datetime.now(timezone.utc),
                build_status="success",
                build_log=None,
            )
            self.db_session.add(cache_entry)
            self.db_session.commit()

            result["from_cache"] = False
            return result

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                _("Failed to get/build site tarball: %s"),
                error,
                exc_info=True,
            )
            return {
                "success": False,
                "site_tgz_path": None,
                "site_tgz_checksum": None,
                "agent_package_path": None,
                "from_cache": False,
                "error": str(error),
            }
