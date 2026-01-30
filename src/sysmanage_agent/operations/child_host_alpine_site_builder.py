"""
Alpine Linux site tarball builder for VMM autoinstall.

This module handles building the site tarball that contains:
- sysmanage-agent configuration file
- First-boot setup scripts
- Optional pre-downloaded Alpine packages
"""

import hashlib
import logging
import os
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from src.i18n import _
from src.sysmanage_agent.operations.child_host_alpine_packages import (
    SUPPORTED_ALPINE_VERSIONS,
)
from src.sysmanage_agent.operations.child_host_alpine_scripts import (
    generate_agent_config,
    generate_firstboot_script,
)


class AlpineSiteTarballBuilder:
    """Builds Alpine site tarball with sysmanage-agent configuration."""

    # GitHub releases URL for pre-built agent packages
    GITHUB_RELEASE_URL_TEMPLATE = (
        "https://github.com/bceverly/sysmanage-agent/releases/download/"
        "v{agent_version}/sysmanage-agent-{agent_version}-alpine{alpine_nodot}.apk"
    )

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
        alpine_version: str,
        agent_version: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
    ) -> Dict[str, Any]:
        """
        Build Alpine site tarball with sysmanage-agent configuration.

        Unlike OpenBSD, Alpine VMs will download packages from repos.
        This tarball contains only configuration files and scripts.

        Args:
            alpine_version: Alpine version (e.g., "3.20")
            agent_version: sysmanage-agent version (e.g., "1.0.0")
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS for server connection
            auto_approve_token: Optional UUID token for automatic host approval

        Returns:
            Dict containing:
                - success: bool
                - site_tgz_path: str if successful
                - agent_apk_path: str if agent APK was downloaded
                - error: str if failed
        """
        try:
            self.logger.info(
                _("Building Alpine site tarball for version %s with agent %s"),
                alpine_version,
                agent_version,
            )

            # Create temporary build directory
            with tempfile.TemporaryDirectory(
                prefix="sysmanage-alpine-site-"
            ) as build_dir:
                build_path = Path(build_dir)

                # Step 1: Try to download pre-built agent APK
                agent_apk_path = None
                if alpine_version in SUPPORTED_ALPINE_VERSIONS:
                    self.logger.info(
                        _("Attempting to download pre-built Alpine package...")
                    )
                    apk_result = self._download_prebuilt_agent_package(
                        alpine_version, agent_version, build_path
                    )
                    if apk_result["success"]:
                        agent_apk_path = apk_result["package_path"]
                        self.logger.info(
                            _("Downloaded pre-built APK: %s"), agent_apk_path
                        )
                    else:
                        self.logger.warning(
                            _("Pre-built APK not available: %s"),
                            apk_result.get("error"),
                        )

                # Step 2: Create site tarball structure
                self.logger.info(_("Creating site tarball structure..."))
                site_result = self._create_site_structure(
                    build_path,
                    agent_apk_path,
                    server_hostname,
                    server_port,
                    use_https,
                    auto_approve_token,
                )
                if not site_result["success"]:
                    return site_result

                # Step 3: Create the tarball
                self.logger.info(_("Creating site tarball..."))
                tarball_result = self._create_tarball(build_path, alpine_version)
                if not tarball_result["success"]:
                    return tarball_result

                site_tgz_path = tarball_result["tarball_path"]
                checksum = self._calculate_checksum(site_tgz_path)

                self.logger.info(
                    _("Alpine site tarball built: %s (checksum: %s)"),
                    site_tgz_path,
                    checksum[:16],
                )

                return {
                    "success": True,
                    "site_tgz_path": site_tgz_path,
                    "site_tgz_checksum": checksum,
                    "agent_apk_path": agent_apk_path,
                    "error": None,
                }

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                _("Failed to build Alpine site tarball: %s"), error, exc_info=True
            )
            return {
                "success": False,
                "site_tgz_path": None,
                "agent_apk_path": None,
                "error": str(error),
            }

    def _download_prebuilt_agent_package(
        self,
        alpine_version: str,
        agent_version: str,
        build_path: Path,
    ) -> Dict[str, Any]:
        """
        Download pre-built sysmanage-agent APK from GitHub releases.

        Args:
            alpine_version: Alpine version (e.g., "3.20")
            agent_version: sysmanage-agent version (e.g., "1.0.0")
            build_path: Directory to download the package to

        Returns:
            Dict containing success status and package path
        """
        # Build the download URL
        alpine_nodot = alpine_version.replace(".", "")
        download_url = self.GITHUB_RELEASE_URL_TEMPLATE.format(
            agent_version=agent_version,
            alpine_nodot=alpine_nodot,
        )

        # Package filename
        pkg_filename = f"sysmanage-agent-{agent_version}-alpine{alpine_nodot}.apk"
        pkg_path = build_path / pkg_filename

        self.logger.info(_("Downloading pre-built Alpine package..."))
        self.logger.debug(_("URL: %s"), download_url)

        # Retry configuration
        max_retries = 3
        base_delay = 5

        for attempt in range(1, max_retries + 1):
            try:
                self.logger.info(
                    _("Download attempt %d of %d..."), attempt, max_retries
                )

                # URL is hardcoded Alpine package repository, not user-provided
                # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                with urllib.request.urlopen(  # nosec B310
                    download_url, timeout=120
                ) as response:
                    with open(pkg_path, "wb") as pkg_file:
                        shutil.copyfileobj(response, pkg_file)

                # Verify the file was downloaded
                if not pkg_path.exists():
                    raise FileNotFoundError(_("Downloaded file not found"))

                file_size = pkg_path.stat().st_size
                if file_size < 1000:
                    raise ValueError(
                        _("Downloaded file too small (%d bytes)") % file_size
                    )

                self.logger.info(
                    _("Downloaded Alpine package: %s (%d bytes)"),
                    pkg_filename,
                    file_size,
                )

                return {
                    "success": True,
                    "package_path": str(pkg_path),
                    "error": None,
                }

            except urllib.error.HTTPError as error:
                self.logger.warning(
                    _("HTTP error downloading package (attempt %d): %s"),
                    attempt,
                    error,
                )
                if error.code == 404:
                    return {
                        "success": False,
                        "package_path": None,
                        "error": _("Pre-built package not found for Alpine %s")
                        % alpine_version,
                    }
            except Exception as error:  # pylint: disable=broad-except
                self.logger.warning(
                    _("Error downloading package (attempt %d): %s"),
                    attempt,
                    error,
                )

            if attempt < max_retries:
                delay = base_delay * attempt
                self.logger.info(_("Waiting %d seconds before retry..."), delay)
                time.sleep(delay)

        return {
            "success": False,
            "package_path": None,
            "error": _("Failed to download after %d attempts") % max_retries,
        }

    def _create_site_structure(
        self,
        build_path: Path,
        agent_apk_path: Optional[str],
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
    ) -> Dict[str, Any]:
        """Create the Alpine site directory structure."""
        try:
            site_dir = build_path / "alpine-site"
            site_dir.mkdir(exist_ok=True)

            # Create etc subdirectory for config files
            etc_dir = site_dir / "etc"
            etc_dir.mkdir(exist_ok=True)

            # Create local.d for first-boot scripts
            local_d_dir = etc_dir / "local.d"
            local_d_dir.mkdir(exist_ok=True)

            # Create root subdirectory for packages
            root_dir = site_dir / "root"
            root_dir.mkdir(exist_ok=True)

            # Copy agent APK if available
            if agent_apk_path and os.path.exists(agent_apk_path):
                shutil.copy2(agent_apk_path, root_dir / "sysmanage-agent.apk")
                self.logger.info(_("Copied agent APK to site tarball"))

            # Create sysmanage-agent.yaml configuration
            config_content = generate_agent_config(
                server_hostname, server_port, use_https, auto_approve_token
            )
            config_path = etc_dir / "sysmanage-agent.yaml"
            config_path.write_text(config_content)
            self.logger.info(_("Created agent configuration"))

            # Create first-boot script
            firstboot_content = generate_firstboot_script()
            firstboot_path = local_d_dir / "sysmanage-firstboot.start"
            firstboot_path.write_text(firstboot_content)
            firstboot_path.chmod(0o755)
            self.logger.info(_("Created first-boot script"))

            return {"success": True, "error": None}

        except Exception as error:  # pylint: disable=broad-except
            return {
                "success": False,
                "error": f"Site structure creation failed: {error}",
            }

    def _create_tarball(self, build_path: Path, alpine_version: str) -> Dict[str, Any]:
        """Create site tarball from site directory."""
        try:
            site_dir = build_path / "alpine-site"
            if not site_dir.exists():
                return {
                    "success": False,
                    "tarball_path": None,
                    "error": _("Site directory not found"),
                }

            # Create output directory
            output_dir = Path("/var/vmm/alpine-site-tarballs")
            output_dir.mkdir(parents=True, exist_ok=True)

            # Create tarball filename
            alpine_nodot = alpine_version.replace(".", "")
            tarball_name = f"alpine-site-{alpine_nodot}.tgz"
            tarball_path = output_dir / tarball_name

            # Create tarball
            with tarfile.open(tarball_path, "w:gz") as tar:  # NOSONAR
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

    def get_or_build_site_tarball(
        self,
        alpine_version: str,
        agent_version: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
    ) -> Dict[str, Any]:
        """
        Get cached site tarball or build new one.

        Each VM needs a unique config (with auto_approve_token), so
        we always build fresh.

        Args:
            alpine_version: Alpine version (e.g., "3.20")
            agent_version: sysmanage-agent version
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS
            auto_approve_token: Optional UUID token for automatic host approval

        Returns:
            Dict with success status and paths
        """
        # Always build fresh since config is unique per VM
        self.logger.info(_("Building new Alpine site tarball..."))
        return self.build_site_tarball(
            alpine_version,
            agent_version,
            server_hostname,
            server_port,
            use_https,
            auto_approve_token,
        )
