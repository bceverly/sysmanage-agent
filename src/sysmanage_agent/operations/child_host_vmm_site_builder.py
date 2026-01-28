"""
OpenBSD site77.tgz builder for VMM autoinstall.

This module handles building the site77.tgz file that contains:
- sysmanage-agent package
- All Python dependencies (for offline installation)
- Configuration files
- First-boot setup scripts
"""

from __future__ import annotations

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
from typing import Any, Dict

from sqlalchemy.orm import Session

from src.i18n import _
from src.sysmanage_agent.operations.child_host_vmm_package_builder import (
    PackageBuilder,
)
from src.sysmanage_agent.operations.child_host_vmm_packages import (
    REQUIRED_PACKAGES,
    REQUIRED_PACKAGES_BY_VERSION,
    SUPPORTED_OPENBSD_VERSIONS,
)
from src.sysmanage_agent.operations.child_host_vmm_scripts import (
    generate_agent_config,
    generate_firsttime_script,
    generate_install_site_script,
)


class SiteTarballBuilder:
    """Builds site77.tgz with sysmanage-agent and dependencies."""

    # OpenBSD package mirror
    PKG_URL_TEMPLATE = "https://ftp.openbsd.org/pub/OpenBSD/{version}/packages/amd64/"

    # GitHub releases URL for pre-built agent packages
    # Format: sysmanage-agent-{version}-openbsd{version_nodot}.tgz
    GITHUB_RELEASE_URL_TEMPLATE = (
        "https://github.com/bceverly/sysmanage-agent/releases/download/"
        "v{agent_version}/sysmanage-agent-{agent_version}-openbsd{openbsd_nodot}.tgz"
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
        openbsd_version: str,
        agent_version: str,
        agent_tarball_url: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
    ) -> Dict[str, Any]:
        """
        Build site77.tgz with sysmanage-agent and dependencies.

        For supported OpenBSD versions (7.4, 7.5, 7.6, 7.7), downloads pre-built
        packages from GitHub releases. Falls back to building from ports if
        pre-built package is not available.

        Args:
            openbsd_version: OpenBSD version (e.g., "7.7")
            agent_version: sysmanage-agent version (e.g., "1.0.0")
            agent_tarball_url: URL to download agent port tarball (fallback)
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS for server connection
            auto_approve_token: Optional UUID token for automatic host approval

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

                # Step 1: Get sysmanage-agent package
                # Check for cached package first, then try GitHub, then build
                agent_pkg_path = None

                # Check if we have a cached agent package
                cached_agent_path = self._get_agent_package_path(
                    openbsd_version, agent_version
                )
                if os.path.exists(cached_agent_path):
                    self.logger.info(
                        _("Using cached agent package: %s"), cached_agent_path
                    )
                    agent_pkg_path = cached_agent_path
                elif openbsd_version in SUPPORTED_OPENBSD_VERSIONS:
                    self.logger.info(
                        _(
                            "Attempting to download pre-built package for "
                            "OpenBSD %s from GitHub releases"
                        ),
                        openbsd_version,
                    )
                    prebuilt_result = self._download_prebuilt_agent_package(
                        openbsd_version, agent_version, build_path
                    )

                    if prebuilt_result["success"]:
                        agent_pkg_path = prebuilt_result["package_path"]
                        self.logger.info(
                            _("Using pre-built package: %s"), agent_pkg_path
                        )
                    else:
                        self.logger.warning(
                            _(
                                "Pre-built package not available: %s. "
                                "Falling back to building from ports."
                            ),
                            prebuilt_result.get("error"),
                        )

                # Fall back to building from ports if pre-built not available
                if agent_pkg_path is None:
                    self.logger.info(_("Building agent package from ports (fallback)"))

                    # Download and extract agent port tarball
                    self.logger.info(_("Downloading agent port tarball"))
                    port_result = self._download_port_tarball(
                        agent_tarball_url, build_path
                    )
                    if not port_result["success"]:
                        self.logger.error(
                            _("Download failed: %s"), port_result.get("error")
                        )
                        return {
                            "success": False,
                            "site_tgz_path": None,
                            "site_tgz_checksum": None,
                            "agent_package_path": None,
                            "error": port_result.get("error"),
                        }
                    port_dir = port_result["port_dir"]

                    # Build sysmanage-agent package
                    self.logger.info(_("Building sysmanage-agent package"))
                    pkg_result = self._build_agent_package(port_dir, agent_version)
                    if not pkg_result["success"]:
                        return {
                            "success": False,
                            "site_tgz_path": None,
                            "site_tgz_checksum": None,
                            "agent_package_path": None,
                            "error": pkg_result.get("error"),
                        }
                    agent_pkg_path = pkg_result["package_path"]

                # Step 2: Download Python dependencies
                self.logger.info(_("Downloading Python dependencies"))
                deps_result = self._download_dependencies(openbsd_version, build_path)
                if not deps_result["success"]:
                    return deps_result
                packages_dir = deps_result["packages_dir"]

                # Step 3: Create site tarball structure
                self.logger.info(_("Creating site tarball structure"))
                site_result = self._create_site_structure(
                    build_path,
                    agent_pkg_path,
                    packages_dir,
                    server_hostname,
                    server_port,
                    use_https,
                    auto_approve_token,
                )
                if not site_result["success"]:
                    return site_result

                # Step 4: Create site77.tgz
                self.logger.info(_("Creating site tarball"))
                tarball_result = self._create_tarball(
                    build_path,
                    openbsd_version,
                )
                if not tarball_result["success"]:
                    return tarball_result

                site_tgz_path = tarball_result["tarball_path"]
                checksum = self._calculate_checksum(site_tgz_path)

                # Step 5: Copy agent package to permanent location
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

            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
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
            # NOSONAR - using safe filter for extraction
            # nosemgrep: trailofbits.python.tarfile-extractall-traversal.tarfile-extractall-traversal
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

    def _validate_and_rename_package(
        self,
        pkg_path: Path,
        pkg_filename: str,
        agent_version: str,
        build_path: Path,
    ) -> Dict[str, Any]:
        """Validate downloaded package and rename to OpenBSD format."""
        # Verify the file was downloaded and is a valid tgz
        if not pkg_path.exists():
            raise FileNotFoundError(_("Downloaded file not found"))

        file_size = pkg_path.stat().st_size
        if file_size < 1000:
            # File too small, probably an error page
            raise ValueError(
                _("Downloaded file too small (%d bytes), likely an error") % file_size
            )

        # Verify it's a valid gzip file by checking magic bytes
        with open(pkg_path, "rb") as file:
            magic = file.read(2)
            if magic != b"\x1f\x8b":
                raise ValueError(_("Downloaded file is not a valid gzip archive"))

        self.logger.info(
            _("Successfully downloaded pre-built package: %s (%d bytes)"),
            pkg_filename,
            file_size,
        )

        # Rename package to match OpenBSD naming convention
        # The internal package name is sysmanage-agent-{version}p0
        # (the p0 comes from REVISION=0 in the port Makefile)
        # pkg_add requires filename to match internal package name
        openbsd_pkg_name = f"sysmanage-agent-{agent_version}p0.tgz"
        openbsd_pkg_path = build_path / openbsd_pkg_name
        pkg_path.rename(openbsd_pkg_path)
        self.logger.info(_("Renamed package to OpenBSD format: %s"), openbsd_pkg_name)

        return {
            "success": True,
            "package_path": str(openbsd_pkg_path),
            "error": None,
        }

    def _handle_download_error(
        self,
        error: Exception,
        attempt: int,
        openbsd_version: str,
        agent_version: str,
    ) -> Dict[str, Any] | None:
        """Handle download errors, returning result dict for fatal errors or None to continue."""
        if isinstance(error, urllib.error.HTTPError):
            self.logger.warning(
                _("HTTP error downloading package (attempt %d): %s"),
                attempt,
                error,
            )
            if error.code == 404:
                # Package doesn't exist for this version
                return {
                    "success": False,
                    "package_path": None,
                    "error": _(
                        "Pre-built package not found for OpenBSD %s agent v%s. "
                        "Please check if this version has been released."
                    )
                    % (openbsd_version, agent_version),
                }
        elif isinstance(error, urllib.error.URLError):
            self.logger.warning(
                _("Network error downloading package (attempt %d): %s"),
                attempt,
                error,
            )
        else:
            self.logger.warning(
                _("Error downloading package (attempt %d): %s"),
                attempt,
                error,
            )
        return None

    def _download_prebuilt_agent_package(
        self,
        openbsd_version: str,
        agent_version: str,
        build_path: Path,
    ) -> Dict[str, Any]:
        """
        Download pre-built sysmanage-agent package from GitHub releases.

        Args:
            openbsd_version: OpenBSD version (e.g., "7.7")
            agent_version: sysmanage-agent version (e.g., "1.0.0")
            build_path: Directory to download the package to

        Returns:
            Dict containing:
                - success: bool
                - package_path: str if successful
                - error: str if failed
        """
        # Validate OpenBSD version
        if openbsd_version not in SUPPORTED_OPENBSD_VERSIONS:
            return {
                "success": False,
                "package_path": None,
                "error": _("OpenBSD version %s not supported. Supported versions: %s")
                % (openbsd_version, ", ".join(SUPPORTED_OPENBSD_VERSIONS)),
            }

        # Build the download URL
        openbsd_nodot = openbsd_version.replace(".", "")
        download_url = self.GITHUB_RELEASE_URL_TEMPLATE.format(
            agent_version=agent_version,
            openbsd_nodot=openbsd_nodot,
        )

        # Package filename
        pkg_filename = f"sysmanage-agent-{agent_version}-openbsd{openbsd_nodot}.tgz"
        pkg_path = build_path / pkg_filename

        self.logger.info(_("Downloading pre-built agent package from GitHub releases"))
        self.logger.info(_("URL: %s"), download_url)

        # Retry configuration
        max_retries = 5
        base_delay = 5

        for attempt in range(1, max_retries + 1):
            try:
                self.logger.info(
                    _("Download attempt %d of %d..."), attempt, max_retries
                )

                # Download the package
                # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                with urllib.request.urlopen(  # nosec B310
                    download_url, timeout=120
                ) as response:
                    with open(pkg_path, "wb") as file:
                        shutil.copyfileobj(response, file)

                return self._validate_and_rename_package(
                    pkg_path, pkg_filename, agent_version, build_path
                )

            except Exception as error:  # pylint: disable=broad-except
                error_result = self._handle_download_error(
                    error, attempt, openbsd_version, agent_version
                )
                if error_result is not None:
                    return error_result

            # Wait before retry (exponential backoff, capped at 60 seconds)
            if attempt < max_retries:
                delay = min(base_delay * (2 ** (attempt - 1)), 60)
                self.logger.info(_("Waiting %d seconds before retry..."), delay)
                time.sleep(delay)

        return {
            "success": False,
            "package_path": None,
            "error": _("Failed to download pre-built package after %d attempts")
            % max_retries,
        }

    def _get_dependency_cache_dir(self, openbsd_version: str) -> Path:
        """Get the cache directory for dependency packages."""
        cache_dir = Path("/var/vmm/package-cache") / openbsd_version
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

    def _download_dependencies(
        self, openbsd_version: str, build_path: Path
    ) -> Dict[str, Any]:
        """Download Python dependencies from OpenBSD mirror (with caching)."""
        try:
            packages_dir = build_path / "packages"
            packages_dir.mkdir(exist_ok=True)

            # Check for cached packages first
            cache_dir = self._get_dependency_cache_dir(openbsd_version)
            pkg_url_base = self.PKG_URL_TEMPLATE.format(version=openbsd_version)

            # Get version-specific package list, fall back to default if not found
            required_packages = REQUIRED_PACKAGES_BY_VERSION.get(
                openbsd_version, REQUIRED_PACKAGES
            )

            cached_count = 0
            download_count = 0

            for package in required_packages:
                pkg_file = f"{package}.tgz"
                dest_path = packages_dir / pkg_file
                cached_path = cache_dir / pkg_file

                # Check cache first
                if cached_path.exists():
                    shutil.copy2(cached_path, dest_path)
                    cached_count += 1
                    continue

                # Download if not cached
                pkg_url = f"{pkg_url_base}{pkg_file}"
                self.logger.debug(_("Downloading %s"), package)

                try:
                    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                    with urllib.request.urlopen(  # nosec B310
                        pkg_url, timeout=120
                    ) as response:
                        with open(dest_path, "wb") as file:
                            shutil.copyfileobj(response, file)
                    # Cache the downloaded package
                    shutil.copy2(dest_path, cached_path)
                    download_count += 1
                except Exception as error:  # pylint: disable=broad-except
                    self.logger.warning(_("Failed to download %s: %s"), package, error)
                    # Continue with other packages

            self.logger.info(
                _("Packages: %d from cache, %d downloaded for OpenBSD %s"),
                cached_count,
                download_count,
                openbsd_version,
            )

            # Verify we got at least some packages
            downloaded = list(packages_dir.glob("*.tgz"))
            if len(downloaded) < len(required_packages) // 2:
                return {
                    "success": False,
                    "packages_dir": None,
                    "error": _("Too few packages downloaded (%d/%d)")
                    % (len(downloaded), len(required_packages)),
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
        auto_approve_token: str = None,
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
            config_content = generate_agent_config(
                server_hostname, server_port, use_https, auto_approve_token
            )
            config_path = etc_dir / "sysmanage-agent.yaml"
            config_path.write_text(config_content)

            # Create rc.firsttime script for first boot
            firsttime_script = generate_firsttime_script()
            firsttime_path = etc_dir / "rc.firsttime"
            firsttime_path.write_text(firsttime_script)
            firsttime_path.chmod(0o755)

            # Create install.site script (runs during installation)
            install_site = generate_install_site_script()
            install_site_path = site_dir / "install.site"
            install_site_path.write_text(install_site)
            install_site_path.chmod(0o755)

            return {"success": True, "error": None}

        except Exception as error:  # pylint: disable=broad-except
            return {
                "success": False,
                "error": f"Site structure creation failed: {error}",
            }

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
            # NOSONAR - creating tarball, not extracting untrusted content
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
        auto_approve_token: str = None,
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
            auto_approve_token: Optional UUID token for automatic host approval.
                If provided, caching is skipped since each VM needs a unique token.

        Returns:
            Dict with success status and paths
        """
        try:
            # Always build fresh - the config file contains server-specific
            # settings (hostname, port, auto_approve_token) that are unique
            # to each VM creation request. Caching would cause VMs to get
            # wrong configurations.
            # Build new tarball
            self.logger.info(_("Building new site tarball (not in cache)"))
            result = self.build_site_tarball(
                openbsd_version,
                agent_version,
                agent_tarball_url,
                server_hostname,
                server_port,
                use_https,
                auto_approve_token,
            )

            if not result["success"]:
                return result

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
