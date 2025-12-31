"""
Debian agent .deb download utilities.

This module handles downloading the sysmanage-agent .deb package
from GitHub releases and serving it via httpd for VM installation.
"""

import json
import logging
import shutil
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from src.i18n import _


class AgentPackageDownloader:
    """Handles downloading and serving sysmanage-agent .deb packages."""

    AGENT_CACHE_DIR = "/var/vmm/agent-packages"
    HTTPD_ROOT = "/var/www/htdocs"
    GITHUB_API_URL = (
        "https://api.github.com/repos/bceverly/sysmanage-agent/releases/latest"
    )

    def __init__(self, logger: logging.Logger):
        """Initialize agent package downloader."""
        self.logger = logger

    def _get_cached_agent_version(self, debian_version: str) -> Optional[str]:
        """
        Get the version of the cached agent .deb for a Debian version.

        Args:
            debian_version: Debian version (e.g., "12")

        Returns:
            Version string if cached, None otherwise
        """
        cache_dir = Path(self.AGENT_CACHE_DIR)
        version_file = cache_dir / f"debian{debian_version}.version"
        if version_file.exists():
            return version_file.read_text().strip()
        return None

    def _get_latest_agent_release(self) -> Optional[Dict[str, Any]]:
        """
        Get the latest sysmanage-agent release info from GitHub.

        Returns:
            Release info dict or None if unavailable
        """
        try:
            req = urllib.request.Request(
                self.GITHUB_API_URL,
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=30) as response:  # nosec B310
                return json.loads(response.read().decode("utf-8"))
        except Exception as error:  # pylint: disable=broad-except
            self.logger.warning(
                _("Failed to get latest agent release from GitHub: %s"), error
            )
            return None

    def _find_deb_asset(
        self, release_info: Dict[str, Any], debian_version: str
    ) -> Optional[Tuple[str, str]]:
        """
        Find the .deb asset URL for a specific Debian version in release assets.

        Args:
            release_info: GitHub release info dict
            debian_version: Debian version (e.g., "12")

        Returns:
            Tuple of (download_url, filename) or None if not found
        """
        assets = release_info.get("assets", [])
        # First pass: look for debian-version-specific package (e.g., _debian12_)
        for asset in assets:
            name = asset.get("name", "")
            if f"debian{debian_version}" in name and name.endswith(".deb"):
                return asset.get("browser_download_url"), name
        # Second pass: look for any .deb with "debian" in name
        for asset in assets:
            name = asset.get("name", "")
            if name.endswith(".deb") and "debian" in name.lower():
                return asset.get("browser_download_url"), name
        # Third pass: look for any .deb file (e.g., _all.deb is arch-independent)
        for asset in assets:
            name = asset.get("name", "")
            if name.endswith(".deb") and not name.endswith(".sha256"):
                return asset.get("browser_download_url"), name
        return None

    def download_agent_deb(self, debian_version: str) -> Dict[str, Any]:
        """
        Download the latest sysmanage-agent .deb for a Debian version.

        Checks GitHub releases for the latest version and downloads if:
        - No cached version exists
        - A newer version is available

        Args:
            debian_version: Debian version (e.g., "12")

        Returns:
            Dict with success status, deb_path, and version info
        """
        try:
            # Ensure cache directory exists
            cache_dir = Path(self.AGENT_CACHE_DIR)
            cache_dir.mkdir(parents=True, exist_ok=True)

            # Get current cached version
            cached_version = self._get_cached_agent_version(debian_version)
            self.logger.info(
                _("Cached agent version for Debian %s: %s"),
                debian_version,
                cached_version or "none",
            )

            # Get latest release info from GitHub
            release_info = self._get_latest_agent_release()
            if not release_info:
                return self._handle_no_github_access(
                    cache_dir, debian_version, cached_version
                )

            latest_version = release_info.get("tag_name", "").lstrip("v")
            self.logger.info(_("Latest agent version on GitHub: %s"), latest_version)

            # Check if we need to download
            cached_deb = cache_dir / f"sysmanage-agent_debian{debian_version}.deb"
            if cached_version == latest_version and cached_deb.exists():
                self.logger.info(_("Agent package is up to date: %s"), cached_version)
                return {
                    "success": True,
                    "deb_path": str(cached_deb),
                    "version": cached_version,
                    "from_cache": True,
                }

            # Find and download the .deb asset
            return self._download_deb_asset(
                release_info,
                debian_version,
                cache_dir,
                cached_deb,
                cached_version,
                latest_version,
            )

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(_("Failed to download agent package: %s"), error)
            return {"success": False, "error": str(error)}

    def _handle_no_github_access(
        self, cache_dir: Path, debian_version: str, cached_version: Optional[str]
    ) -> Dict[str, Any]:
        """Handle case when GitHub is not accessible."""
        cached_deb = cache_dir / f"sysmanage-agent_debian{debian_version}.deb"
        if cached_deb.exists():
            self.logger.info(
                _("Using cached agent package (GitHub unavailable): %s"),
                cached_deb,
            )
            return {
                "success": True,
                "deb_path": str(cached_deb),
                "version": cached_version,
                "from_cache": True,
            }
        return {
            "success": False,
            "error": _("Cannot reach GitHub and no cached package available"),
        }

    def _download_deb_asset(
        self,
        release_info: Dict[str, Any],
        debian_version: str,
        cache_dir: Path,
        cached_deb: Path,
        cached_version: Optional[str],
        latest_version: str,
    ) -> Dict[str, Any]:
        """Download the .deb asset from GitHub."""
        asset_info = self._find_deb_asset(release_info, debian_version)
        if not asset_info:
            if cached_deb.exists():
                self.logger.warning(
                    _("No Debian %s package in latest release, using cached"),
                    debian_version,
                )
                return {
                    "success": True,
                    "deb_path": str(cached_deb),
                    "version": cached_version,
                    "from_cache": True,
                }
            return {
                "success": False,
                "error": _("No .deb package found for Debian %s in release")
                % debian_version,
            }

        download_url, filename = asset_info
        self.logger.info(
            _("Downloading agent package: %s -> %s"), download_url, cached_deb
        )

        # Download to temp file first
        temp_path = cache_dir / f"{filename}.downloading"
        try:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(
                download_url, timeout=300
            ) as response:  # nosec B310
                with open(temp_path, "wb") as deb_file:
                    shutil.copyfileobj(response, deb_file)

            # Atomically move to final location
            temp_path.rename(cached_deb)

            # Save version info
            version_file = cache_dir / f"debian{debian_version}.version"
            version_file.write_text(latest_version)

            self.logger.info(
                _("Downloaded agent package: %s (%s)"),
                cached_deb,
                latest_version,
            )
            return {
                "success": True,
                "deb_path": str(cached_deb),
                "version": latest_version,
                "from_cache": False,
            }

        finally:
            # Clean up temp file if it exists
            if temp_path.exists():
                temp_path.unlink()

    def serve_agent_deb_via_httpd(self, deb_path: str, vm_name: str) -> Dict[str, Any]:
        """
        Copy agent .deb to httpd directory for serving to VM.

        Args:
            deb_path: Path to the .deb file
            vm_name: VM name (for organizing httpd directory)

        Returns:
            Dict with success status and URL
        """
        try:
            # Create httpd directory for this VM
            httpd_vm_dir = Path(self.HTTPD_ROOT) / "debian" / vm_name
            httpd_vm_dir.mkdir(parents=True, exist_ok=True)

            # Copy .deb to httpd directory
            deb_filename = "sysmanage-agent.deb"
            httpd_deb_path = httpd_vm_dir / deb_filename
            shutil.copy2(deb_path, httpd_deb_path)

            # Make readable by httpd
            httpd_deb_path.chmod(0o644)

            # Build URL
            deb_url = f"http://100.64.0.1/debian/{vm_name}/{deb_filename}"

            self.logger.info(_("Agent .deb available at: %s"), deb_url)
            return {
                "success": True,
                "deb_url": deb_url,
                "deb_path": str(httpd_deb_path),
            }

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(_("Failed to serve agent .deb via httpd: %s"), error)
            return {"success": False, "error": str(error)}
