"""
GitHub API integration for sysmanage-agent version checking.

This module provides functionality to check the latest release version
of sysmanage-agent from GitHub releases.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Dict, Optional

from src.i18n import _


class GitHubVersionChecker:
    """Handles GitHub API interactions for version checking."""

    GITHUB_API_URL = (
        "https://api.github.com/repos/bceverly/sysmanage-agent/releases/latest"
    )
    GITHUB_RELEASES_URL = (
        "https://github.com/bceverly/sysmanage-agent/releases/download"
    )

    def __init__(self, logger: logging.Logger):
        """
        Initialize GitHub version checker.

        Args:
            logger: Logger instance for logging operations
        """
        self.logger = logger

    def get_latest_version(self) -> Dict[str, Optional[str]]:
        """
        Get the latest release version from GitHub.

        Returns:
            Dict containing:
                - success: bool
                - version: str (e.g., "0.9.9.8") if successful
                - tag_name: str (e.g., "v0.9.9.8") if successful
                - error: str if failed
        """
        try:
            self.logger.info(_("Checking latest sysmanage-agent version from GitHub"))

            # Make API request
            request = urllib.request.Request(  # nosec B310 # GitHub API HTTPS
                self.GITHUB_API_URL,
                headers={"Accept": "application/vnd.github.v3+json"},
            )

            with urllib.request.urlopen(  # nosec B310 # GitHub API HTTPS
                request, timeout=30
            ) as response:
                data = json.loads(response.read().decode("utf-8"))

            # Extract version information
            tag_name = data.get("tag_name", "")
            if not tag_name:
                return {
                    "success": False,
                    "version": None,
                    "tag_name": None,
                    "error": _("No tag_name in GitHub API response"),
                }

            # Remove 'v' prefix if present
            version = tag_name.lstrip("v")

            self.logger.info(
                _("Latest sysmanage-agent version: %s (tag: %s)"),
                version,
                tag_name,
            )

            return {
                "success": True,
                "version": version,
                "tag_name": tag_name,
                "error": None,
            }

        except urllib.error.HTTPError as error:
            self.logger.error(_("GitHub API HTTP error: %s"), error, exc_info=True)
            return {
                "success": False,
                "version": None,
                "tag_name": None,
                "error": f"GitHub API error: {error}",
            }
        except urllib.error.URLError as error:
            self.logger.error(_("GitHub API URL error: %s"), error, exc_info=True)
            return {
                "success": False,
                "version": None,
                "tag_name": None,
                "error": f"Network error: {error}",
            }
        except json.JSONDecodeError as error:
            self.logger.error(
                _("Failed to parse GitHub API response: %s"),
                error,
                exc_info=True,
            )
            return {
                "success": False,
                "version": None,
                "tag_name": None,
                "error": f"Invalid JSON response: {error}",
            }
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                _("Unexpected error checking GitHub version: %s"),
                error,
                exc_info=True,
            )
            return {
                "success": False,
                "version": None,
                "tag_name": None,
                "error": f"Unexpected error: {error}",
            }

    def get_port_tarball_url(self, version: str) -> str:
        """
        Get the download URL for the OpenBSD port tarball.

        Args:
            version: Version string (e.g., "0.9.9.8")

        Returns:
            Full URL to download the port tarball
        """
        tag = f"v{version}"
        filename = f"sysmanage-agent-{version}-openbsd-port.tar.gz"
        return f"{self.GITHUB_RELEASES_URL}/{tag}/{filename}"

    @staticmethod
    def compare_versions(version1: str, version2: str) -> int:
        """
        Compare two semantic version strings.

        Args:
            version1: First version (e.g., "0.9.9.8")
            version2: Second version (e.g., "0.9.9.7")

        Returns:
            -1 if version1 < version2
             0 if version1 == version2
             1 if version1 > version2
        """
        # Split versions into components
        v1_parts = [int(x) for x in version1.split(".")]
        v2_parts = [int(x) for x in version2.split(".")]

        # Pad shorter version with zeros
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts += [0] * (max_len - len(v1_parts))
        v2_parts += [0] * (max_len - len(v2_parts))

        # Compare each component
        for v1_part, v2_part in zip(v1_parts, v2_parts):
            if v1_part < v2_part:
                return -1
            if v1_part > v2_part:
                return 1

        return 0
