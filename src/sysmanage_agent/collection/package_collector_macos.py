"""
macOS package collection module for SysManage Agent.

This module handles the collection of available packages from macOS package managers.
"""

import logging
import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _
from src.sysmanage_agent.collection.package_collector_base import BasePackageCollector

logger = logging.getLogger(__name__)


class MacOSPackageCollector(BasePackageCollector):
    """Collects available packages from macOS package managers."""

    def collect_packages(self) -> int:
        """Collect packages from macOS package managers."""
        total_collected = 0

        # Try Homebrew
        if self._is_package_manager_available("brew"):
            try:
                count = self._collect_homebrew_packages()
                total_collected += count
                logger.info(_("Collected %d packages from Homebrew"), count)
            except Exception as error:
                logger.error(_("Failed to collect Homebrew packages: %s"), error)

        return total_collected

    def _collect_homebrew_packages(self) -> int:
        """Collect packages from Homebrew (macOS)."""
        try:
            # Find the correct brew path
            brew_cmd = self._get_brew_command()
            if not brew_cmd:
                logger.error(_("Homebrew command not found"))
                return 0

            total_packages = 0

            # Collect formulae (packages)
            # Split brew_cmd in case it contains sudo -u
            brew_args = brew_cmd.split() + ["list", "--formulae", "--versions"]
            formulae_result = subprocess.run(  # nosec B603, B607
                brew_args,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if formulae_result.returncode == 0:
                formulae_packages = self._parse_homebrew_list_output(
                    formulae_result.stdout, "formula"
                )
                formulae_count = self._store_packages("homebrew", formulae_packages)
                total_packages += formulae_count
                logger.info(_("Collected %d Homebrew formulae"), formulae_count)

            # Collect casks (applications)
            # Split brew_cmd in case it contains sudo -u
            brew_args = brew_cmd.split() + ["list", "--casks", "--versions"]
            casks_result = subprocess.run(  # nosec B603, B607
                brew_args,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if casks_result.returncode == 0:
                casks_packages = self._parse_homebrew_list_output(
                    casks_result.stdout, "cask"
                )
                casks_count = self._store_packages("homebrew-cask", casks_packages)
                total_packages += casks_count
                logger.info(_("Collected %d Homebrew casks"), casks_count)

            return total_packages

        except Exception as error:
            logger.error(_("Error collecting Homebrew packages: %s"), error)
            return 0

    def _parse_homebrew_list_output(
        self, output: str, package_type: str
    ) -> List[Dict[str, str]]:
        """Parse Homebrew list --versions output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # Format: "package_name version1 version2 ..."
            # We take the first version listed (usually the currently installed one)
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]  # First version listed

                # Add package type info to description for clarity
                description = f"Homebrew {package_type}"

                packages.append(
                    {"name": name, "version": version, "description": description}
                )
            elif len(parts) == 1:
                # Some packages might not have versions listed
                name = parts[0]
                packages.append(
                    {
                        "name": name,
                        "version": "unknown",
                        "description": f"Homebrew {package_type}",
                    }
                )

        return packages

    def _parse_homebrew_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Homebrew package list output (legacy method - kept for compatibility)."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # For now, just get package names - version requires individual queries
            name = line.strip()
            if name:
                packages.append({"name": name, "version": "latest", "description": ""})

        return packages
