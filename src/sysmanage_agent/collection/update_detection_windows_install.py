#!/usr/bin/env python3
"""
Windows Package Installation Module for SysManage Agent

This module handles installation of new packages on Windows systems:
- winget package installation
- Chocolatey package installation
"""

import logging
import subprocess  # nosec B404
from typing import Any, Dict

logger = logging.getLogger(__name__)


class WindowsPackageInstallerMixin:
    """Mixin class for installing packages on Windows."""

    def _install_with_winget(self, package_name: str) -> Dict[str, Any]:
        """Install package using winget package manager."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["winget", "install", "--id", package_name, "--silent"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

    def _install_with_choco(self, package_name: str) -> Dict[str, Any]:
        """Install package using Chocolatey package manager."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["choco", "install", package_name, "-y"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }
