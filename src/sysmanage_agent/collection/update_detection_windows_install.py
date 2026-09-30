#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Windows Package Installation Module for SysManage Agent

This module handles installation of new packages on Windows systems:
- winget package installation
- Chocolatey package installation
"""

import logging
import subprocess  # nosec B404
from typing import Any, Dict
from src.sysmanage_agent.core.bounded_subprocess import run_bounded

logger = logging.getLogger(__name__)


# winget exit codes meaning the package is already there: "no applicable
# upgrade" (0x8A15002B) and "package already installed" (0x8A150061).
_WINGET_ALREADY_INSTALLED = (0x8A15002B, 0x8A150061)


class WindowsPackageInstallerMixin:
    """Mixin class for installing packages on Windows."""

    def _install_with_winget(self, package_name: str) -> Dict[str, Any]:
        """Install package using winget package manager.

        Unattended: an exact id match, the source and package agreements
        accepted up front (otherwise winget waits for a keypress nobody will
        give), and "already installed / no newer version" counted as success
        -- a deployment plan re-sent to an equipped host must not fail on it.
        """
        try:
            result = run_bounded(  # nosec B603, B607
                [
                    "winget", "install", "--id", package_name, "--exact",
                    "--silent", "--accept-package-agreements",
                    "--accept-source-agreements", "--disable-interactivity",
                ],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )  # fmt: skip
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Installation of {package_name} timed out after 600 seconds",
            }
        code = result.returncode & 0xFFFFFFFF
        if result.returncode == 0 or code in _WINGET_ALREADY_INSTALLED:
            return {"success": True, "version": "unknown", "output": result.stdout}
        return {
            "success": False,
            "error": (
                f"Failed to install {package_name} (winget exit 0x{code:08X}): "
                f"{(result.stderr or result.stdout or '').strip()[-2000:]}"
            ),
        }

    def _install_with_choco(self, package_name: str) -> Dict[str, Any]:
        """Install package using Chocolatey package manager."""
        try:
            result = run_bounded(  # nosec B603, B607
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
