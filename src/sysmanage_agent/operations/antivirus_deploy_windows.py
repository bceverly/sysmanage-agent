"""
Antivirus Deployment Module for Windows Systems

This module handles antivirus deployment for:
- Windows (via Chocolatey - ClamWin)
"""

import asyncio
import os
from typing import Any, Dict

from src.sysmanage_agent.collection.update_detection import UpdateDetector


class AntivirusDeployerWindows:
    """Handles antivirus deployment for Windows systems."""

    def __init__(self, logger):
        """
        Initialize the AntivirusDeployerWindows instance.

        Args:
            logger: Logger instance for logging operations
        """
        self.logger = logger

    async def deploy_windows(self, antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on Windows via Chocolatey."""
        self.logger.info("Detected Windows system, installing ClamAV via Chocolatey")

        # Note: Use clamwin package which includes ClamAV engine for Windows
        package_to_install = "clamwin"

        # Install ClamAV via Chocolatey
        update_detector = UpdateDetector()
        self.logger.info("Installing %s", package_to_install)
        result = update_detector.install_package(package_to_install, "auto")
        self.logger.info("%s installation result: %s", package_to_install, result)

        # Determine success based on result
        success = isinstance(result, dict) and result.get("success", False)
        error_message = result.get("error") if isinstance(result, dict) else None

        if not success:
            return {
                "success": False,
                "result": str(result),
                "package_name": antivirus_package,
                "error": error_message or "Installation failed",
            }

        self.logger.info("Configuring ClamAV on Windows")

        # Common ClamAV/ClamWin installation paths on Windows (Chocolatey)
        common_paths = [
            "C:\\Program Files\\ClamWin\\bin",
            "C:\\Program Files (x86)\\ClamWin\\bin",
            "C:\\Program Files\\ClamAV",
            "C:\\Program Files (x86)\\ClamAV",
            "C:\\ProgramData\\chocolatey\\lib\\clamwin\\tools\\bin",
            "C:\\ProgramData\\chocolatey\\lib\\clamav\\tools",
        ]

        clamav_path = None
        for path in common_paths:
            if os.path.exists(path):
                clamav_path = path
                break

        if not clamav_path:
            self.logger.warning("Could not locate ClamAV installation directory")
            return {
                "success": False,
                "result": "ClamAV installation directory not found",
                "package_name": antivirus_package,
                "error": "Installation directory not found",
            }

        # Path to freshclam.exe
        freshclam_exe = os.path.join(clamav_path, "freshclam.exe")
        if not os.path.exists(freshclam_exe):
            self.logger.warning("freshclam.exe not found at %s", freshclam_exe)

        # Update virus definitions with freshclam
        self.logger.info("Updating virus definitions with freshclam")
        try:
            process = await asyncio.create_subprocess_exec(
                freshclam_exe,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()
            if process.returncode == 0:
                self.logger.info("Virus definitions updated successfully")
            else:
                self.logger.warning(
                    "Failed to update virus definitions: %s",
                    stderr.decode() if stderr else "unknown error",
                )
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.warning("Error running freshclam: %s", error)

        # Note: On Windows, ClamAV doesn't run as a service by default after Chocolatey install
        # The service needs to be manually configured if desired
        # For now, we consider the installation successful if the binaries are present
        await asyncio.sleep(2)

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on Windows",
        }
