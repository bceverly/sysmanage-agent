"""
Antivirus Removal Module for Windows Systems

This module handles antivirus removal for:
- Windows (via Chocolatey)
"""

import asyncio
from typing import Optional


class AntivirusRemoverWindows:
    """Handles antivirus removal for Windows systems."""

    def __init__(self, logger):
        """
        Initialize the AntivirusRemoverWindows instance.

        Args:
            logger: Logger instance for logging operations
        """
        self.logger = logger

    async def remove_windows(self) -> Optional[str]:
        """Remove ClamAV from Windows via Chocolatey."""
        self.logger.info("Removing ClamAV from Windows using Chocolatey")

        # Try to stop the service if it exists
        process = await asyncio.create_subprocess_exec(
            "sc",
            "query",
            "ClamAV",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        if process.returncode == 0:
            # Service exists, stop it
            process = await asyncio.create_subprocess_exec(
                "sc",
                "stop",
                "ClamAV",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            await asyncio.sleep(2)

        # Remove ClamAV/ClamWin via Chocolatey
        # Try clamwin first, then clamav as fallback
        for package in ["clamwin", "clamav"]:
            process = await asyncio.create_subprocess_exec(
                "choco",
                "uninstall",
                package,
                "-y",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()

            if process.returncode == 0:
                self.logger.info("Successfully uninstalled %s", package)
                return None

            self.logger.debug(
                "Failed to uninstall %s: %s",
                package,
                stderr.decode() if stderr else "unknown",
            )

        # If we get here, both attempts failed
        return f"Failed to uninstall ClamAV/ClamWin: {stderr.decode() if stderr else 'unknown error'}"
