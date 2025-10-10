"""
Antivirus Removal Module for Linux Systems

This module handles antivirus removal for:
- openSUSE (via zypper)
- RHEL/CentOS (via yum/dnf)
- Debian/Ubuntu (via apt)
"""

import asyncio
import os
from typing import Optional


class AntivirusRemoverLinux:
    """Handles antivirus removal for Linux systems."""

    def __init__(self, logger):
        """
        Initialize the AntivirusRemoverLinux instance.

        Args:
            logger: Logger instance for logging operations
        """
        self.logger = logger

    async def remove_opensuse(self) -> Optional[str]:
        """Remove ClamAV from openSUSE via zypper."""
        # Stop and disable services first
        for service in ["clamd.service", "freshclam.service"]:
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "stop",
                service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "disable",
                service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        # Remove ClamAV packages
        process = await asyncio.create_subprocess_exec(
            "zypper",
            "remove",
            "-y",
            "clamav",
            "clamav_freshclam",
            "clamav-daemon",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            return stderr.decode()

        return None

    async def remove_debian(self) -> Optional[str]:
        """Remove ClamAV from Debian/Ubuntu via apt."""
        process = await asyncio.create_subprocess_exec(
            "apt",
            "remove",
            "--purge",
            "-y",
            "clamav",
            "clamav-base",
            "clamav_freshclam",
            "libclamav12",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            return stderr.decode()

        # Run autoremove to clean up unused dependencies
        process = await asyncio.create_subprocess_exec(
            "apt",
            "autoremove",
            "-y",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        return None

    async def remove_redhat(self) -> Optional[str]:
        """Remove ClamAV from RHEL/CentOS via yum/dnf."""
        # Determine which package manager to use
        pkg_manager = "dnf" if os.path.exists("/usr/bin/dnf") else "yum"

        # Stop and disable the service first
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "stop",
            "clamd@scan",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "disable",
            "clamd@scan",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Remove ClamAV packages
        process = await asyncio.create_subprocess_exec(
            pkg_manager,
            "remove",
            "-y",
            "clamav",
            "clamd",
            "clamav-update",
            "clamav-data",
            "clamav-lib",
            "clamav-filesystem",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            return stderr.decode()

        # Run autoremove
        process = await asyncio.create_subprocess_exec(
            pkg_manager,
            "autoremove",
            "-y",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        return None
