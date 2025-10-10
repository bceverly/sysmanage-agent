"""
Antivirus Removal Module for Unix Systems (macOS and BSD)

This module handles antivirus removal for:
- macOS (via Homebrew)
- NetBSD (via pkgin)
- FreeBSD (via pkg)
- OpenBSD (via pkg_delete)
"""

import asyncio
import glob
import os
from typing import Optional

from src.sysmanage_agent.operations.antivirus_base import _get_brew_user


class AntivirusRemoverBSD:
    """Handles antivirus removal for Unix systems (macOS and BSD)."""

    def __init__(self, logger):
        """
        Initialize the AntivirusRemoverUnix instance.

        Args:
            logger: Logger instance for logging operations
        """
        self.logger = logger

    async def _cleanup_clamav_cellar_macos(self) -> Optional[str]:
        """
        Manually remove ClamAV from Homebrew Cellar directory.

        Returns:
            None if successful, error message string if failed
        """
        # Determine the Cellar directory based on architecture
        cellar_dir = (
            "/opt/homebrew/Cellar"
            if os.path.exists("/opt/homebrew")
            else "/usr/local/Cellar"
        )

        # Find all clamav version directories
        clamav_path = f"{cellar_dir}/clamav"
        if not os.path.exists(clamav_path):
            return None

        version_dirs = glob.glob(f"{clamav_path}/*")
        if not version_dirs:
            return None

        last_error = None
        for version_dir in version_dirs:
            self.logger.info("Removing clamav directory: %s", version_dir)
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "rm",
                "-rf",
                version_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode()
                self.logger.error(
                    "Manual cleanup of %s failed: %s", version_dir, error_msg
                )
                last_error = error_msg
            else:
                self.logger.info("Manual cleanup of %s successful", version_dir)

        # Remove the parent clamav directory if empty
        try:
            os.rmdir(clamav_path)
            self.logger.info("Removed empty clamav directory")
        except OSError:
            # Directory not empty or doesn't exist, that's fine
            pass

        return last_error

    async def remove_macos(self) -> Optional[str]:
        """Remove ClamAV from macOS via Homebrew."""
        brew_cmd = (
            "/opt/homebrew/bin/brew"
            if os.path.exists("/opt/homebrew/bin/brew")
            else "/usr/local/bin/brew"
        )

        # If running as root, use sudo -u to run as the actual user
        # Homebrew doesn't allow running as root
        brew_user = _get_brew_user() if os.geteuid() == 0 else None

        # Stop service first
        if brew_user:
            self.logger.info("Running brew as user: %s", brew_user)
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-u",
                brew_user,
                brew_cmd,
                "services",
                "stop",
                "clamav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                brew_cmd,
                "services",
                "stop",
                "clamav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        await process.communicate()

        # Wait a moment for service to fully stop
        await asyncio.sleep(2)

        # Remove package with --force flag to handle any locked files
        if brew_user:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-u",
                brew_user,
                brew_cmd,
                "uninstall",
                "--force",
                "clamav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                brew_cmd,
                "uninstall",
                "--force",
                "clamav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            error = stderr.decode()
            # If brew uninstall failed, try manual removal with sudo rm -rf
            # This handles cases where files are locked or permissions prevent removal
            self.logger.warning(
                "brew uninstall failed: %s, attempting manual cleanup", error
            )
            cleanup_error = await self._cleanup_clamav_cellar_macos()
            if cleanup_error is None:
                return None  # Manual cleanup succeeded
            return error

        return None

    async def remove_netbsd(self) -> Optional[str]:
        """Remove ClamAV from NetBSD via pkgin."""
        # Stop and disable services first
        for service in ["clamd", "freshclamd"]:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "service",
                service,
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        # Disable services in rc.conf using sed
        process = await asyncio.create_subprocess_exec(
            "sh",
            "-c",
            "sudo sed -i '' '/^freshclamd=/d; /^clamd=/d' /etc/rc.conf",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Remove ClamAV package
        if os.geteuid() == 0:
            cmd = ["pkgin", "-y", "remove", "clamav"]
        else:
            cmd = ["sudo", "pkgin", "-y", "remove", "clamav"]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            return stderr.decode()

        return None

    async def remove_freebsd(self) -> Optional[str]:
        """Remove ClamAV from FreeBSD via pkg."""
        # Stop and disable services first
        for service in ["clamav_clamd", "clamav_freshclam"]:
            process = await asyncio.create_subprocess_exec(
                "service",
                service,
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        # Disable services in rc.conf
        process = await asyncio.create_subprocess_exec(
            "sysrc",
            "clamav_clamd_enable=NO",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "sysrc",
            "clamav_freshclam_enable=NO",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Remove ClamAV package
        if os.geteuid() == 0:
            cmd = ["pkg", "delete", "-y", "clamav"]
        else:
            cmd = ["sudo", "pkg", "delete", "-y", "clamav"]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            return stderr.decode()

        return None

    async def remove_openbsd(self) -> Optional[str]:
        """Remove ClamAV from OpenBSD via pkg_delete."""
        # Stop and disable services first
        for service in ["clamd", "freshclam"]:
            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "stop",
                service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "disable",
                service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        # Remove ClamAV package (use doas only if not root)
        if os.geteuid() == 0:
            cmd = ["pkg_delete", "clamav"]
        else:
            cmd = ["doas", "pkg_delete", "clamav"]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            return stderr.decode()

        return None
