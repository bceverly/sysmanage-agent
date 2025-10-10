"""
Helper functions for ClamAV removal across different platforms.

This module contains platform-specific removal logic extracted from
the massive remove_antivirus() function to reduce complexity.
"""

import asyncio
import glob
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


def _get_brew_user():
    """Get the user that owns the Homebrew installation."""
    import pwd  # pylint: disable=import-outside-toplevel,import-error

    # Check both possible Homebrew locations
    brew_dirs = ["/opt/homebrew", "/usr/local/Homebrew"]
    for brew_dir in brew_dirs:
        if os.path.exists(brew_dir):
            try:
                stat_info = os.stat(brew_dir)
                return pwd.getpwuid(stat_info.st_uid).pw_name
            except (OSError, KeyError):
                continue

    # Fallback to SUDO_USER if available
    return os.environ.get("SUDO_USER")


async def cleanup_clamav_cellar_macos() -> Optional[str]:
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
        logger.info("Removing clamav directory: %s", version_dir)
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
            logger.error("Manual cleanup of %s failed: %s", version_dir, error_msg)
            last_error = error_msg
        else:
            logger.info("Manual cleanup of %s successful", version_dir)

    # Remove the parent clamav directory if empty
    try:
        os.rmdir(clamav_path)
        logger.info("Removed empty clamav directory")
    except OSError:
        # Directory not empty or doesn't exist, that's fine
        pass

    return last_error


async def remove_clamav_macos() -> Optional[str]:
    """Remove ClamAV on macOS."""
    brew_cmd = (
        "/opt/homebrew/bin/brew"
        if os.path.exists("/opt/homebrew/bin/brew")
        else "/usr/local/bin/brew"
    )

    brew_user = _get_brew_user() if os.geteuid() == 0 else None

    # Stop service first
    if brew_user:
        logger.info("Running brew as user: %s", brew_user)
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

    # Wait for service to fully stop
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
        logger.warning("brew uninstall failed: %s, attempting manual cleanup", error)
        cleanup_error = await cleanup_clamav_cellar_macos()
        if cleanup_error is None:
            return None  # Manual cleanup succeeded
        return error

    return None


async def remove_clamav_netbsd() -> Optional[str]:
    """Remove ClamAV on NetBSD."""
    # Stop services
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
    cmd = (
        ["pkgin", "-y", "remove", "clamav"]
        if os.geteuid() == 0
        else ["sudo", "pkgin", "-y", "remove", "clamav"]
    )

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()

    return stderr.decode() if process.returncode != 0 else None


async def remove_clamav_freebsd() -> Optional[str]:
    """Remove ClamAV on FreeBSD."""
    # Stop services
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
    for setting in ["clamav_clamd_enable=NO", "clamav_freshclam_enable=NO"]:
        process = await asyncio.create_subprocess_exec(
            "sysrc",
            setting,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    # Remove ClamAV package
    cmd = (
        ["pkg", "delete", "-y", "clamav"]
        if os.geteuid() == 0
        else ["sudo", "pkg", "delete", "-y", "clamav"]
    )

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()

    return stderr.decode() if process.returncode != 0 else None


async def remove_clamav_openbsd() -> Optional[str]:
    """Remove ClamAV on OpenBSD."""
    # Stop and disable services
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

    # Remove ClamAV package
    cmd = (
        ["pkg_delete", "clamav"]
        if os.geteuid() == 0
        else ["doas", "pkg_delete", "clamav"]
    )

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()

    return stderr.decode() if process.returncode != 0 else None


async def remove_clamav_opensuse() -> Optional[str]:
    """Remove ClamAV on openSUSE."""
    # Stop and disable services
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

    return stderr.decode() if process.returncode != 0 else None


async def remove_clamav_debian() -> Optional[str]:
    """Remove ClamAV on Debian/Ubuntu."""
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


async def remove_clamav_rhel() -> Optional[str]:
    """Remove ClamAV on RHEL/CentOS."""
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


async def remove_clamav_windows() -> Optional[str]:
    """Remove ClamAV on Windows."""
    logger.info("Removing ClamAV from Windows using Chocolatey")

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
            logger.info("Successfully uninstalled %s", package)
            return None
        logger.debug(
            "Failed to uninstall %s: %s",
            package,
            stderr.decode() if stderr else "unknown",
        )

    return f"Failed to uninstall ClamAV/ClamWin: {stderr.decode() if stderr else 'unknown error'}"
