"""
VMM disk operations for OpenBSD.

This module handles disk image creation and management for VMM VMs.
"""

import os
import subprocess  # nosec B404
from typing import Any, Dict

from src.i18n import _


class VmmDiskOperations:
    """Handles VMM disk image operations."""

    def __init__(self, logger):
        """
        Initialize disk operations.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def create_disk_image(self, disk_path: str, size: str) -> Dict[str, Any]:
        """
        Create a qcow2 disk image using vmctl.

        Args:
            disk_path: Full path for the disk image file
            size: Size of the disk (e.g., "20G", "50G")

        Returns:
            Dict with success status and disk_path or error
        """
        try:
            if os.path.exists(disk_path):
                return {
                    "success": False,
                    "error": _("Disk image already exists: %s") % disk_path,
                }

            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "create", "-s", size, disk_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info(_("Created disk image: %s (%s)"), disk_path, size)
                return {"success": True, "disk_path": disk_path}

            error_msg = result.stderr or result.stdout or "Unknown error"
            return {
                "success": False,
                "error": _("Failed to create disk image: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout creating disk image"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    def disk_exists(self, disk_path: str) -> bool:
        """
        Check if a disk image exists.

        Args:
            disk_path: Path to the disk image

        Returns:
            True if disk exists, False otherwise
        """
        return os.path.exists(disk_path)

    def delete_disk_image(self, disk_path: str) -> Dict[str, Any]:
        """
        Delete a disk image file.

        Args:
            disk_path: Path to the disk image to delete

        Returns:
            Dict with success status
        """
        try:
            if not os.path.exists(disk_path):
                return {"success": True, "message": "Disk image does not exist"}

            os.remove(disk_path)
            self.logger.info(_("Deleted disk image: %s"), disk_path)
            return {"success": True}

        except Exception as error:
            self.logger.error(_("Error deleting disk image %s: %s"), disk_path, error)
            return {"success": False, "error": str(error)}
