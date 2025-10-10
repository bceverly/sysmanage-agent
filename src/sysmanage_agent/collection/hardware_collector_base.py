"""
Base hardware collector module for SysManage Agent.
Provides base class and common utilities for platform-specific collectors.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List


class HardwareCollectorBase(ABC):
    """Base class for platform-specific hardware collectors."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @abstractmethod
    def get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information for the platform."""
        pass  # pylint: disable=unnecessary-pass

    @abstractmethod
    def get_memory_info(self) -> Dict[str, Any]:
        """Get memory information for the platform."""
        pass  # pylint: disable=unnecessary-pass

    @abstractmethod
    def get_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information for the platform."""
        pass  # pylint: disable=unnecessary-pass

    @abstractmethod
    def get_network_info(self) -> List[Dict[str, Any]]:
        """Get network information for the platform."""
        pass  # pylint: disable=unnecessary-pass

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()

    def _parse_size_to_bytes(self, size_str: str) -> int:
        """Parse human-readable size to bytes."""
        if not size_str or size_str == "-":
            return 0

        size_str = size_str.strip().upper()
        try:
            # Handle cases like "42G", "4.7G", "312K", "1.0K", "0B"
            multipliers = {
                "B": 1,
                "K": 1024,
                "M": 1024**2,
                "G": 1024**3,
                "T": 1024**4,
                "P": 1024**5,
            }

            # Extract numeric part and unit
            numeric_part = ""
            unit = ""
            for char in size_str:
                if char.isdigit() or char == ".":
                    numeric_part += char
                else:
                    unit = size_str[len(numeric_part) :].strip()
                    break

            if not numeric_part:
                return 0

            size_float = float(numeric_part)

            # Find the multiplier
            multiplier = 1
            for suffix, mult in multipliers.items():
                if unit.startswith(suffix):
                    multiplier = mult
                    break

            return int(size_float * multiplier)

        except (ValueError, TypeError):
            return 0

    def _bytes_to_human_readable(self, size_bytes: int) -> str:
        """Convert bytes to human readable format."""
        if size_bytes == 0:
            return "0B"

        units = ["B", "K", "M", "G", "T", "P"]
        unit_index = 0
        size = float(size_bytes)

        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        if unit_index == 0:
            return f"{int(size)}B"
        return f"{size:.1f}{units[unit_index]}"

    def _is_physical_volume_generic(self, device_name: str, mount_point: str) -> bool:
        """
        Generic physical/logical volume detection for unknown platforms.

        This is a fallback method for platforms where we don't have
        specific detection logic.
        """
        device_name = device_name.lower()
        mount_point = mount_point.lower()

        # Virtual/special filesystems are logical
        logical_patterns = [
            "tmpfs",
            "proc",
            "sys",
            "dev",
            "run",
            "cgroup",
            "security",
            "loop",
            "ram",
            "swap",
        ]

        for pattern in logical_patterns:
            if pattern in device_name or pattern in mount_point:
                return False

        # Root and common mount points are considered physical
        if mount_point in ["/", "/home", "/var", "/usr", "/opt"]:
            return True

        # Default to physical for unknown cases
        return True
