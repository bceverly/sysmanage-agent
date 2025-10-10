#!/usr/bin/env python3
"""
Base Software Inventory Collection Module

Common functionality for software inventory collection across all platforms.
"""

import logging
import re
import subprocess  # nosec B404
from typing import Optional

logger = logging.getLogger(__name__)


class SoftwareInventoryCollectorBase:
    """
    Base class for software inventory collectors providing common utilities.
    """

    def __init__(self):
        self.collected_packages = []
        self._package_managers = None

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system PATH."""
        try:
            # Special case for pkg_info which doesn't support --version
            if command == "pkg_info":
                result = subprocess.run(
                    [command],
                    capture_output=True,
                    timeout=5,
                    check=False,  # nosec B603, B607
                )
                # pkg_info returns usage info when run without arguments
                return result.returncode in [
                    0,
                    1,
                ]  # Accept both success and usage error

            subprocess.run(
                [command, "--version"],
                capture_output=True,
                timeout=5,
                check=False,  # nosec B603, B607
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _parse_size_string(self, size_str: str) -> Optional[int]:
        """Parse size string like '1.2 MB' to bytes."""
        try:
            if not size_str or size_str.strip() == "":
                return None

            size_str = size_str.strip().upper()

            # Extract number and unit
            match = re.match(r"(\d+(?:\.\d+)?)\s*([KMGT]?B?)", size_str)
            if not match:
                return None

            number = float(match.group(1))
            unit = match.group(2)

            multipliers = {
                "B": 1,
                "KB": 1024,
                "MB": 1024**2,
                "GB": 1024**3,
                "TB": 1024**4,
            }

            return int(number * multipliers.get(unit, 1))

        except (ValueError, AttributeError):
            return None
