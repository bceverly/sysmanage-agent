"""
OS information collection module for SysManage Agent.
Handles platform-specific OS version and architecture information gathering.
"""

import platform
import logging
from typing import Any, Dict


class OSInfoCollector:
    """Collects operating system information across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_os_version_info(self) -> Dict[str, Any]:
        """Get comprehensive OS version information as separate data."""
        # Get CPU architecture (x86_64, arm64, aarch64, riscv64, etc.)
        machine_arch = platform.machine()

        # Get detailed OS information
        os_info = {}
        try:
            # Try to get Linux distribution info if available
            if hasattr(platform, "freedesktop_os_release"):
                os_release = platform.freedesktop_os_release()
                os_info["distribution"] = os_release.get("NAME", "")
                os_info["distribution_version"] = os_release.get("VERSION_ID", "")
                os_info["distribution_codename"] = os_release.get(
                    "VERSION_CODENAME", ""
                )
        except (AttributeError, OSError):
            pass

        # For macOS, get additional version info
        if platform.system() == "Darwin":
            mac_ver = platform.mac_ver()
            os_info["mac_version"] = mac_ver[0] if mac_ver[0] else ""

        # For Windows, get additional version info
        if platform.system() == "Windows":
            win_ver = platform.win32_ver()
            os_info["windows_version"] = win_ver[0] if win_ver[0] else ""
            os_info["windows_service_pack"] = win_ver[1] if win_ver[1] else ""

        return {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "machine_architecture": machine_arch,  # CPU architecture
            "python_version": platform.python_version(),
            "os_info": os_info,
        }
