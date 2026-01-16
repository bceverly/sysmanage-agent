"""
Virtualization support check methods for child host operations.

This module provides a unified interface for checking virtualization support
across multiple platforms. Platform-specific implementations are provided
by mixin classes in separate modules for maintainability.
"""

import os
import platform
import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict

from ._virtualization_bsd import BsdVirtualizationMixin
from ._virtualization_linux import LinuxVirtualizationMixin
from ._virtualization_windows import WindowsVirtualizationMixin


class VirtualizationChecks(
    WindowsVirtualizationMixin,
    LinuxVirtualizationMixin,
    BsdVirtualizationMixin,
):
    """
    Methods to check virtualization support on various platforms.

    This class combines platform-specific virtualization checks through mixins:
    - WindowsVirtualizationMixin: WSL and Hyper-V support
    - LinuxVirtualizationMixin: LXD and KVM support
    - BsdVirtualizationMixin: VMM (OpenBSD) and bhyve (FreeBSD) support

    Cross-platform support (VirtualBox) is provided directly in this class.
    """

    def __init__(self, logger):
        """Initialize with logger."""
        self.logger = logger

    def check_virtualbox_support(self) -> Dict[str, Any]:
        """
        Check VirtualBox support (cross-platform).

        Returns:
            Dict with VirtualBox availability info
        """
        result = {
            "available": False,
            "version": None,
        }

        try:
            # Check for VBoxManage
            vboxmanage = shutil.which("VBoxManage")
            if not vboxmanage:
                # On Windows, try common installation paths
                if platform.system().lower() == "windows":
                    common_paths = [
                        os.path.join(
                            os.environ.get("ProgramFiles", ""),
                            "Oracle",
                            "VirtualBox",
                            "VBoxManage.exe",
                        ),
                        os.path.join(
                            os.environ.get("ProgramFiles(x86)", ""),
                            "Oracle",
                            "VirtualBox",
                            "VBoxManage.exe",
                        ),
                    ]
                    for path in common_paths:
                        if os.path.exists(path):
                            vboxmanage = path
                            break

            if vboxmanage:
                result["available"] = True

                # Get version
                # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
                version_result = subprocess.run(  # nosec B603 B607
                    [
                        vboxmanage,
                        "--version",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if version_result.returncode == 0:
                    result["version"] = version_result.stdout.strip()

        except Exception as error:
            self.logger.debug("Error checking VirtualBox support: %s", error)

        return result
