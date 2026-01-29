"""
Package manager operations for SysManage Agent.
Manages enabling additional package managers on remote hosts.
"""

import asyncio
import logging
import platform
import shutil
from typing import Any, Dict, List, Optional, Tuple

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import is_running_privileged

# Constants for repeated error messages
_INSTALLATION_FAILED = "Installation failed"
_INSTALLATION_TIMEOUT = "Installation timed out after 5 minutes"


async def _run_package_install(
    package_manager_path: str, package_name: str, install_args: List[str]
) -> Tuple[int, str, str]:
    """
    Execute a package installation command with the given package manager.

    Args:
        package_manager_path: Full path to the package manager executable
        install_args: Additional arguments for the install command
        package_name: Name of the package to install

    Returns:
        Tuple of (return_code, stdout_text, stderr_text)
    """
    process = await asyncio.create_subprocess_exec(  # nosec B603 B607
        "sudo",
        package_manager_path,
        *install_args,
        package_name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
    stdout_text = stdout.decode() if stdout else ""
    stderr_text = stderr.decode() if stderr else ""
    return process.returncode, stdout_text, stderr_text


def _get_linux_package_manager() -> Optional[Tuple[str, List[str]]]:
    """
    Detect available Linux package manager and return its path with install args.

    Returns:
        Tuple of (package_manager_path, install_args) or None if not found
    """
    apt_path = shutil.which("apt")
    if apt_path:
        return apt_path, ["install", "-y"]

    dnf_path = shutil.which("dnf")
    if dnf_path:
        return dnf_path, ["install", "-y"]

    zypper_path = shutil.which("zypper")
    if zypper_path:
        return zypper_path, ["install", "-y"]

    return None


class PackageManagerOperations:
    """Manages package manager operations across different operating systems."""

    def __init__(self, agent, logger: Optional[logging.Logger] = None):
        """Initialize the package manager operations handler."""
        self.agent = agent
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system()

    async def enable_package_manager(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enable an additional package manager on this host.

        Args:
            parameters: Dict containing:
                - package_manager: Name of the package manager to enable (e.g., "flatpak", "snap")
                - os_name: Operating system name (e.g., "Ubuntu", "Debian")

        Returns:
            Dict with success status and message
        """
        package_manager = parameters.get("package_manager", "").lower()
        os_name = parameters.get("os_name", "")

        if not package_manager:
            return {
                "success": False,
                "error": _("Package manager name is required"),
            }

        self.logger.info(
            _("Enabling package manager '%s' for OS '%s'"), package_manager, os_name
        )

        # Check if running privileged
        if not is_running_privileged():
            return {
                "success": False,
                "error": _("Enabling package managers requires privileged mode"),
            }

        # Dispatch to appropriate handler based on package manager
        handlers = {
            "flatpak": self._enable_flatpak,
            "snap": self._enable_snap,
            "homebrew": self._enable_homebrew,
            "chocolatey": self._enable_chocolatey,
            "scoop": self._enable_scoop,
        }

        handler = handlers.get(package_manager)
        if not handler:
            return {
                "success": False,
                "error": _("Unknown package manager: %s") % package_manager,
            }

        try:
            return await handler()
        except Exception as err:
            self.logger.error(
                _("Error enabling package manager '%s': %s"), package_manager, err
            )
            return {
                "success": False,
                "error": str(err),
            }

    async def _enable_flatpak(self) -> Dict[str, Any]:
        """Enable Flatpak package manager on Linux systems."""
        if self.system != "Linux":
            return {
                "success": False,
                "error": _("Flatpak is only supported on Linux systems"),
            }

        # Check if flatpak is already installed
        flatpak_path = shutil.which("flatpak")
        if flatpak_path:
            self.logger.info(_("Flatpak is already installed"))
            await self._add_flathub_repo()
            return {
                "success": True,
                "message": _("Flatpak is already installed"),
                "already_installed": True,
            }

        return await self._install_linux_package(
            "flatpak", "Flatpak", self._add_flathub_repo
        )

    async def _install_linux_package(
        self,
        package_name: str,
        display_name: str,
        post_install_hook=None,
    ) -> Dict[str, Any]:
        """
        Install a package using the detected Linux package manager.

        Args:
            package_name: Name of the package to install
            display_name: Human-readable name for messages
            post_install_hook: Optional async function to call after successful install

        Returns:
            Dict with success status and message
        """
        pkg_manager = _get_linux_package_manager()
        if not pkg_manager:
            return {
                "success": False,
                "error": _("No supported package manager found to install %s")
                % package_name,
            }

        pkg_path, install_args = pkg_manager

        try:
            returncode, stdout_text, stderr_text = await _run_package_install(
                pkg_path, package_name, install_args
            )

            if returncode != 0:
                return {
                    "success": False,
                    "error": stderr_text or stdout_text or _(_INSTALLATION_FAILED),
                }

            if post_install_hook:
                await post_install_hook()

            self.logger.info(_("%s installed successfully"), display_name)
            return {
                "success": True,
                "message": _("%s installed successfully") % display_name,
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": _(_INSTALLATION_TIMEOUT),
            }
        except Exception as err:
            return {
                "success": False,
                "error": str(err),
            }

    async def _add_flathub_repo(self) -> None:  # NOSONAR
        """Add Flathub repository to Flatpak."""
        flatpak_path = shutil.which("flatpak")
        if not flatpak_path:
            return

        try:
            process = await asyncio.create_subprocess_exec(  # nosec B603 B607
                "sudo",
                flatpak_path,
                "remote-add",
                "--if-not-exists",
                "flathub",
                "https://flathub.org/repo/flathub.flatpakrepo",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=60)
            self.logger.info(_("Flathub repository added"))
        except Exception as err:
            self.logger.warning(_("Could not add Flathub repository: %s"), err)

    async def _enable_snap(self) -> Dict[str, Any]:
        """Enable Snap package manager on Linux systems."""
        if self.system != "Linux":
            return {
                "success": False,
                "error": _("Snap is only supported on Linux systems"),
            }

        # Check if snapd is already installed
        snap_path = shutil.which("snap")
        if snap_path:
            self.logger.info(_("Snap is already installed"))
            return {
                "success": True,
                "message": _("Snap is already installed"),
                "already_installed": True,
            }

        return await self._install_linux_package(
            "snapd", "Snap", self._enable_snapd_service
        )

    async def _enable_snapd_service(self) -> None:
        """Enable and start the snapd service."""
        systemctl_path = shutil.which("systemctl")
        if not systemctl_path:
            return

        try:
            process = await asyncio.create_subprocess_exec(  # nosec B603 B607
                "sudo",
                systemctl_path,
                "enable",
                "--now",
                "snapd.socket",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=30)
        except Exception as err:
            self.logger.warning(_("Could not enable snapd service: %s"), err)

    async def _enable_homebrew(self) -> Dict[str, Any]:  # NOSONAR
        """Enable Homebrew package manager on macOS or Linux."""
        # Check if homebrew is already installed
        brew_path = shutil.which("brew")
        if brew_path:
            self.logger.info(_("Homebrew is already installed"))
            return {
                "success": True,
                "message": _("Homebrew is already installed"),
                "already_installed": True,
            }

        # Homebrew installation requires user interaction and cannot be
        # easily automated in a non-interactive way. Return guidance instead.
        return {
            "success": False,
            "error": _(
                "Homebrew installation requires manual intervention. "
                'Please install using: /bin/bash -c "$(curl -fsSL '
                'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
            ),
            "requires_manual_install": True,
        }

    async def _enable_chocolatey(self) -> Dict[str, Any]:  # NOSONAR
        """Enable Chocolatey package manager on Windows."""
        if self.system != "Windows":
            return {
                "success": False,
                "error": _("Chocolatey is only supported on Windows systems"),
            }

        # Check if chocolatey is already installed
        choco_path = shutil.which("choco")
        if choco_path:
            self.logger.info(_("Chocolatey is already installed"))
            return {
                "success": True,
                "message": _("Chocolatey is already installed"),
                "already_installed": True,
            }

        try:
            # Install Chocolatey using PowerShell
            install_cmd = (
                "Set-ExecutionPolicy Bypass -Scope Process -Force; "
                "[System.Net.ServicePointManager]::SecurityProtocol = "
                "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
                "iex ((New-Object System.Net.WebClient).DownloadString("
                "'https://community.chocolatey.org/install.ps1'))"
            )

            process = await asyncio.create_subprocess_exec(  # nosec B603 B607
                "powershell",
                "-Command",
                install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": stderr_text or stdout_text or _(_INSTALLATION_FAILED),
                }

            self.logger.info(_("Chocolatey installed successfully"))
            return {
                "success": True,
                "message": _("Chocolatey installed successfully"),
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": _(_INSTALLATION_TIMEOUT),
            }
        except Exception as err:
            return {
                "success": False,
                "error": str(err),
            }

    async def _enable_scoop(self) -> Dict[str, Any]:  # NOSONAR
        """Enable Scoop package manager on Windows."""
        if self.system != "Windows":
            return {
                "success": False,
                "error": _("Scoop is only supported on Windows systems"),
            }

        # Check if scoop is already installed
        scoop_path = shutil.which("scoop")
        if scoop_path:
            self.logger.info(_("Scoop is already installed"))
            return {
                "success": True,
                "message": _("Scoop is already installed"),
                "already_installed": True,
            }

        try:
            # Install Scoop using PowerShell
            install_cmd = (
                "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force; "
                "irm get.scoop.sh | iex"
            )

            process = await asyncio.create_subprocess_exec(  # nosec B603 B607
                "powershell",
                "-Command",
                install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": stderr_text or stdout_text or _(_INSTALLATION_FAILED),
                }

            self.logger.info(_("Scoop installed successfully"))
            return {
                "success": True,
                "message": _("Scoop installed successfully"),
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": _(_INSTALLATION_TIMEOUT),
            }
        except Exception as err:
            return {
                "success": False,
                "error": str(err),
            }
