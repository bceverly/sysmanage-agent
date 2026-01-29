"""
Third-party repository operations module for SysManage agent.
Handles third-party repository management operations.
"""

import logging
import os
import platform
from typing import Any, Dict, Optional

import aiofiles

from src.i18n import _

# Constants for error messages used in multiple places
_UNSUPPORTED_DISTRO = "Unsupported distribution: %s"
_UNSUPPORTED_OS = "Unsupported operating system: %s"

# Distro family detection patterns
_DEBIAN_FAMILY = ("ubuntu", "debian")
_RHEL_FAMILY = ("fedora", "rhel", "centos", "rocky", "alma")
_SUSE_FAMILY = ("opensuse", "suse")


def _is_distro_family(distro: str, family: tuple) -> bool:
    """Check if distro belongs to a family."""
    return any(name in distro for name in family)


# pylint: disable=wrong-import-position
# These imports are placed after constants to avoid circular imports
from .linux_repository_operations import LinuxRepositoryOperations
from .bsd_macos_repository_operations import BSDMacOSRepositoryOperations
from .windows_repository_operations import WindowsRepositoryOperations

# pylint: enable=wrong-import-position


class ThirdPartyRepositoryOperations:  # pylint: disable=too-many-public-methods
    """Handles third-party repository operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize repository operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

        # Initialize platform-specific helpers
        self.linux_ops = LinuxRepositoryOperations(agent_instance)
        self.bsd_macos_ops = BSDMacOSRepositoryOperations(agent_instance)
        self.windows_ops = WindowsRepositoryOperations(agent_instance)

    async def _list_linux_repositories(self) -> list:
        """List repositories on Linux based on detected distro."""
        distro_info = await self._detect_linux_distro()
        distro = distro_info.get("distro", "").lower()

        if _is_distro_family(distro, _DEBIAN_FAMILY):
            return await self.linux_ops.list_apt_repositories()
        if _is_distro_family(distro, _RHEL_FAMILY):
            return await self.linux_ops.list_yum_repositories()
        if _is_distro_family(distro, _SUSE_FAMILY):
            return await self.linux_ops.list_zypper_repositories()
        return []

    async def _list_non_linux_repositories(self, system: str) -> list:
        """List repositories on non-Linux systems."""
        handlers = {
            "Darwin": self.bsd_macos_ops.list_homebrew_taps,
            "FreeBSD": self.bsd_macos_ops.list_freebsd_repositories,
            "NetBSD": self.bsd_macos_ops.list_netbsd_repositories,
            "Windows": self.windows_ops.list_windows_repositories,
        }
        handler = handlers.get(system)
        if handler:
            return await handler()
        return []

    async def list_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """List all third-party repositories on the system."""
        _unused = (
            parameters  # API signature requirement - pylint: disable=unused-variable
        )
        try:
            self.logger.info(_("Listing third-party repositories"))
            system = platform.system()

            if system == "Linux":
                repositories = await self._list_linux_repositories()
            else:
                repositories = await self._list_non_linux_repositories(system)

            return {
                "success": True,
                "repositories": repositories,
                "count": len(repositories),
            }
        except Exception as error:
            self.logger.error(_("Error listing third-party repositories: %s"), error)
            return {"success": False, "error": str(error)}

    async def _detect_linux_distro(self) -> Dict[str, str]:  # NOSONAR
        """Detect Linux distribution."""
        try:
            if os.path.exists("/etc/os-release"):
                async with aiofiles.open(
                    "/etc/os-release", "r", encoding="utf-8"
                ) as file_handle:
                    lines = await file_handle.readlines()
                    for line in lines:
                        if line.startswith("ID="):
                            distro = line.split("=")[1].strip().strip('"')
                            return {"distro": distro}

            return {"distro": platform.system()}
        except Exception as error:
            self.logger.error(_("Error detecting Linux distribution: %s"), error)
            return {"distro": "unknown"}

    async def _add_linux_repository(
        self, repo_identifier: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a repository on Linux based on detected distro."""
        self.logger.debug("Detecting Linux distribution for repository add")
        distro_info = await self._detect_linux_distro()
        distro = distro_info.get("distro", "").lower()
        self.logger.debug("Detected distribution: %s", distro)

        if _is_distro_family(distro, _DEBIAN_FAMILY):
            self.logger.debug("Calling _add_apt_repository for %s", repo_identifier)
            result = await self.linux_ops.add_apt_repository(repo_identifier)
            self.logger.debug("_add_apt_repository returned: %s", result)
            return result

        if _is_distro_family(distro, _RHEL_FAMILY):
            return await self.linux_ops.add_yum_repository(repo_identifier)

        if _is_distro_family(distro, _SUSE_FAMILY):
            return await self.linux_ops.add_zypper_repository(
                repo_identifier, parameters.get("url", "")
            )

        return {"success": False, "error": _(_UNSUPPORTED_DISTRO) % distro}

    async def _add_non_linux_repository(
        self, system: str, repo_identifier: str, parameters: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Add a repository on non-Linux systems. Returns None if system unsupported."""
        handlers = {
            "Darwin": lambda: self.bsd_macos_ops.add_homebrew_tap(repo_identifier),
            "FreeBSD": lambda: self.bsd_macos_ops.add_freebsd_repository(
                repo_identifier, parameters.get("url", "")
            ),
            "NetBSD": lambda: self.bsd_macos_ops.add_netbsd_repository(
                repo_identifier, parameters.get("url", "")
            ),
            "Windows": lambda: self.windows_ops.add_windows_repository(
                repo_identifier,
                parameters.get("url", ""),
                parameters.get("type", ""),
            ),
        }

        handler = handlers.get(system)
        if handler:
            return await handler()
        return None

    async def add_third_party_repository(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a third-party repository to the system."""
        try:
            repo_identifier = parameters.get("repository")

            if not repo_identifier:
                return {
                    "success": False,
                    "error": _("Repository identifier is required"),
                }

            self.logger.info(_("Adding third-party repository: %s"), repo_identifier)

            system = platform.system()

            if system == "Linux":
                result = await self._add_linux_repository(repo_identifier, parameters)
            else:
                result = await self._add_non_linux_repository(
                    system, repo_identifier, parameters
                )
                if result is None:
                    return {"success": False, "error": _(_UNSUPPORTED_OS) % system}

            if result["success"]:
                await self._run_package_update()
                await self._trigger_update_detection()
                await self._trigger_third_party_repository_rescan()

            return result

        except Exception as error:
            self.logger.error(_("Error adding third-party repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def _delete_linux_repository(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a single Linux repository based on distro."""
        distro_info = await self._detect_linux_distro()
        distro = distro_info.get("distro", "").lower()

        if _is_distro_family(distro, _DEBIAN_FAMILY):
            return await self.linux_ops.delete_apt_repository(repo)
        if _is_distro_family(distro, _RHEL_FAMILY):
            return await self.linux_ops.delete_yum_repository(repo)
        if _is_distro_family(distro, _SUSE_FAMILY):
            return await self.linux_ops.delete_zypper_repository(repo)
        return {"success": False, "error": _(_UNSUPPORTED_DISTRO) % distro}

    async def delete_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Delete third-party repositories from the system."""
        try:
            repositories = parameters.get("repositories", [])

            if not repositories:
                return {
                    "success": False,
                    "error": _("No repositories specified for deletion"),
                }

            self.logger.info(
                _("Deleting %d third-party repositories"), len(repositories)
            )

            system = platform.system()
            if system != "Linux":
                return {"success": False, "error": _(_UNSUPPORTED_OS) % system}

            results = []
            for repo in repositories:
                repo_name = repo.get("name")
                result = await self._delete_linux_repository(repo)
                results.append(
                    {
                        "repository": repo_name,
                        "success": result.get("success", False),
                        "message": result.get("result", result.get("error", "")),
                    }
                )

            await self._run_package_update()
            await self._trigger_update_detection()
            await self._trigger_third_party_repository_rescan()

            overall_success = all(r["success"] for r in results)
            return {
                "success": overall_success,
                "results": results,
                "message": _("Deleted %d of %d repositories")
                % (sum(1 for r in results if r["success"]), len(results)),
            }

        except Exception as error:
            self.logger.error(_("Error deleting third-party repositories: %s"), error)
            return {"success": False, "error": str(error)}

    async def _enable_linux_repository(
        self, repo_name: str, file_path: str
    ) -> Dict[str, Any]:
        """Enable a single Linux repository based on distro."""
        distro_info = await self._detect_linux_distro()
        distro = distro_info.get("distro", "").lower()

        if _is_distro_family(distro, _DEBIAN_FAMILY):
            return await self.linux_ops.enable_apt_repository(file_path)
        if _is_distro_family(distro, _RHEL_FAMILY):
            return await self.linux_ops.enable_yum_repository(repo_name)
        if _is_distro_family(distro, _SUSE_FAMILY):
            return await self.linux_ops.enable_zypper_repository(repo_name)
        return {"success": False, "error": _(_UNSUPPORTED_DISTRO) % distro}

    async def enable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable third-party repositories on the system."""
        try:
            repositories = parameters.get("repositories", [])

            if not repositories:
                return {
                    "success": False,
                    "error": _("No repositories specified for enabling"),
                }

            self.logger.info(
                _("Enabling %d third-party repositories"), len(repositories)
            )

            system = platform.system()
            if system != "Linux":
                return {"success": False, "error": _(_UNSUPPORTED_OS) % system}

            results = []
            for repo in repositories:
                repo_name = repo.get("name")
                file_path = repo.get("file_path")
                result = await self._enable_linux_repository(repo_name, file_path)
                results.append(
                    {
                        "repository": repo_name,
                        "success": result.get("success", False),
                        "message": result.get("result", result.get("error", "")),
                    }
                )

            await self._run_package_update()
            await self._trigger_update_detection()
            await self._trigger_third_party_repository_rescan()

            overall_success = all(r["success"] for r in results)
            return {
                "success": overall_success,
                "results": results,
                "message": _("Enabled %d of %d repositories")
                % (sum(1 for r in results if r["success"]), len(results)),
            }

        except Exception as error:
            self.logger.error(_("Error enabling third-party repositories: %s"), error)
            return {"success": False, "error": str(error)}

    async def _disable_linux_repository(
        self, repo_name: str, file_path: str
    ) -> Dict[str, Any]:
        """Disable a single Linux repository based on distro."""
        distro_info = await self._detect_linux_distro()
        distro = distro_info.get("distro", "").lower()

        if _is_distro_family(distro, _DEBIAN_FAMILY):
            return await self.linux_ops.disable_apt_repository(file_path)
        if _is_distro_family(distro, _RHEL_FAMILY):
            return await self.linux_ops.disable_yum_repository(repo_name)
        if _is_distro_family(distro, _SUSE_FAMILY):
            return await self.linux_ops.disable_zypper_repository(repo_name)
        return {"success": False, "error": _(_UNSUPPORTED_DISTRO) % distro}

    async def disable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable third-party repositories on the system."""
        try:
            repositories = parameters.get("repositories", [])

            if not repositories:
                return {
                    "success": False,
                    "error": _("No repositories specified for disabling"),
                }

            self.logger.info(
                _("Disabling %d third-party repositories"), len(repositories)
            )

            system = platform.system()
            if system != "Linux":
                return {"success": False, "error": _(_UNSUPPORTED_OS) % system}

            results = []
            for repo in repositories:
                repo_name = repo.get("name")
                file_path = repo.get("file_path")
                result = await self._disable_linux_repository(repo_name, file_path)
                results.append(
                    {
                        "repository": repo_name,
                        "success": result.get("success", False),
                        "message": result.get("result", result.get("error", "")),
                    }
                )

            await self._run_package_update()
            await self._trigger_update_detection()
            await self._trigger_third_party_repository_rescan()

            overall_success = all(r["success"] for r in results)
            return {
                "success": overall_success,
                "results": results,
                "message": _("Disabled %d of %d repositories")
                % (sum(1 for r in results if r["success"]), len(results)),
            }

        except Exception as error:
            self.logger.error(_("Error disabling third-party repositories: %s"), error)
            return {"success": False, "error": str(error)}

    def _get_package_update_command(self, distro: str) -> Optional[str]:
        """Get the package update command for a Linux distro."""
        if _is_distro_family(distro, _DEBIAN_FAMILY):
            return "sudo apt-get update"
        if _is_distro_family(distro, _RHEL_FAMILY):
            return "sudo dnf check-update"
        if _is_distro_family(distro, _SUSE_FAMILY):
            return "sudo zypper refresh"
        return None

    async def _run_package_update(self) -> None:
        """Run package manager update after repository changes."""
        try:
            system = platform.system()
            if system != "Linux":
                return

            distro_info = await self._detect_linux_distro()
            distro = distro_info.get("distro", "").lower()

            command = self._get_package_update_command(distro)
            if command:
                await self.agent_instance.system_ops.execute_shell_command(
                    {"command": command}
                )
        except Exception as error:
            self.logger.error(_("Error running package update: %s"), error)

    async def _trigger_update_detection(self) -> None:
        """Trigger update detection and send results to server."""
        try:
            self.logger.debug("Triggering update detection after repository change")
            await self.agent_instance.check_updates()
        except Exception as error:
            self.logger.error(_("Error triggering update detection: %s"), error)

    async def _trigger_third_party_repository_rescan(self) -> None:
        """Re-scan and send third-party repository data to server."""
        try:
            if hasattr(self.agent_instance, "_send_third_party_repository_update"):
                # pylint: disable=protected-access
                await self.agent_instance._send_third_party_repository_update()
        except Exception as error:
            self.logger.error(
                _("Error re-scanning third-party repositories: %s"), error
            )
