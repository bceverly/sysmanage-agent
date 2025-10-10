"""
Third-party repository operations module for SysManage agent.
Handles third-party repository management operations.
"""

import logging
import os
import platform
from typing import Any, Dict

from src.i18n import _
from .linux_repository_operations import LinuxRepositoryOperations
from .bsd_macos_repository_operations import BSDMacOSRepositoryOperations
from .windows_repository_operations import WindowsRepositoryOperations


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

    async def list_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """List all third-party repositories on the system."""
        _unused = (
            parameters  # API signature requirement - pylint: disable=unused-variable
        )
        try:
            self.logger.info(_("Listing third-party repositories"))
            repositories = []
            system = platform.system()

            if system == "Linux":
                distro_info = await self._detect_linux_distro()
                distro = distro_info.get("distro", "").lower()

                if "ubuntu" in distro or "debian" in distro:
                    repos = await self.linux_ops.list_apt_repositories()
                    repositories.extend(repos)
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    repos = await self.linux_ops.list_yum_repositories()
                    repositories.extend(repos)
                elif "opensuse" in distro or "suse" in distro:
                    repos = await self.linux_ops.list_zypper_repositories()
                    repositories.extend(repos)
            elif system == "Darwin":
                repos = await self.bsd_macos_ops.list_homebrew_taps()
                repositories.extend(repos)
            elif system == "FreeBSD":
                repos = await self.bsd_macos_ops.list_freebsd_repositories()
                repositories.extend(repos)
            elif system == "NetBSD":
                repos = await self.bsd_macos_ops.list_netbsd_repositories()
                repositories.extend(repos)
            elif system == "Windows":
                repos = await self.windows_ops.list_windows_repositories()
                repositories.extend(repos)

            return {
                "success": True,
                "repositories": repositories,
                "count": len(repositories),
            }
        except Exception as error:
            self.logger.error(_("Error listing third-party repositories: %s"), error)
            return {"success": False, "error": str(error)}

    async def _detect_linux_distro(self) -> Dict[str, str]:
        """Detect Linux distribution."""
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r", encoding="utf-8") as file_handle:
                    lines = file_handle.readlines()
                    for line in lines:
                        if line.startswith("ID="):
                            distro = line.split("=")[1].strip().strip('"')
                            return {"distro": distro}

            return {"distro": platform.system()}
        except Exception as error:
            self.logger.error(_("Error detecting Linux distribution: %s"), error)
            return {"distro": "unknown"}

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
                self.logger.debug("Detecting Linux distribution for repository add")
                distro_info = await self._detect_linux_distro()
                distro = distro_info.get("distro", "").lower()
                self.logger.debug("Detected distribution: %s", distro)

                if "ubuntu" in distro or "debian" in distro:
                    self.logger.debug(
                        "Calling _add_apt_repository for %s", repo_identifier
                    )
                    result = await self.linux_ops.add_apt_repository(repo_identifier)
                    self.logger.debug("_add_apt_repository returned: %s", result)
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    result = await self.linux_ops.add_yum_repository(repo_identifier)
                elif "opensuse" in distro or "suse" in distro:
                    result = await self.linux_ops.add_zypper_repository(
                        repo_identifier, parameters.get("url", "")
                    )
                else:
                    return {
                        "success": False,
                        "error": _("Unsupported distribution: %s") % distro,
                    }
            elif system == "Darwin":
                result = await self.bsd_macos_ops.add_homebrew_tap(repo_identifier)
            elif system == "FreeBSD":
                result = await self.bsd_macos_ops.add_freebsd_repository(
                    repo_identifier, parameters.get("url", "")
                )
            elif system == "NetBSD":
                result = await self.bsd_macos_ops.add_netbsd_repository(
                    repo_identifier, parameters.get("url", "")
                )
            elif system == "Windows":
                result = await self.windows_ops.add_windows_repository(
                    repo_identifier,
                    parameters.get("url", ""),
                    parameters.get("type", ""),
                )
            else:
                return {
                    "success": False,
                    "error": _("Unsupported operating system: %s") % system,
                }

            if result["success"]:
                await self._run_package_update()
                await self._trigger_update_detection()
                await self._trigger_third_party_repository_rescan()

            return result

        except Exception as error:
            self.logger.error(_("Error adding third-party repository: %s"), error)
            return {"success": False, "error": str(error)}

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
            results = []

            for repo in repositories:
                repo_name = repo.get("name")

                if system == "Linux":
                    distro_info = await self._detect_linux_distro()
                    distro = distro_info.get("distro", "").lower()

                    if "ubuntu" in distro or "debian" in distro:
                        result = await self.linux_ops.delete_apt_repository(repo)
                    elif (
                        "fedora" in distro
                        or "rhel" in distro
                        or "centos" in distro
                        or "rocky" in distro
                        or "alma" in distro
                    ):
                        result = await self.linux_ops.delete_yum_repository(repo)
                    elif "opensuse" in distro or "suse" in distro:
                        result = await self.linux_ops.delete_zypper_repository(repo)
                    else:
                        result = {
                            "success": False,
                            "error": _("Unsupported distribution: %s") % distro,
                        }
                else:
                    result = {
                        "success": False,
                        "error": _("Unsupported operating system: %s") % system,
                    }

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
                return {
                    "success": False,
                    "error": _("Unsupported operating system: %s") % system,
                }

            distro_info = await self._detect_linux_distro()
            distro = distro_info.get("distro", "").lower()

            results = []
            for repo in repositories:
                repo_name = repo.get("name")
                file_path = repo.get("file_path")

                if "ubuntu" in distro or "debian" in distro:
                    result = await self.linux_ops.enable_apt_repository(file_path)
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    result = await self.linux_ops.enable_yum_repository(repo_name)
                elif "opensuse" in distro or "suse" in distro:
                    result = await self.linux_ops.enable_zypper_repository(repo_name)
                else:
                    result = {
                        "success": False,
                        "error": _("Unsupported distribution: %s") % distro,
                    }

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
                return {
                    "success": False,
                    "error": _("Unsupported operating system: %s") % system,
                }

            distro_info = await self._detect_linux_distro()
            distro = distro_info.get("distro", "").lower()

            results = []
            for repo in repositories:
                repo_name = repo.get("name")
                file_path = repo.get("file_path")

                if "ubuntu" in distro or "debian" in distro:
                    result = await self.linux_ops.disable_apt_repository(file_path)
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    result = await self.linux_ops.disable_yum_repository(repo_name)
                elif "opensuse" in distro or "suse" in distro:
                    result = await self.linux_ops.disable_zypper_repository(repo_name)
                else:
                    result = {
                        "success": False,
                        "error": _("Unsupported distribution: %s") % distro,
                    }

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

    async def _run_package_update(self) -> None:
        """Run package manager update after repository changes."""
        try:
            system = platform.system()
            if system == "Linux":
                distro_info = await self._detect_linux_distro()
                distro = distro_info.get("distro", "").lower()

                if "ubuntu" in distro or "debian" in distro:
                    command = "sudo apt-get update"
                elif (
                    "fedora" in distro
                    or "rhel" in distro
                    or "centos" in distro
                    or "rocky" in distro
                    or "alma" in distro
                ):
                    command = "sudo dnf check-update"
                elif "opensuse" in distro or "suse" in distro:
                    command = "sudo zypper refresh"
                else:
                    return

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
