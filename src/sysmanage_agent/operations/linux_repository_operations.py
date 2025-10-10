#!/usr/bin/env python3
"""
Linux Repository Operations Helper Module

This module contains Linux-specific repository operations for APT, YUM/DNF, and Zypper.
"""

import logging
import os
from typing import Any, Dict
from urllib.parse import urlparse

from src.i18n import _


class LinuxRepositoryOperations:
    """Helper class for Linux repository operations."""

    def __init__(self, agent_instance):
        """Initialize Linux repository operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    # ========== APT Operations ==========

    async def list_apt_repositories(self) -> list:
        """List APT repositories including PPAs."""
        repositories = []
        sources_dir = "/etc/apt/sources.list.d"

        try:
            if os.path.exists(sources_dir):
                for filename in os.listdir(sources_dir):
                    if filename.endswith((".list", ".sources")):
                        filepath = os.path.join(sources_dir, filename)
                        try:
                            with open(filepath, "r", encoding="utf-8") as file_handle:
                                content = file_handle.read()
                                # Parse repository info
                                for line in content.splitlines():
                                    line = line.strip()
                                    if not line or line.startswith("#"):
                                        continue

                                    # Check if it's a PPA or other third-party repo
                                    is_ppa = False
                                    parts = line.split()
                                    for part in parts:
                                        if part.startswith("http"):
                                            parsed = urlparse(part)
                                            if parsed.hostname and (
                                                parsed.hostname == "ppa.launchpad.net"
                                                or parsed.hostname.endswith(
                                                    ".ppa.launchpad.net"
                                                )
                                            ):
                                                is_ppa = True
                                                break

                                    if not (is_ppa or "deb " in line):
                                        continue

                                    enabled = not line.startswith("#")
                                    repo_type = "PPA" if is_ppa else "APT"

                                    # Extract PPA name if it's a PPA
                                    name = filename.replace(".list", "").replace(
                                        ".sources", ""
                                    )
                                    if is_ppa:
                                        parts = line.split()
                                        for part in parts:
                                            if not part.startswith("http"):
                                                continue
                                            parsed = urlparse(part)
                                            if not (
                                                parsed.hostname
                                                and (
                                                    parsed.hostname
                                                    == "ppa.launchpad.net"
                                                    or parsed.hostname.endswith(
                                                        ".ppa.launchpad.net"
                                                    )
                                                )
                                            ):
                                                continue
                                            url_parts = part.split("/")
                                            if len(url_parts) >= 4:
                                                user = url_parts[-3]
                                                ppa = url_parts[-2]
                                                name = f"ppa:{user}/{ppa}"
                                            break

                                    repositories.append(
                                        {
                                            "name": name,
                                            "type": repo_type,
                                            "url": line,
                                            "enabled": enabled,
                                            "file_path": filepath,
                                        }
                                    )
                        except Exception as error:
                            self.logger.warning(
                                _("Error reading %s: %s"), filepath, error
                            )
        except Exception as error:
            self.logger.error(_("Error listing APT repositories: %s"), error)

        return repositories

    async def add_apt_repository(self, repo_identifier: str) -> Dict[str, Any]:
        """Add APT repository (PPA or manual)."""
        try:
            if repo_identifier.startswith("ppa:"):
                command = f"sudo -n add-apt-repository -y {repo_identifier}"
            else:
                command = f"sudo -n add-apt-repository -y '{repo_identifier}'"

            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            self.logger.debug(
                "add-apt-repository command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Repository %s added successfully", repo_identifier)
                return {
                    "success": True,
                    "result": _("Repository added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add repository %s: %s",
                repo_identifier,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add repository: %s") % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(_("Error adding APT repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def delete_apt_repository(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        """Delete APT repository."""
        try:
            repo_name = repo.get("name", "")
            file_path = repo.get("file_path", "")

            if repo_name.startswith("ppa:"):
                command = f"sudo add-apt-repository --remove -y {repo_name}"
                result = await self.agent_instance.system_ops.execute_shell_command(
                    {"command": command}
                )
            elif file_path and os.path.exists(file_path):
                command = f"sudo rm -f {file_path}"
                result = await self.agent_instance.system_ops.execute_shell_command(
                    {"command": command}
                )
            else:
                return {"success": False, "error": _("Repository file not found")}

            if result["success"]:
                return {"success": True, "result": _("Repository removed successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error deleting APT repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def enable_apt_repository(self, file_path: str) -> Dict[str, Any]:
        """Enable APT repository by uncommenting lines in the file."""
        try:
            if not file_path or not os.path.exists(file_path):
                return {"success": False, "error": _("Repository file not found")}

            command = f"sudo sed -i 's/^# *deb /deb /' {file_path}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {"success": True, "result": _("Repository enabled successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error enabling APT repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def disable_apt_repository(self, file_path: str) -> Dict[str, Any]:
        """Disable APT repository by commenting out lines in the file."""
        try:
            if not file_path or not os.path.exists(file_path):
                return {"success": False, "error": _("Repository file not found")}

            command = f"sudo sed -i 's/^deb /# deb /' {file_path}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {
                    "success": True,
                    "result": _("Repository disabled successfully"),
                }

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error disabling APT repository: %s"), error)
            return {"success": False, "error": str(error)}

    # ========== YUM/DNF Operations ==========

    async def list_yum_repositories(self) -> list:
        """List YUM/DNF repositories including COPR."""
        repositories = []
        repos_dir = "/etc/yum.repos.d"

        try:
            if os.path.exists(repos_dir):
                for filename in os.listdir(repos_dir):
                    if filename.endswith(".repo"):
                        filepath = os.path.join(repos_dir, filename)
                        try:
                            with open(filepath, "r", encoding="utf-8") as file_handle:
                                content = file_handle.read()
                                # Parse INI-style repo file
                                current_repo = None
                                for line in content.splitlines():
                                    line = line.strip()
                                    if line.startswith("[") and line.endswith("]"):
                                        if current_repo:
                                            repositories.append(current_repo)
                                        current_repo = {
                                            "name": line[1:-1],
                                            "type": (
                                                "COPR"
                                                if "copr" in filename.lower()
                                                else "YUM"
                                            ),
                                            "url": "",
                                            "enabled": True,
                                            "file_path": filepath,
                                        }
                                    elif current_repo is not None and "=" in line:
                                        key, value = line.split("=", 1)
                                        key = key.strip()
                                        value = value.strip()
                                        if key == "baseurl":
                                            # pylint: disable=unsupported-assignment-operation
                                            current_repo["url"] = value
                                        elif key == "enabled":
                                            # pylint: disable=unsupported-assignment-operation
                                            current_repo["enabled"] = value == "1"

                                if current_repo:
                                    repositories.append(current_repo)
                        except Exception as error:
                            self.logger.warning(
                                _("Error reading %s: %s"), filepath, error
                            )
        except Exception as error:
            self.logger.error(_("Error listing YUM repositories: %s"), error)

        return repositories

    async def add_yum_repository(self, repo_identifier: str) -> Dict[str, Any]:
        """Add YUM/DNF repository (COPR or manual)."""
        try:
            # Check if it's a COPR repo (format: user/project)
            if "/" in repo_identifier and not repo_identifier.startswith("http"):
                command = f"sudo -n dnf copr enable -y {repo_identifier}"
            else:
                return {
                    "success": False,
                    "error": _("Manual YUM repository addition not yet implemented"),
                }

            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            self.logger.debug(
                "dnf copr enable command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Repository %s added successfully", repo_identifier)
                return {
                    "success": True,
                    "result": _("Repository added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add repository %s: %s",
                repo_identifier,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add repository: %s") % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(_("Error adding YUM repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def delete_yum_repository(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        """Delete YUM/DNF repository."""
        try:
            repo_name = repo.get("name", "")
            repo_type = repo.get("type", "")
            file_path = repo.get("file_path", "")

            if "copr" in repo_type.lower() or "copr" in repo_name.lower():
                command = f"sudo dnf copr remove -y {repo_name}"
                result = await self.agent_instance.system_ops.execute_shell_command(
                    {"command": command}
                )
            elif file_path and os.path.exists(file_path):
                command = f"sudo rm -f {file_path}"
                result = await self.agent_instance.system_ops.execute_shell_command(
                    {"command": command}
                )
            else:
                return {"success": False, "error": _("Repository file not found")}

            if result["success"]:
                return {"success": True, "result": _("Repository removed successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error deleting YUM repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def enable_yum_repository(self, repo_name: str) -> Dict[str, Any]:
        """Enable YUM/DNF repository."""
        try:
            command = f"sudo dnf config-manager --set-enabled {repo_name}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {"success": True, "result": _("Repository enabled successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error enabling YUM repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def disable_yum_repository(self, repo_name: str) -> Dict[str, Any]:
        """Disable YUM/DNF repository."""
        try:
            command = f"sudo dnf config-manager --set-disabled {repo_name}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {
                    "success": True,
                    "result": _("Repository disabled successfully"),
                }

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error disabling YUM repository: %s"), error)
            return {"success": False, "error": str(error)}

    # ========== Zypper Operations ==========

    def _check_obs_url(self, url: str) -> bool:
        """Check if a URL is from opensuse.org domain."""
        if not url:
            return False
        try:
            parsed = urlparse(url)
            return bool(
                parsed.hostname
                and (
                    parsed.hostname == "opensuse.org"
                    or parsed.hostname.endswith(".opensuse.org")
                )
            )
        except Exception:
            return False

    async def list_zypper_repositories(self) -> list:
        """List Zypper repositories including OBS."""
        repositories = []

        try:
            command = "zypper lr -u"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                output = result["result"]["stdout"]
                for line in output.splitlines():
                    # Parse zypper output
                    if "|" in line and not line.startswith("#"):
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) >= 4:
                            url = parts[3] if len(parts) > 3 else ""
                            is_obs = self._check_obs_url(url)

                            repositories.append(
                                {
                                    "name": parts[1],
                                    "type": "OBS" if is_obs else "Zypper",
                                    "url": url,
                                    "enabled": (
                                        parts[2] == "Yes" if len(parts) > 2 else True
                                    ),
                                    "file_path": f"/etc/zypp/repos.d/{parts[1]}.repo",
                                }
                            )
        except Exception as error:
            self.logger.error(_("Error listing Zypper repositories: %s"), error)

        return repositories

    async def add_zypper_repository(self, alias: str, url: str) -> Dict[str, Any]:
        """Add Zypper repository (OBS or manual)."""
        try:
            if not url:
                return {
                    "success": False,
                    "error": _("Repository URL is required for Zypper"),
                }

            command = f"sudo -n zypper addrepo -f {url} {alias}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            self.logger.debug(
                "zypper addrepo command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Repository %s added successfully", alias)
                return {
                    "success": True,
                    "result": _("Repository added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add repository %s: %s",
                alias,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add repository: %s") % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(_("Error adding Zypper repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def delete_zypper_repository(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        """Delete Zypper repository."""
        try:
            repo_name = repo.get("name", "")

            command = f"sudo zypper removerepo {repo_name}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {"success": True, "result": _("Repository removed successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error deleting Zypper repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def enable_zypper_repository(self, repo_name: str) -> Dict[str, Any]:
        """Enable Zypper repository."""
        try:
            command = f"sudo zypper modifyrepo --enable {repo_name}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {"success": True, "result": _("Repository enabled successfully")}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error enabling Zypper repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def disable_zypper_repository(self, repo_name: str) -> Dict[str, Any]:
        """Disable Zypper repository."""
        try:
            command = f"sudo zypper modifyrepo --disable {repo_name}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {
                    "success": True,
                    "result": _("Repository disabled successfully"),
                }

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error disabling Zypper repository: %s"), error)
            return {"success": False, "error": str(error)}
