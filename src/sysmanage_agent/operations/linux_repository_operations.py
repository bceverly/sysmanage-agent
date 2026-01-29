#!/usr/bin/env python3
"""
Linux Repository Operations Helper Module

This module contains Linux-specific repository operations for APT, YUM/DNF, and Zypper.
"""

import logging
import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import aiofiles

from src.i18n import _

# Module-level constants for repeated strings
_EXT_LIST = ".list"
_EXT_SOURCES = ".sources"
_REPO_ADDED_SUCCESS = "Repository %s added successfully"
_REPO_ADDED_SUCCESS_SIMPLE = "Repository added successfully"
_REPO_ADD_FAILED = "Failed to add repository %s: %s"
_REPO_ADD_FAILED_SIMPLE = "Failed to add repository: %s"
_REPO_FILE_NOT_FOUND = "Repository file not found"
_REPO_REMOVED_SUCCESS = "Repository removed successfully"
_REPO_ENABLED_SUCCESS = "Repository enabled successfully"
_REPO_DISABLED_SUCCESS = "Repository disabled successfully"


class LinuxRepositoryOperations:
    """Helper class for Linux repository operations."""

    def __init__(self, agent_instance):
        """Initialize Linux repository operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    # ========== APT Operations ==========

    def _is_ppa_hostname(self, hostname: str) -> bool:
        """Check if a hostname belongs to a PPA service."""
        if not hostname:
            return False
        ppa_hosts = [
            "ppa.launchpad.net",
            "ppa.launchpadcontent.net",
        ]
        for ppa_host in ppa_hosts:
            if hostname == ppa_host or hostname.endswith(f".{ppa_host}"):
                return True
        return False

    def _extract_ppa_name_from_url(self, url: str) -> str:
        """Extract PPA name (ppa:user/repo) from a URL."""
        parsed = urlparse(url)
        if not self._is_ppa_hostname(parsed.hostname):
            return ""
        # URL format: https://ppa.launchpadcontent.net/user/repo/ubuntu/
        path_parts = [p for p in parsed.path.split("/") if p]
        if len(path_parts) >= 2:
            return f"ppa:{path_parts[0]}/{path_parts[1]}"
        return ""

    def _parse_deb822_line(self, line: str, current_entry: dict) -> None:
        """Parse a single line from a DEB822 file and update current_entry."""
        # Parse key: value
        if ":" not in line:
            return

        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        key_handlers = {
            "types": lambda v: current_entry.__setitem__("types", v),
            "uris": lambda v: current_entry.__setitem__("uris", v),
            "suites": lambda v: current_entry.__setitem__("suites", v),
            "components": lambda v: current_entry.__setitem__("components", v),
            "enabled": lambda v: current_entry.__setitem__(
                "enabled", v.lower() != "no"
            ),
        }

        handler = key_handlers.get(key)
        if handler:
            handler(value)

    def _parse_deb822_sources_file(self, content: str, filepath: str) -> list:
        """Parse a DEB822 format .sources file."""
        repositories = []
        current_entry = {}

        for line in content.splitlines():
            line = line.rstrip()

            # Empty line marks end of an entry
            if not line:
                if current_entry.get("uris"):
                    repositories.append(
                        self._create_repo_from_deb822(current_entry, filepath)
                    )
                current_entry = {}
                continue

            # Skip comments and continuation lines
            if line.startswith("#") or line.startswith(" ") or line.startswith("\t"):
                continue

            self._parse_deb822_line(line, current_entry)

        # Don't forget the last entry if file doesn't end with blank line
        if current_entry.get("uris"):
            repositories.append(self._create_repo_from_deb822(current_entry, filepath))

        return repositories

    def _create_repo_from_deb822(self, entry: dict, filepath: str) -> dict:
        """Create a repository dict from a parsed DEB822 entry."""
        uri = entry.get("uris", "")
        types = entry.get("types", "deb")
        suites = entry.get("suites", "")
        components = entry.get("components", "")
        enabled = entry.get("enabled", True)

        # Construct a deb-line style URL for display
        url = f"{types} {uri} {suites} {components}".strip()

        # Check if it's a PPA
        is_ppa = self._is_ppa_hostname(urlparse(uri).hostname)
        repo_type = "PPA" if is_ppa else "APT"

        # Extract name
        name = (
            os.path.basename(filepath).replace(_EXT_SOURCES, "").replace(_EXT_LIST, "")
        )
        if is_ppa:
            ppa_name = self._extract_ppa_name_from_url(uri)
            if ppa_name:
                name = ppa_name

        return {
            "name": name,
            "type": repo_type,
            "url": url,
            "enabled": enabled,
            "file_path": filepath,
        }

    def _check_line_for_ppa(self, line: str) -> bool:
        """Check if a deb line contains a PPA URL."""
        for part in line.split():
            if part.startswith("http"):
                parsed = urlparse(part)
                if self._is_ppa_hostname(parsed.hostname):
                    return True
        return False

    def _extract_ppa_name_from_line(self, line: str) -> str:
        """Extract PPA name from a deb line if present."""
        for part in line.split():
            if part.startswith("http"):
                ppa_name = self._extract_ppa_name_from_url(part)
                if ppa_name:
                    return ppa_name
        return ""

    def _parse_list_line(self, line: str, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse a single line from a .list file and return repo dict or None."""
        line = line.strip()
        if not line:
            return None

        # Check if line is commented out
        enabled = not line.startswith("#")
        if not enabled:
            line = line.lstrip("#").strip()

        # Must start with deb or deb-src
        if not (line.startswith("deb ") or line.startswith("deb-src ")):
            return None

        # Check if it's a PPA
        is_ppa = self._check_line_for_ppa(line)
        repo_type = "PPA" if is_ppa else "APT"

        # Extract name
        name = (
            os.path.basename(filepath).replace(_EXT_LIST, "").replace(_EXT_SOURCES, "")
        )
        if is_ppa:
            ppa_name = self._extract_ppa_name_from_line(line)
            if ppa_name:
                name = ppa_name

        return {
            "name": name,
            "type": repo_type,
            "url": line,
            "enabled": enabled,
            "file_path": filepath,
        }

    def _parse_list_sources_file(self, content: str, filepath: str) -> list:
        """Parse a traditional .list format sources file."""
        repositories = []

        for line in content.splitlines():
            repo = self._parse_list_line(line, filepath)
            if repo:
                repositories.append(repo)

        return repositories

    async def _read_apt_source_file(self, filepath: str, filename: str) -> list:
        """Read and parse a single APT source file."""
        async with aiofiles.open(filepath, "r", encoding="utf-8") as file_handle:
            content = await file_handle.read()

        if filename.endswith(_EXT_SOURCES):
            # Parse DEB822 format
            return self._parse_deb822_sources_file(content, filepath)
        # Parse traditional .list format
        return self._parse_list_sources_file(content, filepath)

    async def list_apt_repositories(
        self,
    ) -> list:  # NOSONAR - async required by interface
        """List APT repositories including PPAs.

        Supports both traditional .list format and modern DEB822 .sources format.
        """
        repositories = []
        sources_dir = "/etc/apt/sources.list.d"

        try:
            if os.path.exists(sources_dir):
                for filename in os.listdir(sources_dir):
                    if not filename.endswith((_EXT_LIST, _EXT_SOURCES)):
                        continue

                    filepath = os.path.join(sources_dir, filename)
                    try:
                        repos = await self._read_apt_source_file(filepath, filename)
                        repositories.extend(repos)

                    except Exception as error:
                        self.logger.warning(_("Error reading %s: %s"), filepath, error)
        except Exception as error:
            self.logger.error(_("Error listing APT repositories: %s"), error)

        return repositories

    async def add_apt_repository(self, repo_identifier: str) -> Dict[str, Any]:
        """Add APT repository (PPA or manual)."""
        try:
            # Use sudo only if not running as root
            sudo_prefix = "" if os.geteuid() == 0 else "sudo -n "

            # Both PPA and non-PPA use the same command format
            command = f"{sudo_prefix}add-apt-repository -y '{repo_identifier}'"

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
                self.logger.info(_REPO_ADDED_SUCCESS, repo_identifier)
                return {
                    "success": True,
                    "result": _(_REPO_ADDED_SUCCESS_SIMPLE),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                _REPO_ADD_FAILED,
                repo_identifier,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _(_REPO_ADD_FAILED_SIMPLE) % result["result"]["stderr"],
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

            # Use sudo only if not running as root
            sudo_prefix = "" if os.geteuid() == 0 else "sudo -n "

            # Prefer direct file removal for .sources files (DEB822 format)
            # as add-apt-repository --remove may not work properly with them
            if file_path and os.path.exists(file_path):
                command = f"{sudo_prefix}rm -f '{file_path}'"
                result = await self.agent_instance.system_ops.execute_shell_command(
                    {"command": command}
                )
            elif repo_name.startswith("ppa:"):
                # For .list files or when no file_path, use add-apt-repository
                command = f"{sudo_prefix}add-apt-repository --remove -y '{repo_name}'"
                result = await self.agent_instance.system_ops.execute_shell_command(
                    {"command": command}
                )
            else:
                return {"success": False, "error": _(_REPO_FILE_NOT_FOUND)}

            if result["success"]:
                return {"success": True, "result": _(_REPO_REMOVED_SUCCESS)}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error deleting APT repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def enable_apt_repository(self, file_path: str) -> Dict[str, Any]:
        """Enable APT repository by uncommenting lines in the file."""
        try:
            if not file_path or not os.path.exists(file_path):
                return {"success": False, "error": _(_REPO_FILE_NOT_FOUND)}

            command = f"sudo sed -i 's/^# *deb /deb /' {file_path}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {"success": True, "result": _(_REPO_ENABLED_SUCCESS)}

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error enabling APT repository: %s"), error)
            return {"success": False, "error": str(error)}

    async def disable_apt_repository(self, file_path: str) -> Dict[str, Any]:
        """Disable APT repository by commenting out lines in the file."""
        try:
            if not file_path or not os.path.exists(file_path):
                return {"success": False, "error": _(_REPO_FILE_NOT_FOUND)}

            command = f"sudo sed -i 's/^deb /# deb /' {file_path}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                return {
                    "success": True,
                    "result": _(_REPO_DISABLED_SUCCESS),
                }

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error disabling APT repository: %s"), error)
            return {"success": False, "error": str(error)}

    # ========== YUM/DNF Operations ==========

    def _create_yum_repo_entry(self, name: str, filename: str, filepath: str) -> dict:
        """Create a new YUM repository entry dict."""
        return {
            "name": name,
            "type": "COPR" if "copr" in filename.lower() else "YUM",
            "url": "",
            "enabled": True,
            "file_path": filepath,
        }

    def _update_repo_from_line(self, current_repo: dict, line: str) -> None:
        """Update a repo dict from a key=value line."""
        if "=" not in line:
            return
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key == "baseurl":
            current_repo["url"] = value
        elif key == "enabled":
            current_repo["enabled"] = value == "1"

    def _parse_yum_repo_file(self, content: str, filename: str, filepath: str) -> list:
        """Parse a YUM/DNF .repo file and return list of repositories."""
        repositories = []
        current_repo = None

        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                if current_repo:
                    repositories.append(current_repo)
                current_repo = self._create_yum_repo_entry(
                    line[1:-1], filename, filepath
                )
            elif current_repo is not None:
                self._update_repo_from_line(current_repo, line)

        if current_repo:
            repositories.append(current_repo)

        return repositories

    async def _read_yum_repo_file(self, filepath: str, filename: str) -> list:
        """Read and parse a single YUM repo file."""
        async with aiofiles.open(filepath, "r", encoding="utf-8") as file_handle:
            content = await file_handle.read()
        return self._parse_yum_repo_file(content, filename, filepath)

    async def list_yum_repositories(
        self,
    ) -> list:  # NOSONAR - async required by interface
        """List YUM/DNF repositories including COPR."""
        repositories = []
        repos_dir = "/etc/yum.repos.d"

        try:
            if os.path.exists(repos_dir):
                for filename in os.listdir(repos_dir):
                    if filename.endswith(".repo"):
                        filepath = os.path.join(repos_dir, filename)
                        try:
                            repos = await self._read_yum_repo_file(filepath, filename)
                            repositories.extend(repos)
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
                self.logger.info(_REPO_ADDED_SUCCESS, repo_identifier)
                return {
                    "success": True,
                    "result": _(_REPO_ADDED_SUCCESS_SIMPLE),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                _REPO_ADD_FAILED,
                repo_identifier,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _(_REPO_ADD_FAILED_SIMPLE) % result["result"]["stderr"],
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
                return {"success": False, "error": _(_REPO_FILE_NOT_FOUND)}

            if result["success"]:
                return {"success": True, "result": _(_REPO_REMOVED_SUCCESS)}

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
                return {"success": True, "result": _(_REPO_ENABLED_SUCCESS)}

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
                    "result": _(_REPO_DISABLED_SUCCESS),
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

    def _parse_zypper_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single line from zypper lr output."""
        if "|" not in line or line.startswith("#"):
            return None

        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            return None

        url = parts[3]
        is_obs = self._check_obs_url(url)

        return {
            "name": parts[1],
            "type": "OBS" if is_obs else "Zypper",
            "url": url,
            "enabled": parts[2] == "Yes",
            "file_path": f"/etc/zypp/repos.d/{parts[1]}.repo",
        }

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
                    repo = self._parse_zypper_line(line)
                    if repo:
                        repositories.append(repo)
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
                self.logger.info(_REPO_ADDED_SUCCESS, alias)
                return {
                    "success": True,
                    "result": _(_REPO_ADDED_SUCCESS_SIMPLE),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                _REPO_ADD_FAILED,
                alias,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _(_REPO_ADD_FAILED_SIMPLE) % result["result"]["stderr"],
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
                return {"success": True, "result": _(_REPO_REMOVED_SUCCESS)}

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
                return {"success": True, "result": _(_REPO_ENABLED_SUCCESS)}

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
                    "result": _(_REPO_DISABLED_SUCCESS),
                }

            return {"success": False, "error": result["result"]["stderr"]}
        except Exception as error:
            self.logger.error(_("Error disabling Zypper repository: %s"), error)
            return {"success": False, "error": str(error)}
