#!/usr/bin/env python3
"""
Windows Repository Operations Helper Module

This module contains Windows-specific repository operations for Chocolatey and winget.
"""

import logging
from typing import Any, Dict, Optional

from src.i18n import _


class WindowsRepositoryOperations:
    """Helper class for Windows repository operations."""

    def __init__(self, agent_instance):
        """Initialize Windows repository operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def list_windows_repositories(self) -> list:
        """List Chocolatey sources and winget sources on Windows."""
        repositories = []

        try:
            # List Chocolatey sources
            choco_repos = await self._list_chocolatey_sources()
            repositories.extend(choco_repos)

            # List winget sources
            winget_repos = await self._list_winget_sources()
            repositories.extend(winget_repos)

        except Exception as error:
            self.logger.error(_("Error listing Windows repositories: %s"), error)

        return repositories

    async def _list_chocolatey_sources(self) -> list:
        """List Chocolatey sources."""
        repositories = []
        choco_result = await self.agent_instance.system_ops.execute_shell_command(
            {"command": "choco source list"}
        )

        if not choco_result.get("success"):
            return repositories

        output = choco_result["result"]["stdout"]
        for line in output.splitlines():
            line = line.strip()
            if not (" - " in line and "http" in line):
                continue

            parts = line.split(" - ")
            if len(parts) < 2:
                continue

            name = parts[0].strip()
            # Skip the official chocolatey source
            if name.lower() == "chocolatey":
                continue

            url_part = parts[1].split("|")[0].strip()
            enabled = "Disabled" not in line
            repositories.append(
                {
                    "name": name,
                    "type": "Chocolatey",
                    "url": url_part,
                    "enabled": enabled,
                    "file_path": None,
                }
            )

        return repositories

    def _is_winget_header_line(self, line: str) -> bool:
        """Check if a line is a winget output header line."""
        if "Name" in line and "Argument" in line:
            return True
        return line.startswith("---")

    def _parse_winget_source_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a winget source line and return repo dict or None if should skip."""
        parts = line.split()
        if len(parts) < 2:
            return None

        name = parts[0]
        # Skip the official msstore and winget sources
        if name.lower() in ["msstore", "winget"]:
            return None

        return {
            "name": name,
            "type": "winget",
            "url": parts[1] if len(parts) > 1 else "",
            "enabled": True,
            "file_path": None,
        }

    async def _list_winget_sources(self) -> list:
        """List winget sources."""
        repositories = []
        winget_result = await self.agent_instance.system_ops.execute_shell_command(
            {"command": "winget source list"}
        )

        if not winget_result.get("success"):
            return repositories

        output = winget_result["result"]["stdout"]
        lines = output.splitlines()

        for i, line in enumerate(lines):
            line = line.strip()
            if self._is_winget_header_line(line):
                continue
            if not (line and i > 1):
                continue

            repo = self._parse_winget_source_line(line)
            if repo:
                repositories.append(repo)

        return repositories

    async def add_windows_repository(
        self, repo_name: str, url: str, repo_type: str
    ) -> Dict[str, Any]:
        """Add a Chocolatey source or winget source on Windows."""
        try:
            if not url:
                return {
                    "success": False,
                    "error": _("Repository URL is required for Windows repositories"),
                }

            if not repo_type or repo_type.lower() not in ["chocolatey", "winget"]:
                return {
                    "success": False,
                    "error": _("Repository type must be 'chocolatey' or 'winget'"),
                }

            if repo_type.lower() == "chocolatey":
                # Add Chocolatey source
                command = f'choco source add --name="{repo_name}" --source="{url}"'
            else:  # winget
                # Add winget source
                command = f'winget source add --name "{repo_name}" --arg "{url}" --type Microsoft.Rest'

            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                self.logger.info("Windows repository %s added successfully", repo_name)
                return {
                    "success": True,
                    "result": _("Repository added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add Windows repository %s: %s",
                repo_name,
                result.get("result", {}).get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add repository: %s")
                % result.get("result", {}).get("stderr", "Unknown error"),
                "output": result.get("result", {}).get("stderr", ""),
            }

        except Exception as error:
            self.logger.error(_("Error adding Windows repository: %s"), error)
            return {"success": False, "error": str(error)}
