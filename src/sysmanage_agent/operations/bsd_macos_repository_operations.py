#!/usr/bin/env python3
"""
BSD and macOS Repository Operations Helper Module

This module contains BSD and macOS-specific repository operations.
"""

import asyncio
import logging
import os
import re
from typing import Any, Dict

import aiofiles

from src.i18n import _


class BSDMacOSRepositoryOperations:
    """Helper class for BSD and macOS repository operations."""

    def __init__(self, agent_instance):
        """Initialize BSD/macOS repository operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    # ========== macOS Homebrew Operations ==========

    async def list_homebrew_taps(self) -> list:
        """List Homebrew taps on macOS."""
        repositories = []

        try:
            # Check if Homebrew is installed
            which_result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": "which brew"}
            )
            if not which_result.get("success"):
                self.logger.warning(_("Homebrew is not installed"))
                return repositories

            # Get list of taps
            command = "brew tap"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            if result["success"]:
                output = result["result"]["stdout"]
                for line in output.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Skip official Homebrew taps
                        if line.startswith("homebrew/"):
                            continue

                        repositories.append(
                            {
                                "name": line,
                                "type": "Homebrew Tap",
                                "url": f"https://github.com/{line}",
                                "enabled": True,
                                "file_path": f"/usr/local/Homebrew/Library/Taps/{line.replace('/', '/homebrew-')}",
                            }
                        )
        except Exception as error:
            self.logger.error(_("Error listing Homebrew taps: %s"), error)

        return repositories

    async def add_homebrew_tap(self, tap_name: str) -> Dict[str, Any]:
        """Add a Homebrew tap on macOS."""
        try:
            # Validate tap name format (should be user/repo)
            if "/" not in tap_name:
                return {
                    "success": False,
                    "error": _("Invalid tap format. Use 'user/repo' format"),
                }

            command = f"brew tap {tap_name}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            self.logger.debug(
                "brew tap command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Tap %s added successfully", tap_name)
                return {
                    "success": True,
                    "result": _("Tap added successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to add tap %s: %s",
                tap_name,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to add tap: %s") % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(_("Error adding Homebrew tap: %s"), error)
            return {"success": False, "error": str(error)}

    # ========== FreeBSD Operations ==========

    async def list_freebsd_repositories(
        self,
    ) -> list:  # NOSONAR - async required by caller interface
        """List pkg repositories on FreeBSD."""
        await asyncio.sleep(0)  # Yield to event loop for interface consistency
        repositories = []

        try:
            # Read pkg configuration files
            repos_dir = "/usr/local/etc/pkg/repos"
            if os.path.exists(repos_dir):
                for filename in os.listdir(repos_dir):
                    if filename.endswith(".conf"):
                        filepath = os.path.join(repos_dir, filename)
                        self._parse_freebsd_repo_file(filepath, filename, repositories)
        except Exception as error:
            self.logger.error(_("Error listing FreeBSD repositories: %s"), error)

        return repositories

    def _parse_freebsd_repo_file(
        self, filepath: str, filename: str, repositories: list
    ):
        """Parse a single FreeBSD pkg repository configuration file."""
        try:
            with open(filepath, "r", encoding="utf-8") as file_handle:
                content = file_handle.read()

            name = filename.replace(".conf", "")
            url = ""
            enabled = True

            # Extract URL
            url_match = re.search(r'url:\s*"([^"]+)"', content)
            if url_match:
                url = url_match.group(1)

            # Check if enabled
            if "enabled: no" in content.lower():
                enabled = False

            repositories.append(
                {
                    "name": name,
                    "type": "FreeBSD pkg",
                    "url": url,
                    "enabled": enabled,
                    "file_path": filepath,
                }
            )
        except Exception as error:
            self.logger.warning(_("Error reading %s: %s"), filepath, error)

    async def add_freebsd_repository(self, repo_name: str, url: str) -> Dict[str, Any]:
        """Add a pkg repository on FreeBSD."""
        try:
            if not url:
                return {
                    "success": False,
                    "error": _("Repository URL is required for FreeBSD pkg"),
                }

            # Create repository configuration
            repos_dir = "/usr/local/etc/pkg/repos"
            repo_file = f"{repos_dir}/{repo_name}.conf"

            # Ensure repos directory exists
            os.makedirs(repos_dir, exist_ok=True)

            # Write repository configuration
            config_content = f'{repo_name}: {{\n  url: "{url}",\n  enabled: yes\n}}\n'

            async with aiofiles.open(repo_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(config_content)

            # Update pkg database
            update_result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": "sudo pkg update"}
            )

            self.logger.debug(
                "pkg update command result: success=%s, exit_code=%s",
                update_result.get("success"),
                update_result.get("exit_code"),
            )

            self.logger.info("Repository %s added successfully", repo_name)
            return {
                "success": True,
                "result": _("Repository added successfully"),
                "output": f"Created {repo_file}",
            }
        except Exception as error:
            self.logger.error(_("Error adding FreeBSD repository: %s"), error)
            return {"success": False, "error": str(error)}

    # ========== NetBSD Operations ==========

    async def list_netbsd_repositories(
        self,
    ) -> list:  # NOSONAR - async required by caller interface
        """List pkgsrc repositories on NetBSD."""
        await asyncio.sleep(0)  # Yield to event loop for interface consistency
        repositories = []

        try:
            # Check for pkgsrc-wip
            wip_path = "/usr/pkgsrc/wip"
            if os.path.exists(wip_path):
                repositories.append(
                    {
                        "name": "pkgsrc-wip",
                        "type": "pkgsrc-wip",
                        "url": "https://github.com/NetBSD/pkgsrc-wip",
                        "enabled": True,
                        "file_path": wip_path,
                    }
                )

            # Check for custom pkgsrc directories
            pkgsrc_base = "/usr/pkgsrc"
            if os.path.exists(pkgsrc_base):
                for item in os.listdir(pkgsrc_base):
                    item_path = os.path.join(pkgsrc_base, item)
                    if os.path.isdir(item_path) and item not in [
                        "wip",
                        "distfiles",
                        "packages",
                    ]:
                        # Check if it looks like a custom pkgsrc overlay
                        if os.path.exists(os.path.join(item_path, "Makefile")):
                            repositories.append(
                                {
                                    "name": item,
                                    "type": "pkgsrc custom",
                                    "url": "",
                                    "enabled": True,
                                    "file_path": item_path,
                                }
                            )
        except Exception as error:
            self.logger.error(_("Error listing NetBSD repositories: %s"), error)

        return repositories

    async def add_netbsd_repository(self, repo_name: str, url: str) -> Dict[str, Any]:
        """Add a pkgsrc repository on NetBSD."""
        try:
            if not url:
                return {
                    "success": False,
                    "error": _("Repository URL is required for NetBSD pkgsrc"),
                }

            # Clone the repository into /usr/pkgsrc
            target_path = f"/usr/pkgsrc/{repo_name}"

            if os.path.exists(target_path):
                return {
                    "success": False,
                    "error": _("Repository directory already exists: %s") % target_path,
                }

            # Clone using git
            command = f"git clone {url} {target_path}"
            result = await self.agent_instance.system_ops.execute_shell_command(
                {"command": command}
            )

            self.logger.debug(
                "git clone command result: success=%s, exit_code=%s, stdout=%s, stderr=%s",
                result.get("success"),
                result.get("exit_code"),
                result.get("result", {}).get("stdout", "")[:200],
                result.get("result", {}).get("stderr", "")[:200],
            )

            if result["success"]:
                self.logger.info("Repository %s cloned successfully", repo_name)
                return {
                    "success": True,
                    "result": _("Repository cloned successfully"),
                    "output": result["result"]["stdout"],
                }

            self.logger.error(
                "Failed to clone repository %s: %s",
                repo_name,
                result["result"].get("stderr", ""),
            )
            return {
                "success": False,
                "error": _("Failed to clone repository: %s")
                % result["result"]["stderr"],
                "output": result["result"]["stderr"],
            }
        except Exception as error:
            self.logger.error(_("Error adding NetBSD repository: %s"), error)
            return {"success": False, "error": str(error)}
