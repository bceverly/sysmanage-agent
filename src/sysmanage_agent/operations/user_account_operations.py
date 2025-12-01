"""
User account and group management operations module for SysManage agent.
Handles creating users and groups on all supported platforms.
"""

import asyncio
import logging
import platform
from typing import Any, Dict

from src.i18n import _


class UserAccountOperations:
    """Handles user account and group management across different platforms."""

    def __init__(self, agent_instance):
        """Initialize user account operations with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self.system_platform = platform.system()

    async def create_host_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new user account on the host.
        After creation, sends an updated user access list to the server.
        """
        username = parameters.get("username")
        if not username:
            return {"success": False, "error": _("Username is required")}

        self.logger.info("Creating user account: %s", username)

        try:
            # Dispatch to platform-specific handler
            if self.system_platform == "Linux":
                result = await self._create_linux_user(parameters)
            elif self.system_platform == "Darwin":
                result = await self._create_macos_user(parameters)
            elif self.system_platform == "Windows":
                result = await self._create_windows_user(parameters)
            elif self.system_platform in ["FreeBSD", "OpenBSD", "NetBSD"]:
                result = await self._create_bsd_user(parameters)
            else:
                return {
                    "success": False,
                    "error": _("Unsupported platform: %s") % self.system_platform,
                }

            # If user was created successfully, send updated user list to server
            if result.get("success"):
                self.logger.info(
                    "User %s created successfully, sending updated user list", username
                )
                await self.agent.update_user_access()

            return result

        except Exception as error:
            self.logger.error("Failed to create user %s: %s", username, error)
            return {"success": False, "error": str(error)}

    async def create_host_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new group on the host.
        After creation, sends an updated user access list to the server.
        """
        group_name = parameters.get("group_name")
        if not group_name:
            return {"success": False, "error": _("Group name is required")}

        self.logger.info("Creating group: %s", group_name)

        try:
            # Dispatch to platform-specific handler
            if self.system_platform == "Linux":
                result = await self._create_linux_group(parameters)
            elif self.system_platform == "Darwin":
                result = await self._create_macos_group(parameters)
            elif self.system_platform == "Windows":
                result = await self._create_windows_group(parameters)
            elif self.system_platform in ["FreeBSD", "OpenBSD", "NetBSD"]:
                result = await self._create_bsd_group(parameters)
            else:
                return {
                    "success": False,
                    "error": _("Unsupported platform: %s") % self.system_platform,
                }

            # If group was created successfully, send updated user list to server
            if result.get("success"):
                self.logger.info(
                    "Group %s created successfully, sending updated user list",
                    group_name,
                )
                await self.agent.update_user_access()

            return result

        except Exception as error:
            self.logger.error("Failed to create group %s: %s", group_name, error)
            return {"success": False, "error": str(error)}

    # ========== Linux User/Group Creation ==========

    async def _create_linux_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user on Linux using useradd."""
        username = parameters["username"]
        cmd = ["useradd"]

        # Add optional parameters
        if parameters.get("uid"):
            cmd.extend(["-u", str(parameters["uid"])])

        if parameters.get("primary_group"):
            cmd.extend(["-g", parameters["primary_group"]])

        if parameters.get("home_directory"):
            cmd.extend(["-d", parameters["home_directory"]])

        if parameters.get("shell"):
            cmd.extend(["-s", parameters["shell"]])

        if parameters.get("full_name"):
            cmd.extend(["-c", parameters["full_name"]])

        if parameters.get("create_home_dir", True):
            cmd.append("-m")

        cmd.append(username)

        return await self._run_command(cmd, f"create user {username}")

    async def _create_linux_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a group on Linux using groupadd."""
        group_name = parameters["group_name"]
        cmd = ["groupadd"]

        if parameters.get("gid"):
            cmd.extend(["-g", str(parameters["gid"])])

        cmd.append(group_name)

        return await self._run_command(cmd, f"create group {group_name}")

    # ========== macOS User/Group Creation ==========

    async def _create_macos_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user on macOS using dscl and createhomedir."""
        username = parameters["username"]
        uid = parameters.get("uid")

        try:
            # If no UID specified, find the next available UID
            if not uid:
                uid = await self._get_next_macos_uid()

            # Create the user record
            user_path = f"/Users/{username}"

            # Create user
            await self._run_dscl_command(["create", user_path])

            # Set UserShell
            shell = parameters.get("shell", "/bin/zsh")
            await self._run_dscl_command(["create", user_path, "UserShell", shell])

            # Set RealName (full name)
            full_name = parameters.get("full_name", username)
            await self._run_dscl_command(["create", user_path, "RealName", full_name])

            # Set UniqueID
            await self._run_dscl_command(["create", user_path, "UniqueID", str(uid)])

            # Set PrimaryGroupID (default to staff group = 20)
            primary_group = parameters.get("primary_group")
            gid = 20  # Default staff group
            if primary_group:
                # Try to look up the group GID
                try:
                    gid_result = await self._run_command_capture(
                        [
                            "dscl",
                            ".",
                            "read",
                            f"/Groups/{primary_group}",
                            "PrimaryGroupID",
                        ]
                    )
                    if gid_result.get("success"):
                        gid = int(gid_result["output"].split()[-1])
                except (ValueError, IndexError):
                    pass
            await self._run_dscl_command(
                ["create", user_path, "PrimaryGroupID", str(gid)]
            )

            # Set NFSHomeDirectory
            home_dir = parameters.get("home_directory", f"/Users/{username}")
            await self._run_dscl_command(
                ["create", user_path, "NFSHomeDirectory", home_dir]
            )

            # Create home directory if requested
            if parameters.get("create_home_dir", True):
                await self._run_command(
                    ["createhomedir", "-c", "-u", username],
                    f"create home directory for {username}",
                )

            return {
                "success": True,
                "message": _("User %s created successfully") % username,
            }

        except Exception as error:
            self.logger.error("Failed to create macOS user %s: %s", username, error)
            return {"success": False, "error": str(error)}

    async def _create_macos_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a group on macOS using dscl."""
        group_name = parameters["group_name"]
        gid = parameters.get("gid")

        try:
            # If no GID specified, find the next available GID
            if not gid:
                gid = await self._get_next_macos_gid()

            group_path = f"/Groups/{group_name}"

            # Create the group
            await self._run_dscl_command(["create", group_path])

            # Set PrimaryGroupID
            await self._run_dscl_command(
                ["create", group_path, "PrimaryGroupID", str(gid)]
            )

            return {
                "success": True,
                "message": _("Group %s created successfully") % group_name,
            }

        except Exception as error:
            self.logger.error("Failed to create macOS group %s: %s", group_name, error)
            return {"success": False, "error": str(error)}

    async def _get_next_macos_uid(self) -> int:
        """Get the next available UID on macOS (starting from 501)."""
        result = await self._run_command_capture(
            ["dscl", ".", "list", "/Users", "UniqueID"]
        )
        if result.get("success"):
            uids = []
            for line in result["output"].strip().split("\n"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        uids.append(int(parts[-1]))
                    except ValueError:
                        continue
            # Find next UID >= 501 (standard macOS user UIDs start at 501)
            next_uid = 501
            while next_uid in uids:
                next_uid += 1
            return next_uid
        return 501

    async def _get_next_macos_gid(self) -> int:
        """Get the next available GID on macOS (starting from 1000)."""
        result = await self._run_command_capture(
            ["dscl", ".", "list", "/Groups", "PrimaryGroupID"]
        )
        if result.get("success"):
            gids = []
            for line in result["output"].strip().split("\n"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        gids.append(int(parts[-1]))
                    except ValueError:
                        continue
            next_gid = 1000
            while next_gid in gids:
                next_gid += 1
            return next_gid
        return 1000

    async def _run_dscl_command(self, args: list) -> Dict[str, Any]:
        """Run a dscl command on macOS."""
        cmd = ["dscl", "."] + args
        return await self._run_command(cmd, f"dscl {' '.join(args)}")

    # ========== Windows User/Group Creation ==========

    async def _create_windows_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user on Windows using net user command."""
        username = parameters["username"]
        password = parameters.get("password")

        if not password:
            return {
                "success": False,
                "error": _("Password is required for Windows user creation"),
            }

        # Build the net user add command
        cmd = ["net", "user", username, password, "/add"]

        # Add full name if provided
        if parameters.get("full_name"):
            cmd.extend(["/fullname:" + parameters["full_name"]])

        # Execute the command
        result = await self._run_command(cmd, f"create user {username}")

        if not result.get("success"):
            return result

        # Handle additional flags
        if parameters.get("password_never_expires"):
            await self._run_command(
                [
                    "wmic",
                    "useraccount",
                    "where",
                    f"name='{username}'",
                    "set",
                    "PasswordExpires=False",
                ],
                "set password never expires",
            )

        if parameters.get("user_must_change_password"):
            await self._run_command(
                ["net", "user", username, "/logonpasswordchg:yes"],
                "set must change password",
            )

        if parameters.get("account_disabled"):
            await self._run_command(
                ["net", "user", username, "/active:no"],
                "disable account",
            )

        return {
            "success": True,
            "message": _("User %s created successfully") % username,
        }

    async def _create_windows_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a group on Windows using net localgroup command."""
        group_name = parameters["group_name"]

        cmd = ["net", "localgroup", group_name, "/add"]

        if parameters.get("description"):
            cmd.extend(["/comment:" + parameters["description"]])

        return await self._run_command(cmd, f"create group {group_name}")

    # ========== BSD User/Group Creation ==========

    async def _create_bsd_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user on BSD systems using pw useradd."""
        username = parameters["username"]
        cmd = ["pw", "useradd", username]

        if parameters.get("uid"):
            cmd.extend(["-u", str(parameters["uid"])])

        if parameters.get("primary_group"):
            cmd.extend(["-g", parameters["primary_group"]])

        if parameters.get("home_directory"):
            cmd.extend(["-d", parameters["home_directory"]])

        if parameters.get("shell"):
            cmd.extend(["-s", parameters["shell"]])

        if parameters.get("full_name"):
            cmd.extend(["-c", parameters["full_name"]])

        if parameters.get("create_home_dir", True):
            cmd.append("-m")

        return await self._run_command(cmd, f"create user {username}")

    async def _create_bsd_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a group on BSD systems using pw groupadd."""
        group_name = parameters["group_name"]
        cmd = ["pw", "groupadd", group_name]

        if parameters.get("gid"):
            cmd.extend(["-g", str(parameters["gid"])])

        return await self._run_command(cmd, f"create group {group_name}")

    # ========== Helper Methods ==========

    async def _run_command(self, cmd: list, description: str) -> Dict[str, Any]:
        """Run a shell command and return the result."""
        try:
            self.logger.debug("Running command: %s", " ".join(cmd))
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                return {
                    "success": True,
                    "message": _("Successfully executed: %s") % description,
                }

            error_msg = stderr.decode().strip() or stdout.decode().strip()
            self.logger.error("Command failed (%s): %s", description, error_msg)
            return {"success": False, "error": error_msg}

        except FileNotFoundError as error:
            self.logger.error("Command not found: %s", cmd[0])
            return {"success": False, "error": str(error)}
        except Exception as error:
            self.logger.error("Command execution failed: %s", error)
            return {"success": False, "error": str(error)}

    async def _run_command_capture(self, cmd: list) -> Dict[str, Any]:
        """Run a command and capture its output."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                return {
                    "success": True,
                    "output": stdout.decode().strip(),
                }

            return {
                "success": False,
                "error": stderr.decode().strip() or stdout.decode().strip(),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}
