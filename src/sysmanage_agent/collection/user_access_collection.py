"""
User and group access collection module for SysManage Agent.
Handles cross-platform collection of local user accounts and groups.
"""

import json
import logging
import platform
import subprocess  # nosec B404
from typing import Any, Dict, List

# Unix-only imports - conditionally imported based on platform
try:
    import grp
    import pwd
except ImportError:
    # Windows doesn't have pwd/grp modules
    pwd = None
    grp = None


_LOG_FAILED_GROUP_MEMBERSHIPS = "Failed to get group memberships for user %s: %s"


class UserAccessCollector:
    """Collects user accounts and groups across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system_platform = platform.system()

    def get_user_accounts(self) -> List[Dict[str, Any]]:
        """Get list of local user accounts based on platform."""
        if self.system_platform == "Linux":
            return self._get_linux_users()
        if self.system_platform == "Darwin":
            return self._get_macos_users()
        if self.system_platform == "Windows":
            return self._get_windows_users()
        if self.system_platform in ["FreeBSD", "OpenBSD", "NetBSD"]:
            return self._get_bsd_users()

        self.logger.warning(
            "Unsupported platform for user collection: %s", self.system_platform
        )
        return []

    def get_user_groups(self) -> List[Dict[str, Any]]:
        """Get list of local user groups based on platform."""
        if self.system_platform == "Linux":
            return self._get_linux_groups()
        if self.system_platform == "Darwin":
            return self._get_macos_groups()
        if self.system_platform == "Windows":
            return self._get_windows_groups()
        if self.system_platform in ["FreeBSD", "OpenBSD", "NetBSD"]:
            return self._get_bsd_groups()

        self.logger.warning(
            "Unsupported platform for group collection: %s", self.system_platform
        )
        return []

    def _collect_unix_group_names(self, username, primary_gid):
        """Collect group memberships for a Unix user via the grp module.

        Returns a list of group names including supplementary and primary groups.
        """
        if grp is None:
            return []
        group_names = []
        try:
            for group in grp.getgrall():
                if username in group.gr_mem:
                    group_names.append(group.gr_name)
            try:
                primary_group = grp.getgrgid(primary_gid)
                if primary_group.gr_name not in group_names:
                    group_names.append(primary_group.gr_name)
            except KeyError:
                pass  # Primary group not found
        except Exception as exc:
            self.logger.debug("Failed to get groups for user %s: %s", username, exc)
        return group_names

    def _get_linux_users(self) -> List[Dict[str, Any]]:
        """Get Linux user accounts from /etc/passwd."""
        users = []
        if pwd is None:
            self.logger.warning("pwd module not available on this platform")
            return users
        try:
            for user in pwd.getpwall():
                group_names = self._collect_unix_group_names(user.pw_name, user.pw_gid)
                users.append(
                    {
                        "username": user.pw_name,
                        "uid": user.pw_uid,
                        "home_directory": user.pw_dir,
                        "shell": user.pw_shell,
                        "is_system_user": user.pw_uid < 1000,
                        "groups": group_names,
                    }
                )
        except Exception as exc:
            self.logger.error("Failed to collect Linux users: %s", exc)

        return users

    def _get_linux_groups(self) -> List[Dict[str, Any]]:
        """Get Linux groups from /etc/group."""
        groups = []
        if grp is None:
            self.logger.warning("grp module not available on this platform")
            return groups
        try:
            for group in grp.getgrall():
                # Determine if it's a system group (typically GID < 1000 for Linux)
                is_system_group = group.gr_gid < 1000

                groups.append(
                    {
                        "group_name": group.gr_name,
                        "gid": group.gr_gid,
                        "is_system_group": is_system_group,
                    }
                )
        except Exception as error:
            self.logger.error("Failed to collect Linux groups: %s", error)

        return groups

    def _read_dscl_attribute(self, record_path, attribute):
        """Read a single attribute from a macOS Directory Services record.

        Returns the last whitespace-delimited token from the output, or None
        if the attribute cannot be read.
        """
        result = subprocess.run(  # nosec B603, B607
            ["dscl", ".", "read", record_path, attribute],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.split()[-1] if result.stdout.strip() else None

    def _collect_macos_group_names(self, username):
        """Collect group memberships for a macOS user via the groups command.

        Returns a list of group names the user belongs to.
        """
        try:
            groups_result = subprocess.run(  # nosec B603, B607
                ["groups", username],
                capture_output=True,
                text=True,
                check=False,
            )
            if groups_result.returncode == 0 and groups_result.stdout.strip():
                return [
                    g.strip() for g in groups_result.stdout.strip().split() if g.strip()
                ]
        except Exception as error:
            self.logger.debug(
                _LOG_FAILED_GROUP_MEMBERSHIPS,
                username,
                error,
            )
        return []

    def _collect_single_macos_user(self, username):
        """Collect details for a single macOS user via dscl.

        Returns a user info dict, or None if the user details cannot be read.
        """
        try:
            uid_str = self._read_dscl_attribute(f"/Users/{username}", "UniqueID")
            uid = int(uid_str) if uid_str is not None else None
            home_dir = self._read_dscl_attribute(
                f"/Users/{username}", "NFSHomeDirectory"
            )
            shell = self._read_dscl_attribute(f"/Users/{username}", "UserShell")

            return {
                "username": username,
                "uid": uid,
                "home_directory": home_dir,
                "shell": shell,
                "is_system_user": uid is not None and uid < 500,
                "groups": self._collect_macos_group_names(username),
            }
        except subprocess.CalledProcessError as error:
            self.logger.debug("Failed to get details for user %s: %s", username, error)
            return None

    def _collect_macos_users_pwd_fallback(self):
        """Collect macOS users via the pwd module as a fallback.

        Used when the dscl command is not available or fails.
        """
        users = []
        if pwd is None:
            return users
        try:
            for user in pwd.getpwall():
                group_names = self._collect_unix_group_names(user.pw_name, user.pw_gid)
                users.append(
                    {
                        "username": user.pw_name,
                        "uid": user.pw_uid,
                        "home_directory": user.pw_dir,
                        "shell": user.pw_shell,
                        "is_system_user": user.pw_uid < 500,
                        "groups": group_names,
                    }
                )
        except Exception as pwd_error:
            self.logger.error("Fallback pwd collection also failed: %s", pwd_error)
        return users

    def _get_macos_users(self) -> List[Dict[str, Any]]:
        """Get macOS user accounts using dscl command."""
        users = []
        try:
            result = subprocess.run(  # nosec B603, B607
                ["dscl", ".", "list", "/Users"],
                capture_output=True,
                text=True,
                check=True,
            )

            for username in result.stdout.strip().split("\n"):
                if not username.strip():
                    continue
                user_info = self._collect_single_macos_user(username)
                if user_info is not None:
                    users.append(user_info)

        except Exception as error:
            self.logger.error("Failed to collect macOS users: %s", error)
            users = self._collect_macos_users_pwd_fallback()

        return users

    def _collect_single_macos_group(self, group_name):
        """Collect details for a single macOS group via dscl.

        Returns a group info dict, or None if the group details cannot be read.
        """
        try:
            gid_str = self._read_dscl_attribute(
                f"/Groups/{group_name}", "PrimaryGroupID"
            )
            gid = int(gid_str) if gid_str is not None else None
            return {
                "group_name": group_name,
                "gid": gid,
                "is_system_group": gid is not None and gid < 500,
            }
        except subprocess.CalledProcessError as error:
            self.logger.debug(
                "Failed to get details for group %s: %s", group_name, error
            )
            return None

    def _collect_macos_groups_grp_fallback(self):
        """Collect macOS groups via the grp module as a fallback.

        Used when the dscl command is not available or fails.
        """
        groups = []
        if grp is None:
            return groups
        try:
            for group in grp.getgrall():
                groups.append(
                    {
                        "group_name": group.gr_name,
                        "gid": group.gr_gid,
                        "is_system_group": group.gr_gid < 500,
                    }
                )
        except Exception as grp_error:
            self.logger.error("Fallback grp collection also failed: %s", grp_error)
        return groups

    def _get_macos_groups(self) -> List[Dict[str, Any]]:
        """Get macOS groups using dscl command."""
        groups = []
        try:
            result = subprocess.run(  # nosec B603, B607
                ["dscl", ".", "list", "/Groups"],
                capture_output=True,
                text=True,
                check=True,
            )

            for group_name in result.stdout.strip().split("\n"):
                if not group_name.strip():
                    continue
                group_info = self._collect_single_macos_group(group_name)
                if group_info is not None:
                    groups.append(group_info)

        except Exception as error:
            self.logger.error("Failed to collect macOS groups: %s", error)
            groups = self._collect_macos_groups_grp_fallback()

        return groups

    @staticmethod
    def _detect_windows_system_user(sid, username):
        """Determine whether a Windows user is a system account.

        Uses the SID and username to match well-known system service accounts,
        well-known RIDs, and known system account names.
        """
        _system_usernames = frozenset(
            ["Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount"]
        )
        _well_known_system_rids = frozenset([500, 501, 502, 503, 504, 505, 506])

        if sid.startswith(("S-1-5-18", "S-1-5-19", "S-1-5-20")):
            return True
        if username.startswith("NT "):
            return True
        if sid.startswith("S-1-5-21-") and sid.count("-") >= 6:
            try:
                rid = int(sid.split("-")[-1])
                return rid in _well_known_system_rids or username in _system_usernames
            except (ValueError, IndexError):
                return username in _system_usernames
        return False

    def _collect_windows_group_names(self, username):
        """Collect local group memberships for a Windows user via PowerShell.

        Returns a list of group names the user belongs to.
        """
        if not username:
            return []
        try:
            group_result = subprocess.run(  # nosec B603, B607
                [
                    "powershell",
                    "-Command",
                    f"Get-LocalGroup | ForEach-Object {{ try {{ $members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue; if ($members | Where-Object {{$_.Name -like '*\\{username}' -or $_.Name -eq '{username}'}}) {{ $_.Name }} }} catch {{ }} }}",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if group_result.returncode == 0 and group_result.stdout.strip():
                return [
                    line.strip()
                    for line in group_result.stdout.strip().split("\n")
                    if line.strip()
                ]
        except Exception as error:
            self.logger.debug(
                _LOG_FAILED_GROUP_MEMBERSHIPS,
                username,
                error,
            )
        return []

    def _parse_windows_profile_map(self):
        """Build a SID-to-home-directory mapping from Windows user profiles.

        Returns a dict mapping SID strings to local path strings.
        """
        profile_result = subprocess.run(  # nosec B603, B607
            [
                "powershell",
                "-Command",
                "Get-WmiObject -Class Win32_UserProfile | Select-Object SID, LocalPath | ConvertTo-Json -Compress",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        profile_data = json.loads(profile_result.stdout)
        if isinstance(profile_data, dict):
            profile_data = [profile_data]
        return {
            profile.get("SID", ""): profile.get("LocalPath", "")
            for profile in profile_data
        }

    @staticmethod
    def _extract_windows_sid(user):
        """Extract the SID string from a Windows user record.

        Handles both dict and string representations of the SID field.
        """
        sid_field = user.get("SID")
        if isinstance(sid_field, dict):
            return sid_field.get("Value", "")
        return user.get("SID", "")

    def _get_windows_users(self) -> List[Dict[str, Any]]:
        """Get Windows user accounts using WMI/PowerShell."""
        users = []
        try:
            result = subprocess.run(  # nosec B603, B607
                [
                    "powershell",
                    "-Command",
                    "Get-LocalUser | Select-Object Name, Enabled, Description, SID | ConvertTo-Json -Compress",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            profile_map = self._parse_windows_profile_map()

            user_data = json.loads(result.stdout)
            if isinstance(user_data, dict):
                user_data = [user_data]

            for user in user_data:
                sid = self._extract_windows_sid(user)
                username = user.get("Name", "")

                users.append(
                    {
                        "username": username,
                        "uid": sid,
                        "home_directory": profile_map.get(sid, None),
                        "shell": None,
                        "is_system_user": self._detect_windows_system_user(
                            sid, username
                        ),
                        "groups": self._collect_windows_group_names(username),
                    }
                )

        except Exception as error:
            self.logger.error("Failed to collect Windows users: %s", error)

        return users

    def _get_windows_groups(self) -> List[Dict[str, Any]]:
        """Get Windows groups using PowerShell."""
        groups = []
        try:
            # Use PowerShell to get local groups
            result = subprocess.run(  # nosec B603, B607
                [
                    "powershell",
                    "-Command",
                    "Get-LocalGroup | Select-Object Name, Description, SID | ConvertTo-Json -Compress",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            group_data = json.loads(result.stdout)

            # Handle single group case
            if isinstance(group_data, dict):
                group_data = [group_data]

            for group in group_data:
                # System groups typically have well-known SIDs
                sid = (
                    group.get("SID", {}).get("Value", "")
                    if isinstance(group.get("SID"), dict)
                    else group.get("SID", "")
                )
                is_system_group = sid.startswith("S-1-5-32") or group.get(
                    "Name", ""
                ) in [
                    "Administrators",
                    "Users",
                    "Guests",
                    "Power Users",
                    "Backup Operators",
                ]

                groups.append(
                    {
                        "group_name": group.get("Name", ""),
                        "gid": sid,  # Use Windows SID as group identifier instead of GID
                        "is_system_group": is_system_group,
                    }
                )

        except Exception as error:
            self.logger.error("Failed to collect Windows groups: %s", error)

        return groups

    def _get_bsd_users(self) -> List[Dict[str, Any]]:
        """Get BSD user accounts from /etc/passwd using pwd module."""
        users = []
        if pwd is None:
            self.logger.warning("pwd module not available on this platform")
            return users
        try:
            for user in pwd.getpwall():
                group_names = self._collect_unix_group_names(user.pw_name, user.pw_gid)
                users.append(
                    {
                        "username": user.pw_name,
                        "uid": user.pw_uid,
                        "gid": user.pw_gid,
                        "home_directory": user.pw_dir,
                        "shell": user.pw_shell,
                        "gecos": user.pw_gecos,
                        "is_system_user": user.pw_uid < 1000,
                        "groups": group_names,
                    }
                )
        except Exception as error:
            self.logger.error("Failed to collect BSD users: %s", error)

        return users

    def _get_bsd_groups(self) -> List[Dict[str, Any]]:
        """Get BSD groups from /etc/group using grp module."""
        groups = []
        if grp is None:
            self.logger.warning("grp module not available on this platform")
            return groups
        try:
            for group in grp.getgrall():
                # BSD systems typically use GID < 1000 for system groups
                is_system_group = group.gr_gid < 1000

                group_info = {
                    "group_name": group.gr_name,
                    "gid": group.gr_gid,
                    "members": list(group.gr_mem),  # Convert tuple to list
                    "is_system_group": is_system_group,
                }

                groups.append(group_info)

        except Exception as error:
            self.logger.error("Failed to collect BSD groups: %s", error)

        return groups

    def get_access_info(self) -> Dict[str, Any]:
        """Get comprehensive user access information."""
        try:
            users = self.get_user_accounts()
            groups = self.get_user_groups()

            return {
                "users": users,
                "groups": groups,
                "platform": self.system_platform,
                "total_users": len(users),
                "total_groups": len(groups),
                "system_users": sum(1 for u in users if u.get("is_system_user", False)),
                "regular_users": sum(
                    1 for u in users if not u.get("is_system_user", False)
                ),
                "system_groups": sum(
                    1 for g in groups if g.get("is_system_group", False)
                ),
                "regular_groups": sum(
                    1 for g in groups if not g.get("is_system_group", False)
                ),
            }

        except Exception as error:
            self.logger.error("Failed to collect access info: %s", error)
            return {
                "users": [],
                "groups": [],
                "platform": self.system_platform,
                "total_users": 0,
                "total_groups": 0,
                "system_users": 0,
                "regular_users": 0,
                "system_groups": 0,
                "regular_groups": 0,
                "error": str(error),
            }
