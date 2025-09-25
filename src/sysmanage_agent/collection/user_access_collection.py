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

    def _get_linux_users(self) -> List[Dict[str, Any]]:
        """Get Linux user accounts from /etc/passwd."""
        users = []
        if pwd is None:
            self.logger.warning("pwd module not available on this platform")
            return users
        try:  # pylint: disable=too-many-nested-blocks
            for user in pwd.getpwall():
                # Determine if it's a system user (typically UID < 1000 for Linux)
                is_system_user = user.pw_uid < 1000

                # Get user's group memberships
                group_names = []
                if grp is not None:
                    try:
                        # Get all groups and check membership
                        for group in grp.getgrall():
                            if user.pw_name in group.gr_mem:
                                group_names.append(group.gr_name)
                        # Also include user's primary group
                        try:
                            primary_group = grp.getgrgid(user.pw_gid)
                            if primary_group.gr_name not in group_names:
                                group_names.append(primary_group.gr_name)
                        except KeyError:
                            pass  # Primary group not found
                    except Exception as exc:
                        self.logger.debug(
                            "Failed to get groups for user %s: %s", user.pw_name, exc
                        )

                users.append(
                    {
                        "username": user.pw_name,
                        "uid": user.pw_uid,
                        "home_directory": user.pw_dir,
                        "shell": user.pw_shell,
                        "is_system_user": is_system_user,
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
        except Exception as e:
            self.logger.error("Failed to collect Linux groups: %s", e)

        return groups

    def _get_macos_users(self) -> List[Dict[str, Any]]:
        """Get macOS user accounts using dscl command."""
        users = []
        try:
            # Get all users using dscl
            result = subprocess.run(  # nosec B603, B607
                ["dscl", ".", "list", "/Users"],
                capture_output=True,
                text=True,
                check=True,
            )

            for username in result.stdout.strip().split("\n"):
                if not username.strip():
                    continue

                try:
                    # Get user details
                    uid_result = subprocess.run(  # nosec B603, B607
                        ["dscl", ".", "read", f"/Users/{username}", "UniqueID"],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    uid = (
                        int(uid_result.stdout.split()[-1])
                        if uid_result.stdout.strip()
                        else None
                    )

                    home_result = subprocess.run(  # nosec B603, B607
                        ["dscl", ".", "read", f"/Users/{username}", "NFSHomeDirectory"],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    home_dir = (
                        home_result.stdout.split()[-1]
                        if home_result.stdout.strip()
                        else None
                    )

                    shell_result = subprocess.run(  # nosec B603, B607
                        ["dscl", ".", "read", f"/Users/{username}", "UserShell"],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    shell = (
                        shell_result.stdout.split()[-1]
                        if shell_result.stdout.strip()
                        else None
                    )

                    # System users on macOS typically have UID < 500
                    is_system_user = uid is not None and uid < 500

                    # Get user's group memberships using faster method
                    group_names = []
                    try:
                        # Use 'groups' command which is much faster
                        groups_result = subprocess.run(  # nosec B603, B607
                            ["groups", username],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        if (
                            groups_result.returncode == 0
                            and groups_result.stdout.strip()
                        ):
                            # Parse output: "group1 group2 group3" (space-separated groups)
                            groups_line = groups_result.stdout.strip()
                            group_names = [
                                g.strip() for g in groups_line.split() if g.strip()
                            ]
                    except Exception as e:
                        self.logger.debug(
                            "Failed to get group memberships for user %s: %s",
                            username,
                            e,
                        )

                    users.append(
                        {
                            "username": username,
                            "uid": uid,
                            "home_directory": home_dir,
                            "shell": shell,
                            "is_system_user": is_system_user,
                            "groups": group_names,
                        }
                    )

                except subprocess.CalledProcessError as e:
                    self.logger.debug(
                        "Failed to get details for user %s: %s", username, e
                    )
                    continue

        except Exception as e:
            self.logger.error("Failed to collect macOS users: %s", e)
            # Fallback to pwd module if dscl fails
            if pwd is not None:  # pylint: disable=too-many-nested-blocks
                try:  # pylint: disable=too-many-nested-blocks
                    for user in pwd.getpwall():
                        is_system_user = (
                            user.pw_uid < 500
                        )  # macOS system user threshold

                        # Get user's group memberships using grp fallback
                        group_names = []
                        if grp is not None:
                            try:
                                for group in grp.getgrall():
                                    if user.pw_name in group.gr_mem:
                                        group_names.append(group.gr_name)
                                # Also include user's primary group
                                try:
                                    primary_group = grp.getgrgid(user.pw_gid)
                                    if primary_group.gr_name not in group_names:
                                        group_names.append(primary_group.gr_name)
                                except KeyError:
                                    pass
                            except Exception as fallback_exc:
                                self.logger.debug(
                                    "Failed to get groups for user %s: %s",
                                    user.pw_name,
                                    fallback_exc,
                                )

                        users.append(
                            {
                                "username": user.pw_name,
                                "uid": user.pw_uid,
                                "home_directory": user.pw_dir,
                                "shell": user.pw_shell,
                                "is_system_user": is_system_user,
                                "groups": group_names,
                            }
                        )
                except Exception as pwd_error:
                    self.logger.error(
                        "Fallback pwd collection also failed: %s", pwd_error
                    )

        return users

    def _get_macos_groups(self) -> List[Dict[str, Any]]:
        """Get macOS groups using dscl command."""
        groups = []
        try:
            # Get all groups using dscl
            result = subprocess.run(  # nosec B603, B607
                ["dscl", ".", "list", "/Groups"],
                capture_output=True,
                text=True,
                check=True,
            )

            for group_name in result.stdout.strip().split("\n"):
                if not group_name.strip():
                    continue

                try:
                    # Get group GID
                    gid_result = subprocess.run(  # nosec B603, B607
                        [
                            "dscl",
                            ".",
                            "read",
                            f"/Groups/{group_name}",
                            "PrimaryGroupID",
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    gid = (
                        int(gid_result.stdout.split()[-1])
                        if gid_result.stdout.strip()
                        else None
                    )

                    # System groups on macOS typically have GID < 500
                    is_system_group = gid is not None and gid < 500

                    groups.append(
                        {
                            "group_name": group_name,
                            "gid": gid,
                            "is_system_group": is_system_group,
                        }
                    )

                except subprocess.CalledProcessError as e:
                    self.logger.debug(
                        "Failed to get details for group %s: %s", group_name, e
                    )
                    continue

        except Exception as e:
            self.logger.error("Failed to collect macOS groups: %s", e)
            # Fallback to grp module if dscl fails
            if grp is not None:
                try:
                    for group in grp.getgrall():
                        is_system_group = (
                            group.gr_gid < 500
                        )  # macOS system group threshold
                        groups.append(
                            {
                                "group_name": group.gr_name,
                                "gid": group.gr_gid,
                                "is_system_group": is_system_group,
                            }
                        )
                except Exception as grp_error:
                    self.logger.error(
                        "Fallback grp collection also failed: %s", grp_error
                    )

        return groups

    def _get_windows_users(self) -> List[Dict[str, Any]]:
        """Get Windows user accounts using WMI/PowerShell."""
        users = []
        try:
            # Use PowerShell to get local users
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

            # Get user profiles separately
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

            # Parse profile data
            profile_data = json.loads(profile_result.stdout)
            if isinstance(profile_data, dict):
                profile_data = [profile_data]

            # Create a mapping of SID to LocalPath
            profile_map = {
                profile.get("SID", ""): profile.get("LocalPath", "")
                for profile in profile_data
            }

            user_data = json.loads(result.stdout)

            # Handle single user case (PowerShell returns dict instead of list)
            if isinstance(user_data, dict):
                user_data = [user_data]

            for user in user_data:
                # Windows doesn't have traditional UID, but we can use SID
                # System accounts typically have well-known SIDs starting with S-1-5-
                sid = (
                    user.get("SID", {}).get("Value", "")
                    if isinstance(user.get("SID"), dict)
                    else user.get("SID", "")
                )
                # Determine if it's a system user based on Windows RID patterns
                # System users have well-known RIDs < 1000 or specific patterns
                is_system_user = False
                username = user.get("Name", "")

                # Check for well-known system service accounts
                if sid.startswith(("S-1-5-18", "S-1-5-19", "S-1-5-20")) or username.startswith("NT "):
                    is_system_user = True
                # Check for local domain users with well-known RIDs
                elif sid.startswith("S-1-5-21-") and sid.count("-") >= 6:
                    # Extract RID (last part after final hyphen)
                    try:
                        rid = int(sid.split("-")[-1])
                        # Well-known local account RIDs that are considered system accounts:
                        # 500=Administrator, 501=Guest, 502=KRBTGT, 503=DefaultAccount, etc.
                        # But NOT all RIDs < 1000 are system accounts - some are regular users
                        system_usernames = [
                            "Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount"
                        ]
                        well_known_system_rids = [500, 501, 502, 503, 504, 505, 506]  # Specific system RIDs
                        is_system_user = (rid in well_known_system_rids) or (username in system_usernames)
                    except (ValueError, IndexError):
                        # If we can't parse the RID, default based on username patterns
                        is_system_user = username in [
                            "Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount"
                        ]

                # Get user's group memberships
                group_names = []
                group_result = None
                try:
                    # Get all local groups, then check if user is a member of each
                    username = user.get("Name", "")
                    if username:
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

                    if (
                        group_result
                        and group_result.returncode == 0
                        and group_result.stdout.strip()
                    ):
                        group_names = [
                            line.strip()
                            for line in group_result.stdout.strip().split("\n")
                            if line.strip()
                        ]
                except Exception as e:
                    self.logger.debug(
                        "Failed to get group memberships for user %s: %s",
                        user.get("Name", ""),
                        e,
                    )

                # Get home directory from profile mapping
                home_directory = profile_map.get(sid, None)

                users.append(
                    {
                        "username": user.get("Name", ""),
                        "uid": sid,  # Use Windows SID as identifier instead of Unix UID
                        "home_directory": home_directory,  # From Win32_UserProfile mapping
                        "shell": None,  # Windows doesn't use shells in the same way
                        "is_system_user": is_system_user,
                        "groups": group_names,
                    }
                )

        except Exception as e:
            self.logger.error("Failed to collect Windows users: %s", e)

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

        except Exception as e:
            self.logger.error("Failed to collect Windows groups: %s", e)

        return groups

    def _get_bsd_users(self) -> List[Dict[str, Any]]:
        """Get BSD user accounts from /etc/passwd using pwd module."""
        users = []
        if pwd is None:
            self.logger.warning("pwd module not available on this platform")
            return users
        try:  # pylint: disable=too-many-nested-blocks
            for user in pwd.getpwall():
                # BSD systems typically use UID < 1000 for system users
                is_system_user = user.pw_uid < 1000

                # Get user's group memberships
                group_names = []
                if grp is not None:
                    try:
                        # Get all groups and check membership
                        for group in grp.getgrall():
                            if user.pw_name in group.gr_mem:
                                group_names.append(group.gr_name)
                        # Also include user's primary group
                        try:
                            primary_group = grp.getgrgid(user.pw_gid)
                            if primary_group.gr_name not in group_names:
                                group_names.append(primary_group.gr_name)
                        except KeyError:
                            pass
                    except Exception as e:
                        self.logger.debug(
                            "Failed to get group memberships for user %s: %s",
                            user.pw_name,
                            e,
                        )

                user_info = {
                    "username": user.pw_name,
                    "uid": user.pw_uid,
                    "gid": user.pw_gid,
                    "home_directory": user.pw_dir,
                    "shell": user.pw_shell,
                    "gecos": user.pw_gecos,  # Real name/comment field
                    "is_system_user": is_system_user,
                    "groups": group_names,
                }

                users.append(user_info)

        except Exception as e:
            self.logger.error("Failed to collect BSD users: %s", e)

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

        except Exception as e:
            self.logger.error("Failed to collect BSD groups: %s", e)

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

        except Exception as e:
            self.logger.error("Failed to collect access info: %s", e)
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
                "error": str(e),
            }
