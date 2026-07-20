# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for platform-specific user access collection.
Covers Windows, BSD, Linux edge cases, Unix group name collection, and Darwin.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.sysmanage_agent.collection.user_access_collection import UserAccessCollector


class TestWindowsSystemUserDetection:
    """Test cases for Windows system user detection."""

    def test_detect_windows_system_user_local_system(self):
        """Test detecting Local System account (S-1-5-18)."""
        result = UserAccessCollector._detect_windows_system_user("S-1-5-18", "SYSTEM")
        assert result is True

    def test_detect_windows_system_user_local_service(self):
        """Test detecting Local Service account (S-1-5-19)."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-19", "LOCAL SERVICE"
        )
        assert result is True

    def test_detect_windows_system_user_network_service(self):
        """Test detecting Network Service account (S-1-5-20)."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-20", "NETWORK SERVICE"
        )
        assert result is True

    def test_detect_windows_system_user_nt_prefix(self):
        """Test detecting accounts with NT prefix."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-12345-67890-11111-500", "NT AUTHORITY\\SYSTEM"
        )
        assert result is True

    def test_detect_windows_system_user_well_known_rid_500(self):
        """Test detecting Administrator account (RID 500)."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-12345-67890-11111-500", "Administrator"
        )
        assert result is True

    def test_detect_windows_system_user_well_known_rid_501(self):
        """Test detecting Guest account (RID 501)."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-12345-67890-11111-501", "Guest"
        )
        assert result is True

    def test_detect_windows_system_user_well_known_rid_503(self):
        """Test detecting DefaultAccount (RID 503)."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-12345-67890-11111-503", "DefaultAccount"
        )
        assert result is True

    def test_detect_windows_system_user_regular_user(self):
        """Test that regular users are not flagged as system users."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-12345-67890-11111-1001", "JohnDoe"
        )
        assert result is False

    def test_detect_windows_system_user_invalid_rid(self):
        """Test handling of invalid RID in SID."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-12345-67890-11111-invalid", "testuser"
        )
        assert result is False

    def test_detect_windows_system_user_short_sid(self):
        """Test handling of SID with insufficient parts."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-123", "testuser"
        )
        assert result is False

    def test_detect_windows_system_user_by_name_only(self):
        """Test detecting system user by well-known username."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-12345-67890-11111-1001", "Administrator"
        )
        # Should be True because username is in _system_usernames
        assert result is True

    def test_detect_windows_system_user_wdagutilityaccount(self):
        """Test detecting WDAGUtilityAccount."""
        result = UserAccessCollector._detect_windows_system_user(
            "S-1-5-21-12345-67890-11111-504", "WDAGUtilityAccount"
        )
        assert result is True


class TestWindowsHelperMethods:
    """Test cases for Windows helper methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    def test_extract_windows_sid_dict_format(self):
        """Test extracting SID from dict format."""
        user = {"SID": {"Value": "S-1-5-21-123456789-123456789-123456789-1001"}}
        result = UserAccessCollector._extract_windows_sid(user)
        assert result == "S-1-5-21-123456789-123456789-123456789-1001"

    def test_extract_windows_sid_string_format(self):
        """Test extracting SID from string format."""
        user = {"SID": "S-1-5-21-123456789-123456789-123456789-1001"}
        result = UserAccessCollector._extract_windows_sid(user)
        assert result == "S-1-5-21-123456789-123456789-123456789-1001"

    def test_extract_windows_sid_missing_sid(self):
        """Test extracting SID when SID field is missing."""
        user = {"Name": "testuser"}
        result = UserAccessCollector._extract_windows_sid(user)
        assert result == ""

    def test_extract_windows_sid_empty_dict(self):
        """Test extracting SID from empty dict format."""
        user = {"SID": {"Value": ""}}
        result = UserAccessCollector._extract_windows_sid(user)
        assert result == ""

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_parse_windows_profile_map_success(self, mock_subprocess):
        """Test parsing Windows profile map successfully."""
        mock_result = Mock()
        mock_result.stdout = json.dumps(
            [
                {"SID": "S-1-5-21-123-456-789-1001", "LocalPath": "C:\\Users\\user1"},
                {"SID": "S-1-5-21-123-456-789-1002", "LocalPath": "C:\\Users\\user2"},
            ]
        )
        mock_subprocess.return_value = mock_result

        result = self.collector._parse_windows_profile_map()

        assert result["S-1-5-21-123-456-789-1001"] == "C:\\Users\\user1"
        assert result["S-1-5-21-123-456-789-1002"] == "C:\\Users\\user2"

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_parse_windows_profile_map_single_profile(self, mock_subprocess):
        """Test parsing Windows profile map with single profile (dict, not list)."""
        mock_result = Mock()
        mock_result.stdout = json.dumps(
            {"SID": "S-1-5-21-123-456-789-1001", "LocalPath": "C:\\Users\\user1"}
        )
        mock_subprocess.return_value = mock_result

        result = self.collector._parse_windows_profile_map()

        assert result["S-1-5-21-123-456-789-1001"] == "C:\\Users\\user1"

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_windows_group_names_success(self, mock_subprocess):
        """Test collecting Windows group names successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Administrators\nUsers\nRemote Desktop Users\n"
        mock_subprocess.return_value = mock_result

        result = self.collector._collect_windows_group_names("testuser")

        assert result == ["Administrators", "Users", "Remote Desktop Users"]

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_windows_group_names_empty_username(self, mock_subprocess):
        """Test collecting Windows group names with empty username."""
        result = self.collector._collect_windows_group_names("")
        assert not result
        mock_subprocess.assert_not_called()

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_windows_group_names_failure(self, mock_subprocess):
        """Test collecting Windows group names when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_subprocess.return_value = mock_result

        result = self.collector._collect_windows_group_names("testuser")

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_windows_group_names_exception(self, mock_subprocess):
        """Test collecting Windows group names handles exceptions."""
        mock_subprocess.side_effect = Exception("PowerShell not found")

        result = self.collector._collect_windows_group_names("testuser")

        assert not result


class TestWindowsUsersGroups:
    """Test cases for Windows user and group collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_users_single_user_dict(self, mock_subprocess):
        """Test Windows users when PowerShell returns single user as dict."""
        mock_user_output = json.dumps(
            {
                "Name": "testuser",
                "SID": "S-1-5-21-123-456-789-1001",
                "Enabled": True,
                "Description": "Test user",
            }
        )

        mock_profile_output = json.dumps(
            {
                "SID": "S-1-5-21-123-456-789-1001",
                "LocalPath": "C:\\Users\\testuser",
            }
        )

        def mock_run_side_effect(*args, **_kwargs):
            mock_result = Mock()
            mock_result.returncode = 0

            if "Get-LocalUser" in str(args[0]):
                mock_result.stdout = mock_user_output
            elif "Win32_UserProfile" in str(args[0]):
                mock_result.stdout = mock_profile_output
            else:
                mock_result.stdout = ""

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._get_windows_users()

        assert len(result) == 1
        assert result[0]["username"] == "testuser"

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_users_exception(self, mock_subprocess):
        """Test Windows users when exception occurs."""
        mock_subprocess.side_effect = Exception("PowerShell error")

        result = self.collector._get_windows_users()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_users_with_dict_sid(self, mock_subprocess):
        """Test Windows users with SID in dict format."""
        mock_user_output = json.dumps(
            [
                {
                    "Name": "testuser",
                    "SID": {"Value": "S-1-5-21-123-456-789-1001"},
                    "Enabled": True,
                    "Description": "Test user",
                }
            ]
        )

        mock_profile_output = json.dumps(
            [
                {
                    "SID": "S-1-5-21-123-456-789-1001",
                    "LocalPath": "C:\\Users\\testuser",
                }
            ]
        )

        def mock_run_side_effect(*args, **_kwargs):
            mock_result = Mock()
            mock_result.returncode = 0

            if "Get-LocalUser" in str(args[0]):
                mock_result.stdout = mock_user_output
            elif "Win32_UserProfile" in str(args[0]):
                mock_result.stdout = mock_profile_output
            else:
                mock_result.stdout = ""

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._get_windows_users()

        assert len(result) == 1
        assert result[0]["uid"] == "S-1-5-21-123-456-789-1001"

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_groups_single_group_dict(self, mock_subprocess):
        """Test Windows groups when PowerShell returns single group as dict."""
        mock_output = json.dumps(
            {
                "Name": "Users",
                "SID": "S-1-5-32-545",
                "Description": "Users group",
            }
        )
        mock_subprocess.return_value.stdout = mock_output
        mock_subprocess.return_value.returncode = 0

        result = self.collector._get_windows_groups()

        assert len(result) == 1
        assert result[0]["group_name"] == "Users"

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_groups_with_dict_sid(self, mock_subprocess):
        """Test Windows groups with SID in dict format."""
        mock_output = json.dumps(
            [
                {
                    "Name": "Users",
                    "SID": {"Value": "S-1-5-32-545"},
                    "Description": "Users group",
                }
            ]
        )
        mock_subprocess.return_value.stdout = mock_output
        mock_subprocess.return_value.returncode = 0

        result = self.collector._get_windows_groups()

        assert len(result) == 1
        assert result[0]["gid"] == "S-1-5-32-545"

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_groups_system_groups(self, mock_subprocess):
        """Test Windows groups correctly identifies system groups."""
        mock_output = json.dumps(
            [
                {
                    "Name": "Administrators",
                    "SID": "S-1-5-32-544",
                    "Description": "Administrators",
                },
                {"Name": "Users", "SID": "S-1-5-32-545", "Description": "Users"},
                {"Name": "Guests", "SID": "S-1-5-32-546", "Description": "Guests"},
                {
                    "Name": "Power Users",
                    "SID": "S-1-5-32-547",
                    "Description": "Power Users",
                },
                {
                    "Name": "Backup Operators",
                    "SID": "S-1-5-32-551",
                    "Description": "Backup Operators",
                },
                {
                    "Name": "CustomGroup",
                    "SID": "S-1-5-21-123-456-789-1001",
                    "Description": "Custom",
                },
            ]
        )
        mock_subprocess.return_value.stdout = mock_output
        mock_subprocess.return_value.returncode = 0

        result = self.collector._get_windows_groups()

        # All S-1-5-32 groups and well-known names should be system groups
        admin_group = next(g for g in result if g["group_name"] == "Administrators")
        custom_group = next(g for g in result if g["group_name"] == "CustomGroup")

        assert admin_group["is_system_group"] is True
        assert custom_group["is_system_group"] is False

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_groups_exception(self, mock_subprocess):
        """Test Windows groups when exception occurs."""
        mock_subprocess.side_effect = Exception("PowerShell error")

        result = self.collector._get_windows_groups()

        assert not result


class TestBSDPlatformVariants:
    """Test cases for BSD platform variants."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_accounts_openbsd(self, mock_platform):
        """Test get_user_accounts for OpenBSD platform."""
        mock_platform.return_value = "OpenBSD"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_bsd_users") as mock_bsd_users:
            mock_bsd_users.return_value = [{"username": "openbsduser"}]

            result = collector.get_user_accounts()

            assert result == [{"username": "openbsduser"}]
            mock_bsd_users.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_accounts_netbsd(self, mock_platform):
        """Test get_user_accounts for NetBSD platform."""
        mock_platform.return_value = "NetBSD"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_bsd_users") as mock_bsd_users:
            mock_bsd_users.return_value = [{"username": "netbsduser"}]

            result = collector.get_user_accounts()

            assert result == [{"username": "netbsduser"}]
            mock_bsd_users.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_groups_openbsd(self, mock_platform):
        """Test get_user_groups for OpenBSD platform."""
        mock_platform.return_value = "OpenBSD"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_bsd_groups") as mock_bsd_groups:
            mock_bsd_groups.return_value = [{"group_name": "openbsdgroup"}]

            result = collector.get_user_groups()

            assert result == [{"group_name": "openbsdgroup"}]
            mock_bsd_groups.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_groups_netbsd(self, mock_platform):
        """Test get_user_groups for NetBSD platform."""
        mock_platform.return_value = "NetBSD"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_bsd_groups") as mock_bsd_groups:
            mock_bsd_groups.return_value = [{"group_name": "netbsdgroup"}]

            result = collector.get_user_groups()

            assert result == [{"group_name": "netbsdgroup"}]
            mock_bsd_groups.assert_called_once()


class TestBSDUsersGroups:
    """Test cases for BSD user and group collection edge cases."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_bsd_users_exception_handling(self, _mock_grp, mock_pwd):
        """Test _get_bsd_users exception handling."""
        mock_pwd.getpwall.side_effect = Exception("Permission denied")

        result = self.collector._get_bsd_users()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_bsd_groups_exception_handling(self, mock_grp):
        """Test _get_bsd_groups exception handling."""
        mock_grp.getgrall.side_effect = Exception("Permission denied")

        result = self.collector._get_bsd_groups()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_bsd_users_system_user(self, mock_grp, mock_pwd):
        """Test BSD system user detection (UID < 1000)."""
        mock_user = SimpleNamespace(
            pw_name="daemon",
            pw_uid=1,
            pw_dir="/",
            pw_shell="/sbin/nologin",
            pw_gid=1,
            pw_gecos="The Daemon",
        )
        mock_pwd.getpwall.return_value = [mock_user]
        mock_grp.getgrall.return_value = []
        mock_grp.getgrgid.side_effect = KeyError("Group not found")

        result = self.collector._get_bsd_users()

        assert len(result) == 1
        assert result[0]["is_system_user"] is True

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_bsd_groups_system_group(self, mock_grp):
        """Test BSD system group detection (GID < 1000)."""
        mock_group = SimpleNamespace(gr_name="wheel", gr_gid=0, gr_mem=["root"])
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._get_bsd_groups()

        assert len(result) == 1
        assert result[0]["is_system_group"] is True

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_bsd_groups_regular_group(self, mock_grp):
        """Test BSD regular group detection (GID >= 1000)."""
        mock_group = SimpleNamespace(
            gr_name="developers", gr_gid=1001, gr_mem=["user1", "user2"]
        )
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._get_bsd_groups()

        assert len(result) == 1
        assert result[0]["is_system_group"] is False


class TestLinuxUsersGroupsEdgeCases:
    """Test cases for Linux user and group collection edge cases."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    def test_get_linux_users_exception_handling(self, mock_pwd):
        """Test _get_linux_users exception handling."""
        mock_pwd.getpwall.side_effect = Exception("Permission denied")

        result = self.collector._get_linux_users()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_linux_groups_exception_handling(self, mock_grp):
        """Test _get_linux_groups exception handling."""
        mock_grp.getgrall.side_effect = Exception("Permission denied")

        result = self.collector._get_linux_groups()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_linux_groups_system_group(self, mock_grp):
        """Test Linux system group detection (GID < 1000)."""
        mock_group = SimpleNamespace(gr_name="root", gr_gid=0, gr_mem=[])
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._get_linux_groups()

        assert len(result) == 1
        assert result[0]["is_system_group"] is True

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_linux_groups_regular_group(self, mock_grp):
        """Test Linux regular group detection (GID >= 1000)."""
        mock_group = SimpleNamespace(gr_name="developers", gr_gid=1001, gr_mem=[])
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._get_linux_groups()

        assert len(result) == 1
        assert result[0]["is_system_group"] is False


class TestUnixGroupNameCollection:
    """Test cases for Unix group name collection helper."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_collect_unix_group_names_primary_already_in_supplementary(self, mock_grp):
        """Test that primary group is not duplicated if already in supplementary."""
        # User is member of 'users' group (supplementary)
        mock_users_group = SimpleNamespace(gr_name="users", gr_mem=["testuser"])
        mock_grp.getgrall.return_value = [mock_users_group]
        # Primary group is also 'users'
        mock_grp.getgrgid.return_value = SimpleNamespace(gr_name="users")

        result = self.collector._collect_unix_group_names("testuser", 100)

        assert result == ["users"]  # Not duplicated

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_collect_unix_group_names_multiple_groups(self, mock_grp):
        """Test collecting multiple group memberships."""
        mock_group1 = SimpleNamespace(gr_name="admin", gr_mem=["testuser"])
        mock_group2 = SimpleNamespace(gr_name="sudo", gr_mem=["testuser"])
        mock_group3 = SimpleNamespace(gr_name="docker", gr_mem=["otheruser"])
        mock_grp.getgrall.return_value = [mock_group1, mock_group2, mock_group3]
        mock_grp.getgrgid.return_value = SimpleNamespace(gr_name="users")

        result = self.collector._collect_unix_group_names("testuser", 100)

        assert "admin" in result
        assert "sudo" in result
        assert "users" in result  # Primary group
        assert "docker" not in result  # testuser is not a member


class TestDarwinPlatform:
    """Test cases for Darwin (macOS) platform dispatch."""

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_accounts_darwin(self, mock_platform):
        """Test get_user_accounts dispatches to macOS for Darwin."""
        mock_platform.return_value = "Darwin"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_macos_users") as mock_macos_users:
            mock_macos_users.return_value = [{"username": "macuser"}]

            result = collector.get_user_accounts()

            assert result == [{"username": "macuser"}]
            mock_macos_users.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_accounts_windows(self, mock_platform):
        """Test get_user_accounts dispatches correctly for Windows."""
        mock_platform.return_value = "Windows"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_windows_users") as mock_windows_users:
            mock_windows_users.return_value = [{"username": "winuser"}]

            result = collector.get_user_accounts()

            assert result == [{"username": "winuser"}]
            mock_windows_users.assert_called_once()
