"""
Comprehensive unit tests for src.sysmanage_agent.collection.user_access_collection module.
Tests additional edge cases, error handling, and platform-specific functionality.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-lines

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.sysmanage_agent.collection.user_access_collection import UserAccessCollector


class TestUserAccessCollectorGetAccessInfo:
    """Test cases for get_access_info method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_access_info_success(self, mock_platform):
        """Test get_access_info returns comprehensive data."""
        mock_platform.return_value = "Linux"
        collector = UserAccessCollector()

        with (
            patch.object(collector, "get_user_accounts") as mock_users,
            patch.object(collector, "get_user_groups") as mock_groups,
        ):
            mock_users.return_value = [
                {"username": "root", "uid": 0, "is_system_user": True},
                {"username": "testuser", "uid": 1001, "is_system_user": False},
                {"username": "daemon", "uid": 2, "is_system_user": True},
            ]
            mock_groups.return_value = [
                {"group_name": "root", "gid": 0, "is_system_group": True},
                {"group_name": "users", "gid": 100, "is_system_group": True},
                {"group_name": "testgroup", "gid": 1001, "is_system_group": False},
            ]

            result = collector.get_access_info()

            assert result["platform"] == "Linux"
            assert result["total_users"] == 3
            assert result["total_groups"] == 3
            assert result["system_users"] == 2
            assert result["regular_users"] == 1
            assert result["system_groups"] == 2
            assert result["regular_groups"] == 1
            assert len(result["users"]) == 3
            assert len(result["groups"]) == 3

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_access_info_empty_data(self, mock_platform):
        """Test get_access_info with no users or groups."""
        mock_platform.return_value = "Linux"
        collector = UserAccessCollector()

        with (
            patch.object(collector, "get_user_accounts") as mock_users,
            patch.object(collector, "get_user_groups") as mock_groups,
        ):
            mock_users.return_value = []
            mock_groups.return_value = []

            result = collector.get_access_info()

            assert result["total_users"] == 0
            assert result["total_groups"] == 0
            assert result["system_users"] == 0
            assert result["regular_users"] == 0
            assert result["system_groups"] == 0
            assert result["regular_groups"] == 0

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_access_info_exception_handling(self, mock_platform):
        """Test get_access_info handles exceptions gracefully."""
        mock_platform.return_value = "Linux"
        collector = UserAccessCollector()

        with patch.object(
            collector, "get_user_accounts", side_effect=Exception("Database error")
        ):
            result = collector.get_access_info()

            assert result["total_users"] == 0
            assert result["total_groups"] == 0
            assert "error" in result
            assert "Database error" in result["error"]


class TestUserAccessCollectorMacOSFallback:
    """Test cases for macOS fallback methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_collect_macos_users_pwd_fallback_success(self, mock_grp, mock_pwd):
        """Test macOS pwd fallback collects users correctly."""
        mock_user = SimpleNamespace(
            pw_name="macuser",
            pw_uid=501,
            pw_dir="/Users/macuser",
            pw_shell="/bin/zsh",
            pw_gid=20,
        )
        mock_pwd.getpwall.return_value = [mock_user]

        # Mock group data
        mock_group = SimpleNamespace(gr_name="staff", gr_mem=["macuser"])
        mock_grp.getgrall.return_value = [mock_group]
        mock_grp.getgrgid.return_value = SimpleNamespace(gr_name="primarygroup")

        result = self.collector._collect_macos_users_pwd_fallback()

        assert len(result) == 1
        assert result[0]["username"] == "macuser"
        assert result[0]["uid"] == 501
        assert result[0]["home_directory"] == "/Users/macuser"
        assert result[0]["shell"] == "/bin/zsh"
        assert result[0]["is_system_user"] is False  # UID >= 500

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_collect_macos_users_pwd_fallback_system_user(self, mock_grp, mock_pwd):
        """Test macOS pwd fallback correctly identifies system users (UID < 500)."""
        mock_user = SimpleNamespace(
            pw_name="_www",
            pw_uid=70,
            pw_dir="/var/empty",
            pw_shell="/usr/bin/false",
            pw_gid=70,
        )
        mock_pwd.getpwall.return_value = [mock_user]
        mock_grp.getgrall.return_value = []
        mock_grp.getgrgid.side_effect = KeyError("Group not found")

        result = self.collector._collect_macos_users_pwd_fallback()

        assert len(result) == 1
        assert result[0]["is_system_user"] is True  # UID < 500

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd", None)
    def test_collect_macos_users_pwd_fallback_no_pwd_module(self):
        """Test macOS pwd fallback when pwd module is not available."""
        result = self.collector._collect_macos_users_pwd_fallback()
        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    def test_collect_macos_users_pwd_fallback_exception(self, mock_pwd):
        """Test macOS pwd fallback handles exceptions."""
        mock_pwd.getpwall.side_effect = Exception("Permission denied")

        result = self.collector._collect_macos_users_pwd_fallback()
        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_collect_macos_groups_grp_fallback_success(self, mock_grp):
        """Test macOS grp fallback collects groups correctly."""
        mock_group = SimpleNamespace(
            gr_name="admin", gr_gid=80, gr_mem=["root", "user"]
        )
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._collect_macos_groups_grp_fallback()

        assert len(result) == 1
        assert result[0]["group_name"] == "admin"
        assert result[0]["gid"] == 80
        assert result[0]["is_system_group"] is True  # GID < 500

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_collect_macos_groups_grp_fallback_regular_group(self, mock_grp):
        """Test macOS grp fallback identifies regular groups (GID >= 500)."""
        mock_group = SimpleNamespace(
            gr_name="developers", gr_gid=501, gr_mem=["user1", "user2"]
        )
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._collect_macos_groups_grp_fallback()

        assert len(result) == 1
        assert result[0]["is_system_group"] is False  # GID >= 500

    @patch("src.sysmanage_agent.collection.user_access_collection.grp", None)
    def test_collect_macos_groups_grp_fallback_no_grp_module(self):
        """Test macOS grp fallback when grp module is not available."""
        result = self.collector._collect_macos_groups_grp_fallback()
        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_collect_macos_groups_grp_fallback_exception(self, mock_grp):
        """Test macOS grp fallback handles exceptions."""
        mock_grp.getgrall.side_effect = Exception("Permission denied")

        result = self.collector._collect_macos_groups_grp_fallback()
        assert not result


class TestUserAccessCollectorMacOSDetails:
    """Test cases for macOS-specific helper methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_read_dscl_attribute_success(self, mock_subprocess):
        """Test reading a dscl attribute successfully."""
        mock_result = Mock()
        mock_result.stdout = "UniqueID: 501\n"
        mock_subprocess.return_value = mock_result

        result = self.collector._read_dscl_attribute("/Users/testuser", "UniqueID")

        assert result == "501"
        mock_subprocess.assert_called_once_with(
            ["dscl", ".", "read", "/Users/testuser", "UniqueID"],
            capture_output=True,
            text=True,
            check=True,
        )

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_read_dscl_attribute_empty_output(self, mock_subprocess):
        """Test reading dscl attribute with empty output."""
        mock_result = Mock()
        mock_result.stdout = "   \n"
        mock_subprocess.return_value = mock_result

        result = self.collector._read_dscl_attribute("/Users/testuser", "UniqueID")

        assert result is None

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_macos_group_names_success(self, mock_subprocess):
        """Test collecting macOS group names successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "admin staff wheel\n"
        mock_subprocess.return_value = mock_result

        result = self.collector._collect_macos_group_names("testuser")

        assert result == ["admin", "staff", "wheel"]

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_macos_group_names_failure(self, mock_subprocess):
        """Test collecting macOS group names when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_subprocess.return_value = mock_result

        result = self.collector._collect_macos_group_names("nonexistent")

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_macos_group_names_exception(self, mock_subprocess):
        """Test collecting macOS group names handles exceptions."""
        mock_subprocess.side_effect = Exception("Command not found")

        result = self.collector._collect_macos_group_names("testuser")

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_single_macos_user_success(self, mock_subprocess):
        """Test collecting a single macOS user's details."""

        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if "UniqueID" in cmd:
                mock_result.stdout = "UniqueID: 502\n"
            elif "NFSHomeDirectory" in cmd:
                mock_result.stdout = "NFSHomeDirectory: /Users/testuser\n"
            elif "UserShell" in cmd:
                mock_result.stdout = "UserShell: /bin/zsh\n"
            elif cmd == ["groups", "testuser"]:
                mock_result.stdout = "admin staff\n"

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._collect_single_macos_user("testuser")

        assert result is not None
        assert result["username"] == "testuser"
        assert result["uid"] == 502
        assert result["home_directory"] == "/Users/testuser"
        assert result["shell"] == "/bin/zsh"
        assert result["is_system_user"] is False

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_single_macos_user_failure(self, mock_subprocess):
        """Test collecting macOS user when dscl command fails."""
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, "dscl")

        result = self.collector._collect_single_macos_user("nonexistent")

        assert result is None

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_single_macos_user_system_user(self, mock_subprocess):
        """Test collecting macOS system user (UID < 500)."""

        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if "UniqueID" in cmd:
                mock_result.stdout = "UniqueID: 0\n"  # root
            elif "NFSHomeDirectory" in cmd:
                mock_result.stdout = "NFSHomeDirectory: /var/root\n"
            elif "UserShell" in cmd:
                mock_result.stdout = "UserShell: /bin/sh\n"
            elif cmd == ["groups", "root"]:
                mock_result.stdout = "wheel\n"

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._collect_single_macos_user("root")

        assert result is not None
        assert result["is_system_user"] is True

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_single_macos_user_none_uid(self, mock_subprocess):
        """Test collecting macOS user with None UID from empty output."""

        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if "UniqueID" in cmd:
                mock_result.stdout = "   \n"  # Empty, returns None
            elif "NFSHomeDirectory" in cmd:
                mock_result.stdout = "NFSHomeDirectory: /Users/testuser\n"
            elif "UserShell" in cmd:
                mock_result.stdout = "UserShell: /bin/zsh\n"
            elif cmd == ["groups", "testuser"]:
                mock_result.stdout = "\n"

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._collect_single_macos_user("testuser")

        assert result is not None
        assert result["uid"] is None
        # When UID is None, is_system_user should be False (since uid < 500 is False)
        assert result["is_system_user"] is False

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_single_macos_group_success(self, mock_subprocess):
        """Test collecting a single macOS group's details."""

        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if "PrimaryGroupID" in cmd:
                mock_result.stdout = "PrimaryGroupID: 501\n"

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._collect_single_macos_group("testgroup")

        assert result is not None
        assert result["group_name"] == "testgroup"
        assert result["gid"] == 501
        assert result["is_system_group"] is False  # GID >= 500

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_single_macos_group_system_group(self, mock_subprocess):
        """Test collecting macOS system group (GID < 500)."""

        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if "PrimaryGroupID" in cmd:
                mock_result.stdout = "PrimaryGroupID: 0\n"  # wheel

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._collect_single_macos_group("wheel")

        assert result is not None
        assert result["is_system_group"] is True

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_single_macos_group_failure(self, mock_subprocess):
        """Test collecting macOS group when dscl command fails."""
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, "dscl")

        result = self.collector._collect_single_macos_group("nonexistent")

        assert result is None

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_collect_single_macos_group_none_gid(self, mock_subprocess):
        """Test collecting macOS group with None GID."""

        def mock_run_side_effect(*_args, **_kwargs):
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = "   \n"  # Empty output
            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._collect_single_macos_group("testgroup")

        assert result is not None
        assert result["gid"] is None
        assert result["is_system_group"] is False


class TestUserAccessCollectorMacOSIntegration:
    """Test macOS user/group collection integration."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_macos_users_empty_usernames(self, mock_subprocess):
        """Test _get_macos_users with empty username lines."""

        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if cmd == ["dscl", ".", "list", "/Users"]:
                mock_result.stdout = "testuser\n\n  \n"
            elif "UniqueID" in cmd:
                mock_result.stdout = "UniqueID: 501\n"
            elif "NFSHomeDirectory" in cmd:
                mock_result.stdout = "NFSHomeDirectory: /Users/testuser\n"
            elif "UserShell" in cmd:
                mock_result.stdout = "UserShell: /bin/zsh\n"
            elif cmd == ["groups", "testuser"]:
                mock_result.stdout = "admin staff\n"

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._get_macos_users()

        # Should only have one user, empty lines skipped
        assert len(result) == 1
        assert result[0]["username"] == "testuser"

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_macos_users_falls_back_on_exception(self, mock_subprocess, mock_pwd):
        """Test _get_macos_users falls back to pwd on exception."""
        mock_subprocess.side_effect = Exception("dscl not found")

        # Mock the fallback
        mock_user = SimpleNamespace(
            pw_name="fallbackuser",
            pw_uid=501,
            pw_dir="/Users/fallbackuser",
            pw_shell="/bin/zsh",
            pw_gid=20,
        )
        mock_pwd.getpwall.return_value = [mock_user]

        with patch.object(
            self.collector, "_collect_unix_group_names", return_value=["staff"]
        ):
            result = self.collector._get_macos_users()

        assert len(result) == 1
        assert result[0]["username"] == "fallbackuser"

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_macos_groups_empty_group_names(self, mock_subprocess):
        """Test _get_macos_groups with empty group name lines."""

        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if cmd == ["dscl", ".", "list", "/Groups"]:
                mock_result.stdout = "admin\n\n  \nstaff\n"
            elif "PrimaryGroupID" in cmd:
                if "/Groups/admin" in str(cmd):
                    mock_result.stdout = "PrimaryGroupID: 80\n"
                else:
                    mock_result.stdout = "PrimaryGroupID: 20\n"

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._get_macos_groups()

        # Should have two groups, empty lines skipped
        assert len(result) == 2

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_macos_groups_falls_back_on_exception(self, mock_subprocess, mock_grp):
        """Test _get_macos_groups falls back to grp on exception."""
        mock_subprocess.side_effect = Exception("dscl not found")

        mock_group = SimpleNamespace(gr_name="fallbackgroup", gr_gid=501, gr_mem=[])
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._get_macos_groups()

        assert len(result) == 1
        assert result[0]["group_name"] == "fallbackgroup"


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
