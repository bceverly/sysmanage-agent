# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for src.sysmanage_agent.collection.user_access_collection module.
Tests additional edge cases, error handling, and platform-specific functionality.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

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
