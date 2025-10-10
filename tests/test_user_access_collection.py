"""
Unit tests for src.sysmanage_agent.collection.user_access_collection module.
Tests user and group collection across different platforms.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.sysmanage_agent.collection.user_access_collection import UserAccessCollector


class TestUserAccessCollector:  # pylint: disable=too-many-public-methods
    """Test cases for UserAccessCollector class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = UserAccessCollector()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_init(self, mock_platform):
        """Test UserAccessCollector initialization."""
        mock_platform.return_value = "Linux"

        collector = UserAccessCollector()

        assert collector.logger is not None
        assert collector.system_platform == "Linux"

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_accounts_linux(self, mock_platform):
        """Test get_user_accounts for Linux platform."""
        mock_platform.return_value = "Linux"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_linux_users") as mock_linux_users:
            mock_linux_users.return_value = [{"username": "testuser"}]

            result = collector.get_user_accounts()

            assert result == [{"username": "testuser"}]
            mock_linux_users.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_accounts_freebsd(self, mock_platform):
        """Test get_user_accounts for FreeBSD platform."""
        mock_platform.return_value = "FreeBSD"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_bsd_users") as mock_bsd_users:
            mock_bsd_users.return_value = [{"username": "bsduser"}]

            result = collector.get_user_accounts()

            assert result == [{"username": "bsduser"}]
            mock_bsd_users.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_accounts_unsupported(self, mock_platform):
        """Test get_user_accounts for unsupported platform."""
        mock_platform.return_value = "UnsupportedOS"
        collector = UserAccessCollector()

        result = collector.get_user_accounts()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_groups_linux(self, mock_platform):
        """Test get_user_groups for Linux platform."""
        mock_platform.return_value = "Linux"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_linux_groups") as mock_linux_groups:
            mock_linux_groups.return_value = [{"group_name": "testgroup"}]

            result = collector.get_user_groups()

            assert result == [{"group_name": "testgroup"}]
            mock_linux_groups.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_groups_darwin(self, mock_platform):
        """Test get_user_groups for macOS platform."""
        mock_platform.return_value = "Darwin"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_macos_groups") as mock_macos_groups:
            mock_macos_groups.return_value = [{"group_name": "macgroup"}]

            result = collector.get_user_groups()

            assert result == [{"group_name": "macgroup"}]
            mock_macos_groups.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_groups_windows(self, mock_platform):
        """Test get_user_groups for Windows platform."""
        mock_platform.return_value = "Windows"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_windows_groups") as mock_windows_groups:
            mock_windows_groups.return_value = [{"group_name": "wingroup"}]

            result = collector.get_user_groups()

            assert result == [{"group_name": "wingroup"}]
            mock_windows_groups.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_groups_freebsd(self, mock_platform):
        """Test get_user_groups for FreeBSD platform."""
        mock_platform.return_value = "FreeBSD"
        collector = UserAccessCollector()

        with patch.object(collector, "_get_bsd_groups") as mock_bsd_groups:
            mock_bsd_groups.return_value = [{"group_name": "bsdgroup"}]

            result = collector.get_user_groups()

            assert result == [{"group_name": "bsdgroup"}]
            mock_bsd_groups.assert_called_once()

    @patch("src.sysmanage_agent.collection.user_access_collection.platform.system")
    def test_get_user_groups_unsupported(self, mock_platform):
        """Test get_user_groups for unsupported platform."""
        mock_platform.return_value = "UnsupportedOS"
        collector = UserAccessCollector()

        result = collector.get_user_groups()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd", None)
    def test_get_linux_users_no_pwd_module(self):
        """Test _get_linux_users when pwd module is not available."""
        result = self.collector._get_linux_users()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_linux_users_success(self, mock_grp, mock_pwd):
        """Test successful _get_linux_users execution."""
        # Mock user data
        mock_user = SimpleNamespace(
            pw_name="testuser",
            pw_uid=1001,
            pw_dir="/home/testuser",
            pw_shell="/bin/bash",
            pw_gid=1001,
        )
        mock_pwd.getpwall.return_value = [mock_user]

        # Mock group data
        mock_group = SimpleNamespace(gr_name="testgroup", gr_mem=["testuser"])
        mock_primary_group = SimpleNamespace(gr_name="primary_group")
        mock_grp.getgrall.return_value = [mock_group]
        mock_grp.getgrgid.return_value = mock_primary_group

        result = self.collector._get_linux_users()

        assert len(result) == 1
        assert result[0]["username"] == "testuser"
        assert result[0]["uid"] == 1001
        assert result[0]["home_directory"] == "/home/testuser"
        assert result[0]["shell"] == "/bin/bash"
        assert result[0]["is_system_user"] is False
        assert "testgroup" in result[0]["groups"]
        assert "primary_group" in result[0]["groups"]

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_linux_users_system_user(self, mock_grp, mock_pwd):
        """Test _get_linux_users with system user (UID < 1000)."""
        mock_user = SimpleNamespace(
            pw_name="daemon",
            pw_uid=2,
            pw_dir="/",
            pw_shell="/usr/sbin/nologin",
            pw_gid=2,
        )
        mock_pwd.getpwall.return_value = [mock_user]
        mock_grp.getgrall.return_value = []
        mock_grp.getgrgid.side_effect = KeyError("Group not found")

        result = self.collector._get_linux_users()

        assert len(result) == 1
        assert result[0]["is_system_user"] is True

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.grp", None)
    def test_get_linux_users_no_grp_module(self, mock_pwd):
        """Test _get_linux_users when grp module is not available."""
        mock_user = SimpleNamespace(
            pw_name="testuser",
            pw_uid=1001,
            pw_dir="/home/testuser",
            pw_shell="/bin/bash",
            pw_gid=1001,
        )
        mock_pwd.getpwall.return_value = [mock_user]

        result = self.collector._get_linux_users()

        assert len(result) == 1
        assert result[0]["groups"] == []

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_linux_users_exception_handling(self, mock_grp, mock_pwd):
        """Test _get_linux_users with exception during group lookup."""
        mock_user = SimpleNamespace(
            pw_name="testuser",
            pw_uid=1001,
            pw_dir="/home/testuser",
            pw_shell="/bin/bash",
            pw_gid=1001,
        )
        mock_pwd.getpwall.return_value = [mock_user]
        mock_grp.getgrall.side_effect = Exception("Group lookup failed")

        result = self.collector._get_linux_users()

        assert len(result) == 1
        assert result[0]["groups"] == []

    @patch("src.sysmanage_agent.collection.user_access_collection.grp", None)
    def test_get_linux_groups_no_grp_module(self):
        """Test _get_linux_groups when grp module is not available."""
        result = self.collector._get_linux_groups()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_linux_groups_success(self, mock_grp):
        """Test successful _get_linux_groups execution."""
        mock_group = SimpleNamespace(
            gr_name="testgroup", gr_gid=1001, gr_mem=["user1", "user2"]
        )
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._get_linux_groups()

        assert len(result) == 1
        assert result[0]["group_name"] == "testgroup"
        assert result[0]["gid"] == 1001
        assert result[0]["is_system_group"] is False

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_macos_users_success(self, mock_subprocess):
        """Test successful _get_macos_users execution."""

        # Mock multiple subprocess calls for dscl commands
        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if cmd == ["dscl", ".", "list", "/Users"]:
                mock_result.stdout = "testuser\n"
            elif "UniqueID" in cmd:
                mock_result.stdout = "UniqueID: 1001\n"
            elif "NFSHomeDirectory" in cmd:
                mock_result.stdout = "NFSHomeDirectory: /Users/testuser\n"
            elif "UserShell" in cmd:
                mock_result.stdout = "UserShell: /bin/zsh\n"
            elif cmd == ["groups", "testuser"]:
                mock_result.stdout = "admin staff\n"

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._get_macos_users()

        assert len(result) == 1
        assert result[0]["username"] == "testuser"
        assert result[0]["uid"] == 1001
        assert result[0]["home_directory"] == "/Users/testuser"
        assert result[0]["shell"] == "/bin/zsh"
        assert result[0]["groups"] == ["admin", "staff"]

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_macos_users_command_failure(self, mock_subprocess):
        """Test _get_macos_users when command fails."""
        mock_subprocess.return_value.returncode = 1
        mock_subprocess.return_value.stderr = "Command failed"

        result = self.collector._get_macos_users()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd", None)
    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_macos_users_invalid_json(self, mock_subprocess):
        """Test _get_macos_users with invalid dscl output causing exception."""
        mock_subprocess.side_effect = Exception("dscl command failed")

        result = self.collector._get_macos_users()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_macos_groups_success(self, mock_subprocess):
        """Test successful _get_macos_groups execution."""

        # Mock multiple subprocess calls for dscl commands
        def mock_run_side_effect(*args, **_kwargs):
            cmd = args[0]
            mock_result = Mock()
            mock_result.returncode = 0

            if cmd == ["dscl", ".", "list", "/Groups"]:
                mock_result.stdout = "testgroup\n"
            elif "PrimaryGroupID" in cmd:
                mock_result.stdout = "PrimaryGroupID: 1001\n"
            elif "GroupMembership" in cmd:
                mock_result.stdout = "GroupMembership: user1 user2\n"

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._get_macos_groups()

        assert len(result) == 1
        assert result[0]["group_name"] == "testgroup"
        assert result[0]["gid"] == 1001
        assert result[0]["is_system_group"] is False
        # macOS groups structure doesn't include members in the base implementation

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_users_success(self, mock_subprocess):
        """Test successful _get_windows_users execution."""
        mock_user_output = """
        [
            {
                "Name": "testuser",
                "SID": "S-1-5-21-123456789-123456789-123456789-1001",
                "Enabled": true,
                "Description": "Test user account"
            }
        ]
        """

        mock_profile_output = """
        [
            {
                "SID": "S-1-5-21-123456789-123456789-123456789-1001",
                "LocalPath": "C:\\\\Users\\\\testuser"
            }
        ]
        """

        def mock_run_side_effect(*args, **_kwargs):
            mock_result = Mock()
            mock_result.returncode = 0

            # Check if it's the Get-LocalUser command
            if (
                isinstance(args[0], list)
                and len(args[0]) > 2
                and "Get-LocalUser" in str(args[0])
            ):
                mock_result.stdout = mock_user_output
            # Check if it's the Win32_UserProfile command
            elif (
                isinstance(args[0], list)
                and len(args[0]) > 2
                and "Win32_UserProfile" in str(args[0])
            ):
                mock_result.stdout = mock_profile_output
            # Other calls (group memberships) - return empty for simplicity
            else:
                mock_result.stdout = ""

            return mock_result

        mock_subprocess.side_effect = mock_run_side_effect

        result = self.collector._get_windows_users()

        assert len(result) == 1
        assert result[0]["username"] == "testuser"
        assert (
            result[0]["uid"] == "S-1-5-21-123456789-123456789-123456789-1001"
        )  # Updated to expect SID
        assert (
            result[0]["home_directory"] == "C:\\Users\\testuser"
        )  # Updated to expect home directory
        assert result[0]["shell"] is None
        assert result[0]["is_system_user"] is False
        assert result[0]["groups"] == []

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_users_command_failure(self, mock_subprocess):
        """Test _get_windows_users when PowerShell command fails."""
        mock_subprocess.return_value.returncode = 1
        mock_subprocess.return_value.stderr = "PowerShell command failed"

        result = self.collector._get_windows_users()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.subprocess.run")
    def test_get_windows_groups_success(self, mock_subprocess):
        """Test successful _get_windows_groups execution."""
        mock_output = """
        [
            {
                "Name": "Administrators",
                "SID": "S-1-5-32-544",
                "Description": "Administrators group"
            }
        ]
        """
        mock_subprocess.return_value.stdout = mock_output
        mock_subprocess.return_value.returncode = 0

        result = self.collector._get_windows_groups()

        assert len(result) == 1
        assert result[0]["group_name"] == "Administrators"
        assert result[0]["gid"] == "S-1-5-32-544"  # Updated to expect SID
        assert result[0]["is_system_group"] is True

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    @patch("src.sysmanage_agent.collection.user_access_collection.pwd")
    def test_get_bsd_users_success(self, mock_pwd, mock_grp):
        """Test successful _get_bsd_users execution."""
        mock_user = SimpleNamespace(
            pw_name="bsduser",
            pw_uid=1001,
            pw_dir="/usr/home/bsduser",
            pw_shell="/bin/tcsh",
            pw_gid=1001,
            pw_gecos="BSD User",
        )
        mock_pwd.getpwall.return_value = [mock_user]

        # Mock group that doesn't include our test user
        mock_group = SimpleNamespace(
            gr_name="wheel", gr_gid=0, gr_mem=["root", "admin"]
        )
        mock_grp.getgrall.return_value = [mock_group]
        # Mock getgrgid to raise KeyError for user's primary group (gid 1001)
        mock_grp.getgrgid.side_effect = KeyError("Group not found")

        result = self.collector._get_bsd_users()

        assert len(result) == 1
        assert result[0]["username"] == "bsduser"
        assert result[0]["uid"] == 1001
        assert result[0]["gid"] == 1001
        assert result[0]["home_directory"] == "/usr/home/bsduser"
        assert result[0]["shell"] == "/bin/tcsh"
        assert result[0]["gecos"] == "BSD User"
        assert result[0]["is_system_user"] is False
        assert result[0]["groups"] == []

    @patch("src.sysmanage_agent.collection.user_access_collection.grp")
    def test_get_bsd_groups_success(self, mock_grp):
        """Test successful _get_bsd_groups execution."""
        mock_group = SimpleNamespace(
            gr_name="wheel", gr_gid=0, gr_mem=["root", "admin"]
        )
        mock_grp.getgrall.return_value = [mock_group]

        result = self.collector._get_bsd_groups()

        assert len(result) == 1
        assert result[0]["group_name"] == "wheel"
        assert result[0]["gid"] == 0
        assert result[0]["members"] == ["root", "admin"]

    @patch("src.sysmanage_agent.collection.user_access_collection.pwd", None)
    def test_get_bsd_users_no_pwd_module(self):
        """Test _get_bsd_users when pwd module is not available."""
        result = self.collector._get_bsd_users()

        assert not result

    @patch("src.sysmanage_agent.collection.user_access_collection.grp", None)
    def test_get_bsd_groups_no_grp_module(self):
        """Test _get_bsd_groups when grp module is not available."""
        result = self.collector._get_bsd_groups()

        assert not result
