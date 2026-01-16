"""
Tests for user account operations module.
Tests user and group creation/deletion across different platforms.
"""

# pylint: disable=redefined-outer-name,protected-access,unused-argument

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.user_account_operations import UserAccountOperations


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = Mock()
    agent.update_user_access = AsyncMock()
    return agent


@pytest.fixture
def user_ops(mock_agent):
    """Create a UserAccountOperations instance for testing."""
    return UserAccountOperations(mock_agent)


class TestUserAccountOperationsInit:
    """Tests for UserAccountOperations initialization."""

    def test_init_sets_agent_instance(self, mock_agent):
        """Test that __init__ sets agent instance."""
        ops = UserAccountOperations(mock_agent)
        assert ops.agent == mock_agent

    def test_init_creates_logger(self, mock_agent):
        """Test that __init__ creates logger."""
        ops = UserAccountOperations(mock_agent)
        assert ops.logger is not None

    def test_init_detects_platform(self, mock_agent):
        """Test that __init__ detects platform."""
        with patch("platform.system", return_value="Linux"):
            ops = UserAccountOperations(mock_agent)
            assert ops.system_platform == "Linux"


class TestCreateHostUser:
    """Tests for create_host_user method."""

    @pytest.mark.asyncio
    async def test_create_host_user_no_username(self, user_ops):
        """Test create_host_user without username."""
        result = await user_ops.create_host_user({})
        assert result["success"] is False
        assert "Username is required" in result["error"]

    @pytest.mark.asyncio
    async def test_create_host_user_linux_success(self, user_ops, mock_agent):
        """Test successful Linux user creation."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_create_linux_user", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "User created"}

            result = await user_ops.create_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_create.assert_called_once()
        mock_agent.update_user_access.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_user_macos(self, user_ops, mock_agent):
        """Test macOS user creation."""
        user_ops.system_platform = "Darwin"

        with patch.object(
            user_ops, "_create_macos_user", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "User created"}

            result = await user_ops.create_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_user_windows(self, user_ops, mock_agent):
        """Test Windows user creation."""
        user_ops.system_platform = "Windows"

        with patch.object(
            user_ops, "_create_windows_user", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "User created"}

            result = await user_ops.create_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_user_freebsd(self, user_ops, mock_agent):
        """Test FreeBSD user creation."""
        user_ops.system_platform = "FreeBSD"

        with patch.object(
            user_ops, "_create_freebsd_user", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "User created"}

            result = await user_ops.create_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_user_openbsd(self, user_ops, mock_agent):
        """Test OpenBSD user creation."""
        user_ops.system_platform = "OpenBSD"

        with patch.object(
            user_ops, "_create_openbsd_netbsd_user", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "User created"}

            result = await user_ops.create_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_user_unsupported_platform(self, user_ops):
        """Test user creation on unsupported platform."""
        user_ops.system_platform = "Unknown"

        result = await user_ops.create_host_user({"username": "testuser"})

        assert result["success"] is False
        assert "Unsupported platform" in result["error"]

    @pytest.mark.asyncio
    async def test_create_host_user_exception(self, user_ops):
        """Test user creation with exception."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_create_linux_user", side_effect=Exception("test error")
        ):
            result = await user_ops.create_host_user({"username": "testuser"})

        assert result["success"] is False
        assert "test error" in result["error"]


class TestCreateHostGroup:
    """Tests for create_host_group method."""

    @pytest.mark.asyncio
    async def test_create_host_group_no_group_name(self, user_ops):
        """Test create_host_group without group name."""
        result = await user_ops.create_host_group({})
        assert result["success"] is False
        assert "Group name is required" in result["error"]

    @pytest.mark.asyncio
    async def test_create_host_group_linux_success(self, user_ops, mock_agent):
        """Test successful Linux group creation."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_create_linux_group", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "Group created"}

            result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_create.assert_called_once()
        mock_agent.update_user_access.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_group_unsupported_platform(self, user_ops):
        """Test group creation on unsupported platform."""
        user_ops.system_platform = "Unknown"

        result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is False
        assert "Unsupported platform" in result["error"]


class TestDeleteHostUser:
    """Tests for delete_host_user method."""

    @pytest.mark.asyncio
    async def test_delete_host_user_no_username(self, user_ops):
        """Test delete_host_user without username."""
        result = await user_ops.delete_host_user({})
        assert result["success"] is False
        assert "Username is required" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_host_user_linux_success(self, user_ops, mock_agent):
        """Test successful Linux user deletion."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_delete_linux_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_delete.assert_called_once()
        mock_agent.update_user_access.assert_called_once()


class TestDeleteHostGroup:
    """Tests for delete_host_group method."""

    @pytest.mark.asyncio
    async def test_delete_host_group_no_group_name(self, user_ops):
        """Test delete_host_group without group name."""
        result = await user_ops.delete_host_group({})
        assert result["success"] is False
        assert "Group name is required" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_host_group_linux_success(self, user_ops, mock_agent):
        """Test successful Linux group deletion."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_delete_linux_group", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_delete.assert_called_once()
        mock_agent.update_user_access.assert_called_once()


class TestLinuxUserOperations:
    """Tests for Linux-specific user operations."""

    @pytest.mark.asyncio
    async def test_create_linux_user_basic(self, user_ops):
        """Test basic Linux user creation."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_linux_user({"username": "testuser"})

        assert result["success"] is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "useradd" in cmd
        assert "-m" in cmd  # create home dir by default
        assert "testuser" in cmd

    @pytest.mark.asyncio
    async def test_create_linux_user_with_options(self, user_ops):
        """Test Linux user creation with options."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_linux_user(
                {
                    "username": "testuser",
                    "uid": 1001,
                    "primary_group": "staff",
                    "home_directory": "/home/custom",
                    "shell": "/bin/zsh",
                    "full_name": "Test User",
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd
        assert "1001" in cmd
        assert "-g" in cmd
        assert "staff" in cmd
        assert "-d" in cmd
        assert "/home/custom" in cmd
        assert "-s" in cmd
        assert "/bin/zsh" in cmd
        assert "-c" in cmd
        assert "Test User" in cmd

    @pytest.mark.asyncio
    async def test_create_linux_group(self, user_ops):
        """Test Linux group creation."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group created"}

            result = await user_ops._create_linux_group(
                {
                    "group_name": "testgroup",
                    "gid": 1001,
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "groupadd" in cmd
        assert "-g" in cmd
        assert "1001" in cmd
        assert "testgroup" in cmd

    @pytest.mark.asyncio
    async def test_delete_linux_user_with_default_group(self, user_ops):
        """Test Linux user deletion with default group."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_run.return_value = {"success": True}
                mock_capture.return_value = {"success": True}  # group exists

                result = await user_ops._delete_linux_user(
                    {
                        "username": "testuser",
                        "delete_default_group": True,
                    }
                )

        assert result["success"] is True


class TestMacOSUserOperations:
    """Tests for macOS-specific user operations."""

    @pytest.mark.asyncio
    async def test_get_next_macos_uid(self, user_ops):
        """Test getting next available macOS UID."""
        with patch.object(
            user_ops, "_run_command_capture", new_callable=AsyncMock
        ) as mock_capture:
            mock_capture.return_value = {
                "success": True,
                "output": "user1 501\nuser2 502\nuser3 503",
            }

            uid = await user_ops._get_next_macos_uid()

        assert uid == 504

    @pytest.mark.asyncio
    async def test_get_next_macos_uid_empty(self, user_ops):
        """Test getting next macOS UID with no users."""
        with patch.object(
            user_ops, "_run_command_capture", new_callable=AsyncMock
        ) as mock_capture:
            mock_capture.return_value = {"success": False}

            uid = await user_ops._get_next_macos_uid()

        assert uid == 501

    @pytest.mark.asyncio
    async def test_get_next_macos_gid(self, user_ops):
        """Test getting next available macOS GID."""
        with patch.object(
            user_ops, "_run_command_capture", new_callable=AsyncMock
        ) as mock_capture:
            mock_capture.return_value = {
                "success": True,
                "output": "group1 1000\ngroup2 1001",
            }

            gid = await user_ops._get_next_macos_gid()

        assert gid == 1002


class TestWindowsUserOperations:
    """Tests for Windows-specific user operations."""

    @pytest.mark.asyncio
    async def test_create_windows_user_no_password(self, user_ops):
        """Test Windows user creation without password."""
        result = await user_ops._create_windows_user({"username": "testuser"})

        assert result["success"] is False
        assert "Password is required" in result["error"]

    @pytest.mark.asyncio
    async def test_create_windows_user_basic(self, user_ops):
        """Test basic Windows user creation."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_windows_user(
                {
                    "username": "testuser",
                    "password": "TestPassword123!",
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "net" in cmd
        assert "user" in cmd
        assert "testuser" in cmd
        assert "/add" in cmd

    @pytest.mark.asyncio
    async def test_create_windows_group(self, user_ops):
        """Test Windows group creation."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group created"}

            result = await user_ops._create_windows_group(
                {
                    "group_name": "testgroup",
                    "description": "Test Group",
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "net" in cmd
        assert "localgroup" in cmd
        assert "testgroup" in cmd


class TestFreeBSDUserOperations:
    """Tests for FreeBSD-specific user operations."""

    @pytest.mark.asyncio
    async def test_create_freebsd_user(self, user_ops):
        """Test FreeBSD user creation."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_freebsd_user(
                {
                    "username": "testuser",
                    "uid": 1001,
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "pw" in cmd
        assert "useradd" in cmd
        assert "testuser" in cmd

    @pytest.mark.asyncio
    async def test_create_freebsd_group(self, user_ops):
        """Test FreeBSD group creation."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group created"}

            result = await user_ops._create_freebsd_group(
                {
                    "group_name": "testgroup",
                    "gid": 1001,
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "pw" in cmd
        assert "groupadd" in cmd
        assert "testgroup" in cmd


class TestHelperMethods:
    """Tests for helper methods."""

    @pytest.mark.asyncio
    async def test_run_command_success(self, user_ops):
        """Test successful command execution."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await user_ops._run_command(["echo", "test"], "test command")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_command_failure(self, user_ops):
        """Test failed command execution."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"error message"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await user_ops._run_command(["false"], "test command")

        assert result["success"] is False
        assert "error message" in result["error"]

    @pytest.mark.asyncio
    async def test_run_command_file_not_found(self, user_ops):
        """Test command not found."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("cmd not found"),
        ):
            result = await user_ops._run_command(["nonexistent"], "test command")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_run_command_capture_success(self, user_ops):
        """Test successful command capture."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"output data", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await user_ops._run_command_capture(["echo", "test"])

        assert result["success"] is True
        assert result["output"] == "output data"

    @pytest.mark.asyncio
    async def test_run_command_capture_failure(self, user_ops):
        """Test failed command capture."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await user_ops._run_command_capture(["false"])

        assert result["success"] is False
        assert "error" in result["error"]
