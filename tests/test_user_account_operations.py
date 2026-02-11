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
    async def test_create_host_user_netbsd(self, user_ops, mock_agent):
        """Test NetBSD user creation."""
        user_ops.system_platform = "NetBSD"

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

    @pytest.mark.asyncio
    async def test_create_host_user_failure_no_update(self, user_ops, mock_agent):
        """Test that failed user creation does not trigger user access update."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_create_linux_user", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": False, "error": "User exists"}

            result = await user_ops.create_host_user({"username": "testuser"})

        assert result["success"] is False
        mock_agent.update_user_access.assert_not_called()


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
    async def test_create_host_group_macos(self, user_ops, mock_agent):
        """Test macOS group creation."""
        user_ops.system_platform = "Darwin"

        with patch.object(
            user_ops, "_create_macos_group", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "Group created"}

            result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_group_windows(self, user_ops, mock_agent):
        """Test Windows group creation."""
        user_ops.system_platform = "Windows"

        with patch.object(
            user_ops, "_create_windows_group", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "Group created"}

            result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_group_freebsd(self, user_ops, mock_agent):
        """Test FreeBSD group creation."""
        user_ops.system_platform = "FreeBSD"

        with patch.object(
            user_ops, "_create_freebsd_group", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "Group created"}

            result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_group_openbsd(self, user_ops, mock_agent):
        """Test OpenBSD group creation."""
        user_ops.system_platform = "OpenBSD"

        with patch.object(
            user_ops, "_create_openbsd_netbsd_group", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "Group created"}

            result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_group_netbsd(self, user_ops, mock_agent):
        """Test NetBSD group creation."""
        user_ops.system_platform = "NetBSD"

        with patch.object(
            user_ops, "_create_openbsd_netbsd_group", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "message": "Group created"}

            result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_host_group_unsupported_platform(self, user_ops):
        """Test group creation on unsupported platform."""
        user_ops.system_platform = "Unknown"

        result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is False
        assert "Unsupported platform" in result["error"]

    @pytest.mark.asyncio
    async def test_create_host_group_exception(self, user_ops):
        """Test group creation with exception."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_create_linux_group", side_effect=Exception("group error")
        ):
            result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is False
        assert "group error" in result["error"]

    @pytest.mark.asyncio
    async def test_create_host_group_failure_no_update(self, user_ops, mock_agent):
        """Test that failed group creation does not trigger user access update."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_create_linux_group", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": False, "error": "Group exists"}

            result = await user_ops.create_host_group({"group_name": "testgroup"})

        assert result["success"] is False
        mock_agent.update_user_access.assert_not_called()


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

    @pytest.mark.asyncio
    async def test_delete_host_user_macos(self, user_ops, mock_agent):
        """Test macOS user deletion."""
        user_ops.system_platform = "Darwin"

        with patch.object(
            user_ops, "_delete_macos_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_user_windows(self, user_ops, mock_agent):
        """Test Windows user deletion."""
        user_ops.system_platform = "Windows"

        with patch.object(
            user_ops, "_delete_windows_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_user_freebsd(self, user_ops, mock_agent):
        """Test FreeBSD user deletion."""
        user_ops.system_platform = "FreeBSD"

        with patch.object(
            user_ops, "_delete_freebsd_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_user_openbsd(self, user_ops, mock_agent):
        """Test OpenBSD user deletion."""
        user_ops.system_platform = "OpenBSD"

        with patch.object(
            user_ops, "_delete_openbsd_netbsd_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_user_netbsd(self, user_ops, mock_agent):
        """Test NetBSD user deletion."""
        user_ops.system_platform = "NetBSD"

        with patch.object(
            user_ops, "_delete_openbsd_netbsd_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_user_unsupported_platform(self, user_ops):
        """Test user deletion on unsupported platform."""
        user_ops.system_platform = "Unknown"

        result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is False
        assert "Unsupported platform" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_host_user_exception(self, user_ops):
        """Test user deletion with exception."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_delete_linux_user", side_effect=Exception("delete error")
        ):
            result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is False
        assert "delete error" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_host_user_failure_no_update(self, user_ops, mock_agent):
        """Test that failed user deletion does not trigger user access update."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_delete_linux_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": False, "error": "User not found"}

            result = await user_ops.delete_host_user({"username": "testuser"})

        assert result["success"] is False
        mock_agent.update_user_access.assert_not_called()


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

    @pytest.mark.asyncio
    async def test_delete_host_group_macos(self, user_ops, mock_agent):
        """Test macOS group deletion."""
        user_ops.system_platform = "Darwin"

        with patch.object(
            user_ops, "_delete_macos_group", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_group_windows(self, user_ops, mock_agent):
        """Test Windows group deletion."""
        user_ops.system_platform = "Windows"

        with patch.object(
            user_ops, "_delete_windows_group", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_group_freebsd(self, user_ops, mock_agent):
        """Test FreeBSD group deletion."""
        user_ops.system_platform = "FreeBSD"

        with patch.object(
            user_ops, "_delete_freebsd_group", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_group_openbsd(self, user_ops, mock_agent):
        """Test OpenBSD group deletion."""
        user_ops.system_platform = "OpenBSD"

        with patch.object(
            user_ops, "_delete_openbsd_netbsd_group", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_group_netbsd(self, user_ops, mock_agent):
        """Test NetBSD group deletion."""
        user_ops.system_platform = "NetBSD"

        with patch.object(
            user_ops, "_delete_openbsd_netbsd_group", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is True
        mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_host_group_unsupported_platform(self, user_ops):
        """Test group deletion on unsupported platform."""
        user_ops.system_platform = "Unknown"

        result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is False
        assert "Unsupported platform" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_host_group_exception(self, user_ops):
        """Test group deletion with exception."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_delete_linux_group", side_effect=Exception("delete error")
        ):
            result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is False
        assert "delete error" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_host_group_failure_no_update(self, user_ops, mock_agent):
        """Test that failed group deletion does not trigger user access update."""
        user_ops.system_platform = "Linux"

        with patch.object(
            user_ops, "_delete_linux_group", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": False, "error": "Group not found"}

            result = await user_ops.delete_host_group({"group_name": "testgroup"})

        assert result["success"] is False
        mock_agent.update_user_access.assert_not_called()


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
    async def test_create_linux_user_no_home_dir(self, user_ops):
        """Test Linux user creation without home directory."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_linux_user(
                {"username": "testuser", "create_home_dir": False}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "-m" not in cmd

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
    async def test_create_linux_group_without_gid(self, user_ops):
        """Test Linux group creation without explicit GID."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group created"}

            result = await user_ops._create_linux_group({"group_name": "testgroup"})

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "groupadd" in cmd
        assert "-g" not in cmd
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
        assert "deleted successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_linux_user_without_default_group(self, user_ops):
        """Test Linux user deletion without deleting default group."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops._delete_linux_user(
                {
                    "username": "testuser",
                    "delete_default_group": False,
                }
            )

        assert result["success"] is True
        # Should only call userdel, not groupdel
        assert mock_run.call_count == 1

    @pytest.mark.asyncio
    async def test_delete_linux_user_group_not_exists(self, user_ops):
        """Test Linux user deletion when default group does not exist."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_run.return_value = {"success": True, "message": "User deleted"}
                mock_capture.return_value = {"success": False}  # group does not exist

                result = await user_ops._delete_linux_user(
                    {
                        "username": "testuser",
                        "delete_default_group": True,
                    }
                )

        assert result["success"] is True
        # Should only call userdel, not groupdel
        assert mock_run.call_count == 1

    @pytest.mark.asyncio
    async def test_delete_linux_user_group_deletion_fails(self, user_ops):
        """Test Linux user deletion when group deletion fails."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                # First call is userdel (success), second is groupdel (fail)
                mock_run.side_effect = [
                    {"success": True, "message": "User deleted"},
                    {"success": False, "error": "Group in use"},
                ]
                mock_capture.return_value = {"success": True}  # group exists

                result = await user_ops._delete_linux_user(
                    {
                        "username": "testuser",
                        "delete_default_group": True,
                    }
                )

        # User deletion should still succeed even if group deletion fails
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_linux_user_fails(self, user_ops):
        """Test Linux user deletion failure."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": False, "error": "User not found"}

            result = await user_ops._delete_linux_user({"username": "testuser"})

        assert result["success"] is False
        assert "User not found" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_linux_group(self, user_ops):
        """Test Linux group deletion."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops._delete_linux_group({"group_name": "testgroup"})

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "groupdel" in cmd
        assert "testgroup" in cmd


class TestMacOSUserOperations:
    """Tests for macOS-specific user operations."""

    @pytest.mark.asyncio
    async def test_create_macos_user_basic(self, user_ops):
        """Test basic macOS user creation."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_run_command", new_callable=AsyncMock
            ) as mock_run:
                with patch.object(
                    user_ops, "_get_next_macos_uid", new_callable=AsyncMock
                ) as mock_uid:
                    mock_dscl.return_value = {"success": True}
                    mock_run.return_value = {"success": True}
                    mock_uid.return_value = 501

                    result = await user_ops._create_macos_user({"username": "testuser"})

        assert result["success"] is True
        assert "testuser" in result["message"]

    @pytest.mark.asyncio
    async def test_create_macos_user_with_uid(self, user_ops):
        """Test macOS user creation with specified UID."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_run_command", new_callable=AsyncMock
            ) as mock_run:
                mock_dscl.return_value = {"success": True}
                mock_run.return_value = {"success": True}

                result = await user_ops._create_macos_user(
                    {"username": "testuser", "uid": 1001}
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_macos_user_with_primary_group(self, user_ops):
        """Test macOS user creation with primary group."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_run_command", new_callable=AsyncMock
            ) as mock_run:
                with patch.object(
                    user_ops, "_run_command_capture", new_callable=AsyncMock
                ) as mock_capture:
                    with patch.object(
                        user_ops, "_get_next_macos_uid", new_callable=AsyncMock
                    ) as mock_uid:
                        mock_dscl.return_value = {"success": True}
                        mock_run.return_value = {"success": True}
                        mock_uid.return_value = 501
                        mock_capture.return_value = {
                            "success": True,
                            "output": "PrimaryGroupID: 80",
                        }

                        result = await user_ops._create_macos_user(
                            {"username": "testuser", "primary_group": "admin"}
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_macos_user_with_primary_group_lookup_fails(self, user_ops):
        """Test macOS user creation with primary group lookup failure."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_run_command", new_callable=AsyncMock
            ) as mock_run:
                with patch.object(
                    user_ops, "_run_command_capture", new_callable=AsyncMock
                ) as mock_capture:
                    with patch.object(
                        user_ops, "_get_next_macos_uid", new_callable=AsyncMock
                    ) as mock_uid:
                        mock_dscl.return_value = {"success": True}
                        mock_run.return_value = {"success": True}
                        mock_uid.return_value = 501
                        # Group lookup fails
                        mock_capture.return_value = {"success": False}

                        result = await user_ops._create_macos_user(
                            {"username": "testuser", "primary_group": "nonexistent"}
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_macos_user_with_primary_group_invalid_gid(self, user_ops):
        """Test macOS user creation with primary group returning invalid GID."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_run_command", new_callable=AsyncMock
            ) as mock_run:
                with patch.object(
                    user_ops, "_run_command_capture", new_callable=AsyncMock
                ) as mock_capture:
                    with patch.object(
                        user_ops, "_get_next_macos_uid", new_callable=AsyncMock
                    ) as mock_uid:
                        mock_dscl.return_value = {"success": True}
                        mock_run.return_value = {"success": True}
                        mock_uid.return_value = 501
                        # Group lookup returns non-numeric value
                        mock_capture.return_value = {
                            "success": True,
                            "output": "PrimaryGroupID: notanumber",
                        }

                        result = await user_ops._create_macos_user(
                            {"username": "testuser", "primary_group": "testgroup"}
                        )

        # Should still succeed, using default GID
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_macos_user_no_home_dir(self, user_ops):
        """Test macOS user creation without home directory."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_get_next_macos_uid", new_callable=AsyncMock
            ) as mock_uid:
                mock_dscl.return_value = {"success": True}
                mock_uid.return_value = 501

                result = await user_ops._create_macos_user(
                    {"username": "testuser", "create_home_dir": False}
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_macos_user_exception(self, user_ops):
        """Test macOS user creation with exception."""
        with patch.object(
            user_ops, "_run_dscl_command", side_effect=Exception("dscl error")
        ):
            result = await user_ops._create_macos_user({"username": "testuser"})

        assert result["success"] is False
        assert "dscl error" in result["error"]

    @pytest.mark.asyncio
    async def test_create_macos_group_basic(self, user_ops):
        """Test basic macOS group creation."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_get_next_macos_gid", new_callable=AsyncMock
            ) as mock_gid:
                mock_dscl.return_value = {"success": True}
                mock_gid.return_value = 1000

                result = await user_ops._create_macos_group({"group_name": "testgroup"})

        assert result["success"] is True
        assert "testgroup" in result["message"]

    @pytest.mark.asyncio
    async def test_create_macos_group_with_gid(self, user_ops):
        """Test macOS group creation with specified GID."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            mock_dscl.return_value = {"success": True}

            result = await user_ops._create_macos_group(
                {"group_name": "testgroup", "gid": 2000}
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_macos_group_exception(self, user_ops):
        """Test macOS group creation with exception."""
        with patch.object(
            user_ops, "_run_dscl_command", side_effect=Exception("dscl error")
        ):
            result = await user_ops._create_macos_group({"group_name": "testgroup"})

        assert result["success"] is False
        assert "dscl error" in result["error"]

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
    async def test_get_next_macos_uid_with_gaps(self, user_ops):
        """Test getting next available macOS UID with gaps."""
        with patch.object(
            user_ops, "_run_command_capture", new_callable=AsyncMock
        ) as mock_capture:
            mock_capture.return_value = {
                "success": True,
                "output": "user1 501\nuser2 503\nuser3 505",
            }

            uid = await user_ops._get_next_macos_uid()

        # Should still return next sequential
        assert uid == 502

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
    async def test_get_next_macos_uid_invalid_output(self, user_ops):
        """Test getting next macOS UID with invalid output."""
        with patch.object(
            user_ops, "_run_command_capture", new_callable=AsyncMock
        ) as mock_capture:
            mock_capture.return_value = {
                "success": True,
                "output": "invalid output\nno uid here",
            }

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

    @pytest.mark.asyncio
    async def test_get_next_macos_gid_empty(self, user_ops):
        """Test getting next macOS GID with no groups."""
        with patch.object(
            user_ops, "_run_command_capture", new_callable=AsyncMock
        ) as mock_capture:
            mock_capture.return_value = {"success": False}

            gid = await user_ops._get_next_macos_gid()

        assert gid == 1000

    @pytest.mark.asyncio
    async def test_get_next_macos_gid_invalid_output(self, user_ops):
        """Test getting next macOS GID with invalid output."""
        with patch.object(
            user_ops, "_run_command_capture", new_callable=AsyncMock
        ) as mock_capture:
            mock_capture.return_value = {
                "success": True,
                "output": "invalid\nno gid",
            }

            gid = await user_ops._get_next_macos_gid()

        assert gid == 1000

    @pytest.mark.asyncio
    async def test_delete_macos_user_basic(self, user_ops):
        """Test basic macOS user deletion."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_dscl.return_value = {"success": True}
                mock_capture.return_value = {"success": False}  # group does not exist

                result = await user_ops._delete_macos_user({"username": "testuser"})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_macos_user_with_group(self, user_ops):
        """Test macOS user deletion with default group."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_dscl.return_value = {"success": True}
                mock_capture.return_value = {"success": True}  # group exists

                result = await user_ops._delete_macos_user(
                    {"username": "testuser", "delete_default_group": True}
                )

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_macos_user_without_group(self, user_ops):
        """Test macOS user deletion without default group."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            mock_dscl.return_value = {"success": True}

            result = await user_ops._delete_macos_user(
                {"username": "testuser", "delete_default_group": False}
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_macos_user_group_deletion_fails(self, user_ops):
        """Test macOS user deletion when group deletion fails."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                # First call succeeds (delete user), second fails (delete group)
                mock_dscl.side_effect = [
                    {"success": True},
                    {"success": False, "error": "Group in use"},
                ]
                mock_capture.return_value = {"success": True}  # group exists

                result = await user_ops._delete_macos_user(
                    {"username": "testuser", "delete_default_group": True}
                )

        # Should still succeed even if group deletion fails
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_macos_user_dscl_fails(self, user_ops):
        """Test macOS user deletion when dscl fails."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            mock_dscl.return_value = {"success": False, "error": "User not found"}

            result = await user_ops._delete_macos_user({"username": "testuser"})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_macos_user_exception(self, user_ops):
        """Test macOS user deletion with exception."""
        with patch.object(
            user_ops, "_run_dscl_command", side_effect=Exception("dscl error")
        ):
            result = await user_ops._delete_macos_user({"username": "testuser"})

        assert result["success"] is False
        assert "dscl error" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_macos_group(self, user_ops):
        """Test macOS group deletion."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            mock_dscl.return_value = {"success": True}

            result = await user_ops._delete_macos_group({"group_name": "testgroup"})

        assert result["success"] is True
        assert "testgroup" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_macos_group_fails(self, user_ops):
        """Test macOS group deletion failure."""
        with patch.object(
            user_ops, "_run_dscl_command", new_callable=AsyncMock
        ) as mock_dscl:
            mock_dscl.return_value = {"success": False, "error": "Group not found"}

            result = await user_ops._delete_macos_group({"group_name": "testgroup"})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_macos_group_exception(self, user_ops):
        """Test macOS group deletion with exception."""
        with patch.object(
            user_ops, "_run_dscl_command", side_effect=Exception("dscl error")
        ):
            result = await user_ops._delete_macos_group({"group_name": "testgroup"})

        assert result["success"] is False
        assert "dscl error" in result["error"]

    @pytest.mark.asyncio
    async def test_run_dscl_command(self, user_ops):
        """Test running dscl command."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True}

            result = await user_ops._run_dscl_command(
                ["create", "/Users/test", "UserShell", "/bin/bash"]
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "dscl" in cmd
        assert "." in cmd
        assert "create" in cmd


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
    async def test_create_windows_user_with_full_name(self, user_ops):
        """Test Windows user creation with full name."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_windows_user(
                {
                    "username": "testuser",
                    "password": "TestPassword123!",
                    "full_name": "Test User",
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert any("/fullname:" in arg for arg in cmd)

    @pytest.mark.asyncio
    async def test_create_windows_user_password_never_expires(self, user_ops):
        """Test Windows user creation with password never expires."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True}

            result = await user_ops._create_windows_user(
                {
                    "username": "testuser",
                    "password": "TestPassword123!",
                    "password_never_expires": True,
                }
            )

        assert result["success"] is True
        # Should call wmic to set password never expires
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_create_windows_user_must_change_password(self, user_ops):
        """Test Windows user creation with must change password flag."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True}

            result = await user_ops._create_windows_user(
                {
                    "username": "testuser",
                    "password": "TestPassword123!",
                    "user_must_change_password": True,
                }
            )

        assert result["success"] is True
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_create_windows_user_account_disabled(self, user_ops):
        """Test Windows user creation with account disabled."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True}

            result = await user_ops._create_windows_user(
                {
                    "username": "testuser",
                    "password": "TestPassword123!",
                    "account_disabled": True,
                }
            )

        assert result["success"] is True
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_create_windows_user_all_options(self, user_ops):
        """Test Windows user creation with all options."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True}

            result = await user_ops._create_windows_user(
                {
                    "username": "testuser",
                    "password": "TestPassword123!",
                    "full_name": "Test User",
                    "password_never_expires": True,
                    "user_must_change_password": True,
                    "account_disabled": True,
                }
            )

        assert result["success"] is True
        # Initial create + 3 option commands
        assert mock_run.call_count == 4

    @pytest.mark.asyncio
    async def test_create_windows_user_creation_fails(self, user_ops):
        """Test Windows user creation failure."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": False, "error": "User exists"}

            result = await user_ops._create_windows_user(
                {
                    "username": "testuser",
                    "password": "TestPassword123!",
                }
            )

        assert result["success"] is False

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
        assert any("/comment:" in arg for arg in cmd)

    @pytest.mark.asyncio
    async def test_create_windows_group_without_description(self, user_ops):
        """Test Windows group creation without description."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group created"}

            result = await user_ops._create_windows_group({"group_name": "testgroup"})

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert not any("/comment:" in str(arg) for arg in cmd)

    @pytest.mark.asyncio
    async def test_delete_windows_user(self, user_ops):
        """Test Windows user deletion."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops._delete_windows_user({"username": "testuser"})

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "net" in cmd
        assert "user" in cmd
        assert "testuser" in cmd
        assert "/delete" in cmd

    @pytest.mark.asyncio
    async def test_delete_windows_group(self, user_ops):
        """Test Windows group deletion."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops._delete_windows_group({"group_name": "testgroup"})

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "net" in cmd
        assert "localgroup" in cmd
        assert "testgroup" in cmd
        assert "/delete" in cmd


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
    async def test_create_freebsd_user_with_options(self, user_ops):
        """Test FreeBSD user creation with all options."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_freebsd_user(
                {
                    "username": "testuser",
                    "uid": 1001,
                    "primary_group": "staff",
                    "home_directory": "/home/testuser",
                    "shell": "/bin/tcsh",
                    "full_name": "Test User",
                    "create_home_dir": True,
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd
        assert "1001" in cmd
        assert "-g" in cmd
        assert "staff" in cmd
        assert "-d" in cmd
        assert "/home/testuser" in cmd
        assert "-s" in cmd
        assert "/bin/tcsh" in cmd
        assert "-c" in cmd
        assert "Test User" in cmd
        assert "-m" in cmd

    @pytest.mark.asyncio
    async def test_create_freebsd_user_no_home_dir(self, user_ops):
        """Test FreeBSD user creation without home directory."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_freebsd_user(
                {"username": "testuser", "create_home_dir": False}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "-m" not in cmd

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
        assert "-g" in cmd
        assert "1001" in cmd

    @pytest.mark.asyncio
    async def test_create_freebsd_group_without_gid(self, user_ops):
        """Test FreeBSD group creation without explicit GID."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group created"}

            result = await user_ops._create_freebsd_group({"group_name": "testgroup"})

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "-g" not in cmd

    @pytest.mark.asyncio
    async def test_delete_freebsd_user(self, user_ops):
        """Test FreeBSD user deletion."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops._delete_freebsd_user(
                {"username": "testuser", "delete_default_group": False}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "pw" in cmd
        assert "userdel" in cmd
        assert "testuser" in cmd

    @pytest.mark.asyncio
    async def test_delete_freebsd_user_with_group(self, user_ops):
        """Test FreeBSD user deletion with default group."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_run.return_value = {"success": True}
                mock_capture.return_value = {"success": True}  # group exists

                result = await user_ops._delete_freebsd_user(
                    {"username": "testuser", "delete_default_group": True}
                )

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_freebsd_user_group_not_exists(self, user_ops):
        """Test FreeBSD user deletion when group does not exist."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_run.return_value = {"success": True, "message": "User deleted"}
                mock_capture.return_value = {"success": False}

                result = await user_ops._delete_freebsd_user(
                    {"username": "testuser", "delete_default_group": True}
                )

        assert result["success"] is True
        assert mock_run.call_count == 1

    @pytest.mark.asyncio
    async def test_delete_freebsd_user_group_deletion_fails(self, user_ops):
        """Test FreeBSD user deletion when group deletion fails."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_run.side_effect = [
                    {"success": True, "message": "User deleted"},
                    {"success": False, "error": "Group in use"},
                ]
                mock_capture.return_value = {"success": True}

                result = await user_ops._delete_freebsd_user(
                    {"username": "testuser", "delete_default_group": True}
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_freebsd_user_fails(self, user_ops):
        """Test FreeBSD user deletion failure."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": False, "error": "User not found"}

            result = await user_ops._delete_freebsd_user({"username": "testuser"})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_freebsd_group(self, user_ops):
        """Test FreeBSD group deletion."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops._delete_freebsd_group({"group_name": "testgroup"})

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "pw" in cmd
        assert "groupdel" in cmd
        assert "testgroup" in cmd


class TestOpenBSDNetBSDUserOperations:
    """Tests for OpenBSD/NetBSD-specific user operations."""

    @pytest.mark.asyncio
    async def test_create_openbsd_netbsd_user_basic(self, user_ops):
        """Test OpenBSD/NetBSD user creation."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_openbsd_netbsd_user(
                {"username": "testuser"}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "useradd" in cmd
        assert "-m" in cmd
        assert "testuser" in cmd

    @pytest.mark.asyncio
    async def test_create_openbsd_netbsd_user_with_options(self, user_ops):
        """Test OpenBSD/NetBSD user creation with all options."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_openbsd_netbsd_user(
                {
                    "username": "testuser",
                    "uid": 1001,
                    "primary_group": "staff",
                    "home_directory": "/home/testuser",
                    "shell": "/bin/ksh",
                    "full_name": "Test User",
                    "create_home_dir": True,
                }
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd
        assert "1001" in cmd
        assert "-g" in cmd
        assert "staff" in cmd
        assert "-d" in cmd
        assert "/home/testuser" in cmd
        assert "-s" in cmd
        assert "/bin/ksh" in cmd
        assert "-c" in cmd
        assert "Test User" in cmd
        assert "-m" in cmd

    @pytest.mark.asyncio
    async def test_create_openbsd_netbsd_user_no_home_dir(self, user_ops):
        """Test OpenBSD/NetBSD user creation without home directory."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User created"}

            result = await user_ops._create_openbsd_netbsd_user(
                {"username": "testuser", "create_home_dir": False}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "-m" not in cmd

    @pytest.mark.asyncio
    async def test_create_openbsd_netbsd_group(self, user_ops):
        """Test OpenBSD/NetBSD group creation."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group created"}

            result = await user_ops._create_openbsd_netbsd_group(
                {"group_name": "testgroup", "gid": 1001}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "groupadd" in cmd
        assert "-g" in cmd
        assert "1001" in cmd
        assert "testgroup" in cmd

    @pytest.mark.asyncio
    async def test_create_openbsd_netbsd_group_without_gid(self, user_ops):
        """Test OpenBSD/NetBSD group creation without explicit GID."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group created"}

            result = await user_ops._create_openbsd_netbsd_group(
                {"group_name": "testgroup"}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "-g" not in cmd

    @pytest.mark.asyncio
    async def test_delete_openbsd_netbsd_user(self, user_ops):
        """Test OpenBSD/NetBSD user deletion."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "User deleted"}

            result = await user_ops._delete_openbsd_netbsd_user(
                {"username": "testuser", "delete_default_group": False}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "userdel" in cmd
        assert "testuser" in cmd

    @pytest.mark.asyncio
    async def test_delete_openbsd_netbsd_user_with_group(self, user_ops):
        """Test OpenBSD/NetBSD user deletion with default group."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_run.return_value = {"success": True}
                mock_capture.return_value = {"success": True}

                result = await user_ops._delete_openbsd_netbsd_user(
                    {"username": "testuser", "delete_default_group": True}
                )

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_openbsd_netbsd_user_group_not_exists(self, user_ops):
        """Test OpenBSD/NetBSD user deletion when group does not exist."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_run.return_value = {"success": True, "message": "User deleted"}
                mock_capture.return_value = {"success": False}

                result = await user_ops._delete_openbsd_netbsd_user(
                    {"username": "testuser", "delete_default_group": True}
                )

        assert result["success"] is True
        assert mock_run.call_count == 1

    @pytest.mark.asyncio
    async def test_delete_openbsd_netbsd_user_group_deletion_fails(self, user_ops):
        """Test OpenBSD/NetBSD user deletion when group deletion fails."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            with patch.object(
                user_ops, "_run_command_capture", new_callable=AsyncMock
            ) as mock_capture:
                mock_run.side_effect = [
                    {"success": True, "message": "User deleted"},
                    {"success": False, "error": "Group in use"},
                ]
                mock_capture.return_value = {"success": True}

                result = await user_ops._delete_openbsd_netbsd_user(
                    {"username": "testuser", "delete_default_group": True}
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_openbsd_netbsd_user_fails(self, user_ops):
        """Test OpenBSD/NetBSD user deletion failure."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": False, "error": "User not found"}

            result = await user_ops._delete_openbsd_netbsd_user(
                {"username": "testuser"}
            )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_openbsd_netbsd_group(self, user_ops):
        """Test OpenBSD/NetBSD group deletion."""
        with patch.object(user_ops, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"success": True, "message": "Group deleted"}

            result = await user_ops._delete_openbsd_netbsd_group(
                {"group_name": "testgroup"}
            )

        assert result["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "groupdel" in cmd
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
    async def test_run_command_failure_stdout_error(self, user_ops):
        """Test failed command execution with error in stdout."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"stdout error", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await user_ops._run_command(["false"], "test command")

        assert result["success"] is False
        assert "stdout error" in result["error"]

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
    async def test_run_command_generic_exception(self, user_ops):
        """Test command execution with generic exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Unexpected error"),
        ):
            result = await user_ops._run_command(["test"], "test command")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

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

    @pytest.mark.asyncio
    async def test_run_command_capture_failure_stdout(self, user_ops):
        """Test failed command capture with error in stdout."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"stdout error", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await user_ops._run_command_capture(["false"])

        assert result["success"] is False
        assert "stdout error" in result["error"]

    @pytest.mark.asyncio
    async def test_run_command_capture_exception(self, user_ops):
        """Test command capture with exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Capture error"),
        ):
            result = await user_ops._run_command_capture(["test"])

        assert result["success"] is False
        assert "Capture error" in result["error"]
