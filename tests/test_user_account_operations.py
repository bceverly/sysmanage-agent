# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

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
