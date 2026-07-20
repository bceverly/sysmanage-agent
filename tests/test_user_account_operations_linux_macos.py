# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for Linux and macOS user account operations.
Split from test_user_account_operations.py to satisfy the 1000-line file limit.
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
