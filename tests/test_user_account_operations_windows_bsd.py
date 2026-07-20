# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for Windows and BSD user account operations plus helper methods.
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
