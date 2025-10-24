#!/usr/bin/env python3
"""
Tests for BSDMacOSRepositoryOperations class.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import AsyncMock, MagicMock, mock_open, patch
from urllib.parse import urlparse

import pytest

from src.sysmanage_agent.operations.bsd_macos_repository_operations import (
    BSDMacOSRepositoryOperations,
)


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = MagicMock()
    agent.system_ops = MagicMock()
    agent.system_ops.execute_shell_command = AsyncMock()
    return agent


@pytest.fixture
def bsd_macos_ops(mock_agent):
    """Create a BSDMacOSRepositoryOperations instance."""
    return BSDMacOSRepositoryOperations(mock_agent)


class TestInit:
    """Test initialization."""

    def test_init(self, mock_agent):
        """Test initialization."""
        ops = BSDMacOSRepositoryOperations(mock_agent)
        assert ops.agent_instance == mock_agent
        assert ops.logger is not None


class TestHomebrewOperations:
    """Test Homebrew tap operations."""

    @pytest.mark.asyncio
    async def test_list_homebrew_taps(self, bsd_macos_ops, mock_agent):
        """Test listing Homebrew taps."""
        mock_agent.system_ops.execute_shell_command.side_effect = [
            {
                "success": True,
                "result": {"stdout": "/usr/local/bin/brew", "stderr": ""},
            },
            {
                "success": True,
                "result": {
                    "stdout": "user/tap1\nuser/tap2\nhomebrew/core\n",
                    "stderr": "",
                },
            },
        ]
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 2
        assert repos[0]["name"] == "user/tap1"
        assert repos[0]["type"] == "Homebrew Tap"
        assert repos[1]["name"] == "user/tap2"

    @pytest.mark.asyncio
    async def test_list_homebrew_taps_not_installed(self, bsd_macos_ops, mock_agent):
        """Test listing Homebrew taps when brew is not installed."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "brew not found"},
        }
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_list_homebrew_taps_error(self, bsd_macos_ops, mock_agent):
        """Test error handling when listing Homebrew taps."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_add_homebrew_tap(self, bsd_macos_ops, mock_agent):
        """Test adding Homebrew tap."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Tap added", "stderr": ""},
        }
        result = await bsd_macos_ops.add_homebrew_tap("user/tap")
        assert result["success"] is True
        assert "successfully" in result["result"]

    @pytest.mark.asyncio
    async def test_add_homebrew_tap_invalid_format(self, bsd_macos_ops):
        """Test adding Homebrew tap with invalid format."""
        result = await bsd_macos_ops.add_homebrew_tap("invalid-tap")
        assert result["success"] is False
        assert "Invalid tap format" in result["error"]

    @pytest.mark.asyncio
    async def test_add_homebrew_tap_failure(self, bsd_macos_ops, mock_agent):
        """Test adding Homebrew tap failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error adding tap"},
        }
        result = await bsd_macos_ops.add_homebrew_tap("user/tap")
        assert result["success"] is False
        assert "Failed to add tap" in result["error"]

    @pytest.mark.asyncio
    async def test_add_homebrew_tap_error(self, bsd_macos_ops, mock_agent):
        """Test error handling when adding Homebrew tap."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await bsd_macos_ops.add_homebrew_tap("user/tap")
        assert result["success"] is False
        assert "Test error" in result["error"]


class TestFreeBSDOperations:
    """Test FreeBSD pkg repository operations."""

    @pytest.mark.asyncio
    async def test_list_freebsd_repositories(self, bsd_macos_ops):
        """Test listing FreeBSD repositories."""
        repo_url = "http://pkg.freebsd.org/FreeBSD:13:amd64/latest"
        repo_content = f'myrepo: {{\n  url: "{repo_url}",\n  enabled: yes\n}}\n'
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["myrepo.conf"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            assert len(repos) == 1
            assert repos[0]["name"] == "myrepo"
            assert repos[0]["type"] == "FreeBSD pkg"
            assert repos[0]["enabled"] is True
            # Properly parse URL to verify hostname
            parsed = urlparse(repos[0]["url"])
            assert parsed.hostname == "pkg.freebsd.org"

    @pytest.mark.asyncio
    async def test_list_freebsd_repositories_disabled(self, bsd_macos_ops):
        """Test listing disabled FreeBSD repositories."""
        repo_content = 'myrepo: {\n  url: "http://example.com/",\n  enabled: no\n}\n'
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["myrepo.conf"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            assert len(repos) == 1
            assert repos[0]["enabled"] is False

    @pytest.mark.asyncio
    async def test_list_freebsd_repositories_no_dir(self, bsd_macos_ops):
        """Test listing FreeBSD repositories when directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_list_freebsd_repositories_error(self, bsd_macos_ops):
        """Test error handling when listing FreeBSD repositories."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_add_freebsd_repository(self, bsd_macos_ops, mock_agent):
        """Test adding FreeBSD repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Updated", "stderr": ""},
        }
        with patch("os.makedirs"), patch("builtins.open", mock_open()):
            result = await bsd_macos_ops.add_freebsd_repository(
                "myrepo", "http://pkg.freebsd.org/"
            )
            assert result["success"] is True
            assert "successfully" in result["result"]

    @pytest.mark.asyncio
    async def test_add_freebsd_repository_no_url(self, bsd_macos_ops):
        """Test adding FreeBSD repository without URL."""
        result = await bsd_macos_ops.add_freebsd_repository("myrepo", "")
        assert result["success"] is False
        assert "required" in result["error"]

    @pytest.mark.asyncio
    async def test_add_freebsd_repository_error(self, bsd_macos_ops):
        """Test error handling when adding FreeBSD repository."""
        with patch("os.makedirs", side_effect=Exception("Test error")):
            result = await bsd_macos_ops.add_freebsd_repository(
                "myrepo", "http://pkg.freebsd.org/"
            )
            assert result["success"] is False
            assert "Test error" in result["error"]


class TestNetBSDOperations:
    """Test NetBSD pkgsrc repository operations."""

    @pytest.mark.asyncio
    async def test_list_netbsd_repositories_wip(self, bsd_macos_ops):
        """Test listing NetBSD repositories with pkgsrc-wip."""
        with (
            patch("os.path.exists", side_effect=lambda p: p == "/usr/pkgsrc/wip"),
            patch("os.listdir", return_value=[]),
        ):
            repos = await bsd_macos_ops.list_netbsd_repositories()
            assert len(repos) == 1
            assert repos[0]["name"] == "pkgsrc-wip"
            assert repos[0]["type"] == "pkgsrc-wip"

    @pytest.mark.asyncio
    async def test_list_netbsd_repositories_custom(self, bsd_macos_ops):
        """Test listing NetBSD custom repositories."""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["wip", "custom"]),
            patch("os.path.isdir", side_effect=lambda p: "custom" in p),
        ):
            repos = await bsd_macos_ops.list_netbsd_repositories()
            assert len(repos) >= 1
            assert repos[0]["name"] == "pkgsrc-wip"

    @pytest.mark.asyncio
    async def test_list_netbsd_repositories_no_dir(self, bsd_macos_ops):
        """Test listing NetBSD repositories when directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            repos = await bsd_macos_ops.list_netbsd_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_list_netbsd_repositories_error(self, bsd_macos_ops):
        """Test error handling when listing NetBSD repositories."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            repos = await bsd_macos_ops.list_netbsd_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_add_netbsd_repository(self, bsd_macos_ops, mock_agent):
        """Test adding NetBSD repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Cloned", "stderr": ""},
        }
        with patch("os.path.exists", return_value=False):
            result = await bsd_macos_ops.add_netbsd_repository(
                "wip", "https://github.com/NetBSD/pkgsrc-wip"
            )
            assert result["success"] is True
            assert "successfully" in result["result"]

    @pytest.mark.asyncio
    async def test_add_netbsd_repository_no_url(self, bsd_macos_ops):
        """Test adding NetBSD repository without URL."""
        result = await bsd_macos_ops.add_netbsd_repository("wip", "")
        assert result["success"] is False
        assert "required" in result["error"]

    @pytest.mark.asyncio
    async def test_add_netbsd_repository_exists(self, bsd_macos_ops):
        """Test adding NetBSD repository when directory exists."""
        with patch("os.path.exists", return_value=True):
            result = await bsd_macos_ops.add_netbsd_repository(
                "wip", "https://github.com/NetBSD/pkgsrc-wip"
            )
            assert result["success"] is False
            assert "already exists" in result["error"]

    @pytest.mark.asyncio
    async def test_add_netbsd_repository_failure(self, bsd_macos_ops, mock_agent):
        """Test adding NetBSD repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Clone failed"},
        }
        with patch("os.path.exists", return_value=False):
            result = await bsd_macos_ops.add_netbsd_repository(
                "wip", "https://github.com/NetBSD/pkgsrc-wip"
            )
            assert result["success"] is False
            assert "Failed to clone" in result["error"]

    @pytest.mark.asyncio
    async def test_add_netbsd_repository_error(self, bsd_macos_ops):
        """Test error handling when adding NetBSD repository."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            result = await bsd_macos_ops.add_netbsd_repository(
                "wip", "https://github.com/NetBSD/pkgsrc-wip"
            )
            assert result["success"] is False
            assert "Test error" in result["error"]
