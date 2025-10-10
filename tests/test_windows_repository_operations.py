#!/usr/bin/env python3
"""
Tests for WindowsRepositoryOperations class.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.sysmanage_agent.operations.windows_repository_operations import (
    WindowsRepositoryOperations,
)


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = MagicMock()
    agent.system_ops = MagicMock()
    agent.system_ops.execute_shell_command = AsyncMock()
    return agent


@pytest.fixture
def windows_ops(mock_agent):
    """Create a WindowsRepositoryOperations instance."""
    return WindowsRepositoryOperations(mock_agent)


class TestInit:
    """Test initialization."""

    def test_init(self, mock_agent):
        """Test initialization."""
        ops = WindowsRepositoryOperations(mock_agent)
        assert ops.agent_instance == mock_agent
        assert ops.logger is not None


class TestListRepositories:
    """Test listing Windows repositories."""

    @pytest.mark.asyncio
    async def test_list_windows_repositories(self, windows_ops, mock_agent):
        """Test listing Windows repositories."""
        mock_agent.system_ops.execute_shell_command.side_effect = [
            {
                "success": True,
                "result": {
                    "stdout": "custom-source - http://myrepo.com/ | Priority 0|Bypass Proxy - False",
                    "stderr": "",
                },
            },
            {
                "success": True,
                "result": {
                    "stdout": "Name  Argument\n----  --------\ncustom-source  http://example.com/",
                    "stderr": "",
                },
            },
        ]
        repos = await windows_ops.list_windows_repositories()
        assert len(repos) == 2

    @pytest.mark.asyncio
    async def test_list_windows_repositories_error(self, windows_ops, mock_agent):
        """Test error handling when listing Windows repositories."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        repos = await windows_ops.list_windows_repositories()
        assert len(repos) == 0


class TestChocolateyOperations:
    """Test Chocolatey source operations."""

    @pytest.mark.asyncio
    async def test_list_chocolatey_sources(self, windows_ops, mock_agent):
        """Test listing Chocolatey sources."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "chocolatey - https://chocolatey.org/api/v2/ | Priority 0\ncustom-source - http://myrepo.com/ | Priority 0",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_chocolatey_sources()
        assert len(repos) == 1
        assert repos[0]["name"] == "custom-source"
        assert repos[0]["type"] == "Chocolatey"
        assert repos[0]["enabled"] is True

    @pytest.mark.asyncio
    async def test_list_chocolatey_sources_disabled(self, windows_ops, mock_agent):
        """Test listing disabled Chocolatey sources."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "custom-source - http://myrepo.com/ | Priority 0|Disabled",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_chocolatey_sources()
        assert len(repos) == 1
        assert repos[0]["enabled"] is False

    @pytest.mark.asyncio
    async def test_list_chocolatey_sources_not_installed(self, windows_ops, mock_agent):
        """Test listing Chocolatey sources when not installed."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "choco not found"},
        }
        repos = await windows_ops._list_chocolatey_sources()
        assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_list_chocolatey_sources_official_only(self, windows_ops, mock_agent):
        """Test listing Chocolatey sources with only official source."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "chocolatey - https://chocolatey.org/api/v2/ | Priority 0",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_chocolatey_sources()
        assert len(repos) == 0


class TestWingetOperations:
    """Test winget source operations."""

    @pytest.mark.asyncio
    async def test_list_winget_sources(self, windows_ops, mock_agent):
        """Test listing winget sources."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "Name  Argument\n----  --------\nwinget  https://cdn.winget.microsoft.com/\nmsstore  https://storeedgefd.dsx.mp.microsoft.com/\ncustom-source  http://example.com/",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_winget_sources()
        assert len(repos) == 1
        assert repos[0]["name"] == "custom-source"
        assert repos[0]["type"] == "winget"

    @pytest.mark.asyncio
    async def test_list_winget_sources_not_installed(self, windows_ops, mock_agent):
        """Test listing winget sources when not installed."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "winget not found"},
        }
        repos = await windows_ops._list_winget_sources()
        assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_list_winget_sources_official_only(self, windows_ops, mock_agent):
        """Test listing winget sources with only official sources."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "Name  Argument\n----  --------\nwinget  https://cdn.winget.microsoft.com/\nmsstore  https://storeedgefd.dsx.mp.microsoft.com/",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_winget_sources()
        assert len(repos) == 0


class TestAddRepository:
    """Test adding Windows repositories."""

    @pytest.mark.asyncio
    async def test_add_chocolatey_repository(self, windows_ops, mock_agent):
        """Test adding Chocolatey repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Source added", "stderr": ""},
        }
        result = await windows_ops.add_windows_repository(
            "custom-source", "http://myrepo.com/", "chocolatey"
        )
        assert result["success"] is True
        assert "successfully" in result["result"]

    @pytest.mark.asyncio
    async def test_add_winget_repository(self, windows_ops, mock_agent):
        """Test adding winget repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Source added", "stderr": ""},
        }
        result = await windows_ops.add_windows_repository(
            "custom-source", "http://example.com/", "winget"
        )
        assert result["success"] is True
        assert "successfully" in result["result"]

    @pytest.mark.asyncio
    async def test_add_repository_no_url(self, windows_ops):
        """Test adding repository without URL."""
        result = await windows_ops.add_windows_repository(
            "custom-source", "", "chocolatey"
        )
        assert result["success"] is False
        assert "required" in result["error"]

    @pytest.mark.asyncio
    async def test_add_repository_invalid_type(self, windows_ops):
        """Test adding repository with invalid type."""
        result = await windows_ops.add_windows_repository(
            "custom-source", "http://example.com/", "invalid"
        )
        assert result["success"] is False
        assert "must be" in result["error"]

    @pytest.mark.asyncio
    async def test_add_repository_no_type(self, windows_ops):
        """Test adding repository without type."""
        result = await windows_ops.add_windows_repository(
            "custom-source", "http://example.com/", ""
        )
        assert result["success"] is False
        assert "must be" in result["error"]

    @pytest.mark.asyncio
    async def test_add_repository_failure(self, windows_ops, mock_agent):
        """Test adding repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error adding source"},
        }
        result = await windows_ops.add_windows_repository(
            "custom-source", "http://myrepo.com/", "chocolatey"
        )
        assert result["success"] is False
        assert "Failed to add repository" in result["error"]

    @pytest.mark.asyncio
    async def test_add_repository_error(self, windows_ops, mock_agent):
        """Test error handling when adding repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await windows_ops.add_windows_repository(
            "custom-source", "http://myrepo.com/", "chocolatey"
        )
        assert result["success"] is False
        assert "Test error" in result["error"]
