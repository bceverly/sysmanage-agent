#!/usr/bin/env python3
"""
Tests for LinuxRepositoryOperations class.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from src.sysmanage_agent.operations.linux_repository_operations import (
    LinuxRepositoryOperations,
)


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = MagicMock()
    agent.system_ops = MagicMock()
    agent.system_ops.execute_shell_command = AsyncMock()
    return agent


@pytest.fixture
def linux_ops(mock_agent):
    """Create a LinuxRepositoryOperations instance."""
    return LinuxRepositoryOperations(mock_agent)


class TestInit:
    """Test initialization."""

    def test_init(self, mock_agent):
        """Test initialization."""
        ops = LinuxRepositoryOperations(mock_agent)
        assert ops.agent_instance == mock_agent
        assert ops.logger is not None


class TestAPTOperations:
    """Test APT repository operations."""

    @pytest.mark.asyncio
    async def test_list_apt_repositories_with_ppa(self, linux_ops):
        """Test listing APT repositories including PPAs."""
        sources_content = "deb http://ppa.launchpad.net/user/ppa/ubuntu focal main\n"
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["user-ppa.list"]),
            patch("builtins.open", mock_open(read_data=sources_content)),
        ):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 1
            assert repos[0]["type"] == "PPA"
            assert "ppa:user/ppa" in repos[0]["name"]
            assert repos[0]["enabled"] is True

    @pytest.mark.asyncio
    async def test_list_apt_repositories_disabled(self, linux_ops):
        """Test listing disabled APT repositories."""
        # Commented line with deb keyword is still considered a repository entry
        sources_content = "# deb http://example.com/ubuntu focal main\n"
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.list"]),
            patch("builtins.open", mock_open(read_data=sources_content)),
        ):
            repos = await linux_ops.list_apt_repositories()
            # The code skips lines that don't have "deb " in them after checking for PPA
            # So commented lines are not returned
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_list_apt_repositories_no_dir(self, linux_ops):
        """Test listing APT repositories when directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_list_apt_repositories_with_sources_file(self, linux_ops):
        """Test listing APT repositories from .sources files."""
        sources_content = "deb http://example.com/ubuntu focal main\n"
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.sources"]),
            patch("builtins.open", mock_open(read_data=sources_content)),
        ):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 1
            assert repos[0]["type"] == "APT"

    @pytest.mark.asyncio
    async def test_list_apt_repositories_error(self, linux_ops):
        """Test error handling when listing APT repositories."""
        # Mock os.listdir to raise exception
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", side_effect=Exception("Test error")),
        ):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_add_apt_repository_ppa(self, linux_ops, mock_agent):
        """Test adding PPA repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "PPA added", "stderr": ""},
        }
        result = await linux_ops.add_apt_repository("ppa:test/ppa")
        assert result["success"] is True
        assert "successfully" in result["result"]
        mock_agent.system_ops.execute_shell_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_apt_repository_manual(self, linux_ops, mock_agent):
        """Test adding manual APT repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Repository added", "stderr": ""},
        }
        result = await linux_ops.add_apt_repository(
            "deb http://example.com/ubuntu focal main"
        )
        assert result["success"] is True
        mock_agent.system_ops.execute_shell_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_apt_repository_failure(self, linux_ops, mock_agent):
        """Test adding APT repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error adding repository"},
        }
        result = await linux_ops.add_apt_repository("ppa:test/ppa")
        assert result["success"] is False
        assert "Failed to add repository" in result["error"]

    @pytest.mark.asyncio
    async def test_add_apt_repository_error(self, linux_ops, mock_agent):
        """Test error handling when adding APT repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await linux_ops.add_apt_repository("ppa:test/ppa")
        assert result["success"] is False
        assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_apt_repository_ppa(self, linux_ops, mock_agent):
        """Test deleting PPA repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "PPA removed", "stderr": ""},
        }
        result = await linux_ops.delete_apt_repository({"name": "ppa:test/ppa"})
        assert result["success"] is True
        assert "successfully" in result["result"]

    @pytest.mark.asyncio
    async def test_delete_apt_repository_file(self, linux_ops, mock_agent):
        """Test deleting APT repository by file."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "File removed", "stderr": ""},
        }
        with patch("os.path.exists", return_value=True):
            result = await linux_ops.delete_apt_repository(
                {"name": "test-repo", "file_path": "/etc/apt/sources.list.d/test.list"}
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_apt_repository_no_file(self, linux_ops):
        """Test deleting APT repository when file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await linux_ops.delete_apt_repository(
                {"name": "test-repo", "file_path": "/etc/apt/sources.list.d/test.list"}
            )
            assert result["success"] is False
            assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_apt_repository_error(self, linux_ops):
        """Test error handling when deleting APT repository."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            result = await linux_ops.delete_apt_repository(
                {"name": "test-repo", "file_path": "/tmp/test.list"}
            )
            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_apt_repository(self, linux_ops, mock_agent):
        """Test enabling APT repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Enabled", "stderr": ""},
        }
        with patch("os.path.exists", return_value=True):
            result = await linux_ops.enable_apt_repository("/tmp/test.list")
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_apt_repository_no_file(self, linux_ops):
        """Test enabling APT repository when file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await linux_ops.enable_apt_repository("/tmp/test.list")
            assert result["success"] is False
            assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_apt_repository_error(self, linux_ops):
        """Test error handling when enabling APT repository."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            result = await linux_ops.enable_apt_repository("/tmp/test.list")
            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_apt_repository(self, linux_ops, mock_agent):
        """Test disabling APT repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Disabled", "stderr": ""},
        }
        with patch("os.path.exists", return_value=True):
            result = await linux_ops.disable_apt_repository("/tmp/test.list")
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_apt_repository_no_file(self, linux_ops):
        """Test disabling APT repository when file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await linux_ops.disable_apt_repository("/tmp/test.list")
            assert result["success"] is False
            assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_apt_repository_error(self, linux_ops):
        """Test error handling when disabling APT repository."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            result = await linux_ops.disable_apt_repository("/tmp/test.list")
            assert result["success"] is False
            assert "Test error" in result["error"]


class TestYUMOperations:
    """Test YUM/DNF repository operations."""

    @pytest.mark.asyncio
    async def test_list_yum_repositories(self, linux_ops):
        """Test listing YUM repositories."""
        repo_content = "[test-repo]\nname=Test Repository\nbaseurl=http://example.com/\nenabled=1\n"
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.repo"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await linux_ops.list_yum_repositories()
            assert len(repos) == 1
            assert repos[0]["name"] == "test-repo"
            assert repos[0]["enabled"] is True

    @pytest.mark.asyncio
    async def test_list_yum_repositories_copr(self, linux_ops):
        """Test listing YUM COPR repositories."""
        repo_content = "[copr:user:project]\nname=COPR Repository\nbaseurl=http://copr.fedorainfracloud.org/\nenabled=1\n"
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["_copr:user:project.repo"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await linux_ops.list_yum_repositories()
            assert len(repos) == 1
            assert repos[0]["type"] == "COPR"

    @pytest.mark.asyncio
    async def test_list_yum_repositories_disabled(self, linux_ops):
        """Test listing disabled YUM repositories."""
        repo_content = "[test-repo]\nname=Test Repository\nbaseurl=http://example.com/\nenabled=0\n"
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.repo"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await linux_ops.list_yum_repositories()
            assert len(repos) == 1
            assert repos[0]["enabled"] is False

    @pytest.mark.asyncio
    async def test_list_yum_repositories_no_dir(self, linux_ops):
        """Test listing YUM repositories when directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            repos = await linux_ops.list_yum_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_list_yum_repositories_error(self, linux_ops):
        """Test error handling when listing YUM repositories."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            repos = await linux_ops.list_yum_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_add_yum_repository_copr(self, linux_ops, mock_agent):
        """Test adding COPR repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "COPR enabled", "stderr": ""},
        }
        result = await linux_ops.add_yum_repository("user/project")
        assert result["success"] is True
        assert "successfully" in result["result"]

    @pytest.mark.asyncio
    async def test_add_yum_repository_manual(self, linux_ops):
        """Test adding manual YUM repository (not implemented)."""
        result = await linux_ops.add_yum_repository("http://example.com/repo")
        assert result["success"] is False
        assert "not yet implemented" in result["error"]

    @pytest.mark.asyncio
    async def test_add_yum_repository_failure(self, linux_ops, mock_agent):
        """Test adding YUM repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error enabling COPR"},
        }
        result = await linux_ops.add_yum_repository("user/project")
        assert result["success"] is False
        assert "Failed to add repository" in result["error"]

    @pytest.mark.asyncio
    async def test_add_yum_repository_error(self, linux_ops, mock_agent):
        """Test error handling when adding YUM repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await linux_ops.add_yum_repository("user/project")
        assert result["success"] is False
        assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_yum_repository_copr(self, linux_ops, mock_agent):
        """Test deleting COPR repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "COPR removed", "stderr": ""},
        }
        result = await linux_ops.delete_yum_repository(
            {"name": "copr:user:project", "type": "COPR"}
        )
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_yum_repository_file(self, linux_ops, mock_agent):
        """Test deleting YUM repository by file."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "File removed", "stderr": ""},
        }
        with patch("os.path.exists", return_value=True):
            result = await linux_ops.delete_yum_repository(
                {
                    "name": "test-repo",
                    "type": "YUM",
                    "file_path": "/etc/yum.repos.d/test.repo",
                }
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_yum_repository_no_file(self, linux_ops):
        """Test deleting YUM repository when file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await linux_ops.delete_yum_repository(
                {
                    "name": "test-repo",
                    "type": "YUM",
                    "file_path": "/etc/yum.repos.d/test.repo",
                }
            )
            assert result["success"] is False
            assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_yum_repository_error(self, linux_ops):
        """Test error handling when deleting YUM repository."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            result = await linux_ops.delete_yum_repository(
                {"name": "test-repo", "type": "YUM", "file_path": "/tmp/test.repo"}
            )
            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_yum_repository(self, linux_ops, mock_agent):
        """Test enabling YUM repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Enabled", "stderr": ""},
        }
        result = await linux_ops.enable_yum_repository("test-repo")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_yum_repository_failure(self, linux_ops, mock_agent):
        """Test enabling YUM repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error enabling"},
        }
        result = await linux_ops.enable_yum_repository("test-repo")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_enable_yum_repository_error(self, linux_ops, mock_agent):
        """Test error handling when enabling YUM repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await linux_ops.enable_yum_repository("test-repo")
        assert result["success"] is False
        assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_yum_repository(self, linux_ops, mock_agent):
        """Test disabling YUM repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Disabled", "stderr": ""},
        }
        result = await linux_ops.disable_yum_repository("test-repo")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_yum_repository_failure(self, linux_ops, mock_agent):
        """Test disabling YUM repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error disabling"},
        }
        result = await linux_ops.disable_yum_repository("test-repo")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_disable_yum_repository_error(self, linux_ops, mock_agent):
        """Test error handling when disabling YUM repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await linux_ops.disable_yum_repository("test-repo")
        assert result["success"] is False
        assert "Test error" in result["error"]


class TestZypperOperations:
    """Test Zypper repository operations."""

    @pytest.mark.asyncio
    async def test_list_zypper_repositories(self, linux_ops, mock_agent):
        """Test listing Zypper repositories."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "# | Alias | Enabled | URL\n1 | repo1 | Yes | http://example.com/\n",
                "stderr": "",
            },
        }
        repos = await linux_ops.list_zypper_repositories()
        assert len(repos) == 1
        assert repos[0]["name"] == "repo1"
        assert repos[0]["enabled"] is True

    @pytest.mark.asyncio
    async def test_list_zypper_repositories_obs(self, linux_ops, mock_agent):
        """Test listing Zypper OBS repositories."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "# | Alias | Enabled | URL\n1 | obs-repo | Yes | http://download.opensuse.org/\n",
                "stderr": "",
            },
        }
        repos = await linux_ops.list_zypper_repositories()
        assert len(repos) == 1
        assert repos[0]["type"] == "OBS"

    @pytest.mark.asyncio
    async def test_list_zypper_repositories_disabled(self, linux_ops, mock_agent):
        """Test listing disabled Zypper repositories."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "# | Alias | Enabled | URL\n1 | repo1 | No | http://example.com/\n",
                "stderr": "",
            },
        }
        repos = await linux_ops.list_zypper_repositories()
        assert len(repos) == 1
        assert repos[0]["enabled"] is False

    @pytest.mark.asyncio
    async def test_list_zypper_repositories_error(self, linux_ops, mock_agent):
        """Test error handling when listing Zypper repositories."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        repos = await linux_ops.list_zypper_repositories()
        assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_check_obs_url(self, linux_ops):
        """Test checking OBS URLs."""
        assert linux_ops._check_obs_url("http://download.opensuse.org/repo") is True
        assert linux_ops._check_obs_url("http://opensuse.org/") is True
        assert linux_ops._check_obs_url("http://example.com/") is False
        assert linux_ops._check_obs_url("") is False

    @pytest.mark.asyncio
    async def test_add_zypper_repository(self, linux_ops, mock_agent):
        """Test adding Zypper repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Repository added", "stderr": ""},
        }
        result = await linux_ops.add_zypper_repository(
            "test-repo", "http://example.com/"
        )
        assert result["success"] is True
        assert "successfully" in result["result"]

    @pytest.mark.asyncio
    async def test_add_zypper_repository_no_url(self, linux_ops):
        """Test adding Zypper repository without URL."""
        result = await linux_ops.add_zypper_repository("test-repo", "")
        assert result["success"] is False
        assert "required" in result["error"]

    @pytest.mark.asyncio
    async def test_add_zypper_repository_failure(self, linux_ops, mock_agent):
        """Test adding Zypper repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error adding repository"},
        }
        result = await linux_ops.add_zypper_repository(
            "test-repo", "http://example.com/"
        )
        assert result["success"] is False
        assert "Failed to add repository" in result["error"]

    @pytest.mark.asyncio
    async def test_add_zypper_repository_error(self, linux_ops, mock_agent):
        """Test error handling when adding Zypper repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await linux_ops.add_zypper_repository(
            "test-repo", "http://example.com/"
        )
        assert result["success"] is False
        assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_zypper_repository(self, linux_ops, mock_agent):
        """Test deleting Zypper repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Repository removed", "stderr": ""},
        }
        result = await linux_ops.delete_zypper_repository({"name": "test-repo"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_zypper_repository_failure(self, linux_ops, mock_agent):
        """Test deleting Zypper repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error removing"},
        }
        result = await linux_ops.delete_zypper_repository({"name": "test-repo"})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_zypper_repository_error(self, linux_ops, mock_agent):
        """Test error handling when deleting Zypper repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await linux_ops.delete_zypper_repository({"name": "test-repo"})
        assert result["success"] is False
        assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_zypper_repository(self, linux_ops, mock_agent):
        """Test enabling Zypper repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Enabled", "stderr": ""},
        }
        result = await linux_ops.enable_zypper_repository("test-repo")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_zypper_repository_failure(self, linux_ops, mock_agent):
        """Test enabling Zypper repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error enabling"},
        }
        result = await linux_ops.enable_zypper_repository("test-repo")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_enable_zypper_repository_error(self, linux_ops, mock_agent):
        """Test error handling when enabling Zypper repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await linux_ops.enable_zypper_repository("test-repo")
        assert result["success"] is False
        assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_zypper_repository(self, linux_ops, mock_agent):
        """Test disabling Zypper repository."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Disabled", "stderr": ""},
        }
        result = await linux_ops.disable_zypper_repository("test-repo")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_zypper_repository_failure(self, linux_ops, mock_agent):
        """Test disabling Zypper repository failure."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": False,
            "result": {"stdout": "", "stderr": "Error disabling"},
        }
        result = await linux_ops.disable_zypper_repository("test-repo")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_disable_zypper_repository_error(self, linux_ops, mock_agent):
        """Test error handling when disabling Zypper repository."""
        mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Test error"
        )
        result = await linux_ops.disable_zypper_repository("test-repo")
        assert result["success"] is False
        assert "Test error" in result["error"]
