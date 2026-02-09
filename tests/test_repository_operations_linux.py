#!/usr/bin/env python3
"""
Tests for Linux-specific repository operations.

This module provides testing coverage for Linux repository operations
including APT, YUM/DNF, and Zypper repository parsing and management.
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.linux_repository_operations import (
    LinuxRepositoryOperations,
)

# Path to patch aiofiles.open in the modules under test
_LINUX_REPO_AIOFILES_OPEN = (
    "src.sysmanage_agent.operations.linux_repository_operations.aiofiles.open"
)


def _mock_aiofiles_open(read_data=""):
    """Create a mock for aiofiles.open that supports async context manager."""
    mock_file = AsyncMock()
    mock_file.read = AsyncMock(return_value=read_data)
    lines = [line + "\n" for line in read_data.split("\n") if line]
    mock_file.readlines = AsyncMock(return_value=lines)
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_file)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = MagicMock()
    agent.system_ops = MagicMock()
    agent.system_ops.execute_shell_command = AsyncMock()
    agent.check_updates = AsyncMock()
    agent._send_third_party_repository_update = AsyncMock()
    return agent


@pytest.fixture
def linux_ops(mock_agent):
    """Create a LinuxRepositoryOperations instance."""
    return LinuxRepositoryOperations(mock_agent)


class TestAPTRepositoryParsing:
    """Test APT repository parsing functionality."""

    @pytest.mark.asyncio
    async def test_parse_deb822_with_enabled_no(self, linux_ops):
        """Test parsing DEB822 format with enabled: no."""
        sources_content = """Types: deb
URIs: http://example.com/ubuntu
Suites: focal
Components: main
Enabled: no
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.sources"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(sources_content),
            ),
        ):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 1
            assert repos[0]["enabled"] is False

    @pytest.mark.asyncio
    async def test_parse_deb822_multiple_entries(self, linux_ops):
        """Test parsing DEB822 format with multiple entries."""
        sources_content = """Types: deb
URIs: http://example1.com/ubuntu
Suites: focal
Components: main

Types: deb
URIs: http://example2.com/ubuntu
Suites: focal
Components: main contrib
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.sources"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(sources_content),
            ),
        ):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 2
            assert repos[0]["url"].startswith("deb http://example1.com")
            assert repos[1]["url"].startswith("deb http://example2.com")

    @pytest.mark.asyncio
    async def test_parse_list_with_deb_src(self, linux_ops):
        """Test parsing .list file with deb-src entries."""
        sources_content = """deb http://example.com/ubuntu focal main
deb-src http://example.com/ubuntu focal main
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.list"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(sources_content),
            ),
        ):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 2
            assert "deb-src" in repos[1]["url"]

    @pytest.mark.asyncio
    async def test_parse_list_with_comments(self, linux_ops):
        """Test parsing .list file with various comment styles."""
        sources_content = """# This is a comment
deb http://example.com/ubuntu focal main
## Another comment style
# deb http://disabled.com/ubuntu focal main
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.list"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(sources_content),
            ),
        ):
            repos = await linux_ops.list_apt_repositories()
            # Should find 2 repos: one enabled, one disabled
            assert len(repos) == 2
            enabled_repos = [r for r in repos if r["enabled"]]
            disabled_repos = [r for r in repos if not r["enabled"]]
            assert len(enabled_repos) == 1
            assert len(disabled_repos) == 1

    @pytest.mark.asyncio
    async def test_parse_ppa_from_launchpadcontent(self, linux_ops):
        """Test parsing PPA from ppa.launchpadcontent.net."""
        sources_content = (
            "deb http://ppa.launchpadcontent.net/user/repo/ubuntu focal main\n"
        )
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["user-repo.list"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(sources_content),
            ),
        ):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 1
            assert repos[0]["type"] == "PPA"
            assert "ppa:user/repo" in repos[0]["name"]

    @pytest.mark.asyncio
    async def test_parse_empty_file(self, linux_ops):
        """Test parsing empty source file."""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["empty.list"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(""),
            ),
        ):
            repos = await linux_ops.list_apt_repositories()
            assert len(repos) == 0

    @pytest.mark.asyncio
    async def test_ignore_non_repo_files(self, linux_ops):
        """Test that non-.list and non-.sources files are ignored."""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["readme.txt", "backup.bak", "test.list"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(
                    "deb http://example.com/ubuntu focal main\n"
                ),
            ),
        ):
            repos = await linux_ops.list_apt_repositories()
            # Only test.list should be processed
            assert len(repos) == 1


class TestYUMRepositoryParsing:
    """Test YUM/DNF repository parsing functionality."""

    @pytest.mark.asyncio
    async def test_parse_yum_repo_multiple_sections(self, linux_ops):
        """Test parsing .repo file with multiple sections."""
        repo_content = """[repo1]
name=Repository 1
baseurl=http://example.com/repo1
enabled=1

[repo2]
name=Repository 2
baseurl=http://example.com/repo2
enabled=0
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.repo"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(repo_content),
            ),
        ):
            repos = await linux_ops.list_yum_repositories()
            assert len(repos) == 2
            assert repos[0]["name"] == "repo1"
            assert repos[0]["enabled"] is True
            assert repos[1]["name"] == "repo2"
            assert repos[1]["enabled"] is False

    @pytest.mark.asyncio
    async def test_parse_yum_repo_no_baseurl(self, linux_ops):
        """Test parsing .repo file without baseurl."""
        repo_content = """[test-repo]
name=Test Repository
enabled=1
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.repo"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(repo_content),
            ),
        ):
            repos = await linux_ops.list_yum_repositories()
            assert len(repos) == 1
            assert repos[0]["url"] == ""

    @pytest.mark.asyncio
    async def test_parse_yum_repo_with_metalink(self, linux_ops):
        """Test parsing .repo file with metalink instead of baseurl."""
        repo_content = """[test-repo]
name=Test Repository
metalink=http://mirrors.example.com/metalink
enabled=1
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["test.repo"]),
            patch(
                _LINUX_REPO_AIOFILES_OPEN,
                return_value=_mock_aiofiles_open(repo_content),
            ),
        ):
            repos = await linux_ops.list_yum_repositories()
            assert len(repos) == 1
            # metalink is not parsed as url currently
            assert repos[0]["url"] == ""

    @pytest.mark.asyncio
    async def test_yum_update_repo_from_line(self, linux_ops):
        """Test _update_repo_from_line helper method."""
        repo = {"name": "test", "url": "", "enabled": True}
        linux_ops._update_repo_from_line(repo, "baseurl=http://example.com")
        assert repo["url"] == "http://example.com"

        linux_ops._update_repo_from_line(repo, "enabled=0")
        assert repo["enabled"] is False

        linux_ops._update_repo_from_line(repo, "enabled=1")
        assert repo["enabled"] is True

    @pytest.mark.asyncio
    async def test_yum_update_repo_from_line_no_equals(self, linux_ops):
        """Test _update_repo_from_line with invalid line."""
        repo = {"name": "test", "url": "", "enabled": True}
        linux_ops._update_repo_from_line(repo, "invalid line without equals")
        # Should not modify the repo
        assert repo["url"] == ""
        assert repo["enabled"] is True


class TestZypperRepositoryParsing:
    """Test Zypper repository parsing functionality."""

    @pytest.mark.asyncio
    async def test_parse_zypper_line_valid(self, linux_ops):
        """Test parsing valid zypper lr line."""
        result = linux_ops._parse_zypper_line(
            "1 | repo-name | Yes | http://example.com/"
        )
        assert result is not None
        assert result["name"] == "repo-name"
        assert result["enabled"] is True
        assert result["url"] == "http://example.com/"

    @pytest.mark.asyncio
    async def test_parse_zypper_line_disabled(self, linux_ops):
        """Test parsing disabled zypper repository."""
        result = linux_ops._parse_zypper_line(
            "1 | repo-name | No | http://example.com/"
        )
        assert result is not None
        assert result["enabled"] is False

    @pytest.mark.asyncio
    async def test_parse_zypper_line_obs(self, linux_ops):
        """Test parsing OBS repository."""
        result = linux_ops._parse_zypper_line(
            "1 | obs-repo | Yes | http://download.opensuse.org/"
        )
        assert result is not None
        assert result["type"] == "OBS"

    @pytest.mark.asyncio
    async def test_parse_zypper_line_comment(self, linux_ops):
        """Test parsing comment line returns None."""
        result = linux_ops._parse_zypper_line("# This is a comment")
        assert result is None

    @pytest.mark.asyncio
    async def test_parse_zypper_line_no_pipe(self, linux_ops):
        """Test parsing line without pipe returns None."""
        result = linux_ops._parse_zypper_line("Some text without pipes")
        assert result is None

    @pytest.mark.asyncio
    async def test_parse_zypper_line_too_few_parts(self, linux_ops):
        """Test parsing line with too few parts returns None."""
        result = linux_ops._parse_zypper_line("1 | repo | Yes")
        assert result is None

    @pytest.mark.asyncio
    async def test_check_obs_url_variations(self, linux_ops):
        """Test OBS URL detection with various URLs."""
        assert linux_ops._check_obs_url("http://download.opensuse.org/") is True
        assert linux_ops._check_obs_url("https://download.opensuse.org/") is True
        assert linux_ops._check_obs_url("http://opensuse.org/") is True
        assert linux_ops._check_obs_url("http://build.opensuse.org/") is True
        assert linux_ops._check_obs_url("http://example.com/") is False
        assert linux_ops._check_obs_url("") is False
        assert linux_ops._check_obs_url("not-a-url") is False


class TestLinuxOperationsRootDetection:
    """Test root user detection in Linux operations."""

    @pytest.mark.asyncio
    async def test_add_apt_repository_as_root(self, linux_ops, mock_agent):
        """Test adding APT repository when running as root."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Repository added", "stderr": ""},
        }
        with patch("os.geteuid", return_value=0, create=True):
            _result = await linux_ops.add_apt_repository("ppa:test/ppa")
            call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
            # Should not have sudo prefix when running as root
            assert not call_args["command"].startswith("sudo")

    @pytest.mark.asyncio
    async def test_add_apt_repository_as_non_root(self, linux_ops, mock_agent):
        """Test adding APT repository when running as non-root."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Repository added", "stderr": ""},
        }
        with patch("os.geteuid", return_value=1000, create=True):
            _result = await linux_ops.add_apt_repository("ppa:test/ppa")
            call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
            # Should have sudo prefix when running as non-root
            assert call_args["command"].startswith("sudo")


class TestDEB822Parsing:
    """Test DEB822 format parsing edge cases."""

    def test_parse_deb822_line_types(self, linux_ops):
        """Test parsing Types: field."""
        entry = {}
        linux_ops._parse_deb822_line("Types: deb deb-src", entry)
        assert entry.get("types") == "deb deb-src"

    def test_parse_deb822_line_uris(self, linux_ops):
        """Test parsing URIs: field."""
        entry = {}
        linux_ops._parse_deb822_line("URIs: http://example.com/", entry)
        assert entry.get("uris") == "http://example.com/"

    def test_parse_deb822_line_suites(self, linux_ops):
        """Test parsing Suites: field."""
        entry = {}
        linux_ops._parse_deb822_line("Suites: focal focal-updates", entry)
        assert entry.get("suites") == "focal focal-updates"

    def test_parse_deb822_line_components(self, linux_ops):
        """Test parsing Components: field."""
        entry = {}
        linux_ops._parse_deb822_line("Components: main contrib non-free", entry)
        assert entry.get("components") == "main contrib non-free"

    def test_parse_deb822_line_enabled_yes(self, linux_ops):
        """Test parsing Enabled: yes."""
        entry = {}
        linux_ops._parse_deb822_line("Enabled: yes", entry)
        assert entry.get("enabled") is True

    def test_parse_deb822_line_enabled_no(self, linux_ops):
        """Test parsing Enabled: no."""
        entry = {}
        linux_ops._parse_deb822_line("Enabled: no", entry)
        assert entry.get("enabled") is False

    def test_parse_deb822_line_no_colon(self, linux_ops):
        """Test parsing line without colon does nothing."""
        entry = {"existing": "value"}
        linux_ops._parse_deb822_line("invalid line", entry)
        assert entry == {"existing": "value"}

    def test_parse_deb822_line_unknown_key(self, linux_ops):
        """Test parsing unknown key is ignored."""
        entry = {}
        linux_ops._parse_deb822_line("SomeOtherKey: value", entry)
        assert not entry

    def test_create_repo_from_deb822_ppa(self, linux_ops):
        """Test creating repo dict from DEB822 PPA entry."""
        entry = {
            "types": "deb",
            "uris": "http://ppa.launchpad.net/user/repo/ubuntu",
            "suites": "focal",
            "components": "main",
            "enabled": True,
        }
        result = linux_ops._create_repo_from_deb822(
            entry, "/etc/apt/sources.list.d/test.sources"
        )
        assert result["type"] == "PPA"
        assert "ppa:user/repo" in result["name"]

    def test_create_repo_from_deb822_non_ppa(self, linux_ops):
        """Test creating repo dict from non-PPA DEB822 entry."""
        entry = {
            "types": "deb",
            "uris": "http://example.com/ubuntu",
            "suites": "focal",
            "components": "main",
            "enabled": True,
        }
        result = linux_ops._create_repo_from_deb822(
            entry, "/etc/apt/sources.list.d/test.sources"
        )
        assert result["type"] == "APT"
        assert result["name"] == "test"
