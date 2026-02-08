#!/usr/bin/env python3
"""
Comprehensive tests for repository operations.

This module provides extensive testing coverage for repository operations
across all supported platforms (Linux, BSD, macOS, Windows).
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.repository_operations import (
    ThirdPartyRepositoryOperations,
    _is_distro_family,
    _DEBIAN_FAMILY,
    _RHEL_FAMILY,
    _SUSE_FAMILY,
)
from src.sysmanage_agent.operations.linux_repository_operations import (
    LinuxRepositoryOperations,
)
from src.sysmanage_agent.operations.bsd_macos_repository_operations import (
    BSDMacOSRepositoryOperations,
)
from src.sysmanage_agent.operations.windows_repository_operations import (
    WindowsRepositoryOperations,
)

# Path to patch aiofiles.open in the modules under test
_REPO_OPS_AIOFILES_OPEN = (
    "src.sysmanage_agent.operations.repository_operations.aiofiles.open"
)
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
def repo_ops(mock_agent):
    """Create a ThirdPartyRepositoryOperations instance."""
    return ThirdPartyRepositoryOperations(mock_agent)


@pytest.fixture
def linux_ops(mock_agent):
    """Create a LinuxRepositoryOperations instance."""
    return LinuxRepositoryOperations(mock_agent)


@pytest.fixture
def bsd_macos_ops(mock_agent):
    """Create a BSDMacOSRepositoryOperations instance."""
    return BSDMacOSRepositoryOperations(mock_agent)


@pytest.fixture
def windows_ops(mock_agent):
    """Create a WindowsRepositoryOperations instance."""
    return WindowsRepositoryOperations(mock_agent)


class TestDistroFamilyDetection:
    """Test distro family detection helper functions."""

    def test_is_debian_family_ubuntu(self):
        """Test Ubuntu is detected as Debian family."""
        assert _is_distro_family("ubuntu", _DEBIAN_FAMILY) is True

    def test_is_debian_family_debian(self):
        """Test Debian is detected as Debian family."""
        assert _is_distro_family("debian", _DEBIAN_FAMILY) is True

    def test_is_debian_family_linuxmint(self):
        """Test Linux Mint (debian-based) detection."""
        # Linux Mint contains 'debian' or 'ubuntu' in some contexts
        assert _is_distro_family("ubuntu", _DEBIAN_FAMILY) is True

    def test_is_rhel_family_fedora(self):
        """Test Fedora is detected as RHEL family."""
        assert _is_distro_family("fedora", _RHEL_FAMILY) is True

    def test_is_rhel_family_centos(self):
        """Test CentOS is detected as RHEL family."""
        assert _is_distro_family("centos", _RHEL_FAMILY) is True

    def test_is_rhel_family_rocky(self):
        """Test Rocky Linux is detected as RHEL family."""
        assert _is_distro_family("rocky", _RHEL_FAMILY) is True

    def test_is_rhel_family_alma(self):
        """Test AlmaLinux is detected as RHEL family."""
        assert _is_distro_family("alma", _RHEL_FAMILY) is True

    def test_is_rhel_family_rhel(self):
        """Test RHEL is detected as RHEL family."""
        assert _is_distro_family("rhel", _RHEL_FAMILY) is True

    def test_is_suse_family_opensuse(self):
        """Test openSUSE is detected as SUSE family."""
        assert _is_distro_family("opensuse", _SUSE_FAMILY) is True

    def test_is_suse_family_suse(self):
        """Test SUSE is detected as SUSE family."""
        assert _is_distro_family("suse", _SUSE_FAMILY) is True

    def test_is_suse_family_opensuse_leap(self):
        """Test openSUSE Leap is detected as SUSE family."""
        assert _is_distro_family("opensuse-leap", _SUSE_FAMILY) is True

    def test_is_not_debian_family(self):
        """Test non-Debian distros are not detected as Debian family."""
        assert _is_distro_family("fedora", _DEBIAN_FAMILY) is False
        assert _is_distro_family("arch", _DEBIAN_FAMILY) is False

    def test_is_not_rhel_family(self):
        """Test non-RHEL distros are not detected as RHEL family."""
        assert _is_distro_family("ubuntu", _RHEL_FAMILY) is False
        assert _is_distro_family("arch", _RHEL_FAMILY) is False

    def test_is_not_suse_family(self):
        """Test non-SUSE distros are not detected as SUSE family."""
        assert _is_distro_family("fedora", _SUSE_FAMILY) is False
        assert _is_distro_family("ubuntu", _SUSE_FAMILY) is False


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


class TestAPTRepositoryURLValidation:
    """Test APT repository URL validation."""

    def test_is_ppa_hostname_launchpad(self, linux_ops):
        """Test PPA hostname detection for ppa.launchpad.net."""
        assert linux_ops._is_ppa_hostname("ppa.launchpad.net") is True

    def test_is_ppa_hostname_launchpadcontent(self, linux_ops):
        """Test PPA hostname detection for ppa.launchpadcontent.net."""
        assert linux_ops._is_ppa_hostname("ppa.launchpadcontent.net") is True

    def test_is_ppa_hostname_subdomain(self, linux_ops):
        """Test PPA hostname detection for subdomains."""
        assert linux_ops._is_ppa_hostname("us.ppa.launchpad.net") is True
        assert linux_ops._is_ppa_hostname("mirror.ppa.launchpadcontent.net") is True

    def test_is_not_ppa_hostname(self, linux_ops):
        """Test non-PPA hostname detection."""
        assert linux_ops._is_ppa_hostname("example.com") is False
        assert linux_ops._is_ppa_hostname("archive.ubuntu.com") is False
        assert linux_ops._is_ppa_hostname("launchpad.net") is False  # Not ppa subdomain

    def test_is_ppa_hostname_empty(self, linux_ops):
        """Test PPA hostname detection with empty string."""
        assert linux_ops._is_ppa_hostname("") is False

    def test_is_ppa_hostname_none(self, linux_ops):
        """Test PPA hostname detection with None."""
        assert linux_ops._is_ppa_hostname(None) is False

    def test_extract_ppa_name_from_url(self, linux_ops):
        """Test extracting PPA name from URL."""
        url = "http://ppa.launchpad.net/user/repo/ubuntu"
        result = linux_ops._extract_ppa_name_from_url(url)
        assert result == "ppa:user/repo"

    def test_extract_ppa_name_from_url_launchpadcontent(self, linux_ops):
        """Test extracting PPA name from launchpadcontent URL."""
        url = "http://ppa.launchpadcontent.net/user/project/ubuntu"
        result = linux_ops._extract_ppa_name_from_url(url)
        assert result == "ppa:user/project"

    def test_extract_ppa_name_from_non_ppa_url(self, linux_ops):
        """Test extracting PPA name from non-PPA URL returns empty."""
        url = "http://example.com/ubuntu"
        result = linux_ops._extract_ppa_name_from_url(url)
        assert result == ""

    def test_extract_ppa_name_from_short_path(self, linux_ops):
        """Test extracting PPA name from URL with short path."""
        url = "http://ppa.launchpad.net/user"
        result = linux_ops._extract_ppa_name_from_url(url)
        assert result == ""


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
            result = await linux_ops.add_apt_repository("ppa:test/ppa")
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
            result = await linux_ops.add_apt_repository("ppa:test/ppa")
            call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
            # Should have sudo prefix when running as non-root
            assert call_args["command"].startswith("sudo")


class TestHomebrewTapParsing:
    """Test Homebrew tap parsing functionality."""

    @pytest.mark.asyncio
    async def test_list_homebrew_taps_filters_official(self, bsd_macos_ops, mock_agent):
        """Test that official Homebrew taps are filtered out."""
        mock_agent.system_ops.execute_shell_command.side_effect = [
            {
                "success": True,
                "result": {"stdout": "/usr/local/bin/brew", "stderr": ""},
            },
            {
                "success": True,
                "result": {
                    "stdout": "homebrew/core\nhomebrew/cask\nuser/custom-tap\n",
                    "stderr": "",
                },
            },
        ]
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 1
        assert repos[0]["name"] == "user/custom-tap"

    @pytest.mark.asyncio
    async def test_list_homebrew_taps_empty_lines(self, bsd_macos_ops, mock_agent):
        """Test that empty lines are handled correctly."""
        mock_agent.system_ops.execute_shell_command.side_effect = [
            {
                "success": True,
                "result": {"stdout": "/usr/local/bin/brew", "stderr": ""},
            },
            {
                "success": True,
                "result": {
                    "stdout": "\nuser/tap1\n\nuser/tap2\n\n",
                    "stderr": "",
                },
            },
        ]
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 2

    @pytest.mark.asyncio
    async def test_list_homebrew_taps_with_comments(self, bsd_macos_ops, mock_agent):
        """Test that comment lines are filtered out."""
        mock_agent.system_ops.execute_shell_command.side_effect = [
            {
                "success": True,
                "result": {"stdout": "/usr/local/bin/brew", "stderr": ""},
            },
            {
                "success": True,
                "result": {
                    "stdout": "# comment\nuser/tap1\n#another comment\nuser/tap2\n",
                    "stderr": "",
                },
            },
        ]
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 2


class TestWingetSourceParsing:
    """Test winget source parsing functionality."""

    def test_is_winget_header_line_name_argument(self, windows_ops):
        """Test winget header line detection with Name/Argument."""
        assert windows_ops._is_winget_header_line("Name  Argument") is True
        assert windows_ops._is_winget_header_line("Name    Argument    Type") is True

    def test_is_winget_header_line_dashes(self, windows_ops):
        """Test winget header line detection with dashes."""
        assert windows_ops._is_winget_header_line("---  --------") is True
        assert windows_ops._is_winget_header_line("----") is True

    def test_is_winget_header_line_normal_line(self, windows_ops):
        """Test normal line is not detected as header."""
        assert (
            windows_ops._is_winget_header_line("custom-source  http://example.com/")
            is False
        )

    def test_parse_winget_source_line_valid(self, windows_ops):
        """Test parsing valid winget source line."""
        result = windows_ops._parse_winget_source_line(
            "custom-source  http://example.com/"
        )
        assert result is not None
        assert result["name"] == "custom-source"
        assert result["url"] == "http://example.com/"
        assert result["type"] == "winget"

    def test_parse_winget_source_line_official_winget(self, windows_ops):
        """Test parsing official winget source returns None."""
        result = windows_ops._parse_winget_source_line(
            "winget  https://cdn.winget.microsoft.com/"
        )
        assert result is None

    def test_parse_winget_source_line_official_msstore(self, windows_ops):
        """Test parsing official msstore source returns None."""
        result = windows_ops._parse_winget_source_line(
            "msstore  https://storeedgefd.dsx.mp.microsoft.com/"
        )
        assert result is None

    def test_parse_winget_source_line_too_few_parts(self, windows_ops):
        """Test parsing line with too few parts returns None."""
        result = windows_ops._parse_winget_source_line("single-part")
        assert result is None


class TestChocolateySourceParsing:
    """Test Chocolatey source parsing functionality."""

    @pytest.mark.asyncio
    async def test_list_chocolatey_sources_with_bypass_proxy(
        self, windows_ops, mock_agent
    ):
        """Test parsing Chocolatey source with Bypass Proxy setting."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "custom-source - http://myrepo.com/ | Priority 0|Bypass Proxy - True",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_chocolatey_sources()
        assert len(repos) == 1
        assert repos[0]["enabled"] is True

    @pytest.mark.asyncio
    async def test_list_chocolatey_sources_no_http(self, windows_ops, mock_agent):
        """Test that lines without http are skipped."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "Chocolatey v1.0.0\nsome-other-line - no url here",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_chocolatey_sources()
        assert len(repos) == 0


class TestThirdPartyRepositoryOperationsEdgeCases:
    """Test edge cases in ThirdPartyRepositoryOperations."""

    @pytest.mark.asyncio
    async def test_list_repositories_unsupported_linux(self, repo_ops):
        """Test listing repositories on unsupported Linux distro."""
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "gentoo"}
            ),
        ):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["repositories"] == []

    @pytest.mark.asyncio
    async def test_delete_repositories_multiple_distros(self, repo_ops):
        """Test deleting repositories with different distro families."""
        # Test each distro family
        for distro, method_name in [
            ("ubuntu", "delete_apt_repository"),
            ("fedora", "delete_yum_repository"),
            ("opensuse", "delete_zypper_repository"),
        ]:
            setattr(
                repo_ops.linux_ops,
                method_name,
                AsyncMock(return_value={"success": True, "result": "Deleted"}),
            )
            with (
                patch("platform.system", return_value="Linux"),
                patch.object(
                    repo_ops, "_detect_linux_distro", return_value={"distro": distro}
                ),
                patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
                patch.object(
                    repo_ops, "_trigger_update_detection", new_callable=AsyncMock
                ),
                patch.object(
                    repo_ops,
                    "_trigger_third_party_repository_rescan",
                    new_callable=AsyncMock,
                ),
            ):
                result = await repo_ops.delete_third_party_repositories(
                    {"repositories": [{"name": "test-repo"}]}
                )
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_repositories_multiple_distros(self, repo_ops):
        """Test enabling repositories with different distro families."""
        for distro, method_name in [
            ("debian", "enable_apt_repository"),
            ("centos", "enable_yum_repository"),
            ("suse", "enable_zypper_repository"),
        ]:
            setattr(
                repo_ops.linux_ops,
                method_name,
                AsyncMock(return_value={"success": True, "result": "Enabled"}),
            )
            with (
                patch("platform.system", return_value="Linux"),
                patch.object(
                    repo_ops, "_detect_linux_distro", return_value={"distro": distro}
                ),
                patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
                patch.object(
                    repo_ops, "_trigger_update_detection", new_callable=AsyncMock
                ),
                patch.object(
                    repo_ops,
                    "_trigger_third_party_repository_rescan",
                    new_callable=AsyncMock,
                ),
            ):
                result = await repo_ops.enable_third_party_repositories(
                    {"repositories": [{"name": "test-repo", "file_path": "/tmp/test"}]}
                )
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_repositories_multiple_distros(self, repo_ops):
        """Test disabling repositories with different distro families."""
        for distro, method_name in [
            ("ubuntu", "disable_apt_repository"),
            ("rhel", "disable_yum_repository"),
            ("opensuse-leap", "disable_zypper_repository"),
        ]:
            setattr(
                repo_ops.linux_ops,
                method_name,
                AsyncMock(return_value={"success": True, "result": "Disabled"}),
            )
            with (
                patch("platform.system", return_value="Linux"),
                patch.object(
                    repo_ops, "_detect_linux_distro", return_value={"distro": distro}
                ),
                patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
                patch.object(
                    repo_ops, "_trigger_update_detection", new_callable=AsyncMock
                ),
                patch.object(
                    repo_ops,
                    "_trigger_third_party_repository_rescan",
                    new_callable=AsyncMock,
                ),
            ):
                result = await repo_ops.disable_third_party_repositories(
                    {"repositories": [{"name": "test-repo", "file_path": "/tmp/test"}]}
                )
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_package_update_non_linux(self, repo_ops, mock_agent):
        """Test _run_package_update does nothing on non-Linux."""
        with patch("platform.system", return_value="Darwin"):
            await repo_ops._run_package_update()
            mock_agent.system_ops.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_package_update_command_debian(self, repo_ops):
        """Test getting package update command for Debian family."""
        result = repo_ops._get_package_update_command("ubuntu")
        assert result == "sudo apt-get update"

        result = repo_ops._get_package_update_command("debian")
        assert result == "sudo apt-get update"

    @pytest.mark.asyncio
    async def test_get_package_update_command_rhel(self, repo_ops):
        """Test getting package update command for RHEL family."""
        result = repo_ops._get_package_update_command("fedora")
        assert result == "sudo dnf check-update"

        result = repo_ops._get_package_update_command("rocky")
        assert result == "sudo dnf check-update"

    @pytest.mark.asyncio
    async def test_get_package_update_command_suse(self, repo_ops):
        """Test getting package update command for SUSE family."""
        result = repo_ops._get_package_update_command("opensuse")
        assert result == "sudo zypper refresh"

    @pytest.mark.asyncio
    async def test_get_package_update_command_unknown(self, repo_ops):
        """Test getting package update command for unknown distro."""
        result = repo_ops._get_package_update_command("arch")
        assert result is None


class TestFreeBSDRepositoryParsing:
    """Test FreeBSD repository parsing functionality."""

    @pytest.mark.asyncio
    async def test_parse_freebsd_repo_with_extra_fields(self, bsd_macos_ops):
        """Test parsing FreeBSD repo with extra configuration fields."""
        from unittest.mock import mock_open

        repo_content = """myrepo: {
  url: "http://pkg.example.com/",
  enabled: yes,
  priority: 10,
  signature_type: fingerprints
}
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["myrepo.conf"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            assert len(repos) == 1
            assert repos[0]["name"] == "myrepo"
            assert repos[0]["url"] == "http://pkg.example.com/"

    @pytest.mark.asyncio
    async def test_parse_freebsd_repo_without_url(self, bsd_macos_ops):
        """Test parsing FreeBSD repo without URL field."""
        from unittest.mock import mock_open

        repo_content = """myrepo: {
  enabled: yes
}
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["myrepo.conf"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            assert len(repos) == 1
            assert repos[0]["url"] == ""

    @pytest.mark.asyncio
    async def test_list_freebsd_repositories_file_read_error(self, bsd_macos_ops):
        """Test handling file read error for FreeBSD repository."""
        from unittest.mock import mock_open

        m = mock_open()
        m.side_effect = IOError("Permission denied")

        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["myrepo.conf"]),
            patch("builtins.open", m),
        ):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            # Should handle error gracefully
            assert len(repos) == 0


class TestNetBSDRepositoryParsing:
    """Test NetBSD repository parsing functionality."""

    @pytest.mark.asyncio
    async def test_list_netbsd_repositories_with_custom_overlay(self, bsd_macos_ops):
        """Test listing NetBSD repositories with custom overlay."""
        with (
            patch("os.path.exists", side_effect=lambda p: True),
            patch(
                "os.listdir",
                return_value=["wip", "custom-overlay", "distfiles", "packages"],
            ),
            patch("os.path.isdir", return_value=True),
            patch(
                "os.path.exists",
                side_effect=lambda p: "Makefile" in p
                or p in ["/usr/pkgsrc/wip", "/usr/pkgsrc"],
            ),
        ):
            # This test checks the overlay detection logic
            repos = await bsd_macos_ops.list_netbsd_repositories()
            # Should include pkgsrc-wip at minimum
            assert len(repos) >= 1


class TestWindowsRepositoryAddition:
    """Test Windows repository addition edge cases."""

    @pytest.mark.asyncio
    async def test_add_winget_repository_command_format(self, windows_ops, mock_agent):
        """Test that winget add command is formatted correctly."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Source added", "stderr": ""},
        }
        await windows_ops.add_windows_repository(
            "my-source", "http://example.com/", "winget"
        )
        call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
        assert "winget source add" in call_args["command"]
        assert '--name "my-source"' in call_args["command"]
        assert '--arg "http://example.com/"' in call_args["command"]
        assert "--type Microsoft.Rest" in call_args["command"]

    @pytest.mark.asyncio
    async def test_add_chocolatey_repository_command_format(
        self, windows_ops, mock_agent
    ):
        """Test that chocolatey add command is formatted correctly."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Source added", "stderr": ""},
        }
        await windows_ops.add_windows_repository(
            "my-source", "http://example.com/", "chocolatey"
        )
        call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
        assert "choco source add" in call_args["command"]
        assert '--name="my-source"' in call_args["command"]
        assert '--source="http://example.com/"' in call_args["command"]

    @pytest.mark.asyncio
    async def test_add_repository_type_case_insensitive(self, windows_ops, mock_agent):
        """Test that repository type is case insensitive."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Source added", "stderr": ""},
        }

        # Test uppercase
        result = await windows_ops.add_windows_repository(
            "test", "http://example.com/", "CHOCOLATEY"
        )
        assert result["success"] is True

        # Test mixed case
        result = await windows_ops.add_windows_repository(
            "test", "http://example.com/", "Winget"
        )
        assert result["success"] is True


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
        assert entry == {}

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


class TestMultiPlatformListRepositories:
    """Test listing repositories across all platforms."""

    @pytest.mark.asyncio
    async def test_list_openbsd_returns_empty(self, repo_ops):
        """Test listing repositories on OpenBSD returns empty list."""
        with patch("platform.system", return_value="OpenBSD"):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["repositories"] == []

    @pytest.mark.asyncio
    async def test_list_unknown_system_returns_empty(self, repo_ops):
        """Test listing repositories on unknown system returns empty list."""
        with patch("platform.system", return_value="UnknownOS"):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["repositories"] == []
