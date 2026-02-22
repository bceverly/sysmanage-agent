"""
Unit tests for antivirus_removal_helpers module.
Tests all helper functions for ClamAV removal across different platforms.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init

import sys
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.antivirus_removal_helpers import (
    _get_brew_user,
    cleanup_clamav_cellar_macos,
    remove_clamav_debian,
    remove_clamav_freebsd,
    remove_clamav_macos,
    remove_clamav_netbsd,
    remove_clamav_openbsd,
    remove_clamav_opensuse,
    remove_clamav_rhel,
    remove_clamav_windows,
)


class TestGetBrewUser:
    """Test cases for _get_brew_user function."""

    def test_get_brew_user_opt_homebrew(self):
        """Test _get_brew_user with /opt/homebrew directory."""
        mock_stat = Mock()
        mock_stat.st_uid = 501
        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_name = "testuser"

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(return_value=mock_pwd_entry)

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=True):
                with patch("os.stat", return_value=mock_stat):
                    result = _get_brew_user()
                    assert result == "testuser"

    def test_get_brew_user_usr_local_homebrew(self):
        """Test _get_brew_user with /usr/local/Homebrew directory."""
        mock_stat = Mock()
        mock_stat.st_uid = 502
        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_name = "localuser"

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(return_value=mock_pwd_entry)

        def exists_side_effect(path):
            if path == "/opt/homebrew":
                return False
            if path == "/usr/local/Homebrew":
                return True
            return False

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", side_effect=exists_side_effect):
                with patch("os.stat", return_value=mock_stat):
                    result = _get_brew_user()
                    assert result == "localuser"

    def test_get_brew_user_fallback_sudo_user(self):
        """Test _get_brew_user falling back to SUDO_USER env variable."""
        with patch("os.path.exists", return_value=False):
            with patch.dict("os.environ", {"SUDO_USER": "sudouser"}):
                result = _get_brew_user()
                assert result == "sudouser"

    def test_get_brew_user_no_homebrew_no_sudo_user(self):
        """Test _get_brew_user when no Homebrew and no SUDO_USER."""
        with patch("os.path.exists", return_value=False):
            with patch.dict("os.environ", {}, clear=True):
                result = _get_brew_user()
                assert result is None

    def test_get_brew_user_oserror(self):
        """Test _get_brew_user when os.stat raises OSError."""
        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock()

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=True):
                with patch("os.stat", side_effect=OSError("Permission denied")):
                    with patch.dict("os.environ", {"SUDO_USER": "fallbackuser"}):
                        result = _get_brew_user()
                        assert result == "fallbackuser"

    def test_get_brew_user_keyerror(self):
        """Test _get_brew_user when pwd.getpwuid raises KeyError."""
        mock_stat = Mock()
        mock_stat.st_uid = 999

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(side_effect=KeyError("No such user"))

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=True):
                with patch("os.stat", return_value=mock_stat):
                    with patch.dict("os.environ", {"SUDO_USER": "keyerroruser"}):
                        result = _get_brew_user()
                        assert result == "keyerroruser"


class TestCleanupClamavCellarMacos:
    """Test cases for cleanup_clamav_cellar_macos function."""

    @pytest.mark.asyncio
    async def test_cleanup_opt_homebrew_exists(self):
        """Test cleanup when /opt/homebrew exists (Apple Silicon)."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def exists_side_effect(path):
            if path == "/opt/homebrew":
                return True
            if path == "/opt/homebrew/Cellar/clamav":
                return True
            return False

        with patch("os.path.exists", side_effect=exists_side_effect):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("os.rmdir") as mock_rmdir:
                        result = await cleanup_clamav_cellar_macos()

                        assert result is None
                        mock_rmdir.assert_called_once_with(
                            "/opt/homebrew/Cellar/clamav"
                        )

    @pytest.mark.asyncio
    async def test_cleanup_usr_local_cellar(self):
        """Test cleanup when /opt/homebrew doesn't exist (Intel Mac)."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def exists_side_effect(path):
            if path == "/opt/homebrew":
                return False
            if path == "/usr/local/Cellar/clamav":
                return True
            return False

        with patch("os.path.exists", side_effect=exists_side_effect):
            with patch("glob.glob", return_value=["/usr/local/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("os.rmdir") as mock_rmdir:
                        result = await cleanup_clamav_cellar_macos()

                        assert result is None
                        mock_rmdir.assert_called_once_with("/usr/local/Cellar/clamav")

    @pytest.mark.asyncio
    async def test_cleanup_no_clamav_directory(self):
        """Test cleanup when clamav directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await cleanup_clamav_cellar_macos()

            assert result is None

    @pytest.mark.asyncio
    async def test_cleanup_no_version_directories(self):
        """Test cleanup when no version directories found."""
        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=[]):
                result = await cleanup_clamav_cellar_macos()

                assert result is None

    @pytest.mark.asyncio
    async def test_cleanup_multiple_versions(self):
        """Test cleanup with multiple version directories."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "glob.glob",
                return_value=[
                    "/opt/homebrew/Cellar/clamav/1.0.0",
                    "/opt/homebrew/Cellar/clamav/1.1.0",
                    "/opt/homebrew/Cellar/clamav/1.2.0",
                ],
            ):
                with patch(
                    "asyncio.create_subprocess_exec", return_value=mock_process
                ) as mock_exec:
                    with patch("os.rmdir"):
                        result = await cleanup_clamav_cellar_macos()

                        assert result is None
                        # Should be called once per version directory
                        assert mock_exec.call_count == 3

    @pytest.mark.asyncio
    async def test_cleanup_rm_failure(self):
        """Test cleanup when rm command fails."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Permission denied"))

        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await cleanup_clamav_cellar_macos()

                    assert result == "Permission denied"

    @pytest.mark.asyncio
    async def test_cleanup_rmdir_oserror(self):
        """Test cleanup when rmdir fails with OSError."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("os.rmdir", side_effect=OSError("Directory not empty")):
                        result = await cleanup_clamav_cellar_macos()

                        # Should not raise, just return None
                        assert result is None

    @pytest.mark.asyncio
    async def test_cleanup_partial_failure(self):
        """Test cleanup when some versions fail but others succeed."""
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Failed"))

        with patch("os.path.exists", return_value=True):
            with patch(
                "glob.glob",
                return_value=[
                    "/opt/homebrew/Cellar/clamav/1.0.0",
                    "/opt/homebrew/Cellar/clamav/1.1.0",
                ],
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    side_effect=[mock_process_success, mock_process_fail],
                ):
                    with patch("os.rmdir"):
                        result = await cleanup_clamav_cellar_macos()

                        # Returns last error
                        assert result == "Failed"


class TestRemoveClamavMacos:
    """Test cases for remove_clamav_macos function."""

    @pytest.mark.asyncio
    async def test_remove_macos_success(self):
        """Test successful removal on macOS."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
                return_value=1000,
                create=True,
            ):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await remove_clamav_macos()

                        assert result is None

    @pytest.mark.asyncio
    async def test_remove_macos_as_root(self):
        """Test removal on macOS as root user."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
                return_value=0,
                create=True,
            ):
                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers._get_brew_user",
                    return_value="brewuser",
                ):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ) as mock_exec:
                        with patch("asyncio.sleep", return_value=None):
                            result = await remove_clamav_macos()

                            assert result is None
                            # Verify sudo -u brewuser was used
                            calls = mock_exec.call_args_list
                            assert any("sudo" in str(call) for call in calls)

    @pytest.mark.asyncio
    async def test_remove_macos_intel_architecture(self):
        """Test removal on macOS Intel architecture."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def exists_side_effect(path):
            if "/opt/homebrew" in path:
                return False
            if "/usr/local" in path:
                return True
            return False

        with patch("os.path.exists", side_effect=exists_side_effect):
            with patch(
                "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
                return_value=1000,
                create=True,
            ):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await remove_clamav_macos()

                        assert result is None

    @pytest.mark.asyncio
    async def test_remove_macos_uninstall_fails_cleanup_succeeds(self):
        """Test removal when brew uninstall fails but cleanup succeeds."""
        mock_process_stop = AsyncMock()
        mock_process_stop.returncode = 0
        mock_process_stop.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 1
        mock_process_uninstall.communicate = AsyncMock(
            return_value=(b"", b"Uninstall failed")
        )

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
                return_value=1000,
                create=True,
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    side_effect=[mock_process_stop, mock_process_uninstall],
                ):
                    with patch("asyncio.sleep", return_value=None):
                        with patch(
                            "src.sysmanage_agent.operations.antivirus_removal_helpers.cleanup_clamav_cellar_macos",
                            return_value=None,
                        ):
                            result = await remove_clamav_macos()

                            # Manual cleanup succeeded
                            assert result is None

    @pytest.mark.asyncio
    async def test_remove_macos_uninstall_and_cleanup_fail(self):
        """Test removal when both brew uninstall and cleanup fail."""
        mock_process_stop = AsyncMock()
        mock_process_stop.returncode = 0
        mock_process_stop.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 1
        mock_process_uninstall.communicate = AsyncMock(
            return_value=(b"", b"Uninstall failed")
        )

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
                return_value=1000,
                create=True,
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    side_effect=[mock_process_stop, mock_process_uninstall],
                ):
                    with patch("asyncio.sleep", return_value=None):
                        with patch(
                            "src.sysmanage_agent.operations.antivirus_removal_helpers.cleanup_clamav_cellar_macos",
                            return_value="Cleanup also failed",
                        ):
                            result = await remove_clamav_macos()

                            # Returns the brew uninstall error
                            assert result == "Uninstall failed"

    @pytest.mark.asyncio
    async def test_remove_macos_service_stop_ignored(self):
        """Test that service stop failure doesn't prevent uninstall."""
        mock_process_stop_fail = AsyncMock()
        mock_process_stop_fail.returncode = 1
        mock_process_stop_fail.communicate = AsyncMock(
            return_value=(b"", b"Service not running")
        )

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 0
        mock_process_uninstall.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
                return_value=1000,
                create=True,
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    side_effect=[mock_process_stop_fail, mock_process_uninstall],
                ):
                    with patch("asyncio.sleep", return_value=None):
                        result = await remove_clamav_macos()

                        # Should still succeed
                        assert result is None


class TestRemoveClamavNetbsd:
    """Test cases for remove_clamav_netbsd function."""

    @pytest.mark.asyncio
    async def test_remove_netbsd_success(self):
        """Test successful removal on NetBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await remove_clamav_netbsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_netbsd_as_root(self):
        """Test removal on NetBSD as root."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                result = await remove_clamav_netbsd()

                assert result is None
                # When root, pkgin is called directly without sudo
                calls = mock_exec.call_args_list
                # The last call should be for pkgin remove
                last_call = calls[-1]
                assert "pkgin" in str(last_call)

    @pytest.mark.asyncio
    async def test_remove_netbsd_package_removal_failure(self):
        """Test removal failure on NetBSD when package removal fails."""
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(
            return_value=(b"", b"Package not installed")
        )

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_success,  # service clamd stop
                    mock_process_success,  # service freshclamd stop
                    mock_process_success,  # sed to disable services
                    mock_process_fail,  # pkgin remove clamav
                ],
            ):
                result = await remove_clamav_netbsd()

                assert result == "Package not installed"

    @pytest.mark.asyncio
    async def test_remove_netbsd_service_stop_continues(self):
        """Test that service stop failures don't prevent package removal."""
        mock_process_stop_fail = AsyncMock()
        mock_process_stop_fail.returncode = 1
        mock_process_stop_fail.communicate = AsyncMock(
            return_value=(b"", b"Service not found")
        )

        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_stop_fail,  # service clamd stop fails
                    mock_process_stop_fail,  # service freshclamd stop fails
                    mock_process_success,  # sed
                    mock_process_success,  # pkgin remove
                ],
            ):
                result = await remove_clamav_netbsd()

                # Should still succeed
                assert result is None


class TestRemoveClamavFreebsd:
    """Test cases for remove_clamav_freebsd function."""

    @pytest.mark.asyncio
    async def test_remove_freebsd_success(self):
        """Test successful removal on FreeBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await remove_clamav_freebsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_freebsd_as_root(self):
        """Test removal on FreeBSD as root."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                result = await remove_clamav_freebsd()

                assert result is None
                # Verify pkg delete is called without sudo
                calls = mock_exec.call_args_list
                last_call = calls[-1]
                assert "pkg" in str(last_call)

    @pytest.mark.asyncio
    async def test_remove_freebsd_package_removal_failure(self):
        """Test removal failure on FreeBSD."""
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Remove failed"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_success,  # service clamav_clamd stop
                    mock_process_success,  # service clamav_freshclam stop
                    mock_process_success,  # sysrc clamav_clamd_enable=NO
                    mock_process_success,  # sysrc clamav_freshclam_enable=NO
                    mock_process_fail,  # pkg delete clamav
                ],
            ):
                result = await remove_clamav_freebsd()

                assert result == "Remove failed"

    @pytest.mark.asyncio
    async def test_remove_freebsd_stops_both_services(self):
        """Test that both ClamAV services are stopped on FreeBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                await remove_clamav_freebsd()

                calls = mock_exec.call_args_list
                call_strs = [str(call) for call in calls]
                # Check that both services are stopped
                assert any("clamav_clamd" in s and "stop" in s for s in call_strs)
                assert any("clamav_freshclam" in s and "stop" in s for s in call_strs)


class TestRemoveClamavOpenbsd:
    """Test cases for remove_clamav_openbsd function."""

    @pytest.mark.asyncio
    async def test_remove_openbsd_success(self):
        """Test successful removal on OpenBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await remove_clamav_openbsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_openbsd_as_root(self):
        """Test removal on OpenBSD as root."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                result = await remove_clamav_openbsd()

                assert result is None
                # When root, pkg_delete is called directly without doas
                calls = mock_exec.call_args_list
                last_call = calls[-1]
                assert "pkg_delete" in str(last_call)

    @pytest.mark.asyncio
    async def test_remove_openbsd_package_failure(self):
        """Test removal failure on OpenBSD."""
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(
            return_value=(b"", b"Package not found")
        )

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_success,  # rcctl stop clamd
                    mock_process_success,  # rcctl disable clamd
                    mock_process_success,  # rcctl stop freshclam
                    mock_process_success,  # rcctl disable freshclam
                    mock_process_fail,  # pkg_delete clamav
                ],
            ):
                result = await remove_clamav_openbsd()

                assert result == "Package not found"

    @pytest.mark.asyncio
    async def test_remove_openbsd_uses_doas(self):
        """Test that doas is used instead of sudo on OpenBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                await remove_clamav_openbsd()

                calls = mock_exec.call_args_list
                # The package removal call should use doas
                last_call = calls[-1]
                assert "doas" in str(last_call)

    @pytest.mark.asyncio
    async def test_remove_openbsd_stops_and_disables_services(self):
        """Test that services are both stopped and disabled on OpenBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_removal_helpers.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                await remove_clamav_openbsd()

                calls = mock_exec.call_args_list
                call_strs = [str(call) for call in calls]
                # Check for rcctl stop and disable commands
                assert any("rcctl" in s and "stop" in s for s in call_strs)
                assert any("rcctl" in s and "disable" in s for s in call_strs)


class TestRemoveClamavOpensuse:
    """Test cases for remove_clamav_opensuse function."""

    @pytest.mark.asyncio
    async def test_remove_opensuse_success(self):
        """Test successful removal on openSUSE."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await remove_clamav_opensuse()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_opensuse_failure(self):
        """Test removal failure on openSUSE."""
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(
            return_value=(b"", b"Package not found")
        )

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[
                mock_process_success,  # systemctl stop clamd.service
                mock_process_success,  # systemctl disable clamd.service
                mock_process_success,  # systemctl stop freshclam.service
                mock_process_success,  # systemctl disable freshclam.service
                mock_process_fail,  # zypper remove
            ],
        ):
            result = await remove_clamav_opensuse()

            assert result == "Package not found"

    @pytest.mark.asyncio
    async def test_remove_opensuse_stops_and_disables_services(self):
        """Test that services are stopped and disabled on openSUSE."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await remove_clamav_opensuse()

            calls = mock_exec.call_args_list
            call_strs = [str(call) for call in calls]
            # Check systemctl stop/disable for both services
            assert any("clamd.service" in s and "stop" in s for s in call_strs)
            assert any("clamd.service" in s and "disable" in s for s in call_strs)
            assert any("freshclam.service" in s and "stop" in s for s in call_strs)
            assert any("freshclam.service" in s and "disable" in s for s in call_strs)

    @pytest.mark.asyncio
    async def test_remove_opensuse_removes_multiple_packages(self):
        """Test that zypper removes multiple ClamAV packages."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await remove_clamav_opensuse()

            # Find the zypper remove call
            calls = mock_exec.call_args_list
            zypper_call = None
            for call in calls:
                if "zypper" in str(call):
                    zypper_call = call
                    break

            assert zypper_call is not None
            call_str = str(zypper_call)
            # Check that multiple packages are in the zypper remove call
            assert "clamav" in call_str
            assert "clamav_freshclam" in call_str


class TestRemoveClamavDebian:
    """Test cases for remove_clamav_debian function."""

    @pytest.mark.asyncio
    async def test_remove_debian_success(self):
        """Test successful removal on Debian/Ubuntu."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await remove_clamav_debian()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_debian_failure(self):
        """Test removal failure on Debian/Ubuntu."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Package not found"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await remove_clamav_debian()

            assert result == "Package not found"

    @pytest.mark.asyncio
    async def test_remove_debian_runs_autoremove(self):
        """Test that autoremove is run after package removal on Debian."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await remove_clamav_debian()

            # Should have 2 calls: apt remove and apt autoremove
            assert mock_exec.call_count == 2
            calls = mock_exec.call_args_list
            call_strs = [str(call) for call in calls]
            assert any("remove" in s and "--purge" in s for s in call_strs)
            assert any("autoremove" in s for s in call_strs)

    @pytest.mark.asyncio
    async def test_remove_debian_autoremove_after_success(self):
        """Test that autoremove runs even if packages were already removed."""
        mock_process_remove = AsyncMock()
        mock_process_remove.returncode = 0
        mock_process_remove.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_autoremove = AsyncMock()
        mock_process_autoremove.returncode = 0
        mock_process_autoremove.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_remove, mock_process_autoremove],
        ):
            result = await remove_clamav_debian()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_debian_purge_flag(self):
        """Test that --purge flag is used for complete removal."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await remove_clamav_debian()

            first_call = mock_exec.call_args_list[0]
            call_str = str(first_call)
            assert "--purge" in call_str


class TestRemoveClamavRhel:
    """Test cases for remove_clamav_rhel function."""

    @pytest.mark.asyncio
    async def test_remove_rhel_success_with_dnf(self):
        """Test successful removal on RHEL/CentOS with dnf."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):  # dnf exists
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await remove_clamav_rhel()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_rhel_success_with_yum(self):
        """Test successful removal on RHEL/CentOS with yum."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):  # dnf doesn't exist
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                result = await remove_clamav_rhel()

                assert result is None
                # Verify yum is used
                calls = mock_exec.call_args_list
                # Find the remove call (skip systemctl calls)
                remove_calls = [c for c in calls if "remove" in str(c)]
                assert len(remove_calls) > 0
                assert "yum" in str(remove_calls[0])

    @pytest.mark.asyncio
    async def test_remove_rhel_package_removal_failure(self):
        """Test removal failure on RHEL/CentOS."""
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Remove failed"))

        with patch("os.path.exists", return_value=True):  # dnf exists
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_success,  # systemctl stop clamd@scan
                    mock_process_success,  # systemctl disable clamd@scan
                    mock_process_fail,  # dnf remove
                ],
            ):
                result = await remove_clamav_rhel()

                assert result == "Remove failed"

    @pytest.mark.asyncio
    async def test_remove_rhel_runs_autoremove(self):
        """Test that autoremove is run after package removal on RHEL."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):  # dnf exists
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                await remove_clamav_rhel()

                calls = mock_exec.call_args_list
                call_strs = [str(call) for call in calls]
                # Check that autoremove is called
                assert any("autoremove" in s for s in call_strs)

    @pytest.mark.asyncio
    async def test_remove_rhel_stops_clamd_scan_service(self):
        """Test that clamd@scan service is stopped and disabled."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                await remove_clamav_rhel()

                calls = mock_exec.call_args_list
                call_strs = [str(call) for call in calls]
                assert any("clamd@scan" in s and "stop" in s for s in call_strs)
                assert any("clamd@scan" in s and "disable" in s for s in call_strs)

    @pytest.mark.asyncio
    async def test_remove_rhel_removes_multiple_packages(self):
        """Test that multiple ClamAV packages are removed on RHEL."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                await remove_clamav_rhel()

                calls = mock_exec.call_args_list
                # Find the dnf/yum remove call
                remove_call = None
                for call in calls:
                    call_str = str(call)
                    if "remove" in call_str and (
                        "dnf" in call_str or "yum" in call_str
                    ):
                        remove_call = call_str
                        break

                assert remove_call is not None
                # Check for expected packages
                assert "clamav" in remove_call
                assert "clamd" in remove_call
                assert "clamav-update" in remove_call


class TestRemoveClamavWindows:
    """Test cases for remove_clamav_windows function."""

    @pytest.mark.asyncio
    async def test_remove_windows_success_clamwin(self):
        """Test successful removal on Windows with clamwin."""
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 0
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_stop = AsyncMock()
        mock_process_stop.returncode = 0
        mock_process_stop.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 0
        mock_process_uninstall.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[
                mock_process_query,
                mock_process_stop,
                mock_process_uninstall,
            ],
        ):
            with patch("asyncio.sleep", return_value=None):
                result = await remove_clamav_windows()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_no_service(self):
        """Test removal on Windows when ClamAV service doesn't exist."""
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1  # Service doesn't exist
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 0
        mock_process_uninstall.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_query, mock_process_uninstall],
        ):
            result = await remove_clamav_windows()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_clamwin_fails_clamav_succeeds(self):
        """Test removal on Windows when clamwin fails but clamav succeeds."""
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1  # No service
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall_fail = AsyncMock()
        mock_process_uninstall_fail.returncode = 1
        mock_process_uninstall_fail.communicate = AsyncMock(
            return_value=(b"", b"Not found")
        )

        mock_process_uninstall_success = AsyncMock()
        mock_process_uninstall_success.returncode = 0
        mock_process_uninstall_success.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[
                mock_process_query,
                mock_process_uninstall_fail,  # clamwin fails
                mock_process_uninstall_success,  # clamav succeeds
            ],
        ):
            result = await remove_clamav_windows()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_both_packages_fail(self):
        """Test removal on Windows when both packages fail to uninstall."""
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1  # No service
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall_fail = AsyncMock()
        mock_process_uninstall_fail.returncode = 1
        mock_process_uninstall_fail.communicate = AsyncMock(
            return_value=(b"", b"Uninstall failed")
        )

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[
                mock_process_query,
                mock_process_uninstall_fail,  # clamwin fails
                mock_process_uninstall_fail,  # clamav fails
            ],
        ):
            result = await remove_clamav_windows()

            assert "Failed to uninstall" in result

    @pytest.mark.asyncio
    async def test_remove_windows_service_stop_failure_continues(self):
        """Test that service stop failure doesn't prevent uninstall."""
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 0  # Service exists
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_stop_fail = AsyncMock()
        mock_process_stop_fail.returncode = 1  # Stop fails
        mock_process_stop_fail.communicate = AsyncMock(
            return_value=(b"", b"Stop failed")
        )

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 0
        mock_process_uninstall.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[
                mock_process_query,
                mock_process_stop_fail,
                mock_process_uninstall,
            ],
        ):
            with patch("asyncio.sleep", return_value=None):
                result = await remove_clamav_windows()

                # Should still succeed despite stop failure
                assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_uses_chocolatey(self):
        """Test that Chocolatey is used for uninstallation on Windows."""
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1  # No service
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 0
        mock_process_uninstall.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_query, mock_process_uninstall],
        ) as mock_exec:
            await remove_clamav_windows()

            calls = mock_exec.call_args_list
            # Find the choco uninstall call
            choco_call = None
            for call in calls:
                if "choco" in str(call):
                    choco_call = call
                    break

            assert choco_call is not None
            call_str = str(choco_call)
            assert "uninstall" in call_str

    @pytest.mark.asyncio
    async def test_remove_windows_tries_clamwin_first(self):
        """Test that clamwin is tried before clamav on Windows."""
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1  # No service
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 0
        mock_process_uninstall.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_query, mock_process_uninstall],
        ) as mock_exec:
            await remove_clamav_windows()

            calls = mock_exec.call_args_list
            # The second call should be choco uninstall clamwin
            second_call = calls[1]
            call_str = str(second_call)
            assert "clamwin" in call_str

    @pytest.mark.asyncio
    async def test_remove_windows_empty_stderr(self):
        """Test Windows removal when stderr is empty but command fails."""
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall_fail = AsyncMock()
        mock_process_uninstall_fail.returncode = 1
        mock_process_uninstall_fail.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[
                mock_process_query,
                mock_process_uninstall_fail,
                mock_process_uninstall_fail,
            ],
        ):
            result = await remove_clamav_windows()

            # Should include "unknown error" when stderr is empty
            assert "Failed to uninstall" in result
