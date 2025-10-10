"""
Unit tests for antivirus removal modules.
Tests removal operations for Linux, BSD, and Windows systems.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.antivirus_remove_bsd import AntivirusRemoverBSD
from src.sysmanage_agent.operations.antivirus_remove_linux import (
    AntivirusRemoverLinux,
)
from src.sysmanage_agent.operations.antivirus_remove_windows import (
    AntivirusRemoverWindows,
)


class TestAntivirusRemoverLinux:
    """Test cases for AntivirusRemoverLinux class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.remover = AntivirusRemoverLinux(self.mock_logger)

    @pytest.mark.asyncio
    async def test_remove_opensuse_success(self):
        """Test successful removal on openSUSE."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await self.remover.remove_opensuse()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_opensuse_failure(self):
        """Test removal failure on openSUSE."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Removal failed"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await self.remover.remove_opensuse()

            assert result == "Removal failed"

    @pytest.mark.asyncio
    async def test_remove_debian_success(self):
        """Test successful removal on Debian/Ubuntu."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await self.remover.remove_debian()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_debian_failure(self):
        """Test removal failure on Debian/Ubuntu."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Package not found"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await self.remover.remove_debian()

            assert result == "Package not found"

    @pytest.mark.asyncio
    async def test_remove_redhat_success_dnf(self):
        """Test successful removal on RHEL/CentOS with dnf."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):  # dnf exists
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.remover.remove_redhat()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_redhat_success_yum(self):
        """Test successful removal on RHEL/CentOS with yum."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):  # dnf doesn't exist
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.remover.remove_redhat()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_redhat_failure(self):
        """Test removal failure on RHEL/CentOS."""
        # Stop and disable succeed, remove fails
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Remove failed"))

        with patch("os.path.exists", return_value=True):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_success,
                    mock_process_success,
                    mock_process_fail,
                ],
            ):
                result = await self.remover.remove_redhat()

                assert result == "Remove failed"


class TestAntivirusRemoverBSD:
    """Test cases for AntivirusRemoverBSD class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.remover = AntivirusRemoverBSD(self.mock_logger)

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_no_directory(self):
        """Test cleanup when directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await self.remover._cleanup_clamav_cellar_macos()

            assert result is None

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_no_versions(self):
        """Test cleanup when no version directories."""
        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=[]):
                result = await self.remover._cleanup_clamav_cellar_macos()

                assert result is None

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_success(self):
        """Test successful cleanup."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("os.rmdir") as mock_rmdir:
                        result = await self.remover._cleanup_clamav_cellar_macos()

                        assert result is None
                        mock_rmdir.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_rm_failure(self):
        """Test cleanup with rm failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Permission denied"))

        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await self.remover._cleanup_clamav_cellar_macos()

                    assert result == "Permission denied"

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_rmdir_fails(self):
        """Test cleanup when final rmdir fails."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("os.rmdir", side_effect=OSError("Not empty")):
                        result = await self.remover._cleanup_clamav_cellar_macos()

                        # Should not raise, just return None
                        assert result is None

    @pytest.mark.asyncio
    async def test_remove_macos_success(self):
        """Test successful removal on macOS."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
                return_value=1000,
                create=True,
            ):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.remover.remove_macos()

                        assert result is None

    @pytest.mark.asyncio
    async def test_remove_macos_as_root(self):
        """Test removal on macOS as root."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
                return_value=0,
                create=True,
            ):
                with patch(
                    "src.sysmanage_agent.operations.antivirus_remove_bsd._get_brew_user",
                    return_value="brewuser",
                ):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        with patch("asyncio.sleep", return_value=None):
                            result = await self.remover.remove_macos()

                            assert result is None

    @pytest.mark.asyncio
    async def test_remove_macos_uninstall_fails_cleanup_succeeds(self):
        """Test removal on macOS when uninstall fails but cleanup succeeds."""
        # Stop succeeds, uninstall fails
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
                "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
                return_value=1000,
                create=True,
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    side_effect=[mock_process_stop, mock_process_uninstall],
                ):
                    with patch("asyncio.sleep", return_value=None):
                        with patch.object(
                            self.remover,
                            "_cleanup_clamav_cellar_macos",
                            return_value=None,
                        ):
                            result = await self.remover.remove_macos()

                            assert result is None

    @pytest.mark.asyncio
    async def test_remove_macos_uninstall_and_cleanup_fail(self):
        """Test removal on macOS when both uninstall and cleanup fail."""
        # Stop succeeds, uninstall fails
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
                "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
                return_value=1000,
                create=True,
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    side_effect=[mock_process_stop, mock_process_uninstall],
                ):
                    with patch("asyncio.sleep", return_value=None):
                        with patch.object(
                            self.remover,
                            "_cleanup_clamav_cellar_macos",
                            return_value="Cleanup failed",
                        ):
                            result = await self.remover.remove_macos()

                            assert result == "Uninstall failed"

    @pytest.mark.asyncio
    async def test_remove_netbsd_success(self):
        """Test successful removal on NetBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.remover.remove_netbsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_netbsd_as_root(self):
        """Test removal on NetBSD as root."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.remover.remove_netbsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_netbsd_failure(self):
        """Test removal failure on NetBSD."""
        # Service stops succeed, package removal fails
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(
            return_value=(b"", b"Package not found")
        )

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_success,
                    mock_process_success,
                    mock_process_success,
                    mock_process_fail,
                ],
            ):
                result = await self.remover.remove_netbsd()

                assert result == "Package not found"

    @pytest.mark.asyncio
    async def test_remove_freebsd_success(self):
        """Test successful removal on FreeBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.remover.remove_freebsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_freebsd_as_root(self):
        """Test removal on FreeBSD as root."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.remover.remove_freebsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_freebsd_failure(self):
        """Test removal failure on FreeBSD."""
        # Service operations succeed, package removal fails
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Remove failed"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_success,
                    mock_process_success,
                    mock_process_success,
                    mock_process_success,
                    mock_process_fail,
                ],
            ):
                result = await self.remover.remove_freebsd()

                assert result == "Remove failed"

    @pytest.mark.asyncio
    async def test_remove_openbsd_success(self):
        """Test successful removal on OpenBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.remover.remove_openbsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_openbsd_as_root(self):
        """Test removal on OpenBSD as root."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.remover.remove_openbsd()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_openbsd_failure(self):
        """Test removal failure on OpenBSD."""
        # Service operations succeed, package removal fails
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(
            return_value=(b"", b"Package not found")
        )

        with patch(
            "src.sysmanage_agent.operations.antivirus_remove_bsd.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[
                    mock_process_success,
                    mock_process_success,
                    mock_process_success,
                    mock_process_success,
                    mock_process_fail,
                ],
            ):
                result = await self.remover.remove_openbsd()

                assert result == "Package not found"


class TestAntivirusRemoverWindows:
    """Test cases for AntivirusRemoverWindows class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.remover = AntivirusRemoverWindows(self.mock_logger)

    @pytest.mark.asyncio
    async def test_remove_windows_success_clamwin(self):
        """Test successful removal on Windows with clamwin."""
        # Query succeeds (service exists), stop succeeds, uninstall succeeds
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
            side_effect=[mock_process_query, mock_process_stop, mock_process_uninstall],
        ):
            with patch("asyncio.sleep", return_value=None):
                result = await self.remover.remove_windows()

                assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_no_service(self):
        """Test removal on Windows when service doesn't exist."""
        # Query fails (service doesn't exist), uninstall succeeds
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 0
        mock_process_uninstall.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_query, mock_process_uninstall],
        ):
            result = await self.remover.remove_windows()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_clamwin_fails_clamav_succeeds(self):
        """Test removal on Windows when clamwin fails but clamav succeeds."""
        # Query fails (service doesn't exist)
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        # First uninstall (clamwin) fails
        mock_process_uninstall_fail = AsyncMock()
        mock_process_uninstall_fail.returncode = 1
        mock_process_uninstall_fail.communicate = AsyncMock(
            return_value=(b"", b"Not found")
        )

        # Second uninstall (clamav) succeeds
        mock_process_uninstall_success = AsyncMock()
        mock_process_uninstall_success.returncode = 0
        mock_process_uninstall_success.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[
                mock_process_query,
                mock_process_uninstall_fail,
                mock_process_uninstall_success,
            ],
        ):
            result = await self.remover.remove_windows()

            assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_both_packages_fail(self):
        """Test removal on Windows when both packages fail to uninstall."""
        # Query fails (service doesn't exist)
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 1
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        # Both uninstall attempts fail
        mock_process_uninstall_fail = AsyncMock()
        mock_process_uninstall_fail.returncode = 1
        mock_process_uninstall_fail.communicate = AsyncMock(
            return_value=(b"", b"Uninstall failed")
        )

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[
                mock_process_query,
                mock_process_uninstall_fail,
                mock_process_uninstall_fail,
            ],
        ):
            result = await self.remover.remove_windows()

            assert "Failed to uninstall" in result

    @pytest.mark.asyncio
    async def test_remove_windows_service_stop_failure(self):
        """Test removal on Windows when service stop fails."""
        # Query succeeds, stop fails, uninstall succeeds
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 0
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_stop = AsyncMock()
        mock_process_stop.returncode = 1
        mock_process_stop.communicate = AsyncMock(return_value=(b"", b"Stop failed"))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 0
        mock_process_uninstall.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_query, mock_process_stop, mock_process_uninstall],
        ):
            with patch("asyncio.sleep", return_value=None):
                result = await self.remover.remove_windows()

                # Should still succeed even if stop fails
                assert result is None
