"""Tests for antivirus removal modules."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.antivirus_remove_linux import AntivirusRemoverLinux
from src.sysmanage_agent.operations.antivirus_remove_windows import (
    AntivirusRemoverWindows,
)


class TestAntivirusRemoverLinuxInit:
    """Tests for AntivirusRemoverLinux initialization."""

    def test_init_sets_logger(self):
        """Test that logger is set correctly."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverLinux(mock_logger)
        assert remover.logger is mock_logger


class TestAntivirusRemoverLinuxOpenSUSE:
    """Tests for openSUSE antivirus removal."""

    @pytest.mark.asyncio
    async def test_remove_opensuse_success(self):
        """Test successful ClamAV removal from openSUSE."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverLinux(mock_logger)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await remover.remove_opensuse()
            assert result is None

    @pytest.mark.asyncio
    async def test_remove_opensuse_failure(self):
        """Test failed ClamAV removal from openSUSE."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverLinux(mock_logger)

        call_count = 0

        async def mock_communicate():
            return (b"", b"Error removing package")

        def create_mock_process(*_args, **_kwargs):
            nonlocal call_count
            mock_process = AsyncMock()
            call_count += 1
            # First 4 calls are for systemctl stop/disable, last is zypper
            if call_count <= 4:
                mock_process.returncode = 0
            else:
                mock_process.returncode = 1
            mock_process.communicate = mock_communicate
            return mock_process

        with patch("asyncio.create_subprocess_exec", side_effect=create_mock_process):
            result = await remover.remove_opensuse()
            assert result == "Error removing package"


class TestAntivirusRemoverLinuxDebian:
    """Tests for Debian/Ubuntu antivirus removal."""

    @pytest.mark.asyncio
    async def test_remove_debian_success(self):
        """Test successful ClamAV removal from Debian/Ubuntu."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverLinux(mock_logger)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await remover.remove_debian()
            assert result is None

    @pytest.mark.asyncio
    async def test_remove_debian_failure(self):
        """Test failed ClamAV removal from Debian/Ubuntu."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverLinux(mock_logger)

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"apt error"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await remover.remove_debian()
            assert result == "apt error"


class TestAntivirusRemoverLinuxRedHat:
    """Tests for RHEL/CentOS antivirus removal."""

    @pytest.mark.asyncio
    async def test_remove_redhat_with_dnf_success(self):
        """Test successful ClamAV removal using dnf."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverLinux(mock_logger)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):  # dnf exists
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await remover.remove_redhat()
                assert result is None

    @pytest.mark.asyncio
    async def test_remove_redhat_with_yum_success(self):
        """Test successful ClamAV removal using yum."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverLinux(mock_logger)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):  # dnf doesn't exist
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await remover.remove_redhat()
                assert result is None

    @pytest.mark.asyncio
    async def test_remove_redhat_failure(self):
        """Test failed ClamAV removal from RHEL/CentOS."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverLinux(mock_logger)

        call_count = 0

        async def mock_communicate():
            return (b"", b"yum error")

        def create_mock_process(*_args, **_kwargs):
            nonlocal call_count
            mock_process = AsyncMock()
            call_count += 1
            # First 2 calls are for systemctl, 3rd is remove (fails)
            if call_count <= 2:
                mock_process.returncode = 0
            else:
                mock_process.returncode = 1
            mock_process.communicate = mock_communicate
            return mock_process

        with patch("os.path.exists", return_value=True):
            with patch(
                "asyncio.create_subprocess_exec", side_effect=create_mock_process
            ):
                result = await remover.remove_redhat()
                assert result == "yum error"


class TestAntivirusRemoverWindowsInit:
    """Tests for AntivirusRemoverWindows initialization."""

    def test_init_sets_logger(self):
        """Test that logger is set correctly."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverWindows(mock_logger)
        assert remover.logger is mock_logger


class TestAntivirusRemoverWindowsRemove:
    """Tests for Windows antivirus removal."""

    @pytest.mark.asyncio
    async def test_remove_windows_clamwin_success(self):
        """Test successful ClamWin removal from Windows."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverWindows(mock_logger)

        call_count = 0

        def create_mock_process(*_args, **_kwargs):
            nonlocal call_count
            mock_process = AsyncMock()
            call_count += 1
            # First call is sc query (service doesn't exist)
            if call_count == 1:
                mock_process.returncode = 1
            # Second call is choco uninstall clamwin (success)
            else:
                mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            return mock_process

        with patch("asyncio.create_subprocess_exec", side_effect=create_mock_process):
            result = await remover.remove_windows()
            assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_service_exists(self):
        """Test Windows removal when service exists."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverWindows(mock_logger)

        call_count = 0

        def create_mock_process(*_args, **_kwargs):
            nonlocal call_count
            mock_process = AsyncMock()
            call_count += 1
            # All calls succeed
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            return mock_process

        with patch("asyncio.create_subprocess_exec", side_effect=create_mock_process):
            with patch("asyncio.sleep", return_value=None):
                result = await remover.remove_windows()
                assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_clamav_fallback(self):
        """Test fallback to clamav package when clamwin fails."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverWindows(mock_logger)

        call_count = 0

        def create_mock_process(*_args, **_kwargs):
            nonlocal call_count
            mock_process = AsyncMock()
            call_count += 1
            # sc query fails (no service)
            if call_count == 1:
                mock_process.returncode = 1
            # choco uninstall clamwin fails
            elif call_count == 2:
                mock_process.returncode = 1
            # choco uninstall clamav succeeds
            else:
                mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            return mock_process

        with patch("asyncio.create_subprocess_exec", side_effect=create_mock_process):
            result = await remover.remove_windows()
            assert result is None

    @pytest.mark.asyncio
    async def test_remove_windows_all_fail(self):
        """Test Windows removal when all attempts fail."""
        mock_logger = MagicMock()
        remover = AntivirusRemoverWindows(mock_logger)

        call_count = 0

        def create_mock_process(*_args, **_kwargs):
            nonlocal call_count
            mock_process = AsyncMock()
            call_count += 1
            # sc query fails
            if call_count == 1:
                mock_process.returncode = 1
                mock_process.communicate = AsyncMock(return_value=(b"", b""))
            # All choco uninstalls fail
            else:
                mock_process.returncode = 1
                mock_process.communicate = AsyncMock(
                    return_value=(b"", b"uninstall failed")
                )
            return mock_process

        with patch("asyncio.create_subprocess_exec", side_effect=create_mock_process):
            result = await remover.remove_windows()
            assert result is not None
            assert "Failed to uninstall" in result
