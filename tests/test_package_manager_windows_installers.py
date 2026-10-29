# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Unit tests for src.sysmanage_agent.operations.package_manager_operations:
the Windows package managers (Chocolatey, Scoop) and their installers, which
are downloaded and run as files, never piped into a shell.  Split from
test_package_manager_operations.py (the 1000-line limit).
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.package_manager_operations import (
    PackageManagerOperations,
)


class TestEnableChocolatey:
    """Test cases for _enable_chocolatey method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)
        # The installer script is downloaded first; never from the network here.
        self.ops._download_installer = Mock(
            return_value="/tmp/sysmanage-pm-x/install.ps1"
        )

    @pytest.mark.asyncio
    async def test_enable_chocolatey_non_windows(self):
        """Test enabling chocolatey on non-Windows system."""
        self.ops.system = "Linux"

        result = await self.ops._enable_chocolatey()

        assert result["success"] is False
        assert "Windows" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_chocolatey_already_installed(self):
        """Test enabling chocolatey when already installed."""
        self.ops.system = "Windows"

        with patch(
            "shutil.which", return_value="C:\\ProgramData\\chocolatey\\bin\\choco.exe"
        ):
            result = await self.ops._enable_chocolatey()

            assert result["success"] is True
            assert result.get("already_installed") is True

    @pytest.mark.asyncio
    async def test_enable_chocolatey_install_success(self):
        """Test successful chocolatey installation."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(b"Chocolatey installed", b"")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_chocolatey()

                assert result["success"] is True
                assert "installed successfully" in result["message"]
                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0]
                assert "powershell" in call_args

    @pytest.mark.asyncio
    async def test_enable_chocolatey_install_failure(self):
        """Test failed chocolatey installation."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            mock_process = Mock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(
                return_value=(b"", b"PowerShell error")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_chocolatey()

                assert result["success"] is False
                assert "PowerShell error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_chocolatey_timeout(self):
        """Test chocolatey installation timeout."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_process = Mock()

                async def slow_communicate():
                    await asyncio.sleep(10)
                    return b"", b""

                mock_process.communicate = slow_communicate
                mock_exec.return_value = mock_process

                with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                    result = await self.ops._enable_chocolatey()

                    assert result["success"] is False
                    assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_chocolatey_exception(self):
        """Test chocolatey installation with exception."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=Exception("PowerShell not found"),
            ):
                result = await self.ops._enable_chocolatey()

                assert result["success"] is False
                assert "PowerShell not found" in result["error"]


class TestEnableScoop:
    """Test cases for _enable_scoop method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)
        # The installer script is downloaded first; never from the network here.
        self.ops._download_installer = Mock(
            return_value="/tmp/sysmanage-pm-x/install.ps1"
        )

    @pytest.mark.asyncio
    async def test_enable_scoop_non_windows(self):
        """Test enabling scoop on non-Windows system."""
        self.ops.system = "Darwin"

        result = await self.ops._enable_scoop()

        assert result["success"] is False
        assert "Windows" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_scoop_already_installed(self):
        """Test enabling scoop when already installed."""
        self.ops.system = "Windows"

        with patch(
            "shutil.which", return_value="C:\\Users\\user\\scoop\\shims\\scoop.exe"
        ):
            result = await self.ops._enable_scoop()

            assert result["success"] is True
            assert result.get("already_installed") is True

    @pytest.mark.asyncio
    async def test_enable_scoop_install_success(self):
        """Test successful scoop installation."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Scoop installed", b""))

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_scoop()

                assert result["success"] is True
                assert "installed successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_enable_scoop_install_failure(self):
        """Test failed scoop installation."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            mock_process = Mock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(
                return_value=(b"", b"Installation error")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_scoop()

                assert result["success"] is False
                assert "Installation error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_scoop_timeout(self):
        """Test scoop installation timeout."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_process = Mock()

                async def slow_communicate():
                    await asyncio.sleep(10)
                    return b"", b""

                mock_process.communicate = slow_communicate
                mock_exec.return_value = mock_process

                with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                    result = await self.ops._enable_scoop()

                    assert result["success"] is False
                    assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_scoop_exception(self):
        """Test scoop installation with exception."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=Exception("PowerShell error"),
            ):
                result = await self.ops._enable_scoop()

                assert result["success"] is False
                assert "PowerShell error" in result["error"]


class TestInstallLinuxPackage:
    """Test cases for _install_linux_package method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_install_linux_package_no_package_manager(self):
        """Test installing package when no package manager is available."""
        with patch("shutil.which", return_value=None):
            result = await self.ops._install_linux_package("flatpak", "Flatpak", None)

            assert result["success"] is False
            assert "No supported package manager" in result["error"]

    @pytest.mark.asyncio
    async def test_install_linux_package_success_with_hook(self):
        """Test successful package installation with post-install hook."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(b"Package installed", b"")
            )

            async def mock_post_install():
                pass

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._install_linux_package(
                    "flatpak", "Flatpak", mock_post_install
                )

                assert result["success"] is True
                assert "installed successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_install_linux_package_success_no_hook(self):
        """Test successful package installation without post-install hook."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._install_linux_package("vim", "Vim", None)

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_install_linux_package_failure(self):
        """Test failed package installation."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            mock_process = Mock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(
                return_value=(b"", b"E: Package not found")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._install_linux_package(
                    "nonexistent", "Nonexistent", None
                )

                assert result["success"] is False
                assert "Package not found" in result["error"]

    @pytest.mark.asyncio
    async def test_install_linux_package_timeout(self):
        """Test package installation timeout."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            with patch(
                "src.sysmanage_agent.operations.package_manager_operations._run_package_install"
            ) as mock_run:
                mock_run.side_effect = asyncio.TimeoutError()

                result = await self.ops._install_linux_package("vim", "Vim", None)

                assert result["success"] is False
                assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_install_linux_package_exception(self):
        """Test package installation with exception."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            with patch(
                "src.sysmanage_agent.operations.package_manager_operations._run_package_install"
            ) as mock_run:
                mock_run.side_effect = Exception("Subprocess error")

                result = await self.ops._install_linux_package("vim", "Vim", None)

                assert result["success"] is False
                assert "Subprocess error" in result["error"]


class TestInstallerScriptsRunAsFiles:
    """Chocolatey and Scoop install from their own scripts run with -File,
    never a one-line download-and-Invoke-Expression: Microsoft Defender
    flagged the agent's installer in winget validation (2026-10-28)."""

    def setup_method(self):
        self.ops = PackageManagerOperations(Mock())
        self.ops.system = "Windows"
        self.ops._download_installer = Mock(
            return_value="/tmp/sysmanage-pm-x/install.ps1"
        )

    async def _argv_for(self, enable):
        process = Mock(returncode=0)
        process.communicate = AsyncMock(return_value=(b"ok", b""))
        with patch("shutil.which", return_value=None), patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ) as mock_exec:
            result = await enable()
        assert result["success"] is True
        return list(mock_exec.call_args[0])

    @pytest.mark.asyncio
    async def test_chocolatey_runs_its_downloaded_script(self):
        argv = await self._argv_for(self.ops._enable_chocolatey)
        assert argv[-2:] == ["-File", "/tmp/sysmanage-pm-x/install.ps1"]
        self.ops._download_installer.assert_called_once_with(
            "https://community.chocolatey.org/install.ps1"
        )

    @pytest.mark.asyncio
    async def test_scoop_runs_its_downloaded_script_as_admin(self):
        argv = await self._argv_for(self.ops._enable_scoop)
        assert argv[-3:] == ["-File", "/tmp/sysmanage-pm-x/install.ps1", "-RunAsAdmin"]

    def test_no_download_and_invoke_one_liner_is_left(self):
        import inspect  # pylint: disable=import-outside-toplevel

        from src.sysmanage_agent.operations import (  # pylint: disable=import-outside-toplevel
            package_manager_operations as pmo,
        )

        source = inspect.getsource(pmo)
        for tell in ("DownloadString", "| iex", "iex (", "Invoke-Expression"):
            assert tell not in source, tell
