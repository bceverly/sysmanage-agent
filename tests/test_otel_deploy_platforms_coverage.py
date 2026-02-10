"""Tests for platform-specific OpenTelemetry deployment modules."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.otel_deploy_macos import MacOSOtelDeployer
from src.sysmanage_agent.operations.otel_deploy_windows import WindowsOtelDeployer


class TestMacOSOtelDeployerDeploy:
    """Tests for MacOS OpenTelemetry deployment."""

    @pytest.mark.asyncio
    async def test_deploy_success(self):
        """Test successful OpenTelemetry deployment on macOS."""
        mock_agent = MagicMock()
        deployer = MacOSOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_file = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_file.write = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("os.makedirs"):
                with patch("aiofiles.open", return_value=mock_file):
                    result = await deployer.deploy("http://grafana.example.com:4317")

                    assert result["success"] is True
                    assert "deployed successfully" in result["message"]
                    assert "config_file" in result

    @pytest.mark.asyncio
    async def test_deploy_install_failure(self):
        """Test deployment failure during brew install."""
        mock_agent = MagicMock()
        deployer = MacOSOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"brew install failed"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Failed to install" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_exception(self):
        """Test deployment with exception."""
        mock_agent = MagicMock()
        deployer = MacOSOtelDeployer(mock_agent)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Unexpected error")
        ):
            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Unexpected error" in result["error"]


class TestMacOSOtelDeployerRemove:
    """Tests for MacOS OpenTelemetry removal."""

    @pytest.mark.asyncio
    async def test_remove_success(self):
        """Test successful OpenTelemetry removal on macOS."""
        mock_agent = MagicMock()
        deployer = MacOSOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await deployer.remove()

            assert result["success"] is True
            assert "removed successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_remove_exception(self):
        """Test removal with exception."""
        mock_agent = MagicMock()
        deployer = MacOSOtelDeployer(mock_agent)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Remove error")
        ):
            result = await deployer.remove()

            assert result["success"] is False
            assert "Remove error" in result["error"]


class TestWindowsOtelDeployerDeploy:
    """Tests for Windows OpenTelemetry deployment."""

    @pytest.mark.asyncio
    async def test_deploy_success(self):
        """Test successful OpenTelemetry deployment on Windows."""
        mock_agent = MagicMock()
        deployer = WindowsOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_file = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_file.write = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("os.makedirs"):
                with patch("aiofiles.open", return_value=mock_file):
                    result = await deployer.deploy("http://grafana.example.com:4317")

                    assert result["success"] is True
                    assert "deployed successfully" in result["message"]
                    assert "config_file" in result

    @pytest.mark.asyncio
    async def test_deploy_install_failure(self):
        """Test deployment failure during choco install."""
        mock_agent = MagicMock()
        deployer = WindowsOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"choco install failed")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Failed to install" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_exception(self):
        """Test deployment with exception."""
        mock_agent = MagicMock()
        deployer = WindowsOtelDeployer(mock_agent)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Unexpected error")
        ):
            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Unexpected error" in result["error"]


class TestWindowsOtelDeployerRemove:
    """Tests for Windows OpenTelemetry removal."""

    @pytest.mark.asyncio
    async def test_remove_success(self):
        """Test successful OpenTelemetry removal on Windows."""
        mock_agent = MagicMock()
        deployer = WindowsOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await deployer.remove()

            assert result["success"] is True
            assert "removed successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_remove_exception(self):
        """Test removal with exception."""
        mock_agent = MagicMock()
        deployer = WindowsOtelDeployer(mock_agent)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Remove error")
        ):
            result = await deployer.remove()

            assert result["success"] is False
            assert "Remove error" in result["error"]
