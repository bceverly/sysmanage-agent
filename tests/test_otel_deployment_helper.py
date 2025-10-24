"""
Unit tests for OpenTelemetry Deployment Helper (otel_deployment_helper.py).
"""

# pylint: disable=protected-access,unused-argument

from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from src.sysmanage_agent.operations.otel_deployment_helper import OtelDeploymentHelper


class TestOtelDeploymentHelper:
    """Test suite for OtelDeploymentHelper class."""

    def test_init(self):
        """Test OtelDeploymentHelper initialization."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        assert helper.agent_instance is agent_instance
        assert helper.logger is logger

    # ========== Removal Tests ==========

    @pytest.mark.asyncio
    async def test_remove_linux_success(self):
        """Test successful Linux removal."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.path.exists", return_value=True),
            patch("shutil.rmtree"),
        ):
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.remove_linux()

            assert result["success"] is True
            assert "successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_remove_linux_with_apt(self):
        """Test Linux removal with apt package manager."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.path.exists") as mock_exists,
            patch("shutil.rmtree"),
        ):
            mock_exists.side_effect = lambda path: path in [
                "/usr/bin/apt",
                "/etc/otelcol-contrib",
            ]

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.remove_linux()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_linux_with_dnf(self):
        """Test Linux removal with dnf package manager."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.path.exists") as mock_exists,
            patch("shutil.rmtree"),
        ):
            mock_exists.side_effect = lambda path: path in [
                "/usr/bin/dnf",
                "/etc/otelcol-contrib",
            ]

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.remove_linux()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_linux_with_yum(self):
        """Test Linux removal with yum package manager."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.path.exists") as mock_exists,
            patch("shutil.rmtree"),
        ):
            mock_exists.side_effect = lambda path: path in [
                "/usr/bin/yum",
                "/etc/otelcol-contrib",
            ]

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.remove_linux()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_linux_exception(self):
        """Test Linux removal with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await helper.remove_linux()

            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_macos_success(self):
        """Test successful macOS removal."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.remove_macos()

            assert result["success"] is True
            assert "successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_remove_macos_exception(self):
        """Test macOS removal with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await helper.remove_macos()

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_remove_bsd_success(self):
        """Test successful BSD removal."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.remove_bsd()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_bsd_exception(self):
        """Test BSD removal with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await helper.remove_bsd()

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_remove_windows_success(self):
        """Test successful Windows removal."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.remove_windows()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_windows_exception(self):
        """Test Windows removal with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await helper.remove_windows()

            assert result["success"] is False

    # ========== Deployment Tests ==========

    @pytest.mark.asyncio
    async def test_deploy_linux_with_apt(self):
        """Test Linux deployment with apt."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with (
            patch("os.path.exists") as mock_exists,
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.makedirs"),
            patch("builtins.open", mock_open()),
            patch("tempfile.NamedTemporaryFile") as mock_tempfile,
            patch("os.unlink"),
            patch("os.chmod"),
        ):
            mock_exists.side_effect = lambda path: path == "/usr/bin/apt"

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"fake deb content", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            # Mock temp file
            mock_temp = MagicMock()
            mock_temp.name = "/tmp/test.deb"
            mock_temp.__enter__ = MagicMock(return_value=mock_temp)
            mock_temp.__exit__ = MagicMock(return_value=False)
            mock_tempfile.return_value = mock_temp

            result = await helper.deploy_linux(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is True
            assert "config_file" in result

    @pytest.mark.asyncio
    async def test_deploy_linux_with_yum_dnf(self):
        """Test Linux deployment with yum/dnf."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with (
            patch("os.path.exists") as mock_exists,
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.makedirs"),
            patch("builtins.open", mock_open()),
            patch("os.chmod"),
        ):
            mock_exists.side_effect = lambda path: path == "/usr/bin/yum"

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.deploy_linux(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_linux_no_package_manager(self):
        """Test Linux deployment with no package manager."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with patch("os.path.exists", return_value=False):
            result = await helper.deploy_linux(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is False
            assert "No supported package manager" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_linux_exception(self):
        """Test Linux deployment with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with patch("os.path.exists", side_effect=Exception("Test error")):
            result = await helper.deploy_linux(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_apt_download_empty(self):
        """Test apt deployment with empty download."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with (
            patch("os.path.exists") as mock_exists,
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
        ):
            mock_exists.side_effect = lambda path: path == "/usr/bin/apt"

            call_count = [0]

            async def side_effect(*args, **kwargs):
                mock_process = AsyncMock()
                if call_count[0] == 0:
                    # Prerequisites install
                    mock_process.communicate.return_value = (b"", b"")
                    mock_process.returncode = 0
                else:
                    # Download returns empty
                    mock_process.communicate.return_value = (b"", b"")
                    mock_process.returncode = 0
                call_count[0] += 1
                return mock_process

            mock_subprocess.side_effect = side_effect

            result = await helper.deploy_linux(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_macos_success(self):
        """Test successful macOS deployment."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.makedirs"),
            patch("builtins.open", mock_open()),
        ):
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.deploy_macos(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is True
            assert "config_file" in result

    @pytest.mark.asyncio
    async def test_deploy_macos_install_failure(self):
        """Test macOS deployment with install failure."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"Install failed")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await helper.deploy_macos(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_macos_exception(self):
        """Test macOS deployment with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await helper.deploy_macos(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_freebsd_success(self):
        """Test successful FreeBSD deployment."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        alloy_config_generator = MagicMock(return_value="test alloy config")

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.makedirs"),
            patch("builtins.open", mock_open()),
        ):
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.deploy_freebsd(
                "http://grafana.example.com", alloy_config_generator
            )

            assert result["success"] is True
            assert result["config_file"] == "/usr/local/etc/alloy/config.alloy"

    @pytest.mark.asyncio
    async def test_deploy_freebsd_install_failure(self):
        """Test FreeBSD deployment with install failure."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        alloy_config_generator = MagicMock(return_value="test alloy config")

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"Install failed")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await helper.deploy_freebsd(
                "http://grafana.example.com", alloy_config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_freebsd_exception(self):
        """Test FreeBSD deployment with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        alloy_config_generator = MagicMock(return_value="test alloy config")

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await helper.deploy_freebsd(
                "http://grafana.example.com", alloy_config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_windows_success(self):
        """Test successful Windows deployment."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("os.makedirs"),
            patch("builtins.open", mock_open()),
        ):
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await helper.deploy_windows(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_windows_install_failure(self):
        """Test Windows deployment with install failure."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"Install failed")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await helper.deploy_windows(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_deploy_windows_exception(self):
        """Test Windows deployment with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await helper.deploy_windows(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_linux_config_success(self):
        """Test successful Linux config creation."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config content")

        with (
            patch("os.makedirs"),
            patch("builtins.open", mock_open()),
            patch("os.chmod"),
        ):
            result = await helper._create_linux_config(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is True
            assert result["config_file"] == "/etc/otelcol-contrib/config.yaml"
            config_generator.assert_called_once_with("http://grafana.example.com")

    @pytest.mark.asyncio
    async def test_create_linux_config_exception(self):
        """Test Linux config creation with exception."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)
        config_generator = MagicMock(return_value="test config")

        with patch("os.makedirs", side_effect=Exception("Test error")):
            result = await helper._create_linux_config(
                "http://grafana.example.com", config_generator
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_start_linux_service(self):
        """Test starting Linux service."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            await helper._start_linux_service()

            # Verify all three systemctl commands were called
            assert mock_subprocess.call_count >= 3

    @pytest.mark.asyncio
    async def test_run_package_remove(self):
        """Test package removal helper method."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            await helper._run_package_remove("dnf")

            mock_subprocess.assert_called_once()
            call_args = mock_subprocess.call_args[0]
            assert "dnf" in call_args
            assert "remove" in call_args

    @pytest.mark.asyncio
    async def test_run_apt_remove(self):
        """Test apt removal helper method."""
        agent_instance = MagicMock()
        logger = MagicMock()
        helper = OtelDeploymentHelper(agent_instance, logger)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            await helper._run_apt_remove()

            # Should be called twice (remove and purge)
            assert mock_subprocess.call_count == 2
