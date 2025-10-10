"""
Unit tests for OpenTelemetry Operations (opentelemetry_operations.py).
"""

# pylint: disable=protected-access,unused-variable

from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest

from src.sysmanage_agent.operations.opentelemetry_operations import (
    OpenTelemetryOperations,
)


class TestOpenTelemetryOperations:
    """Test suite for OpenTelemetryOperations class."""

    def test_init(self):
        """Test OpenTelemetryOperations initialization."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        assert operations.agent_instance is agent_instance
        assert operations.logger is not None
        assert operations.deployment_helper is not None

    def test_generate_otel_config(self):
        """Test OpenTelemetry configuration generation."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        test_url = "http://grafana.example.com"
        config = operations._generate_otel_config(test_url)

        # Properly parse URL to extract expected values
        parsed = urlparse(test_url)
        expected_host = parsed.hostname or test_url
        expected_endpoint = f"{expected_host}:4317"

        assert "receivers:" in config
        assert "hostmetrics:" in config
        assert expected_endpoint in config

    def test_generate_otel_config_with_port(self):
        """Test OpenTelemetry config generation with custom port."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        test_url = "http://grafana.example.com:9090"
        config = operations._generate_otel_config(test_url)

        # Properly parse URL to extract expected values
        parsed = urlparse(test_url)
        expected_host = parsed.hostname or test_url
        expected_port = parsed.port or 4317
        expected_endpoint = f"{expected_host}:{expected_port}"

        assert expected_endpoint in config

    def test_generate_alloy_config(self):
        """Test Alloy configuration generation."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        test_url = "http://grafana.example.com"
        config = operations._generate_alloy_config(test_url)

        # Properly parse URL to extract expected values
        parsed = urlparse(test_url)
        expected_host = parsed.hostname or test_url
        expected_endpoint = f"{expected_host}:3000"

        assert "otelcol.receiver.hostmetrics" in config
        assert expected_endpoint in config

    def test_generate_alloy_config_with_port(self):
        """Test Alloy config generation with custom port."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        test_url = "http://grafana.example.com:8080"
        config = operations._generate_alloy_config(test_url)

        # Properly parse URL to extract expected values
        parsed = urlparse(test_url)
        expected_host = parsed.hostname or test_url
        expected_port = parsed.port or 3000
        expected_endpoint = f"{expected_host}:{expected_port}"

        assert expected_endpoint in config

    # ========== Deploy Tests ==========

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_no_url(self):
        """Test deployment with no Grafana URL."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        result = await operations.deploy_opentelemetry({})

        assert result["success"] is False
        assert "No Grafana URL" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_linux(self):
        """Test OpenTelemetry deployment on Linux."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations.deployment_helper.deploy_linux = AsyncMock(
                return_value={"success": True, "message": "Deployed"}
            )

            result = await operations.deploy_opentelemetry(
                {"grafana_url": "http://grafana.example.com"}
            )

            assert result["success"] is True
            operations.deployment_helper.deploy_linux.assert_called_once()

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_darwin(self):
        """Test OpenTelemetry deployment on macOS."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Darwin"):
            operations.deployment_helper.deploy_macos = AsyncMock(
                return_value={"success": True, "message": "Deployed"}
            )

            result = await operations.deploy_opentelemetry(
                {"grafana_url": "http://grafana.example.com"}
            )

            assert result["success"] is True
            operations.deployment_helper.deploy_macos.assert_called_once()

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_freebsd(self):
        """Test OpenTelemetry deployment on FreeBSD."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="FreeBSD"):
            operations.deployment_helper.deploy_freebsd = AsyncMock(
                return_value={"success": True, "message": "Deployed"}
            )

            result = await operations.deploy_opentelemetry(
                {"grafana_url": "http://grafana.example.com"}
            )

            assert result["success"] is True
            operations.deployment_helper.deploy_freebsd.assert_called_once()

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_openbsd(self):
        """Test OpenTelemetry deployment on OpenBSD (not supported)."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="OpenBSD"):
            result = await operations.deploy_opentelemetry(
                {"grafana_url": "http://grafana.example.com"}
            )

            assert result["success"] is False
            assert "not currently supported" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_netbsd(self):
        """Test OpenTelemetry deployment on NetBSD (not supported)."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="NetBSD"):
            result = await operations.deploy_opentelemetry(
                {"grafana_url": "http://grafana.example.com"}
            )

            assert result["success"] is False
            assert "not currently supported" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_windows(self):
        """Test OpenTelemetry deployment on Windows."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Windows"):
            operations.deployment_helper.deploy_windows = AsyncMock(
                return_value={"success": True, "message": "Deployed"}
            )

            result = await operations.deploy_opentelemetry(
                {"grafana_url": "http://grafana.example.com"}
            )

            assert result["success"] is True
            operations.deployment_helper.deploy_windows.assert_called_once()

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_unsupported_os(self):
        """Test OpenTelemetry deployment on unsupported OS."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="UnknownOS"):
            result = await operations.deploy_opentelemetry(
                {"grafana_url": "http://grafana.example.com"}
            )

            assert result["success"] is False
            assert "Unsupported operating system" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_exception(self):
        """Test OpenTelemetry deployment with exception."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", side_effect=Exception("Test error")):
            result = await operations.deploy_opentelemetry(
                {"grafana_url": "http://grafana.example.com"}
            )

            assert result["success"] is False
            assert "Test error" in result["error"]

    # ========== Remove Tests ==========

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_linux(self):
        """Test OpenTelemetry removal on Linux."""
        agent_instance = MagicMock()
        agent_instance._send_software_inventory_update = AsyncMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations.deployment_helper.remove_linux = AsyncMock(
                return_value={"success": True, "message": "Removed"}
            )

            result = await operations.remove_opentelemetry({})

            assert result["success"] is True
            operations.deployment_helper.remove_linux.assert_called_once()
            agent_instance._send_software_inventory_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_darwin(self):
        """Test OpenTelemetry removal on macOS."""
        agent_instance = MagicMock()
        agent_instance._send_software_inventory_update = AsyncMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Darwin"):
            operations.deployment_helper.remove_macos = AsyncMock(
                return_value={"success": True, "message": "Removed"}
            )

            result = await operations.remove_opentelemetry({})

            assert result["success"] is True
            operations.deployment_helper.remove_macos.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_freebsd(self):
        """Test OpenTelemetry removal on FreeBSD."""
        agent_instance = MagicMock()
        agent_instance._send_software_inventory_update = AsyncMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="FreeBSD"):
            operations.deployment_helper.remove_bsd = AsyncMock(
                return_value={"success": True, "message": "Removed"}
            )

            result = await operations.remove_opentelemetry({})

            assert result["success"] is True
            operations.deployment_helper.remove_bsd.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_openbsd(self):
        """Test OpenTelemetry removal on OpenBSD."""
        agent_instance = MagicMock()
        agent_instance._send_software_inventory_update = AsyncMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="OpenBSD"):
            operations.deployment_helper.remove_bsd = AsyncMock(
                return_value={"success": True, "message": "Removed"}
            )

            result = await operations.remove_opentelemetry({})

            assert result["success"] is True
            operations.deployment_helper.remove_bsd.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_netbsd(self):
        """Test OpenTelemetry removal on NetBSD."""
        agent_instance = MagicMock()
        agent_instance._send_software_inventory_update = AsyncMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="NetBSD"):
            operations.deployment_helper.remove_bsd = AsyncMock(
                return_value={"success": True, "message": "Removed"}
            )

            result = await operations.remove_opentelemetry({})

            assert result["success"] is True
            operations.deployment_helper.remove_bsd.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_windows(self):
        """Test OpenTelemetry removal on Windows."""
        agent_instance = MagicMock()
        agent_instance._send_software_inventory_update = AsyncMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Windows"):
            operations.deployment_helper.remove_windows = AsyncMock(
                return_value={"success": True, "message": "Removed"}
            )

            result = await operations.remove_opentelemetry({})

            assert result["success"] is True
            operations.deployment_helper.remove_windows.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_unsupported_os(self):
        """Test OpenTelemetry removal on unsupported OS."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="UnknownOS"):
            result = await operations.remove_opentelemetry({})

            assert result["success"] is False
            assert "Unsupported operating system" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_exception(self):
        """Test OpenTelemetry removal with exception."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", side_effect=Exception("Test error")):
            result = await operations.remove_opentelemetry({})

            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_refresh_failure(self):
        """Test OpenTelemetry removal with software refresh failure."""
        agent_instance = MagicMock()
        agent_instance._send_software_inventory_update = AsyncMock(
            side_effect=Exception("Refresh failed")
        )
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations.deployment_helper.remove_linux = AsyncMock(
                return_value={"success": True, "message": "Removed"}
            )

            result = await operations.remove_opentelemetry({})

            # Should still succeed even if refresh fails
            assert result["success"] is True

    # ========== Service Control Tests ==========

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_linux(self):
        """Test starting OpenTelemetry service on Linux."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": True}
            )

            result = await operations.start_opentelemetry_service({})

            assert result["success"] is True
            operations._execute_shell_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_darwin(self):
        """Test starting OpenTelemetry service on macOS."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Darwin"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": True}
            )

            result = await operations.start_opentelemetry_service({})

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_freebsd(self):
        """Test starting OpenTelemetry service on FreeBSD."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="FreeBSD"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": True}
            )

            result = await operations.start_opentelemetry_service({})

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_netbsd(self):
        """Test starting OpenTelemetry service on NetBSD."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="NetBSD"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": True}
            )

            result = await operations.start_opentelemetry_service({})

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_unsupported(self):
        """Test starting OpenTelemetry service on unsupported platform."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="UnknownOS"):
            result = await operations.start_opentelemetry_service({})

            assert result["success"] is False
            assert "Unsupported platform" in result["error"]

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_failure(self):
        """Test starting OpenTelemetry service with failure."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": False, "error": "Command failed"}
            )

            result = await operations.start_opentelemetry_service({})

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_exception(self):
        """Test starting OpenTelemetry service with exception."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", side_effect=Exception("Test error")):
            result = await operations.start_opentelemetry_service({})

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_stop_opentelemetry_service_linux(self):
        """Test stopping OpenTelemetry service on Linux."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": True}
            )

            result = await operations.stop_opentelemetry_service({})

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_opentelemetry_service_failure(self):
        """Test stopping OpenTelemetry service with failure."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": False, "error": "Stop failed"}
            )

            result = await operations.stop_opentelemetry_service({})

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_restart_opentelemetry_service_linux(self):
        """Test restarting OpenTelemetry service on Linux."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": True}
            )

            result = await operations.restart_opentelemetry_service({})

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_opentelemetry_service_failure(self):
        """Test restarting OpenTelemetry service with failure."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("platform.system", return_value="Linux"):
            operations._execute_shell_command = AsyncMock(
                return_value={"success": False, "error": "Restart failed"}
            )

            result = await operations.restart_opentelemetry_service({})

            assert result["success"] is False

    # ========== Grafana Connection Tests ==========

    @pytest.mark.asyncio
    async def test_connect_opentelemetry_grafana_no_url(self):
        """Test connecting OpenTelemetry to Grafana without URL."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        result = await operations.connect_opentelemetry_grafana({})

        assert result["success"] is False
        assert "Grafana URL is required" in result["error"]

    @pytest.mark.asyncio
    async def test_connect_opentelemetry_grafana_success(self):
        """Test successful OpenTelemetry connection to Grafana."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        operations.restart_opentelemetry_service = AsyncMock(
            return_value={"success": True}
        )

        result = await operations.connect_opentelemetry_grafana(
            {"grafana_url": "http://grafana.example.com"}
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_connect_opentelemetry_grafana_failure(self):
        """Test OpenTelemetry connection to Grafana with failure."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        operations.restart_opentelemetry_service = AsyncMock(
            return_value={"success": False, "error": "Restart failed"}
        )

        result = await operations.connect_opentelemetry_grafana(
            {"grafana_url": "http://grafana.example.com"}
        )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_connect_opentelemetry_grafana_exception(self):
        """Test OpenTelemetry connection to Grafana with exception."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        operations.restart_opentelemetry_service = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await operations.connect_opentelemetry_grafana(
            {"grafana_url": "http://grafana.example.com"}
        )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_disconnect_opentelemetry_grafana_success(self):
        """Test successful OpenTelemetry disconnection from Grafana."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        operations.restart_opentelemetry_service = AsyncMock(
            return_value={"success": True}
        )

        result = await operations.disconnect_opentelemetry_grafana({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disconnect_opentelemetry_grafana_failure(self):
        """Test OpenTelemetry disconnection from Grafana with failure."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        operations.restart_opentelemetry_service = AsyncMock(
            return_value={"success": False, "error": "Restart failed"}
        )

        result = await operations.disconnect_opentelemetry_grafana({})

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_disconnect_opentelemetry_grafana_exception(self):
        """Test OpenTelemetry disconnection from Grafana with exception."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        operations.restart_opentelemetry_service = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await operations.disconnect_opentelemetry_grafana({})

        assert result["success"] is False

    # ========== Execute Shell Command Tests ==========

    @pytest.mark.asyncio
    async def test_execute_shell_command_success(self):
        """Test successful shell command execution."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"output", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await operations._execute_shell_command({"command": "echo test"})

            assert result["success"] is True
            assert result["result"]["stdout"] == "output"

    @pytest.mark.asyncio
    async def test_execute_shell_command_failure(self):
        """Test failed shell command execution."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"error")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await operations._execute_shell_command({"command": "false"})

            assert result["success"] is False
            assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_execute_shell_command_no_command(self):
        """Test shell command execution with no command."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        result = await operations._execute_shell_command({})

        assert result["success"] is False
        assert "No command specified" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_shell_command_with_working_dir(self):
        """Test shell command execution with working directory."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await operations._execute_shell_command(
                {"command": "pwd", "working_directory": "/tmp"}
            )

            mock_subprocess.assert_called_once()
            call_kwargs = mock_subprocess.call_args[1]
            assert call_kwargs["cwd"] == "/tmp"

    @pytest.mark.asyncio
    async def test_execute_shell_command_exception(self):
        """Test shell command execution with exception."""
        agent_instance = MagicMock()
        operations = OpenTelemetryOperations(agent_instance)

        with patch(
            "asyncio.create_subprocess_shell", side_effect=Exception("Test error")
        ):
            result = await operations._execute_shell_command({"command": "test"})

            assert result["success"] is False
            assert "Test error" in result["error"]
