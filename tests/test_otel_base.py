"""
Unit tests for OpenTelemetry base module (otel_base.py).
"""

# pylint: disable=protected-access,unused-variable

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.otel_base import OtelDeployerBase


class ConcreteOtelDeployer(OtelDeployerBase):
    """Concrete implementation of OtelDeployerBase for testing."""

    async def deploy(self, grafana_url: str):
        """Concrete deploy implementation."""
        return {"success": True, "message": "Deployed"}

    async def remove(self):
        """Concrete remove implementation."""
        return {"success": True, "message": "Removed"}


class TestOtelDeployerBase:
    """Test suite for OtelDeployerBase class."""

    def test_init(self):
        """Test OtelDeployerBase initialization."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        assert deployer.agent_instance is agent_instance
        assert deployer.logger is not None

    def test_generate_otel_config_basic(self):
        """Test basic OpenTelemetry configuration generation."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_otel_config("http://grafana.example.com")

        assert "receivers:" in config
        assert "hostmetrics:" in config
        assert "exporters:" in config
        assert "otlp:" in config
        assert "grafana.example.com:4317" in config
        assert "insecure: true" in config

    def test_generate_otel_config_with_port(self):
        """Test OpenTelemetry configuration generation with custom port."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_otel_config("http://grafana.example.com:9090")

        assert "grafana.example.com:9090" in config

    def test_generate_otel_config_no_scheme(self):
        """Test OpenTelemetry configuration with URL without scheme."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_otel_config("grafana.example.com")

        assert "grafana.example.com:4317" in config

    def test_generate_otel_config_scrapers(self):
        """Test that all required scrapers are in configuration."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_otel_config("http://grafana.example.com")

        assert "cpu:" in config
        assert "disk:" in config
        assert "filesystem:" in config
        assert "load:" in config
        assert "memory:" in config
        assert "network:" in config

    def test_generate_otel_config_processors(self):
        """Test that processors are configured."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_otel_config("http://grafana.example.com")

        assert "processors:" in config
        assert "batch:" in config
        assert "timeout: 10s" in config

    def test_generate_otel_config_service_pipeline(self):
        """Test that service pipeline is configured."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_otel_config("http://grafana.example.com")

        assert "service:" in config
        assert "pipelines:" in config
        assert "metrics:" in config
        assert "receivers: [hostmetrics]" in config
        assert "processors: [batch]" in config
        assert "exporters: [otlp, debug]" in config

    def test_generate_alloy_config_basic(self):
        """Test basic Grafana Alloy configuration generation."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_alloy_config("http://grafana.example.com")

        assert "otelcol.receiver.hostmetrics" in config
        assert "otelcol.processor.batch" in config
        assert "otelcol.exporter.otlp" in config
        assert "grafana.example.com:3000" in config

    def test_generate_alloy_config_with_port(self):
        """Test Alloy configuration with custom port."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_alloy_config("http://grafana.example.com:8080")

        assert "grafana.example.com:8080" in config

    def test_generate_alloy_config_scrapers(self):
        """Test that all scrapers are in Alloy configuration."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_alloy_config("http://grafana.example.com")

        assert "cpu {}" in config
        assert "disk {}" in config
        assert "filesystem {}" in config
        assert "load {}" in config
        assert "memory {}" in config
        assert "network {}" in config
        assert "paging {}" in config
        assert "process {}" in config

    def test_generate_alloy_config_collection_interval(self):
        """Test that collection interval is set in Alloy config."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_alloy_config("http://grafana.example.com")

        assert 'collection_interval = "30s"' in config

    def test_generate_alloy_config_batch_timeout(self):
        """Test that batch timeout is set in Alloy config."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_alloy_config("http://grafana.example.com")

        assert 'timeout = "10s"' in config

    def test_generate_alloy_config_tls_insecure(self):
        """Test that TLS insecure is set in Alloy config."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        config = deployer._generate_alloy_config("http://grafana.example.com")

        assert "insecure = true" in config

    @pytest.mark.asyncio
    async def test_execute_shell_command_success(self):
        """Test successful shell command execution."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"output", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer._execute_shell_command({"command": "echo test"})

            assert result["success"] is True
            assert result["exit_code"] == 0
            assert result["result"]["stdout"] == "output"
            assert result["result"]["stderr"] == ""

    @pytest.mark.asyncio
    async def test_execute_shell_command_failure(self):
        """Test failed shell command execution."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"error message")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await deployer._execute_shell_command({"command": "false"})

            assert result["success"] is False
            assert result["exit_code"] == 1
            assert result["result"]["stderr"] == "error message"

    @pytest.mark.asyncio
    async def test_execute_shell_command_no_command(self):
        """Test shell command execution with no command specified."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        result = await deployer._execute_shell_command({})

        assert result["success"] is False
        assert "No command specified" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_shell_command_with_working_dir(self):
        """Test shell command execution with working directory."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"output", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer._execute_shell_command(
                {"command": "pwd", "working_directory": "/tmp"}
            )

            mock_subprocess.assert_called_once()
            call_kwargs = mock_subprocess.call_args[1]
            assert call_kwargs["cwd"] == "/tmp"

    @pytest.mark.asyncio
    async def test_execute_shell_command_exception(self):
        """Test shell command execution with exception."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        with patch(
            "asyncio.create_subprocess_shell", side_effect=Exception("Test error")
        ):
            result = await deployer._execute_shell_command({"command": "test"})

            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_abstract_method(self):
        """Test that deploy is properly overridden in concrete class."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        result = await deployer.deploy("http://grafana.example.com")

        assert result["success"] is True
        assert result["message"] == "Deployed"

    @pytest.mark.asyncio
    async def test_remove_abstract_method(self):
        """Test that remove is properly overridden in concrete class."""
        agent_instance = MagicMock()
        deployer = ConcreteOtelDeployer(agent_instance)

        result = await deployer.remove()

        assert result["success"] is True
        assert result["message"] == "Removed"
