"""Tests for OpenTelemetry base module."""

# pylint: disable=protected-access

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


class TestOtelDeployerBaseInit:
    """Tests for OtelDeployerBase initialization."""

    def test_init_sets_agent_instance(self):
        """Test that agent instance is set correctly."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)
        assert deployer.agent_instance is mock_agent

    def test_init_creates_logger(self):
        """Test that logger is created."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)
        assert deployer.logger is not None


class TestGenerateOtelConfig:
    """Tests for _generate_otel_config method."""

    def test_generate_otel_config_with_port(self):
        """Test config generation with explicit port."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        config = deployer._generate_otel_config("http://grafana.example.com:4317")

        assert "grafana.example.com:4317" in config
        assert "hostmetrics:" in config
        assert "collection_interval: 30s" in config
        assert "otlp:" in config

    def test_generate_otel_config_default_port(self):
        """Test config generation with default port."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        config = deployer._generate_otel_config("http://grafana.example.com")

        assert "grafana.example.com:4317" in config

    def test_generate_otel_config_structure(self):
        """Test that config has required sections."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        config = deployer._generate_otel_config("http://localhost:4317")

        assert "receivers:" in config
        assert "processors:" in config
        assert "exporters:" in config
        assert "service:" in config
        assert "pipelines:" in config
        assert "cpu:" in config
        assert "disk:" in config
        assert "memory:" in config
        assert "network:" in config


class TestGenerateAlloyConfig:
    """Tests for _generate_alloy_config method."""

    def test_generate_alloy_config_with_port(self):
        """Test Alloy config generation with explicit port."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        config = deployer._generate_alloy_config("http://grafana.example.com:3000")

        assert "grafana.example.com:3000" in config
        assert "otelcol.receiver.hostmetrics" in config
        assert "otelcol.processor.batch" in config
        assert "otelcol.exporter.otlp" in config

    def test_generate_alloy_config_default_port(self):
        """Test Alloy config generation with default port."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        config = deployer._generate_alloy_config("http://grafana.example.com")

        assert "grafana.example.com:3000" in config

    def test_generate_alloy_config_structure(self):
        """Test that Alloy config has required components."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        config = deployer._generate_alloy_config("http://localhost")

        assert "collection_interval" in config
        assert "cpu {}" in config
        assert "disk {}" in config
        assert "memory {}" in config
        assert "network {}" in config
        assert "paging {}" in config
        assert "process {}" in config
        assert 'timeout = "10s"' in config
        assert "insecure = true" in config


class TestExecuteShellCommand:
    """Tests for _execute_shell_command method."""

    @pytest.mark.asyncio
    async def test_execute_shell_command_success(self):
        """Test successful command execution."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"output", b""))

        with patch("asyncio.create_subprocess_shell", return_value=mock_process):
            result = await deployer._execute_shell_command({"command": "echo hello"})

            assert result["success"] is True
            assert result["result"]["stdout"] == "output"
            assert result["result"]["stderr"] == ""
            assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_execute_shell_command_failure(self):
        """Test failed command execution."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"error message"))

        with patch("asyncio.create_subprocess_shell", return_value=mock_process):
            result = await deployer._execute_shell_command({"command": "false"})

            assert result["success"] is False
            assert result["result"]["stderr"] == "error message"
            assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_execute_shell_command_no_command(self):
        """Test with no command specified."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        result = await deployer._execute_shell_command({})

        assert result["success"] is False
        assert "No command specified" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_shell_command_with_working_directory(self):
        """Test command execution with working directory."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_shell", return_value=mock_process
        ) as mock_create:
            await deployer._execute_shell_command(
                {"command": "pwd", "working_directory": "/tmp"}
            )

            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["cwd"] == "/tmp"

    @pytest.mark.asyncio
    async def test_execute_shell_command_exception(self):
        """Test handling of exception during command execution."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)

        with patch(
            "asyncio.create_subprocess_shell", side_effect=Exception("Process error")
        ):
            result = await deployer._execute_shell_command({"command": "test"})

            assert result["success"] is False
            assert "Process error" in result["error"]


class TestAbstractMethods:
    """Tests for abstract method behavior."""

    def test_cannot_instantiate_base_class(self):
        """Test that OtelDeployerBase cannot be instantiated directly."""
        mock_agent = MagicMock()
        with pytest.raises(TypeError):
            OtelDeployerBase(mock_agent)  # pylint: disable=abstract-class-instantiated

    @pytest.mark.asyncio
    async def test_deploy_must_be_implemented(self):
        """Test that deploy method works in concrete class."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)
        result = await deployer.deploy("http://localhost")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_must_be_implemented(self):
        """Test that remove method works in concrete class."""
        mock_agent = MagicMock()
        deployer = ConcreteOtelDeployer(mock_agent)
        result = await deployer.remove()
        assert result["success"] is True
