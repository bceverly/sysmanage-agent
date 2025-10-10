"""
Base module for OpenTelemetry deployment operations.

This module contains common functionality shared across all platform-specific
OpenTelemetry deployment implementations.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict
from urllib.parse import urlparse


class OtelDeployerBase(ABC):
    """Base class for platform-specific OpenTelemetry deployers."""

    def __init__(self, agent_instance):
        """
        Initialize OpenTelemetry deployer with agent instance.

        Args:
            agent_instance: Reference to the main agent instance for accessing
                          agent methods and properties.
        """
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    @abstractmethod
    async def deploy(self, grafana_url: str) -> Dict[str, Any]:
        """
        Deploy OpenTelemetry collector to the system.

        Args:
            grafana_url: URL of the Grafana server to connect to

        Returns:
            Dict with 'success' (bool), 'message' (str), and optionally 'config_file' (str)
        """

    @abstractmethod
    async def remove(self) -> Dict[str, Any]:
        """
        Remove OpenTelemetry collector from the system.

        Returns:
            Dict with 'success' (bool) and 'message' or 'error' (str)
        """

    def _generate_otel_config(self, grafana_url: str) -> str:
        """Generate OpenTelemetry collector configuration."""
        # Parse Grafana URL to extract host and port
        parsed_url = urlparse(grafana_url)
        grafana_host = parsed_url.hostname or grafana_url
        # Use port 4317 for OTLP gRPC (Grafana Alloy default)
        grafana_port = parsed_url.port or 4317

        # Generate a basic OpenTelemetry configuration
        # This sends metrics to Grafana via OTLP
        config = f"""receivers:
  hostmetrics:
    collection_interval: 30s
    scrapers:
      cpu:
      disk:
      filesystem:
      load:
      memory:
      network:

processors:
  batch:
    timeout: 10s

exporters:
  otlp:
    endpoint: "{grafana_host}:{grafana_port}"
    tls:
      insecure: true

  debug:
    verbosity: normal

service:
  pipelines:
    metrics:
      receivers: [hostmetrics]
      processors: [batch]
      exporters: [otlp, debug]
"""
        return config

    def _generate_alloy_config(self, grafana_url: str) -> str:
        """Generate Grafana Alloy configuration for FreeBSD."""
        # Parse Grafana URL
        parsed_url = urlparse(grafana_url)
        grafana_host = parsed_url.hostname or grafana_url
        grafana_port = parsed_url.port or 3000

        # Alloy uses a different configuration format (River)
        config = f"""// Grafana Alloy configuration
otelcol.receiver.hostmetrics "default" {{
  collection_interval = "30s"

  scrapers {{
    cpu {{}}
    disk {{}}
    filesystem {{}}
    load {{}}
    memory {{}}
    network {{}}
    paging {{}}
    process {{}}
  }}

  output {{
    metrics = [otelcol.processor.batch.default.input]
  }}
}}

otelcol.processor.batch "default" {{
  timeout = "10s"

  output {{
    metrics = [otelcol.exporter.otlp.grafana.input]
  }}
}}

otelcol.exporter.otlp "grafana" {{
  client {{
    endpoint = "{grafana_host}:{grafana_port}"
    tls {{
      insecure = true
    }}
  }}
}}
"""
        return config

    async def _execute_shell_command(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a shell command (internal helper method)."""
        command = parameters.get("command")
        working_dir = parameters.get("working_directory")

        if not command:
            return {"success": False, "error": "No command specified"}

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=working_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "result": {
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode(),
                    "exit_code": process.returncode,
                },
                "exit_code": process.returncode,
            }
        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}
