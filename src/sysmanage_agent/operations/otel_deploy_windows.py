"""
Windows-specific OpenTelemetry deployment operations.

This module handles OpenTelemetry collector deployment and removal on Windows
using Chocolatey package manager.
"""

import asyncio
import os
from typing import Any, Dict

from src.sysmanage_agent.operations.otel_base import OtelDeployerBase


class WindowsOtelDeployer(OtelDeployerBase):
    """Handles OpenTelemetry deployment on Windows systems."""

    async def deploy(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on Windows using Chocolatey."""
        try:
            self.logger.info("Installing OpenTelemetry collector using Chocolatey")

            # Install using Chocolatey
            process = await asyncio.create_subprocess_exec(
                "choco",
                "install",
                "opentelemetry-collector-contrib",
                "-y",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install OpenTelemetry collector: {stderr.decode()}",
                }

            # Create configuration file
            config_file = "C:\\Program Files\\OpenTelemetry Collector\\config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_otel_config(grafana_url)
            with open(config_file, "w", encoding="utf-8") as file_handle:
                file_handle.write(config_content)

            # Start service using sc.exe
            process = await asyncio.create_subprocess_exec(
                "sc",
                "start",
                "otelcol",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_file,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}

    async def remove(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from Windows systems."""
        try:
            self.logger.info("Removing OpenTelemetry from Windows system")

            # Stop service
            process = await asyncio.create_subprocess_exec(
                "sc",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Delete service
            process = await asyncio.create_subprocess_exec(
                "sc",
                "delete",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "OpenTelemetry collector removed successfully",
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}
