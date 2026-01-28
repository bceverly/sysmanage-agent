"""
macOS-specific OpenTelemetry deployment operations.

This module handles OpenTelemetry collector deployment and removal on macOS
using Homebrew package manager.
"""

import asyncio
import os
from typing import Any, Dict

import aiofiles

from src.sysmanage_agent.operations.otel_base import OtelDeployerBase


class MacOSOtelDeployer(OtelDeployerBase):
    """Handles OpenTelemetry deployment on macOS systems."""

    async def deploy(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on macOS using Homebrew."""
        try:
            self.logger.info("Installing OpenTelemetry collector using Homebrew")

            # Install using Homebrew
            process = await asyncio.create_subprocess_exec(
                "brew",
                "install",
                "opentelemetry-collector-contrib",
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
            config_file = "/usr/local/etc/otelcol-contrib/config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_otel_config(grafana_url)
            async with aiofiles.open(config_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(config_content)

            # Start service
            process = await asyncio.create_subprocess_exec(
                "brew",
                "services",
                "start",
                "opentelemetry-collector-contrib",
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
        """Remove OpenTelemetry from macOS systems."""
        try:
            self.logger.info("Removing OpenTelemetry from macOS system")

            # Stop service if running
            process = await asyncio.create_subprocess_exec(
                "brew",
                "services",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Uninstall package
            process = await asyncio.create_subprocess_exec(
                "brew",
                "uninstall",
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
