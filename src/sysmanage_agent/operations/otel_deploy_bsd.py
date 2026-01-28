"""
BSD-specific OpenTelemetry deployment operations.

This module handles OpenTelemetry collector deployment and removal on BSD systems
(FreeBSD, OpenBSD, NetBSD).
"""

import asyncio
import os
from typing import Any, Dict

import aiofiles

from src.sysmanage_agent.operations.otel_base import OtelDeployerBase

# Module-level constants for SonarQube compliance
_OTEL_REMOVED_SUCCESS = "OpenTelemetry collector removed successfully"


class FreeBSDOtelDeployer(OtelDeployerBase):
    """Handles OpenTelemetry deployment on FreeBSD using Grafana Alloy."""

    async def deploy(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on FreeBSD using Grafana Alloy."""
        try:
            self.logger.info(
                "Installing Grafana Alloy (OpenTelemetry Collector) on FreeBSD"
            )

            # Install Grafana Alloy using pkg
            process = await asyncio.create_subprocess_exec(
                "pkg",
                "install",
                "-y",
                "alloy",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install Grafana Alloy: {stderr.decode()}",
                }

            # Create configuration file for Alloy
            config_file = "/usr/local/etc/alloy/config.alloy"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_alloy_config(grafana_url)
            async with aiofiles.open(config_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(config_content)

            # Enable and start service
            process = await asyncio.create_subprocess_exec(
                "sysrc",
                "alloy_enable=YES",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "service",
                "alloy",
                "start",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": "Grafana Alloy (OpenTelemetry Collector) deployed successfully",
                "config_file": config_file,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}

    async def remove(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from FreeBSD systems."""
        try:
            self.logger.info("Removing OpenTelemetry from FreeBSD system")

            # Stop service
            process = await asyncio.create_subprocess_exec(
                "service",
                "alloy",
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Remove package
            process = await asyncio.create_subprocess_exec(
                "pkg",
                "delete",
                "-y",
                "grafana-alloy",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": _OTEL_REMOVED_SUCCESS,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}


class OpenBSDOtelDeployer(OtelDeployerBase):
    """Handles OpenTelemetry deployment on OpenBSD."""

    async def deploy(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on OpenBSD."""
        try:
            # Install using pkg_add
            process = await asyncio.create_subprocess_exec(
                "pkg_add",
                "opentelemetry-collector",
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
            config_file = "/etc/otelcol/config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_otel_config(grafana_url)
            async with aiofiles.open(config_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(config_content)

            # Enable and start service
            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "enable",
                "otelcol",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "rcctl",
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
        """Remove OpenTelemetry from OpenBSD systems."""
        try:
            self.logger.info("Removing OpenTelemetry from OpenBSD system")

            # Stop service
            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "stop",
                "otelcol",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Disable service
            process = await asyncio.create_subprocess_exec(
                "rcctl",
                "disable",
                "otelcol",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Remove package
            process = await asyncio.create_subprocess_exec(
                "pkg_delete",
                "opentelemetry-collector",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": _OTEL_REMOVED_SUCCESS,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}


class NetBSDOtelDeployer(OtelDeployerBase):
    """Handles OpenTelemetry deployment on NetBSD."""

    async def deploy(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on NetBSD."""
        try:
            # Install using pkgin
            process = await asyncio.create_subprocess_exec(
                "pkgin",
                "-y",
                "install",
                "opentelemetry-collector",
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
            config_file = "/usr/pkg/etc/otelcol/config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            config_content = self._generate_otel_config(grafana_url)
            async with aiofiles.open(config_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(config_content)

            # Enable and start service (NetBSD uses rc.d)
            process = await asyncio.create_subprocess_exec(
                "/etc/rc.d/otelcol",
                "start",
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
        """Remove OpenTelemetry from NetBSD systems."""
        try:
            self.logger.info("Removing OpenTelemetry from NetBSD system")

            # Stop service
            process = await asyncio.create_subprocess_exec(
                "/etc/rc.d/otelcol",
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Remove package
            process = await asyncio.create_subprocess_exec(
                "pkgin",
                "-y",
                "remove",
                "opentelemetry-collector",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": _OTEL_REMOVED_SUCCESS,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}


class BSDOtelDeployer(OtelDeployerBase):
    """Generic BSD deployer that delegates to specific BSD variant deployers."""

    async def deploy(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on BSD systems (delegates to specific variant)."""
        # This is handled by the factory in opentelemetry_operations.py
        return {
            "success": False,
            "error": "BSDOtelDeployer should not be called directly",
        }

    async def remove(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from BSD systems."""
        try:
            self.logger.info("Removing OpenTelemetry from BSD system")

            # Stop service
            process = await asyncio.create_subprocess_exec(
                "service",
                "alloy",
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Remove package
            process = await asyncio.create_subprocess_exec(
                "pkg",
                "delete",
                "-y",
                "grafana-alloy",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            return {
                "success": True,
                "message": _OTEL_REMOVED_SUCCESS,
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}
