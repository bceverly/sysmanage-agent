"""
OpenTelemetry Operations Module for SysManage Agent

This module handles all OpenTelemetry-related operations including:
- Deployment of OpenTelemetry collector across multiple platforms
- Removal of OpenTelemetry collector
- Service control (start, stop, restart)
- Configuration management
- Grafana integration
"""

import asyncio
import logging
import platform
from typing import Any, Dict
from urllib.parse import urlparse

from src.i18n import _
from .otel_deployment_helper import OtelDeploymentHelper


class OpenTelemetryOperations:
    """Handles OpenTelemetry collector deployment, management, and removal operations."""

    def __init__(self, agent_instance):
        """Initialize OpenTelemetry operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)
        self.deployment_helper = OtelDeploymentHelper(agent_instance, self.logger)

    async def deploy_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy OpenTelemetry collector to the system."""
        try:
            grafana_url = parameters.get("grafana_url")
            if not grafana_url:
                return {
                    "success": False,
                    "error": "No Grafana URL provided for OpenTelemetry deployment",
                }

            self.logger.info(
                "Deploying OpenTelemetry collector with Grafana URL: %s", grafana_url
            )
            system = platform.system().lower()

            if system == "linux":
                return await self.deployment_helper.deploy_linux(
                    grafana_url, self._generate_otel_config
                )
            if system == "darwin":
                return await self.deployment_helper.deploy_macos(
                    grafana_url, self._generate_otel_config
                )
            if system == "freebsd":
                return await self.deployment_helper.deploy_freebsd(
                    grafana_url, self._generate_alloy_config
                )
            if system in ["openbsd", "netbsd"]:
                return {
                    "success": False,
                    "error": f"OpenTelemetry deployment on {system.upper()} is not currently supported. Manual installation required.",
                }
            if system == "windows":
                return await self.deployment_helper.deploy_windows(
                    grafana_url, self._generate_otel_config
                )
            return {
                "success": False,
                "error": f"Unsupported operating system for OpenTelemetry deployment: {system}",
            }

        except Exception as error:
            self.logger.error("Failed to deploy OpenTelemetry: %s", str(error))
            return {
                "success": False,
                "error": f"Failed to deploy OpenTelemetry: {str(error)}",
            }

    async def remove_opentelemetry(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove OpenTelemetry collector from the system."""
        try:
            self.logger.info("Starting OpenTelemetry removal")
            system = platform.system().lower()

            if system == "linux":
                removal_result = await self.deployment_helper.remove_linux()
            elif system == "darwin":
                removal_result = await self.deployment_helper.remove_macos()
            elif system in ["freebsd", "openbsd", "netbsd"]:
                removal_result = await self.deployment_helper.remove_bsd()
            elif system == "windows":
                removal_result = await self.deployment_helper.remove_windows()
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operating system: {system}",
                }

            if removal_result.get("success"):
                self.logger.info(
                    "OpenTelemetry removed successfully, triggering software refresh"
                )
                try:
                    await self.agent_instance._send_software_inventory_update()  # pylint: disable=protected-access
                except Exception as refresh_error:
                    self.logger.warning(
                        "Failed to refresh software inventory: %s", str(refresh_error)
                    )

            return removal_result

        except Exception as error:
            self.logger.error("Failed to remove OpenTelemetry: %s", str(error))
            return {
                "success": False,
                "error": f"Failed to remove OpenTelemetry: {str(error)}",
            }

    def _generate_otel_config(self, grafana_url: str) -> str:
        """Generate OpenTelemetry collector configuration."""
        parsed_url = urlparse(grafana_url)
        grafana_host = parsed_url.hostname or grafana_url
        grafana_port = parsed_url.port or 4317

        return f"""receivers:
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

    def _generate_alloy_config(self, grafana_url: str) -> str:
        """Generate Grafana Alloy configuration for FreeBSD."""
        parsed_url = urlparse(grafana_url)
        grafana_host = parsed_url.hostname or grafana_url
        grafana_port = parsed_url.port or 3000

        return f"""// Grafana Alloy configuration
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

    async def start_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Start OpenTelemetry service."""
        # pylint: disable=unused-argument
        try:
            self.logger.info(_("Starting OpenTelemetry service..."))

            if platform.system() == "Linux":
                command = "sudo systemctl start otelcol-contrib"
            elif platform.system() == "Darwin":
                command = "sudo brew services start otelcol-contrib"
            elif platform.system() == "FreeBSD":
                command = "sudo service otelcol start"
            elif platform.system() == "NetBSD":
                command = "sudo /etc/rc.d/otelcol start"
            else:
                return {
                    "success": False,
                    "error": _(
                        "Unsupported platform for OpenTelemetry service control"
                    ),
                }

            result = await self._execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info(_("OpenTelemetry service started successfully"))
                return {
                    "success": True,
                    "result": _("OpenTelemetry service started successfully"),
                }

            self.logger.error(
                _("Failed to start OpenTelemetry service: %s"),
                result.get("error", "Unknown error"),
            )
            return {
                "success": False,
                "error": _("Failed to start OpenTelemetry service: %s")
                % result.get("error", "Unknown error"),
            }
        except Exception as error:
            self.logger.error(_("Error starting OpenTelemetry service: %s"), error)
            return {"success": False, "error": str(error)}

    async def stop_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stop OpenTelemetry service."""
        # pylint: disable=unused-argument
        try:
            self.logger.info(_("Stopping OpenTelemetry service..."))

            if platform.system() == "Linux":
                command = "sudo systemctl stop otelcol-contrib"
            elif platform.system() == "Darwin":
                command = "sudo brew services stop otelcol-contrib"
            elif platform.system() == "FreeBSD":
                command = "sudo service otelcol stop"
            elif platform.system() == "NetBSD":
                command = "sudo /etc/rc.d/otelcol stop"
            else:
                return {
                    "success": False,
                    "error": _(
                        "Unsupported platform for OpenTelemetry service control"
                    ),
                }

            result = await self._execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info(_("OpenTelemetry service stopped successfully"))
                return {
                    "success": True,
                    "result": _("OpenTelemetry service stopped successfully"),
                }

            self.logger.error(
                _("Failed to stop OpenTelemetry service: %s"),
                result.get("error", "Unknown error"),
            )
            return {
                "success": False,
                "error": _("Failed to stop OpenTelemetry service: %s")
                % result.get("error", "Unknown error"),
            }
        except Exception as error:
            self.logger.error(_("Error stopping OpenTelemetry service: %s"), error)
            return {"success": False, "error": str(error)}

    async def restart_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Restart OpenTelemetry service."""
        # pylint: disable=unused-argument
        try:
            self.logger.info(_("Restarting OpenTelemetry service..."))

            if platform.system() == "Linux":
                command = "sudo systemctl restart otelcol-contrib"
            elif platform.system() == "Darwin":
                command = "sudo brew services restart otelcol-contrib"
            elif platform.system() == "FreeBSD":
                command = "sudo service otelcol restart"
            elif platform.system() == "NetBSD":
                command = "sudo /etc/rc.d/otelcol restart"
            else:
                return {
                    "success": False,
                    "error": _(
                        "Unsupported platform for OpenTelemetry service control"
                    ),
                }

            result = await self._execute_shell_command({"command": command})

            if result["success"]:
                self.logger.info(_("OpenTelemetry service restarted successfully"))
                return {
                    "success": True,
                    "result": _("OpenTelemetry service restarted successfully"),
                }

            self.logger.error(
                _("Failed to restart OpenTelemetry service: %s"),
                result.get("error", "Unknown error"),
            )
            return {
                "success": False,
                "error": _("Failed to restart OpenTelemetry service: %s")
                % result.get("error", "Unknown error"),
            }
        except Exception as error:
            self.logger.error(_("Error restarting OpenTelemetry service: %s"), error)
            return {"success": False, "error": str(error)}

    async def connect_opentelemetry_grafana(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Connect OpenTelemetry to Grafana server."""
        grafana_url = parameters.get("grafana_url")

        if not grafana_url:
            return {"success": False, "error": _("Grafana URL is required")}

        try:
            self.logger.info(
                _("Connecting OpenTelemetry to Grafana at %s"), grafana_url
            )
            restart_result = await self.restart_opentelemetry_service(parameters)

            if restart_result["success"]:
                self.logger.info(_("OpenTelemetry connected to Grafana successfully"))
                return {
                    "success": True,
                    "result": _("OpenTelemetry connected to Grafana successfully"),
                }

            return restart_result
        except Exception as error:
            self.logger.error(_("Error connecting OpenTelemetry to Grafana: %s"), error)
            return {"success": False, "error": str(error)}

    async def disconnect_opentelemetry_grafana(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disconnect OpenTelemetry from Grafana server."""
        try:
            self.logger.info(_("Disconnecting OpenTelemetry from Grafana"))
            restart_result = await self.restart_opentelemetry_service(parameters)

            if restart_result["success"]:
                self.logger.info(
                    _("OpenTelemetry disconnected from Grafana successfully")
                )
                return {
                    "success": True,
                    "result": _("OpenTelemetry disconnected from Grafana successfully"),
                }

            return restart_result
        except Exception as error:
            self.logger.error(
                _("Error disconnecting OpenTelemetry from Grafana: %s"), error
            )
            return {"success": False, "error": str(error)}

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
        except Exception as error:
            return {"success": False, "error": str(error)}
