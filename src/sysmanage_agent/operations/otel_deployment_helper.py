#!/usr/bin/env python3
"""
OpenTelemetry Deployment and Removal Helper Module

This module contains all platform-specific deployment and removal logic
for OpenTelemetry collectors across Linux, macOS, BSD, and Windows.
"""

import asyncio
import os
import shutil
import tempfile
from typing import Any, Dict

import aiofiles

# Module-level constants for SonarQube compliance
_DNF_PATH = "/usr/bin/dnf"
_OTEL_REMOVED_SUCCESS = "OpenTelemetry collector removed successfully"
_OTEL_DEPLOYED_SUCCESS = "OpenTelemetry collector deployed successfully"


class OtelDeploymentHelper:
    """Helper class for OpenTelemetry deployment and removal operations."""

    def __init__(self, agent_instance, logger):
        """Initialize with agent instance and logger."""
        self.agent_instance = agent_instance
        self.logger = logger

    # ========== Removal Methods ==========

    async def remove_linux(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from Linux systems."""
        try:
            self.logger.info("Removing OpenTelemetry from Linux system")

            # Stop and disable service
            for action in ["stop", "disable"]:
                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    action,
                    "otelcol-contrib",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

            # Remove package based on package manager
            if os.path.exists("/usr/bin/apt"):
                await self._run_apt_remove()
            elif os.path.exists(_DNF_PATH):
                await self._run_package_remove("dnf")
            elif os.path.exists("/usr/bin/yum"):
                await self._run_package_remove("yum")

            # Remove config files
            if os.path.exists("/etc/otelcol-contrib"):
                shutil.rmtree("/etc/otelcol-contrib")

            return {
                "success": True,
                "message": _OTEL_REMOVED_SUCCESS,
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _run_apt_remove(self):
        """Remove package using apt."""
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        for cmd in [["remove", "-y"], ["purge", "-y"]]:
            process = await asyncio.create_subprocess_exec(
                "apt-get",
                *cmd,
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            await process.communicate()

    async def _run_package_remove(self, pkg_manager: str):
        """Remove package using given package manager."""
        process = await asyncio.create_subprocess_exec(
            pkg_manager,
            "remove",
            "-y",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    async def remove_macos(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from macOS."""
        try:
            for cmd in [["services", "stop"], ["uninstall"]]:
                process = await asyncio.create_subprocess_exec(
                    "brew",
                    *cmd,
                    "otelcol-contrib",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()
            return {
                "success": True,
                "message": _OTEL_REMOVED_SUCCESS,
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def remove_bsd(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from BSD."""
        try:
            process = await asyncio.create_subprocess_exec(
                "service",
                "alloy",
                "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

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
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def remove_windows(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from Windows."""
        try:
            for cmd in [["stop"], ["delete"]]:
                process = await asyncio.create_subprocess_exec(
                    "sc",
                    *cmd,
                    "otelcol-contrib",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()
            return {
                "success": True,
                "message": _OTEL_REMOVED_SUCCESS,
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    # ========== Deployment Methods ==========

    async def deploy_linux(self, grafana_url: str, config_generator) -> Dict[str, Any]:
        """Deploy OpenTelemetry on Linux."""
        try:
            if os.path.exists("/usr/bin/apt"):
                return await self._deploy_apt(grafana_url, config_generator)
            if os.path.exists("/usr/bin/yum") or os.path.exists(_DNF_PATH):
                return await self._deploy_yum_dnf(grafana_url, config_generator)
            return {"success": False, "error": "No supported package manager found"}
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _deploy_apt(self, grafana_url: str, config_generator) -> Dict[str, Any]:
        """Deploy using apt."""
        try:
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"

            # Install prerequisites
            process = await asyncio.create_subprocess_exec(
                "apt-get",
                "install",
                "-y",
                "wget",
                "gnupg2",
                "software-properties-common",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            _stdout, stderr = await process.communicate()
            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install prerequisites: {stderr.decode()}",
                }

            # Download and install OpenTelemetry
            download_url = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.112.0/otelcol-contrib_0.112.0_linux_amd64.deb"
            process = await asyncio.create_subprocess_exec(
                "wget",
                "-O-",
                download_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            deb_content, stderr = await process.communicate()

            if process.returncode != 0 or len(deb_content) == 0:
                return {
                    "success": False,
                    "error": "Failed to download OpenTelemetry package",
                }

            # Write to temp file and install
            # NOSONAR: Using sync tempfile for file creation is acceptable; the file
            # creation itself is fast and the content is already in memory
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".deb", delete=False
            ) as file_handle:
                file_handle.write(deb_content)
                deb_file = file_handle.name

            try:
                process = await asyncio.create_subprocess_exec(
                    "dpkg",
                    "-i",
                    deb_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                await process.communicate()

                if process.returncode != 0:
                    # Fix dependencies
                    process = await asyncio.create_subprocess_exec(
                        "apt-get",
                        "install",
                        "-f",
                        "-y",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                    )
                    await process.communicate()
            finally:
                if os.path.exists(deb_file):
                    os.unlink(deb_file)

            # Stop service
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Create config and start service
            config_result = await self._create_linux_config(
                grafana_url, config_generator
            )
            if not config_result["success"]:
                return config_result

            await self._start_linux_service()

            return {
                "success": True,
                "message": _OTEL_DEPLOYED_SUCCESS,
                "config_file": config_result.get("config_file"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _deploy_yum_dnf(
        self, grafana_url: str, config_generator
    ) -> Dict[str, Any]:
        """Deploy using yum/dnf."""
        try:
            pkg_manager = "dnf" if os.path.exists(_DNF_PATH) else "yum"
            process = await asyncio.create_subprocess_exec(
                pkg_manager,
                "install",
                "-y",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to install: {stderr.decode()}",
                }

            config_result = await self._create_linux_config(
                grafana_url, config_generator
            )
            if not config_result["success"]:
                return config_result

            await self._start_linux_service()

            return {
                "success": True,
                "message": _OTEL_DEPLOYED_SUCCESS,
                "config_file": config_result.get("config_file"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    # NOSONAR: async keyword required by interface contract even though limited awaits
    async def _create_linux_config(
        self, grafana_url: str, config_generator
    ) -> Dict[str, Any]:
        """Create config file for Linux."""
        try:
            config_file = "/etc/otelcol-contrib/config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            async with aiofiles.open(config_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(config_generator(grafana_url))
            os.chmod(
                config_file, 0o644
            )  # NOSONAR - permissions are appropriate for this file type

            env_file = "/etc/otelcol-contrib/otelcol-contrib.conf"
            async with aiofiles.open(env_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(f'OTELCOL_OPTIONS="--config={config_file}"\n')
            os.chmod(
                env_file, 0o644
            )  # NOSONAR - permissions are appropriate for this file type

            return {"success": True, "config_file": config_file}
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _start_linux_service(self):
        """Start Linux service."""
        for cmd in [
            ["daemon-reload"],
            ["enable", "otelcol-contrib"],
            ["start", "otelcol-contrib"],
        ]:
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

    async def deploy_macos(self, grafana_url: str, config_generator) -> Dict[str, Any]:
        """Deploy on macOS."""
        try:
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
                    "error": f"Failed to install: {stderr.decode()}",
                }

            config_file = "/usr/local/etc/otelcol-contrib/config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            async with aiofiles.open(config_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(config_generator(grafana_url))

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
                "message": _OTEL_DEPLOYED_SUCCESS,
                "config_file": config_file,
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def deploy_freebsd(
        self, grafana_url: str, alloy_config_generator
    ) -> Dict[str, Any]:
        """Deploy on FreeBSD."""
        try:
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
                    "error": f"Failed to install: {stderr.decode()}",
                }

            config_file = "/usr/local/etc/alloy/config.alloy"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            async with aiofiles.open(config_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(alloy_config_generator(grafana_url))

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
                "message": "Grafana Alloy deployed successfully",
                "config_file": config_file,
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def deploy_windows(
        self, grafana_url: str, config_generator
    ) -> Dict[str, Any]:
        """Deploy on Windows."""
        try:
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
                    "error": f"Failed to install: {stderr.decode()}",
                }

            config_file = "C:\\Program Files\\OpenTelemetry Collector\\config.yaml"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)

            async with aiofiles.open(config_file, "w", encoding="utf-8") as file_handle:
                await file_handle.write(config_generator(grafana_url))

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
                "message": _OTEL_DEPLOYED_SUCCESS,
                "config_file": config_file,
            }
        except Exception as error:
            return {"success": False, "error": str(error)}
