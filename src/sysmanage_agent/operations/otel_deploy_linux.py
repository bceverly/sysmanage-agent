"""
Linux-specific OpenTelemetry deployment operations.

This module handles OpenTelemetry collector deployment and removal on Linux systems
using apt, yum, or dnf package managers.
"""

import asyncio
import os
import tempfile
from typing import Any, Dict

from src.sysmanage_agent.operations.otel_base import OtelDeployerBase


class LinuxOtelDeployer(OtelDeployerBase):
    """Handles OpenTelemetry deployment on Linux systems."""

    async def deploy(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry on Linux systems."""
        try:
            # Detect package manager
            if os.path.exists("/usr/bin/apt"):
                return await self._deploy_with_apt(grafana_url)
            if os.path.exists("/usr/bin/yum") or os.path.exists("/usr/bin/dnf"):
                return await self._deploy_with_yum_dnf(grafana_url)
            return {
                "success": False,
                "error": "No supported package manager found (apt/yum/dnf)",
            }
        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}

    async def remove(self) -> Dict[str, Any]:
        """Remove OpenTelemetry from Linux systems."""
        try:
            self.logger.info("Removing OpenTelemetry from Linux system")

            # Stop service
            self.logger.info("Stopping otelcol-contrib service...")
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Disable service
            self.logger.info("Disabling otelcol-contrib service...")
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "disable",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Remove package
            if os.path.exists("/usr/bin/apt"):
                await self._remove_with_apt()
            elif os.path.exists("/usr/bin/yum"):
                await self._remove_with_yum()
            elif os.path.exists("/usr/bin/dnf"):
                await self._remove_with_dnf()

            # Remove config files
            self.logger.info("Removing config files...")
            config_dir = "/etc/otelcol-contrib"
            if os.path.exists(config_dir):
                import shutil  # pylint: disable=import-outside-toplevel

                shutil.rmtree(config_dir)

            self.logger.info("OpenTelemetry removed successfully")
            return {
                "success": True,
                "message": "OpenTelemetry collector removed successfully",
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error("Error removing OpenTelemetry: %s", str(error))
            return {"success": False, "error": str(error)}

    async def _remove_with_apt(self):
        """Remove OpenTelemetry using apt."""
        self.logger.info("Removing package with apt...")
        process = await asyncio.create_subprocess_exec(
            "apt-get",
            "remove",
            "-y",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        await process.communicate()

        # Purge to remove residual config
        self.logger.info("Purging package with apt...")
        process = await asyncio.create_subprocess_exec(
            "apt-get",
            "purge",
            "-y",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        await process.communicate()

    async def _remove_with_yum(self):
        """Remove OpenTelemetry using yum."""
        self.logger.info("Removing package with yum...")
        process = await asyncio.create_subprocess_exec(
            "yum",
            "remove",
            "-y",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    async def _remove_with_dnf(self):
        """Remove OpenTelemetry using dnf."""
        self.logger.info("Removing package with dnf...")
        process = await asyncio.create_subprocess_exec(
            "dnf",
            "remove",
            "-y",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    async def _deploy_with_apt(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry using apt package manager."""
        # pylint: disable=too-many-return-statements,too-many-locals,too-many-branches,too-many-statements
        try:
            # Install OpenTelemetry collector
            self.logger.info("Installing OpenTelemetry collector using apt")

            # Set environment to prevent interactive prompts
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"

            # Install prerequisites
            self.logger.info("Installing prerequisites...")
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
                error_msg = f"Failed to install prerequisites: {stderr.decode()}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}

            # Download OpenTelemetry package
            self.logger.info("Downloading OpenTelemetry collector package...")
            download_url = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.112.0/otelcol-contrib_0.112.0_linux_amd64.deb"
            self.logger.info("Download URL: %s", download_url)

            process = await asyncio.create_subprocess_exec(
                "wget",
                "-O-",  # Output to stdout
                download_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            deb_content, stderr = await process.communicate()

            self.logger.info(
                "Download completed. Return code: %d, Content size: %d bytes",
                process.returncode,
                len(deb_content),
            )

            if stderr:
                self.logger.info(
                    "Download stderr: %s", stderr.decode()[:500]
                )  # Log first 500 chars

            if process.returncode != 0:
                error_msg = (
                    f"Failed to download OpenTelemetry package: {stderr.decode()}"
                )
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                }

            if len(deb_content) == 0:
                error_msg = "Downloaded file is empty"
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                }

            # Write the package to a temp file
            self.logger.info("Writing package to temporary file...")
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".deb", delete=False
            ) as file_handle:
                file_handle.write(deb_content)
                deb_file = file_handle.name
            self.logger.info("Package written to: %s", deb_file)

            try:
                # Install the package
                self.logger.info(
                    "Installing OpenTelemetry collector package with dpkg..."
                )
                process = await asyncio.create_subprocess_exec(
                    "dpkg",
                    "-i",
                    deb_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                dpkg_stdout, dpkg_stderr = await process.communicate()

                self.logger.info(
                    "dpkg install completed. Return code: %d", process.returncode
                )
                if dpkg_stdout:
                    self.logger.info("dpkg stdout: %s", dpkg_stdout.decode()[:500])
                if dpkg_stderr:
                    self.logger.info("dpkg stderr: %s", dpkg_stderr.decode()[:500])

                if process.returncode != 0:
                    # Try to fix dependencies
                    self.logger.info("Fixing dependencies with apt-get install -f...")
                    process = await asyncio.create_subprocess_exec(
                        "apt-get",
                        "install",
                        "-f",
                        "-y",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                    )
                    fix_stdout, fix_stderr = await process.communicate()

                    self.logger.info(
                        "apt-get fix completed. Return code: %d", process.returncode
                    )
                    if fix_stdout:
                        self.logger.info(
                            "apt-get stdout: %s", fix_stdout.decode()[:500]
                        )
                    if fix_stderr:
                        self.logger.info(
                            "apt-get stderr: %s", fix_stderr.decode()[:500]
                        )

                    if process.returncode != 0:
                        error_msg = f"Failed to install OpenTelemetry collector: {dpkg_stderr.decode()}"
                        self.logger.error(error_msg)
                        return {
                            "success": False,
                            "error": error_msg,
                        }
            finally:
                # Clean up temp file
                self.logger.info("Cleaning up temporary file: %s", deb_file)
                if os.path.exists(deb_file):
                    os.unlink(deb_file)

            # Stop service if it was auto-started by dpkg (it will have wrong config)
            self.logger.info("Stopping otelcol-contrib service...")
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "stop",
                "otelcol-contrib",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            # Ignore return code - service may not be running

            # Create configuration file
            self.logger.info("Creating OpenTelemetry configuration file...")
            config_result = await self._create_otel_config_linux(grafana_url)
            if not config_result["success"]:
                self.logger.error(
                    "Failed to create config: %s", config_result.get("error")
                )
                return config_result
            self.logger.info(
                "Configuration file created: %s", config_result.get("config_file")
            )

            # Enable and start service
            self.logger.info("Enabling and starting OpenTelemetry service...")
            await self._enable_and_start_otel_service_linux()
            self.logger.info("OpenTelemetry service started successfully")

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_result.get("config_file"),
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error(
                "Exception during OpenTelemetry deployment: %s",
                str(error),
                exc_info=True,
            )
            return {"success": False, "error": str(error)}

    async def _deploy_with_yum_dnf(self, grafana_url: str) -> Dict[str, Any]:
        """Deploy OpenTelemetry using yum/dnf package manager."""
        try:
            # Determine which package manager to use
            pkg_manager = "dnf" if os.path.exists("/usr/bin/dnf") else "yum"

            self.logger.info("Installing OpenTelemetry collector using %s", pkg_manager)

            # Install OpenTelemetry collector
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
                    "error": f"Failed to install OpenTelemetry collector: {stderr.decode()}",
                }

            # Create configuration file
            config_result = await self._create_otel_config_linux(grafana_url)
            if not config_result["success"]:
                return config_result

            # Enable and start service
            await self._enable_and_start_otel_service_linux()

            return {
                "success": True,
                "message": "OpenTelemetry collector deployed successfully",
                "config_file": config_result.get("config_file"),
            }

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}

    async def _create_otel_config_linux(self, grafana_url: str) -> Dict[str, Any]:
        """Create OpenTelemetry configuration file for Linux."""
        try:
            config_file = "/etc/otelcol-contrib/config.yaml"
            env_file = "/etc/otelcol-contrib/otelcol-contrib.conf"
            config_dir = os.path.dirname(config_file)

            # Create config directory
            os.makedirs(config_dir, exist_ok=True)

            # Generate config content
            config_content = self._generate_otel_config(grafana_url)

            # Write config file
            with open(config_file, "w", encoding="utf-8") as file_handle:
                file_handle.write(config_content)

            # Set proper permissions
            os.chmod(config_file, 0o644)

            # Create environment file with config path
            env_content = f'OTELCOL_OPTIONS="--config={config_file}"\n'
            with open(env_file, "w", encoding="utf-8") as file_handle:
                file_handle.write(env_content)

            # Set proper permissions
            os.chmod(env_file, 0o644)

            return {"success": True, "config_file": config_file}

        except Exception as error:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(error)}

    async def _enable_and_start_otel_service_linux(self):
        """Enable and start OpenTelemetry service on Linux."""
        # Reload systemd to pick up environment file changes
        self.logger.info("Reloading systemd daemon...")
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "daemon-reload",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Enable service
        self.logger.info("Enabling otelcol-contrib service...")
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "enable",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            self.logger.error(
                "Failed to enable service. Return code: %d", process.returncode
            )
            if stdout:
                self.logger.error("Enable stdout: %s", stdout.decode())
            if stderr:
                self.logger.error("Enable stderr: %s", stderr.decode())
        else:
            self.logger.info("Service enabled successfully")

        # Start service
        self.logger.info("Starting otelcol-contrib service...")
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "start",
            "otelcol-contrib",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            self.logger.error(
                "Failed to start service. Return code: %d", process.returncode
            )
            if stdout:
                self.logger.error("Start stdout: %s", stdout.decode())
            if stderr:
                self.logger.error("Start stderr: %s", stderr.decode())
        else:
            self.logger.info("Service started successfully")
