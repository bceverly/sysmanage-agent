"""
Antivirus Deployment Module for Linux Systems

This module handles antivirus deployment for:
- openSUSE (via zypper)
- RHEL/CentOS (via yum/dnf)
- Debian/Ubuntu (via apt)
"""

import asyncio
from typing import Any, Dict

from src.sysmanage_agent.collection.update_detection import UpdateDetector


class AntivirusDeployerLinux:
    """Handles antivirus deployment for Linux systems."""

    def __init__(self, logger):
        """
        Initialize the AntivirusDeployerLinux instance.

        Args:
            logger: Logger instance for logging operations
        """
        self.logger = logger

    async def deploy_opensuse(self, _antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on openSUSE via zypper."""
        self.logger.info("Detected openSUSE system, installing ClamAV packages")

        # Install ClamAV packages
        update_detector = UpdateDetector()
        packages = ["clamav", "clamav_freshclam", "clamav-daemon"]
        for pkg in packages:
            self.logger.info("Installing %s", pkg)
            result = update_detector.install_package(pkg, "auto")
            self.logger.info("%s installation result: %s", pkg, result)

        # Enable and start freshclam service
        self.logger.info("Enabling and starting freshclam service")
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "enable",
            "--now",
            "freshclam.service",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("freshclam service enabled and started successfully")
        else:
            self.logger.warning(
                "Failed to enable/start freshclam: %s",
                stderr.decode() if stderr else "unknown error",
            )

        # Enable and start clamd service
        service_name = "clamd.service"
        self.logger.info("Enabling and starting service: %s", service_name)
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "enable",
            "--now",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode == 0:
            self.logger.info(
                "Service %s enabled and started successfully", service_name
            )
            await asyncio.sleep(2)
        else:
            self.logger.warning(
                "Failed to enable/start service %s: %s",
                service_name,
                stderr.decode() if stderr else "unknown error",
            )

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on openSUSE",
        }

    async def deploy_redhat(self, _antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on RHEL/CentOS via yum/dnf."""
        self.logger.info(
            "Detected RHEL/CentOS system, enabling EPEL and installing ClamAV packages"
        )

        # Enable EPEL repository
        update_detector = UpdateDetector()
        epel_result = update_detector.install_package("epel-release", "auto")
        self.logger.info("EPEL installation result: %s", epel_result)

        # Install ClamAV packages
        packages = ["clamav", "clamd", "clamav-update"]
        for pkg in packages:
            self.logger.info("Installing %s", pkg)
            result = update_detector.install_package(pkg, "auto")
            self.logger.info("%s installation result: %s", pkg, result)

        # Update virus definitions
        self.logger.info("Updating virus definitions with freshclam")
        process = await asyncio.create_subprocess_exec(
            "freshclam",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("Virus definitions updated successfully")
        else:
            self.logger.warning(
                "Failed to update virus definitions: %s",
                stderr.decode() if stderr else "unknown error",
            )

        # Configure clamd@scan service
        config_file = "/etc/clamd.d/scan.conf"
        self.logger.info("Configuring %s", config_file)

        # Read the config file
        with open(config_file, "r", encoding="utf-8") as file_handle:
            config_content = file_handle.read()

        # Uncomment LocalSocket and remove Example line
        config_content = config_content.replace("#Example", "# Example").replace(
            "#LocalSocket /run/clamd.scan/clamd.sock",
            "LocalSocket /run/clamd.scan/clamd.sock",
        )

        # Write back the config file
        with open(config_file, "w", encoding="utf-8") as file_handle:
            file_handle.write(config_content)

        self.logger.info("Configuration updated successfully")

        # Enable and start clamd@scan service
        service_name = "clamd@scan"
        self.logger.info("Enabling and starting service: %s", service_name)
        process = await asyncio.create_subprocess_exec(
            "systemctl",
            "enable",
            "--now",
            service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode == 0:
            self.logger.info(
                "Service %s enabled and started successfully", service_name
            )
            await asyncio.sleep(2)
        else:
            self.logger.warning(
                "Failed to enable/start service %s: %s",
                service_name,
                stderr.decode() if stderr else "unknown error",
            )

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on RHEL/CentOS",
        }

    async def deploy_debian(self, _antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on Debian/Ubuntu via apt."""
        self.logger.info("Installing ClamAV on Debian/Ubuntu system")

        # Standard installation for Debian/Ubuntu
        update_detector = UpdateDetector()
        result = update_detector.install_package(_antivirus_package, "auto")

        # Determine success based on result
        success = True
        error_message = None
        installed_version = None

        if isinstance(result, dict):
            success = result.get("success", True)
            error_message = result.get("error")
            installed_version = result.get("version")
        elif isinstance(result, str):
            if "error" in result.lower() or "failed" in result.lower():
                success = False
                error_message = result

        # After installation, enable and start the service
        if success and "clamav" in _antivirus_package.lower():
            self.logger.info(
                "Antivirus package %s installed successfully, enabling and starting service",
                _antivirus_package,
            )
            try:
                # Ubuntu/Debian uses clamav_freshclam
                service_name = "clamav_freshclam"
                self.logger.info("Enabling and starting service: %s", service_name)
                process = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "enable",
                    "--now",
                    service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()

                if process.returncode == 0:
                    self.logger.info(
                        "Service %s enabled and started successfully",
                        service_name,
                    )
                    await asyncio.sleep(2)
                else:
                    self.logger.warning(
                        "Failed to enable/start service %s: %s",
                        service_name,
                        stderr.decode() if stderr else "unknown error",
                    )
            except Exception as service_error:
                self.logger.warning("Failed to enable service: %s", str(service_error))

        return {
            "success": success,
            "error_message": error_message,
            "installed_version": installed_version,
            "result": result,
        }
