"""
Antivirus Deployment Module for Unix Systems (macOS and BSD)

This module handles antivirus deployment for:
- macOS (via Homebrew)
- NetBSD (via pkgin)
- FreeBSD (via pkg)
- OpenBSD (via pkg_add)
"""

import asyncio
import os
from typing import Any, Dict

from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.sysmanage_agent.operations.antivirus_base import _get_brew_user

# Module-level constants for repeated strings
_MSG_INSTALLING_CLAMAV = "Installing clamav"
_MSG_CLAMAV_INSTALL_RESULT = "clamav installation result: %s"
_PATH_OPT_HOMEBREW = "/opt/homebrew"
_MSG_CREATING_FRESHCLAM_CONF = "Creating freshclam.conf from sample"
_SED_COMMENT_EXAMPLE = "s/^Example/#Example/"
_MSG_FRESHCLAM_CONF_CONFIGURED = "freshclam.conf configured"
_MSG_CREATING_CLAMD_CONF = "Creating clamd.conf from sample"
_MSG_CLAMD_CONF_CONFIGURED = "clamd.conf configured"
_MSG_UNKNOWN_ERROR = "unknown error"
_SED_UNCOMMENT_LOCAL_SOCKET = "s/^#LocalSocket /LocalSocket /"
_MSG_VIRUS_DB_DOWNLOADED = "Virus database downloaded successfully"
_MSG_VIRUS_DB_TIMEOUT = (
    "Virus database not downloaded after 30 seconds, proceeding anyway"
)


class AntivirusDeployerBSD:
    """Handles antivirus deployment for Unix systems (macOS and BSD)."""

    def __init__(self, logger):
        """
        Initialize the AntivirusDeployerUnix instance.

        Args:
            logger: Logger instance for logging operations
        """
        self.logger = logger

    async def deploy_macos(self, _antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on macOS via Homebrew."""
        self.logger.info("Detected macOS system, installing ClamAV via Homebrew")

        # Install ClamAV via Homebrew
        update_detector = UpdateDetector()
        self.logger.info(_MSG_INSTALLING_CLAMAV)
        result = update_detector.install_package("clamav", "auto")
        self.logger.info(_MSG_CLAMAV_INSTALL_RESULT, result)

        # Determine the correct config path based on architecture
        config_base = (
            "/opt/homebrew/etc/clamav"
            if os.path.exists(_PATH_OPT_HOMEBREW)
            else "/usr/local/etc/clamav"
        )
        log_dir = (
            "/opt/homebrew/var/log/clamav"
            if os.path.exists(_PATH_OPT_HOMEBREW)
            else "/usr/local/var/log/clamav"
        )

        self.logger.info("Configuring ClamAV on macOS")

        # Create log and database directories
        os.makedirs(log_dir, exist_ok=True)

        # Create database directory for virus definitions
        db_dir = (
            "/opt/homebrew/var/lib/clamav"
            if os.path.exists(_PATH_OPT_HOMEBREW)
            else "/usr/local/var/lib/clamav"
        )
        os.makedirs(db_dir, exist_ok=True)

        # Configure freshclam.conf and clamd.conf
        await self._configure_macos_freshclam(config_base)
        await self._configure_macos_clamd(config_base, log_dir, db_dir)

        # Update virus definitions with freshclam
        await self._run_macos_freshclam()

        # Start ClamAV service via Homebrew
        await self._start_macos_brew_service()

        await asyncio.sleep(2)

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on macOS",
        }

    async def _configure_macos_freshclam(self, config_base: str):
        """Configure freshclam.conf from sample on macOS."""
        freshclam_conf = f"{config_base}/freshclam.conf"
        freshclam_sample = f"{config_base}/freshclam.conf.sample"
        if os.path.exists(freshclam_sample):
            self.logger.info(_MSG_CREATING_FRESHCLAM_CONF)
            process = await asyncio.create_subprocess_exec(
                "cp",
                freshclam_sample,
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                _SED_COMMENT_EXAMPLE,
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info(_MSG_FRESHCLAM_CONF_CONFIGURED)

    async def _configure_macos_clamd(self, config_base: str, log_dir: str, db_dir: str):
        """Configure clamd.conf from sample on macOS."""
        clamd_conf = f"{config_base}/clamd.conf"
        clamd_sample = f"{config_base}/clamd.conf.sample"
        if os.path.exists(clamd_sample):
            self.logger.info(_MSG_CREATING_CLAMD_CONF)
            process = await asyncio.create_subprocess_exec(
                "cp",
                clamd_sample,
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            sed_commands = [
                _SED_COMMENT_EXAMPLE,
                f"s|^#LogFile.*|LogFile {log_dir}/clamd.log|",
                f"s|^#PidFile.*|PidFile {log_dir}/clamd.pid|",
                f"s|^#DatabaseDirectory.*|DatabaseDirectory {db_dir}|",
                f"s|^#LocalSocket.*|LocalSocket {log_dir}/clamd.sock|",
            ]

            for sed_cmd in sed_commands:
                process = await asyncio.create_subprocess_exec(
                    "sed",
                    "-i",
                    "",
                    "-e",
                    sed_cmd,
                    clamd_conf,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()

            self.logger.info(_MSG_CLAMD_CONF_CONFIGURED)

    async def _run_macos_freshclam(self):
        """Run freshclam to update virus definitions on macOS."""
        self.logger.info("Updating virus definitions with freshclam")
        freshclam_cmd = (
            "/opt/homebrew/bin/freshclam"
            if os.path.exists("/opt/homebrew/bin/freshclam")
            else "/usr/local/bin/freshclam"
        )

        brew_user = _get_brew_user() if os.geteuid() == 0 else None

        if brew_user:
            self.logger.info("Running freshclam as user: %s", brew_user)
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-u",
                brew_user,
                freshclam_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                freshclam_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("Virus definitions updated successfully")
        else:
            self.logger.warning(
                "Failed to update virus definitions: %s",
                stderr.decode() if stderr else _MSG_UNKNOWN_ERROR,
            )

    async def _start_macos_brew_service(self):
        """Start ClamAV service via Homebrew on macOS."""
        self.logger.info("Starting ClamAV service via brew services")
        brew_cmd = (
            "/opt/homebrew/bin/brew"
            if os.path.exists("/opt/homebrew/bin/brew")
            else "/usr/local/bin/brew"
        )

        process = await asyncio.create_subprocess_exec(
            "sudo",
            brew_cmd,
            "services",
            "start",
            "clamav",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("ClamAV service started successfully")
        else:
            self.logger.warning(
                "Failed to start ClamAV service: %s",
                stderr.decode() if stderr else _MSG_UNKNOWN_ERROR,
            )

    async def deploy_netbsd(self, _antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on NetBSD via pkgin."""
        self.logger.info("Detected NetBSD system, installing ClamAV package")

        # Install ClamAV package using pkgin
        update_detector = UpdateDetector()
        self.logger.info(_MSG_INSTALLING_CLAMAV)
        result = update_detector.install_package("clamav", "auto")
        self.logger.info(_MSG_CLAMAV_INSTALL_RESULT, result)

        # Configure ClamAV on NetBSD
        self.logger.info("Configuring ClamAV on NetBSD")

        await self._configure_bsd_freshclam(
            "/usr/pkg/etc/freshclam.conf.sample",
            "/usr/pkg/etc/freshclam.conf",
        )
        await self._configure_bsd_clamd(
            "/usr/pkg/etc/clamd.conf.sample",
            "/usr/pkg/etc/clamd.conf",
        )

        # Copy rc.d scripts to /etc/rc.d/ (NetBSD requirement)
        self.logger.info("Copying rc.d scripts to /etc/rc.d/")
        for script in ["clamd", "freshclamd"]:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "cp",
                f"/usr/pkg/share/examples/rc.d/{script}",
                "/etc/rc.d/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        # Enable services in rc.conf using shell commands
        self.logger.info("Enabling ClamAV services in rc.conf")

        process = await asyncio.create_subprocess_exec(
            "sh",
            "-c",
            "grep -q '^freshclamd=' /etc/rc.conf 2>/dev/null || echo 'freshclamd=YES' | sudo tee -a /etc/rc.conf > /dev/null",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "sh",
            "-c",
            "grep -q '^clamd=' /etc/rc.conf 2>/dev/null || echo 'clamd=YES' | sudo tee -a /etc/rc.conf > /dev/null",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Start freshclamd service first
        self.logger.info("Starting freshclamd service")
        process = await asyncio.create_subprocess_exec(
            "sudo",
            "service",
            "freshclamd",
            "start",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("freshclamd service started successfully")
        else:
            self.logger.warning(
                "Failed to start freshclamd: %s",
                stderr.decode() if stderr else _MSG_UNKNOWN_ERROR,
            )

        # Wait for virus database download
        await self._wait_for_virus_database(
            ["/var/clamav/main.cvd", "/var/clamav/main.cld"]
        )

        # Start clamd service
        self.logger.info("Starting clamd service")
        process = await asyncio.create_subprocess_exec(
            "sudo",
            "service",
            "clamd",
            "start",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("clamd service started successfully")
        else:
            self.logger.warning(
                "Failed to start clamd: %s",
                stderr.decode() if stderr else _MSG_UNKNOWN_ERROR,
            )

        await asyncio.sleep(2)

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on NetBSD",
        }

    async def deploy_freebsd(self, _antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on FreeBSD via pkg."""
        self.logger.info("Detected FreeBSD system, installing ClamAV package")

        # Install ClamAV package
        update_detector = UpdateDetector()
        self.logger.info(_MSG_INSTALLING_CLAMAV)
        result = update_detector.install_package("clamav", "auto")
        self.logger.info(_MSG_CLAMAV_INSTALL_RESULT, result)

        # Configure ClamAV on FreeBSD
        self.logger.info("Configuring ClamAV on FreeBSD")

        await self._configure_bsd_freshclam(
            "/usr/local/etc/freshclam.conf.sample",
            "/usr/local/etc/freshclam.conf",
        )
        await self._configure_bsd_clamd(
            "/usr/local/etc/clamd.conf.sample",
            "/usr/local/etc/clamd.conf",
        )

        # Enable services in rc.conf
        self.logger.info("Enabling ClamAV services in rc.conf")
        process = await asyncio.create_subprocess_exec(
            "sysrc",
            "clamav_freshclam_enable=YES",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "sysrc",
            "clamav_clamd_enable=YES",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Start freshclam service first
        self.logger.info("Starting clamav_freshclam service")
        process = await asyncio.create_subprocess_exec(
            "service",
            "clamav_freshclam",
            "start",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("clamav_freshclam service started successfully")
        else:
            self.logger.warning(
                "Failed to start clamav_freshclam: %s",
                stderr.decode() if stderr else _MSG_UNKNOWN_ERROR,
            )

        # Wait for virus database download
        await self._wait_for_virus_database(
            ["/var/db/clamav/main.cvd", "/var/db/clamav/main.cld"]
        )

        # Start clamd service
        self.logger.info("Starting clamav_clamd service")
        process = await asyncio.create_subprocess_exec(
            "service",
            "clamav_clamd",
            "start",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("clamav_clamd service started successfully")
        else:
            self.logger.warning(
                "Failed to start clamav_clamd: %s",
                stderr.decode() if stderr else _MSG_UNKNOWN_ERROR,
            )

        await asyncio.sleep(2)

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on FreeBSD",
        }

    async def deploy_openbsd(self, _antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on OpenBSD via pkg_add."""
        self.logger.info("Detected OpenBSD system, installing ClamAV package")

        # Install ClamAV package
        update_detector = UpdateDetector()
        self.logger.info(_MSG_INSTALLING_CLAMAV)
        result = update_detector.install_package("clamav", "auto")
        self.logger.info(_MSG_CLAMAV_INSTALL_RESULT, result)

        # Configure ClamAV on OpenBSD
        self.logger.info("Configuring ClamAV on OpenBSD")

        await self._configure_openbsd_freshclam()
        await self._configure_openbsd_clamd()
        await self._create_openbsd_runtime_dirs()

        # Enable and start freshclam service first
        self.logger.info("Enabling and starting freshclam service")
        process = await asyncio.create_subprocess_exec(
            "rcctl",
            "enable",
            "freshclam",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "rcctl",
            "start",
            "freshclam",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("freshclam service enabled and started successfully")
        else:
            self.logger.warning(
                "Failed to start freshclam: %s",
                stderr.decode() if stderr else _MSG_UNKNOWN_ERROR,
            )

        # Wait for freshclam to download the database
        await self._wait_for_virus_database(
            ["/var/db/clamav/main.cvd", "/var/db/clamav/main.cld"]
        )

        # Enable and start clamd service
        self.logger.info("Enabling and starting clamd service")
        process = await asyncio.create_subprocess_exec(
            "rcctl",
            "enable",
            "clamd",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "rcctl",
            "start",
            "clamd",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            self.logger.info("clamd service enabled and started successfully")
        else:
            self.logger.warning(
                "Failed to start clamd: %s",
                stderr.decode() if stderr else _MSG_UNKNOWN_ERROR,
            )

        await asyncio.sleep(2)

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on OpenBSD",
        }

    async def _configure_bsd_freshclam(self, sample_path: str, conf_path: str):
        """Configure freshclam.conf from sample for BSD systems."""
        if os.path.exists(sample_path):
            self.logger.info(_MSG_CREATING_FRESHCLAM_CONF)
            process = await asyncio.create_subprocess_exec(
                "cp",
                sample_path,
                conf_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                _SED_COMMENT_EXAMPLE,
                conf_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info(_MSG_FRESHCLAM_CONF_CONFIGURED)

    async def _configure_bsd_clamd(self, sample_path: str, conf_path: str):
        """Configure clamd.conf from sample for BSD systems (NetBSD/FreeBSD)."""
        if os.path.exists(sample_path):
            self.logger.info(_MSG_CREATING_CLAMD_CONF)
            process = await asyncio.create_subprocess_exec(
                "cp",
                sample_path,
                conf_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                _SED_COMMENT_EXAMPLE,
                "-e",
                _SED_UNCOMMENT_LOCAL_SOCKET,
                conf_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info(_MSG_CLAMD_CONF_CONFIGURED)

    async def _configure_openbsd_freshclam(self):
        """Configure freshclam.conf from sample for OpenBSD."""
        freshclam_conf = "/etc/freshclam.conf"
        freshclam_sample = "/usr/local/share/examples/clamav/freshclam.conf.sample"
        if os.path.exists(freshclam_sample):
            self.logger.info(_MSG_CREATING_FRESHCLAM_CONF)
            process = await asyncio.create_subprocess_exec(
                "cp",
                freshclam_sample,
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                _SED_COMMENT_EXAMPLE,
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info(_MSG_FRESHCLAM_CONF_CONFIGURED)

    async def _configure_openbsd_clamd(self):
        """Configure clamd.conf from sample for OpenBSD."""
        clamd_conf = "/etc/clamd.conf"
        clamd_sample = "/usr/local/share/examples/clamav/clamd.conf.sample"
        if os.path.exists(clamd_sample):
            self.logger.info(_MSG_CREATING_CLAMD_CONF)
            process = await asyncio.create_subprocess_exec(
                "cp",
                clamd_sample,
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "-e",
                _SED_COMMENT_EXAMPLE,
                "-e",
                _SED_UNCOMMENT_LOCAL_SOCKET,
                "-e",
                "s|/run/clamav/|/var/run/clamav/|g",
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info(_MSG_CLAMD_CONF_CONFIGURED)

    async def _create_openbsd_runtime_dirs(self):
        """Create required runtime directories for ClamAV on OpenBSD."""
        self.logger.info("Creating runtime directories for ClamAV")
        clamav_run_dir = "/var/run/clamav"
        if not os.path.exists(clamav_run_dir):
            process = await asyncio.create_subprocess_exec(
                "mkdir",
                "-p",
                clamav_run_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            process = await asyncio.create_subprocess_exec(
                "chown",
                "_clamav:_clamav",
                clamav_run_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("Created and configured /var/run/clamav directory")

    async def _wait_for_virus_database(self, db_paths: list):
        """Wait for virus database to be downloaded (up to 30 seconds)."""
        self.logger.info("Waiting for freshclam to download virus database")
        database_ready = False
        for _ in range(30):
            if any(os.path.exists(p) for p in db_paths):
                self.logger.info(_MSG_VIRUS_DB_DOWNLOADED)
                database_ready = True
                break
            await asyncio.sleep(1)

        if not database_ready:
            self.logger.warning(_MSG_VIRUS_DB_TIMEOUT)
