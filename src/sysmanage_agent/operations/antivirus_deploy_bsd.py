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
        self.logger.info("Installing clamav")
        result = update_detector.install_package("clamav", "auto")
        self.logger.info("clamav installation result: %s", result)

        # Determine the correct config path based on architecture
        config_base = (
            "/opt/homebrew/etc/clamav"
            if os.path.exists("/opt/homebrew")
            else "/usr/local/etc/clamav"
        )
        log_dir = (
            "/opt/homebrew/var/log/clamav"
            if os.path.exists("/opt/homebrew")
            else "/usr/local/var/log/clamav"
        )

        self.logger.info("Configuring ClamAV on macOS")

        # Create log and database directories
        os.makedirs(log_dir, exist_ok=True)

        # Create database directory for virus definitions
        db_dir = (
            "/opt/homebrew/var/lib/clamav"
            if os.path.exists("/opt/homebrew")
            else "/usr/local/var/lib/clamav"
        )
        os.makedirs(db_dir, exist_ok=True)

        # Configure freshclam.conf
        freshclam_conf = f"{config_base}/freshclam.conf"
        freshclam_sample = f"{config_base}/freshclam.conf.sample"
        if os.path.exists(freshclam_sample):
            self.logger.info("Creating freshclam.conf from sample")
            process = await asyncio.create_subprocess_exec(
                "cp",
                freshclam_sample,
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Comment out Example line in freshclam.conf
            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                "s/^Example/#Example/",
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("freshclam.conf configured")

        # Configure clamd.conf
        clamd_conf = f"{config_base}/clamd.conf"
        clamd_sample = f"{config_base}/clamd.conf.sample"
        if os.path.exists(clamd_sample):
            self.logger.info("Creating clamd.conf from sample")
            process = await asyncio.create_subprocess_exec(
                "cp",
                clamd_sample,
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Comment out Example line and configure clamd
            sed_commands = [
                "s/^Example/#Example/",
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

            self.logger.info("clamd.conf configured")

        # Update virus definitions with freshclam
        self.logger.info("Updating virus definitions with freshclam")
        # Use full path since brew link creates symlinks in /opt/homebrew/bin or /usr/local/bin
        freshclam_cmd = (
            "/opt/homebrew/bin/freshclam"
            if os.path.exists("/opt/homebrew/bin/freshclam")
            else "/usr/local/bin/freshclam"
        )

        # If running as root, use sudo -u to run as the brew user
        # This ensures freshclam has proper permissions to write to Homebrew directories
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
                stderr.decode() if stderr else "unknown error",
            )

        # Start ClamAV service via Homebrew
        # Note: ClamAV service must be started with sudo (as root) to run at system startup
        # This is different from other brew commands which shouldn't run as root
        self.logger.info("Starting ClamAV service via brew services")
        brew_cmd = (
            "/opt/homebrew/bin/brew"
            if os.path.exists("/opt/homebrew/bin/brew")
            else "/usr/local/bin/brew"
        )

        # Always use sudo for brew services start clamav
        # ClamAV requires root to start at system startup
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
                stderr.decode() if stderr else "unknown error",
            )

        await asyncio.sleep(2)

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on macOS",
        }

    async def deploy_netbsd(self, _antivirus_package: str) -> Dict[str, Any]:
        """Deploy ClamAV on NetBSD via pkgin."""
        self.logger.info("Detected NetBSD system, installing ClamAV package")

        # Install ClamAV package using pkgin
        update_detector = UpdateDetector()
        self.logger.info("Installing clamav")
        result = update_detector.install_package("clamav", "auto")
        self.logger.info("clamav installation result: %s", result)

        # Configure ClamAV on NetBSD
        self.logger.info("Configuring ClamAV on NetBSD")

        # NetBSD config files are typically in /usr/pkg/etc
        # Copy sample config files and comment out Example line
        # freshclam.conf
        freshclam_conf = "/usr/pkg/etc/freshclam.conf"
        freshclam_sample = "/usr/pkg/etc/freshclam.conf.sample"
        if os.path.exists(freshclam_sample):
            self.logger.info("Creating freshclam.conf from sample")
            process = await asyncio.create_subprocess_exec(
                "cp",
                freshclam_sample,
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Comment out Example line in freshclam.conf
            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                "s/^Example/#Example/",
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("freshclam.conf configured")

        # clamd.conf
        clamd_conf = "/usr/pkg/etc/clamd.conf"
        clamd_sample = "/usr/pkg/etc/clamd.conf.sample"
        if os.path.exists(clamd_sample):
            self.logger.info("Creating clamd.conf from sample")
            process = await asyncio.create_subprocess_exec(
                "cp",
                clamd_sample,
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Comment out Example line and configure LocalSocket in clamd.conf
            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                "s/^Example/#Example/",
                "-e",
                "s/^#LocalSocket /LocalSocket /",
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("clamd.conf configured")

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
        # NetBSD service name is freshclamd (with d), not freshclam
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
                stderr.decode() if stderr else "unknown error",
            )

        # Wait for virus database download
        self.logger.info("Waiting for freshclamd to download virus database")
        database_ready = False
        for _ in range(30):
            if os.path.exists("/var/clamav/main.cvd") or os.path.exists(
                "/var/clamav/main.cld"
            ):
                self.logger.info("Virus database downloaded successfully")
                database_ready = True
                break
            await asyncio.sleep(1)

        if not database_ready:
            self.logger.warning(
                "Virus database not downloaded after 30 seconds, proceeding anyway"
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
                stderr.decode() if stderr else "unknown error",
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
        self.logger.info("Installing clamav")
        result = update_detector.install_package("clamav", "auto")
        self.logger.info("clamav installation result: %s", result)

        # Configure ClamAV on FreeBSD
        self.logger.info("Configuring ClamAV on FreeBSD")

        # FreeBSD config files are typically in /usr/local/etc
        # Copy sample config files and comment out Example line
        # freshclam.conf
        freshclam_conf = "/usr/local/etc/freshclam.conf"
        freshclam_sample = "/usr/local/etc/freshclam.conf.sample"
        if os.path.exists(freshclam_sample):
            self.logger.info("Creating freshclam.conf from sample")
            process = await asyncio.create_subprocess_exec(
                "cp",
                freshclam_sample,
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Comment out Example line in freshclam.conf
            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                "s/^Example/#Example/",
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("freshclam.conf configured")

        # clamd.conf
        clamd_conf = "/usr/local/etc/clamd.conf"
        clamd_sample = "/usr/local/etc/clamd.conf.sample"
        if os.path.exists(clamd_sample):
            self.logger.info("Creating clamd.conf from sample")
            process = await asyncio.create_subprocess_exec(
                "cp",
                clamd_sample,
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Comment out Example line and configure LocalSocket in clamd.conf
            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                "s/^Example/#Example/",
                "-e",
                "s/^#LocalSocket /LocalSocket /",
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("clamd.conf configured")

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
                stderr.decode() if stderr else "unknown error",
            )

        # Wait for virus database download
        self.logger.info("Waiting for freshclam to download virus database")
        database_ready = False
        for _ in range(30):
            if os.path.exists("/var/db/clamav/main.cvd") or os.path.exists(
                "/var/db/clamav/main.cld"
            ):
                self.logger.info("Virus database downloaded successfully")
                database_ready = True
                break
            await asyncio.sleep(1)

        if not database_ready:
            self.logger.warning(
                "Virus database not downloaded after 30 seconds, proceeding anyway"
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
                stderr.decode() if stderr else "unknown error",
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
        self.logger.info("Installing clamav")
        result = update_detector.install_package("clamav", "auto")
        self.logger.info("clamav installation result: %s", result)

        # Configure ClamAV on OpenBSD
        self.logger.info("Configuring ClamAV on OpenBSD")

        # Copy sample config files and comment out Example line
        # freshclam.conf
        freshclam_conf = "/etc/freshclam.conf"
        freshclam_sample = "/usr/local/share/examples/clamav/freshclam.conf.sample"
        if os.path.exists(freshclam_sample):
            self.logger.info("Creating freshclam.conf from sample")
            process = await asyncio.create_subprocess_exec(
                "cp",
                freshclam_sample,
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Comment out Example line in freshclam.conf
            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "s/^Example/#Example/",
                freshclam_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("freshclam.conf configured")

        # clamd.conf
        clamd_conf = "/etc/clamd.conf"
        clamd_sample = "/usr/local/share/examples/clamav/clamd.conf.sample"
        if os.path.exists(clamd_sample):
            self.logger.info("Creating clamd.conf from sample")
            process = await asyncio.create_subprocess_exec(
                "cp",
                clamd_sample,
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # Comment out Example line and configure LocalSocket in clamd.conf
            # On OpenBSD, use /var/run instead of /run
            # Use sed to do multiple edits
            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "-e",
                "s/^Example/#Example/",
                "-e",
                "s/^#LocalSocket /LocalSocket /",
                "-e",
                "s|/run/clamav/|/var/run/clamav/|g",
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("clamd.conf configured")

        # Create required runtime directories for clamd
        # On OpenBSD, runtime directory is /var/run, not /run
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

            # Set ownership to _clamav user
            process = await asyncio.create_subprocess_exec(
                "chown",
                "_clamav:_clamav",
                clamav_run_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self.logger.info("Created and configured /var/run/clamav directory")

        # Enable and start freshclam service first (OpenBSD uses freshclam)
        # Note: freshclam must run first to download virus database before clamd can start
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
                stderr.decode() if stderr else "unknown error",
            )

        # Wait for freshclam to download the database (give it up to 30 seconds)
        self.logger.info("Waiting for freshclam to download virus database")
        database_ready = False
        for _ in range(30):
            if os.path.exists("/var/db/clamav/main.cvd") or os.path.exists(
                "/var/db/clamav/main.cld"
            ):
                self.logger.info("Virus database downloaded successfully")
                database_ready = True
                break
            await asyncio.sleep(1)

        if not database_ready:
            self.logger.warning(
                "Virus database not downloaded after 30 seconds, proceeding anyway"
            )

        # Enable and start clamd service (OpenBSD uses clamd)
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
                stderr.decode() if stderr else "unknown error",
            )

        await asyncio.sleep(2)

        return {
            "success": True,
            "error_message": None,
            "installed_version": None,
            "result": "ClamAV installed successfully on OpenBSD",
        }
