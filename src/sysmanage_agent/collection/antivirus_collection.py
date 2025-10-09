"""
Antivirus detection module for SysManage Agent.
Handles detection of installed antivirus software and their status across different platforms.
"""

import logging
import os
import platform
import subprocess  # nosec B404
from typing import Dict, Optional

from src.i18n import _


class AntivirusCollector:
    """Collects antivirus software information across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system = platform.system()

    def collect_antivirus_status(self) -> Dict[str, Optional[str]]:
        """
        Collect antivirus status information for the current system.

        Returns:
            dict: Dictionary containing:
                - software_name: Name of antivirus software (or None)
                - install_path: Installation path (or None)
                - version: Version number (or None)
                - enabled: Whether antivirus is enabled (or None)
        """
        self.logger.info(_("Starting antivirus detection"))

        antivirus_info = {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

        try:
            if self.system == "Linux":
                antivirus_info = self._detect_linux_antivirus()
            elif self.system == "Darwin":  # macOS
                antivirus_info = self._detect_macos_antivirus()
            elif self.system == "Windows":
                antivirus_info = self._detect_windows_antivirus()
            elif "BSD" in self.system:
                antivirus_info = self._detect_bsd_antivirus()

            if antivirus_info["software_name"]:
                self.logger.info(
                    _("Detected antivirus: %s (enabled: %s)"),
                    antivirus_info["software_name"],
                    antivirus_info["enabled"],
                )
            else:
                self.logger.info(_("No antivirus software detected"))

        except Exception as e:
            self.logger.error(_("Error detecting antivirus: %s"), e, exc_info=True)

        return antivirus_info

    def _detect_linux_antivirus(self) -> Dict[str, Optional[str]]:
        """Detect antivirus software on Linux systems."""
        # Check for ClamAV
        clamav_info = self._check_clamav()
        if clamav_info["software_name"]:
            return clamav_info

        # Check for chkrootkit
        chkrootkit_info = self._check_chkrootkit()
        if chkrootkit_info["software_name"]:
            return chkrootkit_info

        # Check for rkhunter
        rkhunter_info = self._check_rkhunter()
        if rkhunter_info["software_name"]:
            return rkhunter_info

        return {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

    def _detect_macos_antivirus(self) -> Dict[str, Optional[str]]:
        """Detect antivirus software on macOS systems."""
        # Check for ClamAV on macOS
        clamav_info = self._check_clamav()
        if clamav_info["software_name"]:
            return clamav_info

        return {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

    def _detect_windows_antivirus(self) -> Dict[str, Optional[str]]:
        """Detect antivirus software on Windows systems."""
        # Check for ClamAV on Windows
        clamav_info = self._check_clamav_windows()
        if clamav_info["software_name"]:
            return clamav_info

        return {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

    def _detect_bsd_antivirus(self) -> Dict[str, Optional[str]]:
        """Detect antivirus software on BSD systems."""
        # Check for ClamAV
        clamav_info = self._check_clamav()
        if clamav_info["software_name"]:
            return clamav_info

        # Check for rkhunter (available on FreeBSD and NetBSD)
        if self.system in ["FreeBSD", "NetBSD"]:
            rkhunter_info = self._check_rkhunter()
            if rkhunter_info["software_name"]:
                return rkhunter_info

        return {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

    def _check_clamav(self) -> Dict[str, Optional[str]]:
        """Check for ClamAV on Unix-like systems."""
        try:
            # Try to find clamscan binary
            which_result = subprocess.run(
                ["which", "clamscan"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603 B607

            if which_result.returncode == 0:
                install_path = which_result.stdout.strip()

                # Get version
                version = None
                try:
                    version_result = subprocess.run(
                        ["clamscan", "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )  # nosec B603 B607
                    if version_result.returncode == 0:
                        # Parse version from output like "ClamAV 0.103.8/26853/..."
                        version_line = version_result.stdout.strip()
                        if version_line.startswith("ClamAV "):
                            version = version_line.split()[1].split("/")[0]
                except Exception as e:
                    self.logger.debug("Error getting ClamAV version: %s", e)

                # Check if clamd daemon or freshclam is running (indicates enabled)
                # Different distros use different service names:
                # - Ubuntu/Debian: clamav-freshclam, clamav-daemon
                # - RHEL/CentOS: clamd@scan
                # - openSUSE: clamd.service
                # - OpenBSD: clamd
                # - FreeBSD: clamav_clamd (underscore not hyphen)
                # - Generic: clamd
                enabled = (
                    self._is_service_running("clamd")
                    or self._is_service_running("clamav_clamd")
                    or self._is_service_running("clamav-daemon")
                    or self._is_service_running("clamav-freshclam")
                    or self._is_service_running("clamd@scan")
                    or self._is_service_running("clamd.service")
                )

                return {
                    "software_name": "clamav",
                    "install_path": install_path,
                    "version": version,
                    "enabled": enabled,
                }

        except Exception as e:
            self.logger.debug("Error checking ClamAV: %s", e)

        return {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

    def _get_clamav_windows_version(self, path: str) -> Optional[str]:
        """Get ClamAV version from Windows installation."""
        try:
            version_result = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603
            if version_result.returncode == 0:
                version_line = version_result.stdout.strip()
                if version_line.startswith("ClamAV "):
                    return version_line.split()[1].split("/")[0]
        except Exception as e:
            self.logger.debug("Error getting ClamAV version: %s", e)
        return None

    def _check_clamav_windows(self) -> Dict[str, Optional[str]]:
        """Check for ClamAV on Windows systems."""
        try:
            # Common ClamAV installation paths on Windows
            common_paths = [
                "C:\\Program Files\\ClamAV\\clamscan.exe",
                "C:\\Program Files (x86)\\ClamAV\\clamscan.exe",
            ]

            for path in common_paths:
                if not os.path.exists(path):
                    continue

                version = self._get_clamav_windows_version(path)
                enabled = self._is_windows_service_running("ClamAV")

                return {
                    "software_name": "clamav",
                    "install_path": path,
                    "version": version,
                    "enabled": enabled,
                }

        except Exception as e:
            self.logger.debug("Error checking ClamAV on Windows: %s", e)

        return {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

    def _get_chkrootkit_version(self) -> Optional[str]:
        """Get chkrootkit version."""
        try:
            version_result = subprocess.run(
                ["chkrootkit", "-V"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603 B607
            if version_result.returncode != 0:
                return None

            version_line = version_result.stdout.strip()
            if "chkrootkit" not in version_line.lower():
                return None

            parts = version_line.split()
            if len(parts) >= 2:
                return parts[-1]
        except Exception as e:
            self.logger.debug("Error getting chkrootkit version: %s", e)
        return None

    def _check_chkrootkit(self) -> Dict[str, Optional[str]]:
        """Check for chkrootkit on Unix-like systems."""
        try:
            # Try to find chkrootkit binary
            which_result = subprocess.run(
                ["which", "chkrootkit"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603 B607

            if which_result.returncode != 0:
                return {
                    "software_name": None,
                    "install_path": None,
                    "version": None,
                    "enabled": None,
                }

            install_path = which_result.stdout.strip()
            version = self._get_chkrootkit_version()
            enabled = self._is_in_cron("chkrootkit")

            return {
                "software_name": "chkrootkit",
                "install_path": install_path,
                "version": version,
                "enabled": enabled if enabled is not None else True,
            }

        except Exception as e:
            self.logger.debug("Error checking chkrootkit: %s", e)

        return {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

    def _parse_rkhunter_version(self, output: str) -> Optional[str]:
        """Parse rkhunter version from command output."""
        for line in output.split("\n"):
            if "rkhunter" not in line.lower():
                continue
            parts = line.split()
            for part in parts:
                if part and part[0].isdigit():
                    return part
        return None

    def _get_rkhunter_version(self) -> Optional[str]:
        """Get rkhunter version."""
        try:
            version_result = subprocess.run(
                ["rkhunter", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B607 B603
            if version_result.returncode == 0:
                return self._parse_rkhunter_version(version_result.stdout)
        except Exception as e:
            self.logger.debug("Error getting rkhunter version: %s", e)
        return None

    def _check_rkhunter(self) -> Dict[str, Optional[str]]:
        """Check for rkhunter on Unix-like systems."""
        try:
            # Try to find rkhunter binary
            which_result = subprocess.run(
                ["which", "rkhunter"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603 B607

            if which_result.returncode != 0:
                return {
                    "software_name": None,
                    "install_path": None,
                    "version": None,
                    "enabled": None,
                }

            install_path = which_result.stdout.strip()
            version = self._get_rkhunter_version()
            enabled = self._is_in_cron("rkhunter")

            return {
                "software_name": "rkhunter",
                "install_path": install_path,
                "version": version,
                "enabled": enabled if enabled is not None else True,
            }

        except Exception as e:
            self.logger.debug("Error checking rkhunter: %s", e)

        return {
            "software_name": None,
            "install_path": None,
            "version": None,
            "enabled": None,
        }

    def _is_service_running(self, service_name: str) -> bool:
        """Check if a systemd/init/rcctl service is running."""
        try:
            self.logger.info("Checking if service %s is running", service_name)

            # Try rcctl first (OpenBSD)
            if os.path.exists("/usr/sbin/rcctl"):
                self.logger.info("Using rcctl to check %s", service_name)
                result = subprocess.run(
                    ["rcctl", "check", service_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )  # nosec B603 B607

                # rcctl check returns 0 if running, 1 if not
                if result.returncode == 0:
                    self.logger.info("Service %s is running (via rcctl)", service_name)
                    return True

            # Try systemctl (systemd)
            self.logger.info("Trying systemctl for %s", service_name)
            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603 B607

            self.logger.info(
                "systemctl check for %s: returncode=%s, stdout='%s'",
                service_name,
                result.returncode,
                result.stdout.strip(),
            )

            if result.returncode == 0 and result.stdout.strip() == "active":
                self.logger.info("Service %s is active (via systemctl)", service_name)
                return True

            # Try service command (SysV init and FreeBSD)
            self.logger.info("Trying service command for %s", service_name)
            result = subprocess.run(
                ["service", service_name, "status"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603 B607

            self.logger.info(
                "Service command check for %s: returncode=%s, stdout='%s', stderr='%s'",
                service_name,
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip(),
            )

            if result.returncode == 0:
                self.logger.info(
                    "Service %s is running (via service command)", service_name
                )
                return True

            self.logger.info("Service %s is NOT running", service_name)

        except Exception as e:
            self.logger.debug("Error checking service %s: %s", service_name, e)

        return False

    def _is_windows_service_running(self, service_name: str) -> bool:
        """Check if a Windows service is running."""
        try:
            result = subprocess.run(
                ["sc", "query", service_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603 B607

            if result.returncode == 0 and "RUNNING" in result.stdout:
                return True

        except Exception as e:
            self.logger.debug("Error checking Windows service %s: %s", service_name, e)

        return False

    def _check_cron_file(self, file_path: str, command: str) -> bool:
        """Check if command exists in a cron file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return command in f.read()
        except Exception:
            return False

    def _check_cron_directory(self, cron_dir: str, command: str) -> bool:
        """Check if command exists in any file in a cron directory."""
        if not os.path.exists(cron_dir):
            return False

        try:
            for filename in os.listdir(cron_dir):
                file_path = os.path.join(cron_dir, filename)
                if os.path.isfile(file_path) and self._check_cron_file(
                    file_path, command
                ):
                    return True
        except Exception as e:
            self.logger.debug("Error checking cron directory %s: %s", cron_dir, e)
        return False

    def _is_in_cron(self, command: str) -> Optional[bool]:
        """Check if a command is scheduled in crontab."""
        try:
            # Check user crontab
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603 B607

            if result.returncode == 0 and command in result.stdout:
                return True

            # Check system cron directories
            cron_dirs = [
                "/etc/cron.d",
                "/etc/cron.daily",
                "/etc/cron.weekly",
                "/etc/cron.monthly",
            ]
            for cron_dir in cron_dirs:
                if self._check_cron_directory(cron_dir, command):
                    return True

            return False

        except Exception as e:
            self.logger.debug("Error checking cron for %s: %s", command, e)
            return None
