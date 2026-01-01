"""
Service status detection utilities for role detection.
"""

import fnmatch
import logging
import os
import re
import shutil
import subprocess  # nosec B404 # Required for service status checking
from typing import Optional


def is_valid_unix_username(username: str) -> bool:
    """
    Validate that a string is a valid Unix username.

    Valid usernames:
    - Start with a lowercase letter or underscore
    - Contain only lowercase letters, digits, underscores, and hyphens
    - Are 1-32 characters long

    Args:
        username: The username to validate

    Returns:
        True if valid, False otherwise
    """
    if not username:
        return False
    # POSIX portable username: starts with letter/underscore, alphanumeric/underscore/hyphen
    pattern = r"^[a-z_][a-z0-9_-]{0,31}$"
    return bool(re.match(pattern, username))


class ServiceStatusDetector:
    """Handles service status checking across different operating systems."""

    def __init__(self, system: str, logger: logging.Logger):
        self.system = system
        self.logger = logger

    def get_service_status(self, service_name: str) -> str:
        """Get the status of a service."""
        try:
            if self.system == "linux":
                return self._get_linux_service_status(service_name)
            if self.system == "darwin":  # macOS
                return self._get_macos_service_status(service_name)
            if self.system in ["netbsd", "freebsd", "openbsd"]:
                return self._get_bsd_service_status(service_name)
            if self.system == "windows":
                return self._get_windows_service_status(service_name)
        except Exception as error:
            self.logger.debug("Error checking service %s: %s", service_name, error)

        return "unknown"

    def _get_linux_service_status(self, service_name: str) -> str:
        """Get the status of a service on Linux."""
        # Try snap services first (for snap packages)
        if self._command_exists("snap"):
            snap_status = self._get_snap_service_status(service_name)
            if snap_status != "unknown":
                return snap_status

        # Try systemctl
        systemctl_path = self._get_command_path("systemctl")
        if systemctl_path:
            result = subprocess.run(  # nosec B603 B607 # systemctl with controlled args
                [systemctl_path, "is-active", service_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip() == "active":
                return "running"
            if result.stdout.strip() in ["inactive", "failed"]:
                return "stopped"

        # Try service command as fallback
        service_path = self._get_command_path("service")
        if service_path:
            result = subprocess.run(  # nosec B603 B607 # service with controlled args
                [service_path, service_name, "status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return "running" if result.returncode == 0 else "stopped"

        return "unknown"

    def _get_macos_service_status(self, service_name: str) -> str:
        """Get the status of a service on macOS."""
        # Try brew services first
        brew_status = self._check_brew_services(service_name)
        if brew_status != "unknown":
            return brew_status

        # Try checking running processes as fallback
        return self._check_process_status(service_name)

    def _check_brew_services(self, service_name: str) -> str:
        """Check service status using brew services."""
        brew_path = self._get_command_path("brew")
        if not brew_path:
            return "unknown"

        try:
            cmd = self._build_brew_command(brew_path)
            result = subprocess.run(  # nosec B603 B607 # brew with controlled args
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return self._parse_brew_services_output(result.stdout, service_name)

        except Exception as error:
            self.logger.debug(
                "Error checking brew services for %s: %s", service_name, error
            )

        return "unknown"

    def _build_brew_command(self, brew_path: str) -> list:
        """Build the brew services command, handling root user case."""
        cmd = [brew_path, "services", "list"]
        if os.getuid() == 0:  # Running as root
            # Get the original user from SUDO_USER environment variable
            # and validate it to prevent command injection
            original_user = os.environ.get("SUDO_USER")
            if original_user and is_valid_unix_username(original_user):
                cmd = ["sudo", "-u", original_user] + cmd
        return cmd

    def _parse_brew_services_output(self, output: str, service_name: str) -> str:
        """Parse brew services output to find service status."""
        for line in output.strip().split("\n"):
            if not line.strip() or line.startswith("Name"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            name = parts[0]
            status = parts[1]

            # Check if this service matches our target
            if (
                service_name in name.lower()
                or name.lower() in service_name
                or service_name == name
            ):
                if status == "started":
                    return "running"
                if status == "stopped":
                    return "stopped"

        return "unknown"

    def _check_process_status(self, service_name: str) -> str:
        """Check if service is running by examining processes."""
        try:
            result = subprocess.run(  # nosec B603 B607 # ps with controlled args
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                # Look for the service process in the output
                for line in result.stdout.lower().split("\n"):
                    if service_name.lower() in line and "grep" not in line:
                        return "running"
                    # Also check for common process name variations
                    if (
                        service_name in ["postgresql", "postgres"]
                        and "postgres:" in line
                        and "grep" not in line
                    ):
                        return "running"
                # If we checked processes and didn't find it, it's stopped
                return "stopped"
        except Exception as error:
            self.logger.debug(
                "Error checking processes for %s: %s", service_name, error
            )

        return "unknown"

    def _get_bsd_service_status(self, service_name: str) -> str:
        """Get the status of a service on BSD systems."""
        # BSD systems - check if process is running
        result = subprocess.run(  # nosec B603 B607 # ps with controlled args
            ["ps", "aux"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            # Look for the service process in the output
            for line in result.stdout.lower().split("\n"):
                if service_name.lower() in line and "grep" not in line:
                    return "running"
                # Also check for common process name variations
                if (
                    service_name in ["postgresql", "postgres"]
                    and "postgres:" in line
                    and "grep" not in line
                ):
                    return "running"
            # If we checked processes and didn't find it, it's stopped
            return "stopped"

        # Try service command as fallback for BSD
        service_path = self._get_command_path("service")
        if service_path:
            result = subprocess.run(  # nosec B603 B607 # service with controlled args
                [service_path, service_name, "onestatus"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return "running" if result.returncode == 0 else "stopped"

        return "unknown"

    def _get_snap_service_status(self, service_name: str) -> str:
        """Check the status of a snap service."""
        snap_path = self._get_command_path("snap")
        if not snap_path:
            return "unknown"

        try:
            result = subprocess.run(  # nosec B603 B607 # snap with controlled args
                [snap_path, "services"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return "unknown"

            return self._parse_snap_services_output(result.stdout, service_name)

        except Exception as error:
            self.logger.debug(
                "Error checking snap services for %s: %s", service_name, error
            )

        return "unknown"

    def _parse_snap_services_output(self, output: str, service_name: str) -> str:
        """Parse snap services output to find service status."""
        lines = output.strip().split("\n")
        # Skip the header line
        for line in lines[1:]:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            snap_service_name = parts[0]
            status = parts[2]

            # Check for service name match
            if self._is_snap_service_match(snap_service_name, service_name):
                if status == "active":
                    return "running"
                if status in ["inactive", "disabled"]:
                    return "stopped"

        return "unknown"

    def _is_snap_service_match(self, snap_service_name: str, service_name: str) -> bool:
        """Check if snap service name matches the target service name."""
        return (
            snap_service_name == service_name
            or service_name in snap_service_name
            or snap_service_name.endswith(f".{service_name}")
        )

    def _get_windows_service_status(self, service_name: str) -> str:
        """Get the status of a service on Windows."""
        # Windows services can have different names
        service_mappings = {
            "postgresql": ["postgresql-x64-*", "postgresql*"],
            "postgres": ["postgresql-x64-*", "postgresql*"],
            "mysql": ["MySQL*", "MySQL", "MySQL80", "MySQL57"],
            "mysqld": ["MySQL*", "MySQL", "MySQL80", "MySQL57"],
            "mongodb": ["MongoDB"],
            "mongod": ["MongoDB"],
            "redis": ["Redis"],
        }

        # Get actual service names to check
        services_to_check = service_mappings.get(service_name, [service_name])

        for svc_pattern in services_to_check:
            status = self._check_single_service_pattern(svc_pattern)
            if status != "unknown":
                return status

        return "unknown"

    def _check_single_service_pattern(self, svc_pattern: str) -> str:
        """Check a single service pattern and return its status."""
        try:
            # Use sc query to list services
            result = subprocess.run(
                [
                    "sc",
                    "query",
                    "state=",
                    "all",
                ],  # nosec B603, B607 # Safe: no user input
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return self._parse_service_output(result.stdout, svc_pattern)

        except Exception as error:
            self.logger.debug(
                "Error checking Windows service %s: %s", svc_pattern, error
            )

        return "unknown"

    def _parse_service_output(self, output: str, svc_pattern: str) -> str:
        """Parse sc query output for a specific service pattern."""
        lines = output.split("\n")
        current_service = None

        for line in lines:
            if "SERVICE_NAME:" in line:
                current_service = line.split("SERVICE_NAME:")[1].strip()
            elif "STATE" in line and current_service:
                # Check if this service matches our pattern
                if self._matches_service_pattern(current_service, svc_pattern):
                    if "RUNNING" in line:
                        self.logger.info(
                            "Found running Windows service: %s", current_service
                        )
                        return "running"
                    if "STOPPED" in line:
                        self.logger.info(
                            "Found stopped Windows service: %s", current_service
                        )
                        return "stopped"

        return "unknown"

    def _matches_service_pattern(self, service_name: str, pattern: str) -> bool:
        """Check if a Windows service name matches a pattern."""
        # Case-insensitive matching
        service_lower = service_name.lower()
        pattern_lower = pattern.lower()

        # Try exact match first
        if service_lower == pattern_lower:
            return True

        # Try wildcard match
        if "*" in pattern:
            return fnmatch.fnmatch(service_lower, pattern_lower)

        # Try substring match
        return pattern_lower in service_lower

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system."""
        return shutil.which(command) is not None

    def _get_command_path(self, command: str) -> Optional[str]:
        """Get the full path to a command."""
        return shutil.which(command)
