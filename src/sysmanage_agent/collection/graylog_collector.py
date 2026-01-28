"""
Graylog attachment status collector for the SysManage agent.

This module detects whether the host is forwarding logs to a Graylog server
and through what mechanism (syslog TCP/UDP, GELF TCP, Windows Sidecar).
"""

import ipaddress
import logging
import os
import platform
import re
import socket
import subprocess  # nosec B404 - subprocess needed for service checks
from typing import Dict, Optional

import yaml

RSYSLOG_CONF_DIR = "/etc/rsyslog.d"


class GraylogCollector:
    """Collects Graylog attachment status for the host."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the Graylog collector.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system()

    def collect_graylog_status(self) -> Dict:
        """
        Collect Graylog attachment status.

        Returns:
            Dictionary containing:
                - is_attached: bool
                - target_hostname: str or None
                - target_ip: str or None
                - mechanism: str or None (syslog_tcp, syslog_udp, gelf_tcp, windows_sidecar)
                - port: int or None
        """
        try:
            if self.system == "Linux":
                return self._detect_linux_syslog()
            if self.system in ("FreeBSD", "OpenBSD", "NetBSD"):
                return self._detect_bsd_syslog()
            if self.system == "Windows":
                return self._detect_windows_sidecar()

            self.logger.warning(
                "Graylog detection not supported on platform: %s", self.system
            )
            return self._no_attachment()
        except Exception as error:
            self.logger.error("Error collecting Graylog status: %s", error)
            return self._no_attachment()

    def _no_attachment(self) -> Dict:
        """Return a dictionary indicating no Graylog attachment."""
        return {
            "is_attached": False,
            "target_hostname": None,
            "target_ip": None,
            "mechanism": None,
            "port": None,
        }

    def _detect_linux_syslog(self) -> Dict:
        """
        Detect syslog/rsyslog configuration on Linux.

        Checks /etc/rsyslog.conf and /etc/rsyslog.d/* for remote forwarding.
        """
        # Check if rsyslog is running
        rsyslog_running = self._is_service_running("rsyslog")

        if rsyslog_running:
            # Check rsyslog configuration
            result = self._parse_rsyslog_config()
            if result["is_attached"]:
                return result

        # Check if syslog-ng is running
        syslog_ng_running = self._is_service_running("syslog-ng")

        if syslog_ng_running:
            # Check syslog-ng configuration
            result = self._parse_syslog_ng_config()
            if result["is_attached"]:
                return result

        return self._no_attachment()

    def _detect_bsd_syslog(self) -> Dict:
        """
        Detect syslog configuration on BSD systems.

        Checks /etc/syslog.conf for remote forwarding.
        """
        syslog_conf = "/etc/syslog.conf"

        if not os.path.exists(syslog_conf):
            return self._no_attachment()

        try:
            with open(syslog_conf, "r", encoding="utf-8") as file:
                content = file.read()

            result = self._parse_bsd_syslog_content(content)
            if result["is_attached"]:
                return result

        except Exception as error:
            self.logger.error("Error reading BSD syslog.conf: %s", error)

        return self._no_attachment()

    def _parse_bsd_syslog_content(self, content: str) -> Dict:
        """Parse BSD syslog.conf content for remote forwarding configuration."""
        # UDP pattern (@host:port or @host, with or without space)
        udp_pattern = r"^\s*[\*\w\.]+\s*@([^@\s]+?)(?::(\d+))?\s*$"
        # TCP pattern (@@host:port or @@host, with or without space)
        tcp_pattern = r"^\s*[\*\w\.]+\s*@@([^\s]+?)(?::(\d+))?\s*$"

        for line in content.splitlines():
            if line.strip().startswith("#"):
                continue

            # Check for TCP forwarding
            result = self._match_syslog_forwarding(line, tcp_pattern, "syslog_tcp", 514)
            if result:
                return result

            # Check for UDP forwarding
            result = self._match_syslog_forwarding(line, udp_pattern, "syslog_udp", 514)
            if result:
                return result

        return self._no_attachment()

    def _detect_windows_sidecar(self) -> Dict:
        """
        Detect Windows Graylog Sidecar service and parse configuration.

        Checks if Graylog Sidecar service is running and parses its YAML config.
        """
        if not self._is_windows_sidecar_running():
            return self._no_attachment()

        return self._parse_windows_sidecar_config()

    def _is_windows_sidecar_running(self) -> bool:
        """Check if the Graylog Sidecar Windows service is running."""
        try:
            result = subprocess.run(  # nosec B603, B607 - safe: hardcoded args, no user input
                ["sc", "query", "graylog-sidecar"],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                return False

            return "RUNNING" in result.stdout

        except Exception as error:
            self.logger.error("Error checking Graylog Sidecar service: %s", error)
            return False

    def _parse_windows_sidecar_config(self) -> Dict:
        """Parse Graylog Sidecar configuration files to find the target server."""
        sidecar_config_paths = [
            r"C:\Program Files\graylog\sidecar\sidecar.yml",
            r"C:\Program Files (x86)\graylog\sidecar\sidecar.yml",
        ]

        for config_path in sidecar_config_paths:
            result = self._parse_single_sidecar_config(config_path)
            if result and result["is_attached"]:
                return result

        return self._no_attachment()

    def _parse_single_sidecar_config(self, config_path: str) -> Optional[Dict]:
        """Parse a single Graylog Sidecar config file for server URL."""
        if not os.path.exists(config_path):
            return None

        try:
            with open(config_path, "r", encoding="utf-8") as file:
                config = yaml.safe_load(file)

            server_url = config.get("server_url", "")
            if not server_url:
                return None

            url_pattern = r"https?://([^:/]+)(?::(\d+))?"
            match = re.match(url_pattern, server_url)
            if match:
                target = match.group(1)
                hostname, ip_addr = self._resolve_target(target)

                return {
                    "is_attached": True,
                    "target_hostname": hostname,
                    "target_ip": ip_addr,
                    "mechanism": "windows_sidecar",
                    "port": 5044,
                }

        except Exception as error:
            self.logger.error("Error parsing Graylog Sidecar config: %s", error)

        return None

    def _parse_rsyslog_config(self) -> Dict:
        """
        Parse rsyslog configuration files.

        Checks /etc/rsyslog.conf and /etc/rsyslog.d/*.conf for remote forwarding.
        """
        config_files = self._collect_rsyslog_config_files()

        for config_file in config_files:
            if not os.path.exists(config_file):
                continue

            try:
                with open(config_file, "r", encoding="utf-8") as file:
                    content = file.read()

                result = self._parse_rsyslog_content(content)
                if result["is_attached"]:
                    return result

            except Exception as error:
                self.logger.error(
                    "Error reading rsyslog config %s: %s", config_file, error
                )

        return self._no_attachment()

    def _collect_rsyslog_config_files(self) -> list:
        """Collect all rsyslog configuration file paths."""
        config_files = ["/etc/rsyslog.conf"]

        if os.path.exists(RSYSLOG_CONF_DIR):
            for filename in os.listdir(RSYSLOG_CONF_DIR):
                if filename.endswith(".conf"):
                    config_files.append(os.path.join(RSYSLOG_CONF_DIR, filename))

        return config_files

    def _parse_rsyslog_content(self, content: str) -> Dict:
        """Parse rsyslog config content for remote forwarding patterns."""
        # GELF TCP pattern (with or without space before @)
        gelf_pattern = r"^\s*[\*\w\.]+\s*@([^@\s]+?)(?::(\d+))?;GELF"
        # TCP pattern (@@host:port or @@host, with or without space)
        tcp_pattern = r"^\s*[\*\w\.]+\s*@@([^\s;]+)(?::(\d+))?\s*(?:;|$)"
        # UDP pattern (@host:port or @host, with or without space)
        udp_pattern = r"^\s*[\*\w\.]+\s*@([^@\s;]+)(?::(\d+))?\s*(?:;|$)"

        for line in content.splitlines():
            if line.strip().startswith("#"):
                continue

            # Check for GELF TCP
            result = self._match_syslog_forwarding(
                line, gelf_pattern, "gelf_tcp", 12201
            )
            if result:
                return result

            # Check for TCP forwarding
            result = self._match_syslog_forwarding(line, tcp_pattern, "syslog_tcp", 514)
            if result:
                return result

            # Check for UDP forwarding
            result = self._match_syslog_forwarding(line, udp_pattern, "syslog_udp", 514)
            if result:
                return result

        return self._no_attachment()

    def _match_syslog_forwarding(
        self, line: str, pattern: str, mechanism: str, default_port: int
    ) -> Optional[Dict]:
        """Match a syslog forwarding pattern in a config line and return attachment info."""
        match = re.match(pattern, line)
        if not match:
            return None

        target = match.group(1)
        port = int(match.group(2)) if match.group(2) else default_port
        hostname, ip_addr = self._resolve_target(target)

        return {
            "is_attached": True,
            "target_hostname": hostname,
            "target_ip": ip_addr,
            "mechanism": mechanism,
            "port": port,
        }

    def _parse_syslog_ng_config(self) -> Dict:
        """
        Parse syslog-ng configuration.

        Checks /etc/syslog-ng/syslog-ng.conf for remote forwarding.
        """
        config_file = "/etc/syslog-ng/syslog-ng.conf"

        if not os.path.exists(config_file):
            return self._no_attachment()

        try:
            with open(config_file, "r", encoding="utf-8") as file:
                content = file.read()

            # Look for destination blocks with network() or tcp() or udp()
            # Example:
            # destination d_graylog {
            #   network("192.168.1.100" port(514) transport("tcp"));
            # };

            # Pattern to match network destinations
            network_pattern = r'network\s*\(\s*"([^"]+)"\s+port\s*\(\s*(\d+)\s*\)\s+transport\s*\(\s*"([^"]+)"\s*\)'

            for match in re.finditer(network_pattern, content):
                target = match.group(1)
                port = int(match.group(2))
                transport = match.group(3).lower()

                hostname, ip_addr = self._resolve_target(target)

                mechanism = f"syslog_{transport}"  # syslog_tcp or syslog_udp

                return {
                    "is_attached": True,
                    "target_hostname": hostname,
                    "target_ip": ip_addr,
                    "mechanism": mechanism,
                    "port": port,
                }

        except Exception as error:
            self.logger.error("Error reading syslog-ng config: %s", error)

        return self._no_attachment()

    def _is_service_running(self, service_name: str) -> bool:
        """
        Check if a systemd service is running.

        Args:
            service_name: Name of the service to check

        Returns:
            True if service is running, False otherwise
        """
        try:
            result = subprocess.run(  # nosec B603, B607 - safe: hardcoded args, service_name validated
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.stdout.strip() == "active"
        except Exception:
            return False

    def _resolve_target(self, target: str) -> tuple:
        """
        Resolve target to hostname and IP address.

        Args:
            target: Hostname or IP address

        Returns:
            Tuple of (hostname, ip_address)
            If target is an IP, hostname will be None
            If target is a hostname, both will be set (IP may be None if resolution fails)
        """
        # Check if target is an IP address
        try:
            ipaddress.ip_address(target)
            # It's an IP address
            return (None, target)
        except ValueError:
            # It's a hostname - try to resolve it
            try:
                ip_addr = socket.gethostbyname(target)
                return (target, ip_addr)
            except socket.gaierror:
                # Resolution failed, return hostname only
                return (target, None)
