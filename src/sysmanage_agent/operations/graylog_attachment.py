"""
Graylog attachment operations for configuring log forwarding to Graylog.
"""

import logging
import os
import platform
import subprocess  # nosec B404 - subprocess needed for system service management
import tempfile
import urllib.parse
import urllib.request
from typing import Any, Dict

import yaml


class GraylogAttachmentOperations:
    """Handles attachment of hosts to Graylog log aggregation server."""

    def __init__(self, agent_instance, logger: logging.Logger = None):
        """
        Initialize the Graylog attachment operations handler.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
            logger: Logger instance
        """
        self.agent_instance = agent_instance
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system()

    async def attach_to_graylog(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attach the host to Graylog using the specified mechanism.

        Args:
            parameters: Dictionary containing:
                - mechanism: syslog_tcp, syslog_udp, gelf_tcp, windows_sidecar
                - graylog_server: IP or hostname of Graylog server
                - port: Port number for the mechanism

        Returns:
            Dictionary with status and message
        """
        mechanism = parameters.get("mechanism")
        graylog_server = parameters.get("graylog_server")
        port = parameters.get("port")

        self.logger.info(
            "Attaching to Graylog: server=%s, mechanism=%s, port=%s",
            graylog_server,
            mechanism,
            port,
        )

        try:
            if self.system == "Windows":
                if mechanism == "windows_sidecar":
                    result = await self._configure_windows_sidecar(graylog_server, port)
                else:
                    return {
                        "status": "error",
                        "message": f"Mechanism {mechanism} not supported on Windows",
                    }
            elif self.system in ("Linux", "FreeBSD", "OpenBSD", "NetBSD"):
                if mechanism in ("syslog_tcp", "syslog_udp", "gelf_tcp"):
                    result = await self._configure_unix_syslog(
                        graylog_server, port, mechanism
                    )
                else:
                    return {
                        "status": "error",
                        "message": f"Mechanism {mechanism} not supported on {self.system}",
                    }
            else:
                return {
                    "status": "error",
                    "message": f"Platform {self.system} not supported",
                }

            if result["status"] == "success":
                # Re-collect Graylog status and send update
                await self._send_graylog_status_update()

            return result

        except Exception as error:
            self.logger.error("Error attaching to Graylog: %s", error, exc_info=True)
            return {"status": "error", "message": str(error)}

    async def _configure_unix_syslog(
        self, graylog_server: str, port: int, mechanism: str
    ) -> Dict[str, Any]:
        """
        Configure rsyslog or syslog-ng on Unix-like systems.

        Args:
            graylog_server: Graylog server IP or hostname
            port: Port number
            mechanism: syslog_tcp, syslog_udp, or gelf_tcp

        Returns:
            Status dictionary
        """
        # Determine which syslog daemon is running
        if self._is_service_running("rsyslog"):
            return await self._configure_rsyslog(graylog_server, port, mechanism)
        if self._is_service_running("syslog-ng"):
            return await self._configure_syslog_ng(graylog_server, port, mechanism)
        if self.system in ("FreeBSD", "OpenBSD", "NetBSD"):
            return await self._configure_bsd_syslog(graylog_server, port, mechanism)

        return {
            "status": "error",
            "message": "No supported syslog daemon found (rsyslog, syslog-ng, or BSD syslog)",
        }

    async def _configure_rsyslog(
        self, graylog_server: str, port: int, mechanism: str
    ) -> Dict[str, Any]:
        """Configure rsyslog for Graylog."""
        config_file = "/etc/rsyslog.d/60-graylog.conf"

        try:
            # Generate configuration based on mechanism
            if mechanism == "syslog_tcp":
                config_line = (
                    f"*.*@@{graylog_server}:{port};RSYSLOG_SyslogProtocol23Format\n"
                )
            elif mechanism == "syslog_udp":
                config_line = (
                    f"*.*@{graylog_server}:{port};RSYSLOG_SyslogProtocol23Format\n"
                )
            elif mechanism == "gelf_tcp":
                # GELF format requires additional template
                config_line = f"""
# GELF TCP output to Graylog
template(name="gelf" type="list") {{
    constant(value="{{")
    constant(value="\\"version\\":\\"1.1\\",")
    constant(value="\\"host\\":\\"")
    property(name="hostname")
    constant(value="\\",")
    constant(value="\\"short_message\\":\\"")
    property(name="msg" format="json")
    constant(value="\\",")
    constant(value="\\"timestamp\\":")
    property(name="timegenerated" dateFormat="unixtimestamp")
    constant(value=",")
    constant(value="\\"level\\":")
    property(name="syslogseverity")
    constant(value=",")
    constant(value="\\"facility\\":")
    property(name="syslogfacility")
    constant(value="}}")
    constant(value="\\n")
}}

*.* action(type="omfwd" target="{graylog_server}" port="{port}" protocol="tcp" template="gelf")
"""
            else:
                return {"status": "error", "message": f"Unknown mechanism: {mechanism}"}

            # Write configuration
            with open(config_file, "w", encoding="utf-8") as file_handle:
                file_handle.write(config_line)

            self.logger.info("Wrote rsyslog configuration to %s", config_file)

            # Restart rsyslog
            restart_result = (
                subprocess.run(  # nosec B603, B607 - safe: hardcoded systemctl command
                    ["systemctl", "restart", "rsyslog"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            )

            if restart_result.returncode == 0:
                self.logger.info("Successfully restarted rsyslog")
                return {
                    "status": "success",
                    "message": f"Configured rsyslog for Graylog ({mechanism})",
                }

            self.logger.error("Failed to restart rsyslog: %s", restart_result.stderr)
            return {
                "status": "error",
                "message": f"Failed to restart rsyslog: {restart_result.stderr}",
            }

        except Exception as error:
            self.logger.error("Error configuring rsyslog: %s", error)
            return {"status": "error", "message": str(error)}

    async def _configure_syslog_ng(
        self, graylog_server: str, port: int, mechanism: str
    ) -> Dict[str, Any]:
        """Configure syslog-ng for Graylog."""
        config_file = "/etc/syslog-ng/conf.d/60-graylog.conf"

        try:
            # Generate configuration based on mechanism
            if mechanism == "syslog_tcp":
                config_content = f"""
destination d_graylog {{
    network("{graylog_server}" port({port}) transport("tcp"));
}};

log {{
    source(s_src);
    destination(d_graylog);
}};
"""
            elif mechanism == "syslog_udp":
                config_content = f"""
destination d_graylog {{
    network("{graylog_server}" port({port}) transport("udp"));
}};

log {{
    source(s_src);
    destination(d_graylog);
}};
"""
            elif mechanism == "gelf_tcp":
                # GELF format for syslog-ng
                config_content = f"""
destination d_graylog_gelf {{
    network("{graylog_server}" port({port}) transport("tcp")
        template("$(format-json --scope rfc5424 --key ISODATE)")
    );
}};

log {{
    source(s_src);
    destination(d_graylog_gelf);
}};
"""
            else:
                return {"status": "error", "message": f"Unknown mechanism: {mechanism}"}

            # Ensure conf.d directory exists
            os.makedirs("/etc/syslog-ng/conf.d", exist_ok=True)

            # Write configuration
            with open(config_file, "w", encoding="utf-8") as file_handle:
                file_handle.write(config_content)

            self.logger.info("Wrote syslog-ng configuration to %s", config_file)

            # Restart syslog-ng
            restart_result = (
                subprocess.run(  # nosec B603, B607 - safe: hardcoded systemctl command
                    ["systemctl", "restart", "syslog-ng"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            )

            if restart_result.returncode == 0:
                self.logger.info("Successfully restarted syslog-ng")
                return {
                    "status": "success",
                    "message": f"Configured syslog-ng for Graylog ({mechanism})",
                }

            self.logger.error("Failed to restart syslog-ng: %s", restart_result.stderr)
            return {
                "status": "error",
                "message": f"Failed to restart syslog-ng: {restart_result.stderr}",
            }

        except Exception as error:
            self.logger.error("Error configuring syslog-ng: %s", error)
            return {"status": "error", "message": str(error)}

    async def _configure_bsd_syslog(
        self, graylog_server: str, port: int, mechanism: str
    ) -> Dict[str, Any]:
        """Configure BSD syslog for Graylog."""
        config_file = "/etc/syslog.conf"

        try:
            # Read existing configuration
            if os.path.exists(config_file):
                with open(config_file, "r", encoding="utf-8") as file_handle:
                    existing_config = file_handle.read()
            else:
                existing_config = ""

            # Generate forwarding line based on mechanism
            if mechanism == "syslog_tcp":
                forward_line = f"*.*\t@@{graylog_server}:{port}\n"
            elif mechanism == "syslog_udp":
                forward_line = f"*.*\t@{graylog_server}:{port}\n"
            else:
                return {
                    "status": "error",
                    "message": f"Mechanism {mechanism} not supported on BSD",
                }

            # Check if already configured
            if graylog_server in existing_config:
                self.logger.info("Graylog forwarding already configured in syslog.conf")
                # Update existing line
                lines = existing_config.split("\n")
                new_lines = []
                for line in lines:
                    if graylog_server in line and not line.strip().startswith("#"):
                        new_lines.append(forward_line.strip())
                    else:
                        new_lines.append(line)
                new_config = "\n".join(new_lines)
            else:
                # Append new forwarding rule
                new_config = (
                    existing_config.rstrip()
                    + "\n\n# Graylog forwarding\n"
                    + forward_line
                )

            # Write updated configuration
            with open(config_file, "w", encoding="utf-8") as file_handle:
                file_handle.write(new_config)

            self.logger.info("Updated BSD syslog configuration")

            # Restart syslog - service name varies by BSD variant
            service_name = "syslogd"
            if self.system == "FreeBSD":
                restart_cmd = ["service", service_name, "restart"]
            else:  # OpenBSD, NetBSD
                restart_cmd = ["rcctl", "restart", service_name]

            restart_result = (
                subprocess.run(  # nosec B603 - safe: hardcoded BSD service commands
                    restart_cmd, capture_output=True, text=True, check=False
                )
            )

            if restart_result.returncode == 0:
                self.logger.info("Successfully restarted BSD syslog")
                return {
                    "status": "success",
                    "message": f"Configured BSD syslog for Graylog ({mechanism})",
                }

            self.logger.error("Failed to restart BSD syslog: %s", restart_result.stderr)
            return {
                "status": "error",
                "message": f"Failed to restart BSD syslog: {restart_result.stderr}",
            }

        except Exception as error:
            self.logger.error("Error configuring BSD syslog: %s", error)
            return {"status": "error", "message": str(error)}

    async def _configure_windows_sidecar(
        self, graylog_server: str, port: int
    ) -> Dict[str, Any]:
        """
        Configure Graylog Sidecar on Windows.

        Downloads and installs Sidecar if not present.
        """
        try:
            # Check if Graylog Sidecar is installed
            sidecar_path = r"C:\Program Files\Graylog\sidecar\graylog-sidecar.exe"
            sidecar_installed = os.path.exists(sidecar_path)

            if not sidecar_installed:
                self.logger.info("Graylog Sidecar not installed, downloading...")
                install_result = await self._install_windows_sidecar()
                if install_result["status"] != "success":
                    return install_result

            # Configure Sidecar
            config_path = r"C:\Program Files\Graylog\sidecar\sidecar.yml"

            # Read existing config or create new one
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as file_handle:
                    config = yaml.safe_load(file_handle) or {}
            else:
                config = {}

            # Update configuration
            config["server_url"] = f"http://{graylog_server}:{port}/api/"
            # Placeholder token - must be set manually or via API
            config["server_api_token"] = ""  # nosec B105  # Placeholder value
            config["update_interval"] = 10
            config["tls_skip_verify"] = False
            config["send_status"] = True
            config["list_log_files"] = []

            # Write updated configuration
            with open(config_path, "w", encoding="utf-8") as file_handle:
                yaml.dump(config, file_handle, default_flow_style=False)

            self.logger.info("Updated Graylog Sidecar configuration")

            # Install and start service
            install_service_result = subprocess.run(  # nosec B603 - safe: sidecar_path validated, hardcoded args
                [sidecar_path, "-service", "install"],
                capture_output=True,
                text=True,
                check=False,
            )

            if install_service_result.returncode != 0:
                self.logger.warning(
                    "Service install returned non-zero: %s",
                    install_service_result.stderr,
                )

            # Start service
            start_service_result = subprocess.run(  # nosec B603 - safe: sidecar_path validated, hardcoded args
                [sidecar_path, "-service", "start"],
                capture_output=True,
                text=True,
                check=False,
            )

            if start_service_result.returncode == 0:
                self.logger.info("Successfully started Graylog Sidecar service")
                return {
                    "status": "success",
                    "message": "Configured Graylog Sidecar for Windows",
                }

            self.logger.error(
                "Failed to start Graylog Sidecar: %s", start_service_result.stderr
            )
            return {
                "status": "error",
                "message": f"Failed to start Graylog Sidecar: {start_service_result.stderr}",
            }

        except Exception as error:
            self.logger.error("Error configuring Windows Sidecar: %s", error)
            return {"status": "error", "message": str(error)}

    def _validate_download_url(self, url: str) -> bool:
        """
        Validate that the download URL is safe (HTTPS and from github.com).

        Args:
            url: The URL to validate

        Returns:
            True if URL is safe, False otherwise
        """
        try:
            parsed = urllib.parse.urlparse(url)
            # Only allow HTTPS scheme (prevents file:// and other schemes)
            if parsed.scheme != "https":
                self.logger.error(
                    "Invalid URL scheme: %s (only HTTPS allowed)", parsed.scheme
                )
                return False
            # Only allow github.com domain
            if parsed.netloc.lower() != "github.com":
                self.logger.error(
                    "Invalid URL domain: %s (only github.com allowed)", parsed.netloc
                )
                return False
            return True
        except Exception as error:
            self.logger.error("Error validating URL: %s", error)
            return False

    async def _install_windows_sidecar(self) -> Dict[str, Any]:
        """Download and install Graylog Sidecar on Windows."""
        try:
            # Determine architecture
            arch = platform.machine().lower()
            if "amd64" in arch or "x86_64" in arch:
                arch_suffix = "amd64"
            else:
                arch_suffix = "386"

            # Download URL for latest Sidecar
            # Note: You may want to pin a specific version
            download_url = f"https://github.com/Graylog2/collector-sidecar/releases/latest/download/graylog-sidecar-installer-{arch_suffix}.exe"

            # Validate URL before downloading (prevents file:// and other schemes)
            if not self._validate_download_url(download_url):
                return {
                    "status": "error",
                    "message": "Invalid download URL - security check failed",
                }

            self.logger.info("Downloading Graylog Sidecar from %s", download_url)

            # Download to temp directory
            temp_dir = tempfile.gettempdir()
            installer_path = os.path.join(temp_dir, "graylog-sidecar-installer.exe")

            # Download using urlopen with explicit HTTP/HTTPS-only opener
            # This avoids file:// scheme vulnerability from urlretrieve
            req = urllib.request.Request(download_url)
            with urllib.request.urlopen(
                req, timeout=300
            ) as response:  # nosec B310 - URL validated above (HTTPS only, github.com domain)
                with open(installer_path, "wb") as out_file:
                    out_file.write(response.read())

            self.logger.info("Downloaded Sidecar installer to %s", installer_path)

            # Run installer silently
            install_result = subprocess.run(  # nosec B603 - safe: installer_path is temp file, /S is hardcoded
                [installer_path, "/S"],  # Silent install
                capture_output=True,
                text=True,
                check=False,
                timeout=300,  # 5 minute timeout
            )

            if install_result.returncode == 0:
                self.logger.info("Successfully installed Graylog Sidecar")
                # Clean up installer
                try:
                    os.remove(installer_path)
                except Exception as error:
                    self.logger.warning("Failed to remove installer: %s", error)
                return {
                    "status": "success",
                    "message": "Installed Graylog Sidecar successfully",
                }

            self.logger.error("Sidecar installation failed: %s", install_result.stderr)
            return {
                "status": "error",
                "message": f"Failed to install Graylog Sidecar: {install_result.stderr}",
            }

        except Exception as error:
            self.logger.error("Error installing Windows Sidecar: %s", error)
            return {"status": "error", "message": str(error)}

    def _is_service_running(self, service_name: str) -> bool:
        """Check if a service is running."""
        try:
            if self.system == "Windows":
                result = subprocess.run(  # nosec B603, B607 - safe: hardcoded sc command, service_name validated
                    ["sc", "query", service_name],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                return "RUNNING" in result.stdout
            # Linux/BSD with systemd
            result = subprocess.run(  # nosec B603, B607 - safe: hardcoded systemctl, service_name validated
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def _send_graylog_status_update(self):
        """Re-collect Graylog status and send update to server."""
        try:
            # pylint: disable=import-outside-toplevel
            from src.sysmanage_agent.collection.graylog_collector import (
                GraylogCollector,
            )

            collector = GraylogCollector(self.logger)
            graylog_status = collector.collect_graylog_status()

            # Get host approval for host_id
            host_approval = (
                self.agent_instance.registration_manager.get_host_approval_from_db()
            )
            if not host_approval:
                self.logger.warning(
                    "No host approval found, cannot send Graylog status"
                )
                return

            # Create message
            message_data = {
                "hostname": self.agent_instance.registration.get_system_info()[
                    "hostname"
                ],
                "host_id": str(host_approval.host_id),
                "is_attached": graylog_status["is_attached"],
                "target_hostname": graylog_status["target_hostname"],
                "target_ip": graylog_status["target_ip"],
                "mechanism": graylog_status["mechanism"],
                "port": graylog_status["port"],
            }

            message = self.agent_instance.create_message(
                "graylog_status_update", message_data
            )

            success = await self.agent_instance.send_message(message)
            if success:
                self.logger.info("Sent updated Graylog status to server")
            else:
                self.logger.warning("Failed to send Graylog status update")

        except Exception as error:
            self.logger.error("Error sending Graylog status update: %s", error)
