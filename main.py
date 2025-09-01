"""
This module is the main entry point for the SysManage agent that will run
on all clients. It provides real-time bidirectional communication with the
SysManage server using WebSockets with concurrent send/receive operations.
"""

import asyncio
import json
import logging
import os
import platform
import secrets
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import Dict, Any

import aiohttp
import websockets
import yaml

from config import ConfigManager
from registration import ClientRegistration
from i18n import _, set_language
from discovery import discovery_client
from security.certificate_store import CertificateStore


class SysManageAgent:  # pylint: disable=too-many-public-methods
    """Main agent class for SysManage fleet management."""

    def __init__(self, config_file: str = "sysmanage-agent.yaml"):
        # Try to discover server if no config file exists
        self.config_file = config_file
        # Setup basic logging first
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        if not self.try_load_config(config_file):
            self.logger.info(_("No configuration found, attempting auto-discovery..."))
            if not self.auto_discover_and_configure():
                raise RuntimeError(
                    _(
                        "Unable to configure agent: no config file and auto-discovery failed"
                    )
                )

        # Load configuration (now guaranteed to exist)
        self.config = ConfigManager(self.config_file)

        # Set language from configuration
        configured_language = self.config.get_language()
        set_language(configured_language)

        # Setup proper logging with config
        self.setup_logging()

        # Initialize agent properties
        self.agent_id = str(uuid.uuid4())
        self.websocket = None
        self.connected = False
        self.running = False
        self.connection_failures = 0

        # Initialize registration handler
        self.registration = ClientRegistration(self.config)

        # Initialize certificate store
        self.cert_store = CertificateStore()

        # Get server URL from config
        self.server_url = self.config.get_server_url()

        self.logger.info("%s ID: %s", _("Starting SysManage Agent"), self.agent_id)
        self.logger.info("Server URL: %s", self.server_url)

    def try_load_config(self, config_file: str) -> bool:
        """Try to load configuration file."""
        return os.path.exists(config_file)

    def auto_discover_and_configure(self) -> bool:
        """Auto-discover server and create configuration."""

        # Setup basic logging for discovery process
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        logger = logging.getLogger(__name__)

        logger.info("Starting auto-discovery process...")

        try:
            # Discover servers
            discovered_servers = asyncio.run(discovery_client.discover_servers())

            if not discovered_servers:
                logger.error("No SysManage servers found on the network")
                return False

            # Select best server
            best_server = discovery_client.select_best_server(discovered_servers)
            if not best_server:
                logger.error("Unable to select a server from discovered servers")
                return False

            logger.info("Selected server at %s", best_server.get("server_ip"))

            # Create configuration from discovery
            config_data = discovery_client.create_agent_config_from_discovery(
                best_server
            )

            # Write configuration file
            with open(self.config_file, "w", encoding="utf-8") as f:
                yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

            logger.info("Configuration written to %s", self.config_file)
            return True

        except Exception as e:
            logger.error("Auto-discovery failed: %s", e)
            return False

    def setup_logging(self):
        """Setup logging based on configuration."""
        log_level = self.config.get_log_level()
        log_format = self.config.get_log_format()
        log_file = self.config.get_log_file()

        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format=log_format,
            filename=log_file,
        )

        # Also log to console if file logging is enabled
        if log_file:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, log_level.upper()))
            console_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(console_handler)

    def create_message(
        self, message_type: str, data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create a standardized message."""
        return {
            "message_type": message_type,
            "message_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data or {},
        }

    def create_system_info_message(self):
        """Create system info message."""
        system_info = self.registration.get_system_info()
        return self.create_message("system_info", system_info)

    async def _check_server_health(self) -> bool:
        """Check if server is available by testing the root endpoint."""
        try:
            # Build health check URL (use HTTP endpoint, not WebSocket)
            http_url = self.config.get_server_rest_url()

            # Create SSL context if needed
            ssl_context = None
            if http_url.startswith("https://"):
                ssl_context = ssl.create_default_context()
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=5)  # 5 second timeout

            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get(f"{http_url}/") as response:
                    return response.status == 200
        except Exception as e:
            self.logger.debug("Server health check failed: %s", e)
            return False

    def create_heartbeat_message(self):
        """Create heartbeat message."""
        # Include system info in heartbeat to allow server to recreate deleted hosts
        system_info = self.registration.get_system_info()
        return self.create_message(
            "heartbeat",
            {
                "agent_status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": system_info["hostname"],
                "ipv4": system_info["ipv4"],
                "ipv6": system_info["ipv6"],
            },
        )

    async def send_message(self, message: Dict[str, Any]):
        """Send a message to the server."""
        if not self.connected or not self.websocket:
            self.logger.warning(_("Cannot send message: not connected to server"))
            return False

        try:
            await self.websocket.send(json.dumps(message))
            self.logger.debug("Sent message: %s", message["message_type"])
            return True
        except websockets.ConnectionClosed:
            self.logger.warning("Connection closed while sending message")
            self.connected = False
            self.websocket = None
            return False
        except Exception as e:
            self.logger.error("Failed to send message: %s", e)
            # Assume connection is broken on any send failure
            self.connected = False
            self.websocket = None
            return False

    async def handle_command(self, message: Dict[str, Any]):
        """Handle command from server."""
        command_id = message.get("message_id")
        command_data = message.get("data", {})
        command_type = command_data.get("command_type")
        parameters = command_data.get("parameters", {})

        self.logger.info(
            "Received command: %s with parameters: %s", command_type, parameters
        )

        try:
            if command_type == "execute_shell":
                result = await self.execute_shell_command(parameters)
            elif command_type == "get_system_info":
                result = await self.get_detailed_system_info()
            elif command_type == "install_package":
                result = await self.install_package(parameters)
            elif command_type == "update_system":
                result = await self.update_system()
            elif command_type == "restart_service":
                result = await self.restart_service(parameters)
            elif command_type == "reboot_system":
                result = await self.reboot_system()
            elif command_type == "update_os_version":
                result = await self.update_os_version()
            elif command_type == "update_hardware":
                result = await self.update_hardware()
            elif command_type == "update_user_access":
                result = await self.update_user_access()
            else:
                result = {
                    "success": False,
                    "error": f"Unknown command type: {command_type}",
                }
        except Exception as e:
            result = {"success": False, "error": str(e)}

        # Send result back to server
        response = self.create_message(
            "command_result", {"command_id": command_id, **result}
        )
        await self.send_message(response)

    async def execute_shell_command(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command."""
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
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_detailed_system_info(self) -> Dict[str, Any]:
        """Get detailed system information."""
        try:
            # Get basic system info
            info = {
                "hostname": self.hostname,
                "platform": self.platform,
                "ipv4": self.ipv4,
                "ipv6": self.ipv6,
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
            }

            return {"success": True, "result": info}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def install_package(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Install a package (platform-specific implementation needed)."""
        package_name = parameters.get("package_name")

        if not package_name:
            return {"success": False, "error": "No package name specified"}

        # This is a placeholder - real implementation would be platform-specific
        return {
            "success": False,
            "error": f"Package installation not yet implemented for {self.platform}",
        }

    async def update_system(self) -> Dict[str, Any]:
        """Update the system (platform-specific implementation needed)."""
        return {
            "success": False,
            "error": f"System updates not yet implemented for {self.platform}",
        }

    async def restart_service(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart a service (platform-specific implementation needed)."""
        service_name = parameters.get("service_name")

        if not service_name:
            return {"success": False, "error": "No service name specified"}

        return {
            "success": False,
            "error": f"Service management not yet implemented for {self.platform}",
        }

    async def reboot_system(self) -> Dict[str, Any]:
        """Reboot the system."""
        try:
            # Schedule reboot in 10 seconds to allow response to be sent
            if self.platform == "Windows":
                await asyncio.create_subprocess_shell("shutdown /r /t 10")
            else:
                await asyncio.create_subprocess_shell("sudo shutdown -r +1")

            return {"success": True, "result": "Reboot scheduled"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def send_initial_data_updates(self):
        """Send initial data updates after WebSocket connection."""
        try:
            self.logger.info(_("Sending initial OS version data..."))

            # Send OS version data
            os_info = self.registration.get_os_version_info()
            # Add hostname to OS data for server processing
            system_info = self.registration.get_system_info()
            os_info["hostname"] = system_info["hostname"]
            os_message = self.create_message("os_version_update", os_info)
            await self.send_message(os_message)

            self.logger.info(_("Sending initial hardware data..."))

            # Send hardware data
            hardware_info = self.registration.get_hardware_info()
            # Add hostname to hardware data for server processing
            system_info = self.registration.get_system_info()
            hardware_info["hostname"] = system_info["hostname"]
            self.logger.info("Hardware info keys: %s", list(hardware_info.keys()))
            self.logger.info(
                "Storage devices count: %s",
                len(hardware_info.get("storage_devices", [])),
            )
            self.logger.info(
                "Network interfaces count: %s",
                len(hardware_info.get("network_interfaces", [])),
            )
            hardware_message = self.create_message("hardware_update", hardware_info)
            await self.send_message(hardware_message)

            self.logger.info(_("Sending initial user access data..."))

            # Send user access data
            user_access_info = self.registration.get_user_access_info()
            # Add hostname to user access data for server processing
            system_info = self.registration.get_system_info()
            user_access_info["hostname"] = system_info["hostname"]
            self.logger.info("User access info keys: %s", list(user_access_info.keys()))
            self.logger.info(
                "Users count: %s",
                user_access_info.get("total_users", 0),
            )
            self.logger.info(
                "Groups count: %s",
                user_access_info.get("total_groups", 0),
            )
            user_access_message = self.create_message(
                "user_access_update", user_access_info
            )
            await self.send_message(user_access_message)

            self.logger.info(_("Sending initial software inventory data..."))

            # Send software inventory data
            software_info = self.registration.get_software_inventory_info()
            # Add hostname to software inventory data for server processing
            system_info = self.registration.get_system_info()
            software_info["hostname"] = system_info["hostname"]
            self.logger.info(
                "Software inventory info keys: %s", list(software_info.keys())
            )
            self.logger.info(
                "Software packages count: %s",
                software_info.get("total_packages", 0),
            )
            software_message = self.create_message(
                "software_inventory_update", software_info
            )
            await self.send_message(software_message)

            self.logger.info(_("Initial data updates sent successfully"))
        except Exception as e:
            self.logger.error(_("Failed to send initial data updates: %s"), e)

    async def update_os_version(self) -> Dict[str, Any]:
        """Gather and send updated OS version information to the server."""
        try:
            # Get fresh OS version info
            os_info = self.registration.get_os_version_info()
            # Add hostname to OS data for server processing
            system_info = self.registration.get_system_info()
            os_info["hostname"] = system_info["hostname"]

            # Create OS version message
            os_message = self.create_message("os_version_update", os_info)

            # Send OS version update to server
            await self.send_message(os_message)

            return {"success": True, "result": "OS version information sent"}
        except Exception as e:
            self.logger.error("Failed to update OS version: %s", e)
            return {"success": False, "error": str(e)}

    async def update_hardware(self) -> Dict[str, Any]:
        """Gather and send updated hardware information to the server."""
        try:
            # Get fresh hardware info
            hardware_info = self.registration.get_hardware_info()
            # Add hostname to hardware data for server processing
            system_info = self.registration.get_system_info()
            hardware_info["hostname"] = system_info["hostname"]

            # Create hardware message
            hardware_message = self.create_message("hardware_update", hardware_info)

            # Send hardware update to server
            await self.send_message(hardware_message)

            return {"success": True, "result": "Hardware information sent"}
        except Exception as e:
            self.logger.error("Failed to update hardware: %s", e)
            return {"success": False, "error": str(e)}

    async def update_user_access(self) -> Dict[str, Any]:
        """Gather and send updated user access information to the server."""
        try:
            # Get fresh user access info
            user_access_info = self.registration.get_user_access_info()
            # Add hostname to user access data for server processing
            system_info = self.registration.get_system_info()
            user_access_info["hostname"] = system_info["hostname"]

            # Create user access message
            user_access_message = self.create_message(
                "user_access_update", user_access_info
            )

            # Send user access update to server
            await self.send_message(user_access_message)

            return {"success": True, "result": "User access information sent"}
        except Exception as e:
            self.logger.error("Failed to update user access: %s", e)
            return {"success": False, "error": str(e)}

    async def message_receiver(self):
        """Handle incoming messages from server."""
        self.logger.debug("Message receiver started")
        try:
            while self.running:
                message = await self.websocket.recv()
                self.logger.debug("Received: %s", message)

                try:
                    data = json.loads(message)
                    message_type = data.get("message_type")

                    if message_type == "command":
                        await self.handle_command(data)
                    elif message_type == "ping":
                        # Respond to ping
                        pong = self.create_message(
                            "pong", {"ping_id": data.get("message_id")}
                        )
                        await self.send_message(pong)
                    elif message_type == "ack":
                        self.logger.debug(
                            "Server acknowledged message: %s", data.get("message_id")
                        )
                    elif message_type == "error":
                        # Handle error messages from server
                        error_data = data.get("data", {})
                        error_code = error_data.get("error_code", "unknown")
                        error_message = error_data.get(
                            "error_message", "No error message provided"
                        )
                        self.logger.error(
                            "Server error [%s]: %s", error_code, error_message
                        )

                        # If it's a host not approved error, log more specific message
                        if error_code == "host_not_approved":
                            self.logger.warning(
                                "Host registration is pending approval. WebSocket connection will be closed."
                            )
                    else:
                        self.logger.warning("Unknown message type: %s", message_type)

                except json.JSONDecodeError:
                    self.logger.error("Invalid JSON received: %s", message)
                except Exception as e:
                    self.logger.error("Error processing message: %s", e)

        except websockets.ConnectionClosed:
            self.logger.info("Connection to server closed")
            self.connected = False
            self.websocket = None
        except Exception as e:
            self.logger.error("Message receiver error: %s", e)
            self.connected = False
            self.websocket = None

    async def message_sender(self):
        """Handle periodic outgoing messages to server."""
        self.logger.debug("Message sender started")

        # Send initial system info
        system_info = self.create_system_info_message()
        await self.send_message(system_info)

        # Send periodic heartbeats
        ping_interval = self.config.get_ping_interval()
        while self.running:
            try:
                await asyncio.sleep(ping_interval)
                if self.running and self.connected:
                    heartbeat = self.create_heartbeat_message()
                    success = await self.send_message(heartbeat)
                    if not success:
                        self.logger.warning("Heartbeat failed, connection may be lost")
                        # Don't break, let the connection handling in run() deal with it
                        return
            except asyncio.CancelledError:
                # Graceful shutdown - re-raise to propagate cancellation
                self.logger.debug("Message sender cancelled")
                raise
            except Exception as e:
                self.logger.error("Message sender error: %s", e)
                # Don't break the loop on non-critical errors, but return to trigger reconnection
                return

    async def get_auth_token(self) -> str:
        """Get authentication token for WebSocket connection."""
        server_config = self.config.get_server_config()
        hostname = server_config.get("hostname", "localhost")
        port = server_config.get("port", 8000)
        use_https = server_config.get("use_https", False)

        # Build auth URL
        protocol = "https" if use_https else "http"
        auth_url = f"{protocol}://{hostname}:{port}/agent/auth"

        # Set up SSL context if needed
        ssl_context = None
        if use_https:
            ssl_context = ssl.create_default_context()
            if not self.config.should_verify_ssl():
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

        # Get hostname to send in header
        system_hostname = socket.gethostname()

        connector = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = {"x-agent-hostname": system_hostname}

            async with session.post(auth_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("connection_token", "")

                raise ConnectionError(
                    f"Failed to get auth token: HTTP {response.status}"
                )

    async def fetch_certificates(self, host_id: int) -> bool:
        """Fetch certificates from server after approval."""
        try:
            server_config = self.config.get_server_config()
            hostname = server_config.get("hostname", "localhost")
            port = server_config.get("port", 8000)
            use_https = server_config.get("use_https", False)

            # Build certificate URL
            protocol = "https" if use_https else "http"
            cert_url = f"{protocol}://{hostname}:{port}/certificates/client/{host_id}"

            # Set up SSL context if needed
            ssl_context = None
            if use_https:
                ssl_context = ssl.create_default_context()
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            # Get authentication token
            auth_token = await self.get_auth_token()

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                headers = {"Authorization": f"Bearer {auth_token}"}

                async with session.get(cert_url, headers=headers) as response:
                    if response.status == 200:
                        cert_data = await response.json()
                        self.cert_store.store_certificates(cert_data)
                        self.logger.info(
                            "Certificates retrieved and stored successfully"
                        )
                        return True
                    if response.status == 403:
                        self.logger.warning(
                            "Host not yet approved for certificate retrieval"
                        )
                        return False
                    self.logger.error(
                        "Failed to fetch certificates: HTTP %s", response.status
                    )
                    return False

        except Exception as e:
            self.logger.error("Error fetching certificates: %s", e)
            return False

    async def ensure_certificates(self) -> bool:
        """Ensure agent has valid certificates for mTLS."""
        # Check if we already have valid certificates
        if self.cert_store.has_certificates():
            self.logger.debug("Valid certificates already available")
            return True

        # If no certificates, we need to check if host is approved and fetch them
        self.logger.info(
            "No valid certificates found, checking host approval status..."
        )

        # Get server fingerprint first for security validation
        try:
            server_config = self.config.get_server_config()
            hostname = server_config.get("hostname", "localhost")
            port = server_config.get("port", 8000)
            use_https = server_config.get("use_https", False)

            protocol = "https" if use_https else "http"
            fingerprint_url = (
                f"{protocol}://{hostname}:{port}/certificates/server-fingerprint"
            )

            ssl_context = None
            if use_https:
                ssl_context = ssl.create_default_context()
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(fingerprint_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        server_fingerprint = data.get("fingerprint")
                        self.logger.info(
                            "Retrieved server fingerprint for validation: %s",
                            (
                                server_fingerprint[:16] + "..."
                                if server_fingerprint
                                else "None"
                            ),
                        )
                        # We'll store it when we get the full cert data

        except Exception as e:
            self.logger.error("Failed to get server fingerprint: %s", e)
            return False

        # Check if we can find our host ID from previous registration
        # This is a simplified approach - in a real implementation you might
        # store the host ID during registration
        system_info = self.registration.get_system_info()
        hostname = system_info["hostname"]

        # For now, we'll try to fetch with a known host ID or wait for manual approval
        # This would be improved with a more sophisticated approval checking mechanism
        self.logger.warning(
            "Certificate-based authentication requires manual host approval"
        )
        self.logger.warning("Please approve this host in the SysManage web interface")
        return False

    async def run(self):
        """Main agent execution loop."""
        system_info = self.registration.get_system_info()

        self.logger.info(_("Starting SysManage Agent"))
        self.logger.info("Agent ID: %s", self.agent_id)
        self.logger.info("Hostname: %s", system_info["hostname"])
        self.logger.info("Platform: %s", system_info["platform"])
        self.logger.info("IPv4: %s", system_info["ipv4"])
        self.logger.info("IPv6: %s", system_info["ipv6"])

        # Attempt registration with server
        self.logger.info(_("Registering with SysManage server..."))
        if not await self.registration.register_with_retry():
            self.logger.error(_("Failed to register with server. Exiting."))
            return

        self.logger.info(_("Registration successful, checking certificates..."))

        # Check if we have certificates for secure authentication
        # For now, we'll continue with token-based auth but log certificate status
        if self.cert_store.has_certificates():
            self.logger.info(
                _("Valid certificates found - secure authentication available")
            )
        else:
            self.logger.info(
                _("No certificates found - using token-based authentication")
            )
            self.logger.info(
                _(
                    "For enhanced security, approve this host to enable certificate-based auth"
                )
            )

        self.logger.info(_("Starting WebSocket connection..."))

        base_reconnect_interval = self.config.get_reconnect_interval()

        while True:
            try:
                # Check if server is available before attempting connection
                if not await self._check_server_health():
                    self.logger.warning(
                        "Server health check failed, waiting before retry..."
                    )
                    await asyncio.sleep(5)
                    continue

                # Get authentication token
                auth_token = await self.get_auth_token()
                self.logger.info("Got authentication token for WebSocket connection")

                # Add token to WebSocket URL
                websocket_url = f"{self.server_url}?token={auth_token}"

                # Create SSL context based on configuration
                ssl_context = None
                if self.server_url.startswith("wss://"):
                    ssl_context = ssl.create_default_context()

                    # If we have certificates, use them for mutual TLS
                    cert_paths = self.cert_store.load_certificates()
                    if cert_paths:
                        client_cert_path, client_key_path, ca_cert_path = cert_paths
                        ssl_context.load_cert_chain(client_cert_path, client_key_path)
                        ssl_context.load_verify_locations(ca_cert_path)
                        ssl_context.check_hostname = True
                        ssl_context.verify_mode = ssl.CERT_REQUIRED
                        self.logger.info("Using mutual TLS with client certificates")
                    elif not self.config.should_verify_ssl():
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE

                # Set up WebSocket connection with proper timeouts and ping/pong
                ping_interval = self.config.get_ping_interval()
                ping_timeout = ping_interval / 2  # Half of ping interval for timeout

                async with websockets.connect(
                    websocket_url,
                    ssl=ssl_context,
                    ping_interval=ping_interval,
                    ping_timeout=ping_timeout,
                    close_timeout=10,
                ) as websocket:
                    self.websocket = websocket
                    self.connected = True
                    self.running = True
                    self.connection_failures = (
                        0  # Reset failure count on successful connection
                    )
                    self.logger.info(_("Connected to server successfully"))

                    # Send OS version data immediately after connection
                    await self.send_initial_data_updates()

                    # Run sender and receiver concurrently with proper error handling
                    try:
                        sender_task = asyncio.create_task(self.message_sender())
                        receiver_task = asyncio.create_task(self.message_receiver())

                        # Wait for either task to complete (which indicates an error or disconnection)
                        done, pending = await asyncio.wait(
                            [sender_task, receiver_task],
                            return_when=asyncio.FIRST_COMPLETED,
                        )

                        # Cancel any remaining tasks
                        for task in pending:
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass

                        # Check if any task had an exception
                        for task in done:
                            if task.exception():
                                raise task.exception()

                    except asyncio.CancelledError:
                        self.logger.debug("Connection tasks cancelled")
                        raise

            except websockets.ConnectionClosed:
                self.logger.warning("WebSocket connection closed by server")
            except websockets.InvalidStatusCode as e:
                self.logger.error("WebSocket connection rejected: %s", e)
            except Exception as e:
                self.logger.error("Connection error: %s", e)

            # Clean up connection state
            self.connected = False
            self.websocket = None
            self.running = False
            self.connection_failures += 1

            self.logger.info(
                "Connection attempt %d failed, current failure count: %d",
                self.connection_failures,
                self.connection_failures,
            )

            # Only reconnect if auto-reconnect is enabled
            if self.config.should_auto_reconnect():
                # Calculate exponential backoff with jitter
                reconnect_interval = min(
                    base_reconnect_interval * (2 ** min(self.connection_failures, 6)),
                    300,
                )
                # Add jitter to prevent thundering herd (using secrets for cryptographic randomness)
                jitter = 0.5 + (secrets.randbelow(1000) / 1000.0)  # 0.5 to 1.5
                reconnect_interval *= jitter

                self.logger.info(
                    "Reconnecting in %.1f seconds (attempt %d)",
                    reconnect_interval,
                    self.connection_failures + 1,
                )
                await asyncio.sleep(reconnect_interval)
            else:
                self.logger.info("Auto-reconnect disabled, exiting...")
                break


if __name__ == "__main__":
    agent = SysManageAgent()
    asyncio.run(agent.run())
