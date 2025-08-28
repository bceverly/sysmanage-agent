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


class SysManageAgent:
    """Main agent class for SysManage fleet management."""

    def __init__(self, config_file: str = "client.yaml"):
        # Try to discover server if no config file exists
        self.config_file = config_file
        # Setup basic logging first
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        if not self.try_load_config(config_file):
            self.logger.info("No configuration found, attempting auto-discovery...")
            if not self.auto_discover_and_configure():
                raise RuntimeError(
                    "Unable to configure agent: no config file and auto-discovery failed"
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
        self.running = False

        # Initialize registration handler
        self.registration = ClientRegistration(self.config)

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

    def create_heartbeat_message(self):
        """Create heartbeat message."""
        return self.create_message(
            "heartbeat",
            {
                "agent_status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def send_message(self, message: Dict[str, Any]):
        """Send a message to the server."""
        if self.websocket:
            try:
                await self.websocket.send(json.dumps(message))
                self.logger.debug("Sent message: %s", message["message_type"])
            except Exception as e:
                self.logger.error("Failed to send message: %s", e)

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
                    else:
                        self.logger.warning("Unknown message type: %s", message_type)

                except json.JSONDecodeError:
                    self.logger.error("Invalid JSON received: %s", message)
                except Exception as e:
                    self.logger.error("Error processing message: %s", e)

        except websockets.ConnectionClosed:
            self.logger.info("Connection to server closed")
        except Exception as e:
            self.logger.error("Message receiver error: %s", e)

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
                if self.running:
                    heartbeat = self.create_heartbeat_message()
                    await self.send_message(heartbeat)
            except Exception as e:
                self.logger.error("Message sender error: %s", e)
                break

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
        self.logger.info("Registering with SysManage server...")
        if not await self.registration.register_with_retry():
            self.logger.error("Failed to register with server. Exiting.")
            return

        self.logger.info("Registration successful, starting WebSocket connection...")

        reconnect_interval = self.config.get_reconnect_interval()

        while True:
            try:
                # Get authentication token
                auth_token = await self.get_auth_token()
                self.logger.info("Got authentication token for WebSocket connection")

                # Add token to WebSocket URL
                websocket_url = f"{self.server_url}?token={auth_token}"

                # Create SSL context based on configuration
                ssl_context = None
                if self.server_url.startswith("wss://"):
                    ssl_context = ssl.create_default_context()
                    if not self.config.should_verify_ssl():
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE

                async with websockets.connect(
                    websocket_url, ssl=ssl_context
                ) as websocket:
                    self.websocket = websocket
                    self.running = True
                    self.logger.info(_("Connected to server successfully"))

                    # Run sender and receiver concurrently
                    await asyncio.gather(self.message_sender(), self.message_receiver())

            except websockets.ConnectionClosed:
                self.logger.warning(
                    "Connection lost, attempting to reconnect in %s seconds...",
                    reconnect_interval,
                )
            except Exception as e:
                self.logger.error(
                    "Connection error: %s, retrying in %s seconds...",
                    e,
                    reconnect_interval,
                )

            self.running = False

            # Only reconnect if auto-reconnect is enabled
            if self.config.should_auto_reconnect():
                await asyncio.sleep(reconnect_interval)
            else:
                self.logger.info("Auto-reconnect disabled, exiting...")
                break


if __name__ == "__main__":
    agent = SysManageAgent()
    asyncio.run(agent.run())
