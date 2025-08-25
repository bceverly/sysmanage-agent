"""
This module is the main entry point for the SysManage agent that will run
on all clients. It provides real-time bidirectional communication with the
SysManage server using WebSockets with concurrent send/receive operations.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any
import websockets

from config import ConfigManager
from registration import ClientRegistration


class SysManageAgent:
    """Main agent class for SysManage fleet management."""

    def __init__(self, config_file: str = "client.yaml"):
        # Load configuration
        self.config = ConfigManager(config_file)
        
        # Setup logging
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Initialize agent properties
        self.agent_id = str(uuid.uuid4())
        self.websocket = None
        self.running = False
        
        # Initialize registration handler
        self.registration = ClientRegistration(self.config)
        
        # Get server URL from config
        self.server_url = self.config.get_server_url()
        
        self.logger.info(f"SysManage Agent initialized with ID: {self.agent_id}")
        self.logger.info(f"Server URL: {self.server_url}")

    def setup_logging(self):
        """Setup logging based on configuration."""
        log_level = self.config.get_log_level()
        log_format = self.config.get_log_format()
        log_file = self.config.get_log_file()
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format=log_format,
            filename=log_file
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
                self.logger.debug(f"Sent message: {message['message_type']}")
            except Exception as e:
                self.logger.error(f"Failed to send message: {e}")

    async def handle_command(self, message: Dict[str, Any]):
        """Handle command from server."""
        command_id = message.get("message_id")
        command_data = message.get("data", {})
        command_type = command_data.get("command_type")
        parameters = command_data.get("parameters", {})

        self.logger.info(f"Received command: {command_type} with parameters: {parameters}")

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
                self.logger.debug(f"Received: {message}")

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
                        self.logger.debug(f"Server acknowledged message: {data.get('message_id')}")
                    else:
                        self.logger.warning(f"Unknown message type: {message_type}")

                except json.JSONDecodeError:
                    self.logger.error(f"Invalid JSON received: {message}")
                except Exception as e:
                    self.logger.error(f"Error processing message: {e}")

        except websockets.exceptions.ConnectionClosed:
            self.logger.info("Connection to server closed")
        except Exception as e:
            self.logger.error(f"Message receiver error: {e}")

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
                self.logger.error(f"Message sender error: {e}")
                break

    async def run(self):
        """Main agent execution loop."""
        system_info = self.registration.get_system_info()
        
        self.logger.info("SysManage Agent starting")
        self.logger.info(f"Agent ID: {self.agent_id}")
        self.logger.info(f"Hostname: {system_info['hostname']}")
        self.logger.info(f"Platform: {system_info['platform']}")
        self.logger.info(f"IPv4: {system_info['ipv4']}")
        self.logger.info(f"IPv6: {system_info['ipv6']}")

        # Attempt registration with server
        self.logger.info("Registering with SysManage server...")
        if not await self.registration.register_with_retry():
            self.logger.error("Failed to register with server. Exiting.")
            return

        self.logger.info("Registration successful, starting WebSocket connection...")

        reconnect_interval = self.config.get_reconnect_interval()
        
        while True:
            try:
                async with websockets.connect(self.server_url) as websocket:
                    self.websocket = websocket
                    self.running = True
                    self.logger.info("Connected to SysManage server via WebSocket")

                    # Run sender and receiver concurrently
                    await asyncio.gather(self.message_sender(), self.message_receiver())

            except websockets.exceptions.ConnectionClosed:
                self.logger.warning(f"Connection lost, attempting to reconnect in {reconnect_interval} seconds...")
            except Exception as e:
                self.logger.error(f"Connection error: {e}, retrying in {reconnect_interval} seconds...")

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
