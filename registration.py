"""
Client registration module for SysManage Agent.
Handles initial registration and periodic re-registration with the server.
"""

import socket
import platform
import logging
import asyncio
import ssl
from typing import Dict, Any, Optional, Tuple
import json

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("⚠️  WARNING: aiohttp not available, registration will be skipped")


class ClientRegistration:
    """Handles client registration with the SysManage server."""

    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = logging.getLogger(__name__)
        self.registered = False
        self.registration_data: Optional[Dict[str, Any]] = None

    def get_hostname(self) -> str:
        """Get the hostname, with optional override from config."""
        override = self.config.get_hostname_override()
        if override:
            return override
        return socket.getfqdn()

    def get_ip_addresses(self) -> Tuple[Optional[str], Optional[str]]:
        """Get both IPv4 and IPv6 addresses of the machine."""
        ipv4 = None
        ipv6 = None

        try:
            # Get IPv4 address by connecting to a remote host
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ipv4 = s.getsockname()[0]
        except Exception as e:
            self.logger.debug(f"Could not determine IPv4 address: {e}")

        try:
            # Get IPv6 address by connecting to a remote host
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.connect(("2001:4860:4860::8888", 80))
                ipv6 = s.getsockname()[0]
        except Exception as e:
            self.logger.debug(f"Could not determine IPv6 address: {e}")

        return ipv4, ipv6

    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information for registration."""
        hostname = self.get_hostname()
        ipv4, ipv6 = self.get_ip_addresses()

        return {
            "hostname": hostname,
            "fqdn": hostname,  # For compatibility with server's Host model
            "ipv4": ipv4,
            "ipv6": ipv6,
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "active": True,  # Mark as active when registering
        }

    async def register_with_server(self) -> bool:
        """
        Register the client with the SysManage server.

        Returns:
            True if registration successful, False otherwise
        """
        if not AIOHTTP_AVAILABLE:
            self.logger.warning("aiohttp not available, skipping registration")
            self.registered = True  # Pretend we're registered for now
            return True

        server_url = self.config.get_server_rest_url()
        registration_url = f"{server_url}/host/register"

        system_info = self.get_system_info()

        self.logger.info(f"Attempting to register with server at {registration_url}")
        self.logger.debug(f"Registration data: {system_info}")

        try:
            # Create SSL context that doesn't verify certificates (for development)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    registration_url,
                    json=system_info,
                    headers={"Content-Type": "application/json"},
                ) as response:

                    if response.status in [200, 201]:
                        response_data = await response.json()
                        self.registration_data = response_data
                        self.registered = True
                        self.logger.info(
                            f"Successfully registered with server. Host ID: {response_data.get('id')}"
                        )
                        return True
                    elif response.status == 409:
                        # Host already exists - this is OK
                        self.logger.info("Host already registered with server")
                        self.registered = True
                        return True
                    else:
                        error_text = await response.text()
                        self.logger.error(
                            f"Registration failed with status {response.status}: {error_text}"
                        )
                        return False

        except (
            Exception
        ) as e:  # Catch all since aiohttp.ClientError might not be available
            self.logger.error(f"Error during registration: {e}")
            return False

    async def register_with_retry(self) -> bool:
        """
        Register with server using configured retry settings.

        Returns:
            True if registration eventually succeeds, False if max retries exceeded
        """
        retry_interval = self.config.get_registration_retry_interval()
        max_retries = self.config.get_max_registration_retries()

        attempt = 0
        while max_retries == -1 or attempt < max_retries:
            attempt += 1

            self.logger.info(
                f"Registration attempt {attempt}"
                + (f" of {max_retries}" if max_retries != -1 else "")
            )

            if await self.register_with_server():
                return True

            if max_retries != -1 and attempt >= max_retries:
                self.logger.error(f"Failed to register after {max_retries} attempts")
                return False

            self.logger.warning(
                f"Registration failed, retrying in {retry_interval} seconds..."
            )
            await asyncio.sleep(retry_interval)

        return False

    def is_registered(self) -> bool:
        """Check if client is currently registered."""
        return self.registered

    def get_registration_data(self) -> Optional[Dict[str, Any]]:
        """Get the registration response data."""
        return self.registration_data

    def get_host_id(self) -> Optional[int]:
        """Get the host ID from registration data."""
        if self.registration_data:
            return self.registration_data.get("id")
        return None
