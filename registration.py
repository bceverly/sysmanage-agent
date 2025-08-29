"""
Client registration module for SysManage Agent.
Handles initial registration and periodic re-registration with the server.
"""

import socket
import platform
import logging
import asyncio
import ssl
from typing import Any, Dict, Optional, Tuple

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
            self.logger.debug("Could not determine IPv4 address: %s", e)

        try:
            # Get IPv6 address by connecting to a remote host
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.connect(("2001:4860:4860::8888", 80))
                ipv6 = s.getsockname()[0]
        except Exception as e:
            self.logger.debug("Could not determine IPv6 address: %s", e)

        return ipv4, ipv6

    def get_basic_registration_info(self) -> Dict[str, Any]:
        """Get minimal system information for initial registration."""
        hostname = self.get_hostname()
        ipv4, ipv6 = self.get_ip_addresses()

        return {
            "hostname": hostname,
            "fqdn": hostname,  # For compatibility with server's Host model
            "ipv4": ipv4,
            "ipv6": ipv6,
            "active": True,  # Mark as active when registering
        }

    def get_os_version_info(self) -> Dict[str, Any]:
        """Get comprehensive OS version information as separate data."""
        # Get CPU architecture (x86_64, arm64, aarch64, riscv64, etc.)
        machine_arch = platform.machine()

        # Get detailed OS information
        os_info = {}
        try:
            # Try to get Linux distribution info if available
            if hasattr(platform, "freedesktop_os_release"):
                os_release = platform.freedesktop_os_release()
                os_info["distribution"] = os_release.get("NAME", "")
                os_info["distribution_version"] = os_release.get("VERSION_ID", "")
                os_info["distribution_codename"] = os_release.get(
                    "VERSION_CODENAME", ""
                )
        except (AttributeError, OSError):
            pass

        # For macOS, get additional version info
        if platform.system() == "Darwin":
            mac_ver = platform.mac_ver()
            os_info["mac_version"] = mac_ver[0] if mac_ver[0] else ""

        # For Windows, get additional version info
        if platform.system() == "Windows":
            win_ver = platform.win32_ver()
            os_info["windows_version"] = win_ver[0] if win_ver[0] else ""
            os_info["windows_service_pack"] = win_ver[1] if win_ver[1] else ""

        return {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "machine_architecture": machine_arch,  # CPU architecture
            "python_version": platform.python_version(),
            "os_info": os_info,
        }

    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information (legacy method for compatibility)."""
        basic_info = self.get_basic_registration_info()
        os_info = self.get_os_version_info()

        # Merge for backward compatibility
        return {**basic_info, **os_info}

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

        # Use minimal registration data
        basic_info = self.get_basic_registration_info()

        self.logger.info("Attempting to register with server at %s", registration_url)
        self.logger.info("=== Minimal Registration Data Being Sent ===")
        for key, value in basic_info.items():
            self.logger.info("  %s: %s", key, value)
        self.logger.info("=== End Registration Data ===")
        self.logger.debug("Registration data: %s", basic_info)

        try:
            # Create SSL context that doesn't verify certificates (for development)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    registration_url,
                    json=basic_info,
                    headers={"Content-Type": "application/json"},
                ) as response:

                    if response.status in [200, 201]:
                        response_data = await response.json()
                        self.registration_data = response_data
                        self.registered = True
                        self.logger.info(
                            "Successfully registered with server. Host ID: %s",
                            response_data.get("id"),
                        )
                        return True
                    if response.status == 409:
                        # Host already exists - this is OK
                        self.logger.info("Host already registered with server")
                        self.registered = True
                        return True
                    error_text = await response.text()
                    self.logger.error(
                        "Registration failed with status %s: %s",
                        response.status,
                        error_text,
                    )
                    return False

        except (
            Exception
        ) as e:  # Catch all since aiohttp.ClientError might not be available
            self.logger.error("Error during registration: %s", e)
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
                "Registration attempt %s%s",
                attempt,
                # pylint: disable-next=consider-using-f-string
                (" of %s" % max_retries if max_retries != -1 else ""),
            )

            if await self.register_with_server():
                return True

            if max_retries != -1 and attempt >= max_retries:
                self.logger.error("Failed to register after %s attempts", max_retries)
                return False

            self.logger.warning(
                "Registration failed, retrying in %s seconds...", retry_interval
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
