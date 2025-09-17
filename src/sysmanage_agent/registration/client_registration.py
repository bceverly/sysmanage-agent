"""
Client registration module for SysManage Agent.
Handles initial registration and periodic re-registration with the server.
"""

import ssl
import logging
import asyncio
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.collection.hardware_collection import HardwareCollector
from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector
from src.sysmanage_agent.communication.network_utils import NetworkUtils
from src.sysmanage_agent.collection.user_access_collection import UserAccessCollector
from src.sysmanage_agent.collection.software_inventory_collection import (
    SoftwareInventoryCollector,
)

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print(_("⚠️  WARNING: aiohttp not available, registration will be skipped"))


class ClientRegistration:
    """Handles client registration with the SysManage server."""

    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = logging.getLogger(__name__)
        self.registered = False
        self.registration_data: Optional[Dict[str, Any]] = None

        # Initialize component modules
        self.hardware_collector = HardwareCollector()
        self.os_info_collector = OSInfoCollector()
        self.network_utils = NetworkUtils(config_manager)
        self.user_access_collector = UserAccessCollector()
        self.software_inventory_collector = SoftwareInventoryCollector()

    def _create_basic_registration_dict(
        self, hostname: str, ipv4: str, ipv6: str
    ) -> Dict[str, Any]:
        """Create basic registration dictionary structure."""
        return {
            "hostname": hostname,
            "fqdn": hostname,  # For compatibility with server's Host model
            "ipv4": ipv4,
            "ipv6": ipv6,
            "active": True,  # Mark as active when registering
        }

    def get_basic_registration_info(self) -> Dict[str, Any]:
        """Get minimal system information for initial registration."""
        hostname = self.network_utils.get_hostname()
        ipv4, ipv6 = self.network_utils.get_ip_addresses()
        basic_info = self._create_basic_registration_dict(hostname, ipv4, ipv6)

        # Add script execution capability
        script_exec_enabled = self.config.is_script_execution_enabled()
        basic_info["script_execution_enabled"] = script_exec_enabled
        # Debug logging
        import logging

        logger = logging.getLogger(__name__)
        logger.info("=== AGENT REGISTRATION DEBUG ===")
        logger.info("Script execution enabled from config: %s", script_exec_enabled)
        logger.info(
            "Basic info script_execution_enabled: %s",
            basic_info["script_execution_enabled"],
        )
        logger.info("=================================")

        return basic_info

    def get_os_version_info(self) -> Dict[str, Any]:
        """Get comprehensive OS version information as separate data."""
        return self.os_info_collector.get_os_version_info()

    def get_hardware_info(self) -> Dict[str, Any]:
        """Get comprehensive hardware information formatted for database storage."""
        return self.hardware_collector.get_hardware_info()

    def get_user_access_info(self) -> Dict[str, Any]:
        """Get comprehensive user and group access information."""
        return self.user_access_collector.get_access_info()

    def get_software_inventory_info(self) -> Dict[str, Any]:
        """Get comprehensive software inventory information."""
        return self.software_inventory_collector.get_software_inventory()

    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information (legacy method for compatibility)."""
        basic_info = self.get_basic_registration_info()
        os_info = self.get_os_version_info()

        # Add script execution status
        system_info = {**basic_info, **os_info}
        script_exec_enabled = self.config.is_script_execution_enabled()
        system_info["script_execution_enabled"] = script_exec_enabled
        # Debug logging
        import logging

        logger = logging.getLogger(__name__)
        logger.info("=== AGENT SYSTEM INFO DEBUG ===")
        logger.info("Script execution enabled from config: %s", script_exec_enabled)
        logger.info(
            "System info script_execution_enabled: %s",
            system_info["script_execution_enabled"],
        )
        logger.info("===============================")

        # Merge for backward compatibility
        return system_info

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

        # Registration is unauthenticated like login, so use base server URL without /api prefix
        server_config = self.config.get_server_config()
        hostname = server_config.get("hostname", "localhost")
        port = server_config.get("port", 8000)
        use_https = server_config.get("use_https", False)
        protocol = "https" if use_https else "http"
        base_url = f"{protocol}://{hostname}:{port}"
        registration_url = f"{base_url}/host/register"

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
