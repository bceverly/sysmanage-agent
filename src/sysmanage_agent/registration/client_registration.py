"""
Client registration module for SysManage Agent.
Handles initial registration and periodic re-registration with the server.
"""

import asyncio
import logging
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text

from src.database.base import get_db_session
from src.database.models import HostApproval
from src.i18n import _
from src.sysmanage_agent.collection.hardware_collection import HardwareCollector
from src.sysmanage_agent.core.agent_utils import is_running_privileged
from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector
from src.sysmanage_agent.collection.software_inventory_collection import (
    SoftwareInventoryCollector,
)
from src.sysmanage_agent.collection.user_access_collection import UserAccessCollector
from src.sysmanage_agent.communication.network_utils import NetworkUtils

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

        # Load existing authentication data from database
        self._load_stored_auth_data()

    def _create_basic_registration_dict(
        self, hostname: str, ipv4: str, ipv6: str
    ) -> Dict[str, Any]:
        """Create basic registration dictionary structure."""
        return {
            "message_type": "registration_request",
            "message_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
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

        # Add privileged status - whether agent is running as root/admin
        is_privileged = is_running_privileged()
        basic_info["is_privileged"] = is_privileged

        # Add enabled shells from configuration
        enabled_shells = self.config.get_allowed_shells()
        basic_info["enabled_shells"] = enabled_shells

        # Add auto-approve token if configured (used for automatic host approval
        # during child host creation)
        auto_approve_token = self.config.get_auto_approve_token()
        if auto_approve_token:
            basic_info["auto_approve_token"] = auto_approve_token
            self.logger.info("Including auto_approve_token in registration data")

        # Debug logging
        logger = logging.getLogger(__name__)
        logger.info("=== AGENT REGISTRATION DEBUG ===")
        logger.info("Script execution enabled from config: %s", script_exec_enabled)
        logger.info(
            "Basic info script_execution_enabled: %s",
            basic_info["script_execution_enabled"],
        )
        logger.info("Is privileged: %s", is_privileged)
        logger.info("Enabled shells: %s", enabled_shells)
        # nosemgrep: python.lang.security.audit.python-logger-credential-disclosure
        # Safe: only logs boolean (is not None), not the actual token value
        logger.info("Auto-approve token present: %s", auto_approve_token is not None)
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

        # Merge basic_info and os_info
        system_info = {**basic_info, **os_info}

        # Explicitly set these fields to ensure they're always present
        system_info["script_execution_enabled"] = (
            self.config.is_script_execution_enabled()
        )
        system_info["is_privileged"] = is_running_privileged()
        system_info["enabled_shells"] = self.config.get_allowed_shells()

        # Add auto-approve token if configured
        auto_approve_token = self.config.get_auto_approve_token()
        if auto_approve_token:
            system_info["auto_approve_token"] = auto_approve_token

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
            ssl_context = (
                ssl.create_default_context()
            )  # NOSONAR - SSL verification is intentionally configurable
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # NOSONAR
            ssl_context.check_hostname = (
                False  # NOSONAR - SSL verification is intentionally configurable
            )
            ssl_context.verify_mode = (
                ssl.CERT_NONE
            )  # NOSONAR - SSL verification is intentionally configurable

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

                        # Store authentication data in database
                        host_id = response_data.get("id")
                        host_token = response_data.get("host_token")
                        if host_id:
                            self._store_auth_data(host_id, host_token)

                        self.logger.info(
                            "Successfully registered with server. Host ID: %s",
                            host_id,
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
        ) as error:  # Catch all since aiohttp.ClientError might not be available
            self.logger.error("Error during registration: %s", error)
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

    def get_host_id(self) -> Optional[str]:
        """Get the host ID from registration data or stored data."""
        if self.registration_data:
            host_id = self.registration_data.get("id")
            return str(host_id) if host_id is not None else None

        # Try to get from stored authentication data
        return self._get_stored_host_id()

    def get_host_token(self) -> Optional[str]:
        """Get the host token from registration data or stored data."""
        if self.registration_data:
            host_token = self.registration_data.get("host_token")
            return str(host_token) if host_token is not None else None

        # Try to get from stored authentication data
        return self._get_stored_host_token()

    def _load_stored_auth_data(self) -> None:
        """Load stored authentication data from database on startup."""
        try:
            with get_db_session() as session:
                approval = (
                    session.query(HostApproval)
                    .filter(HostApproval.approval_status == "approved")
                    .first()
                )

                if approval and approval.host_id:
                    # Create registration data from stored authentication
                    self.registration_data = {
                        "id": str(approval.host_id),
                        "host_token": approval.host_token,
                    }
                    self.registered = True
                    self.logger.info(
                        "Loaded stored authentication: Host ID %s", approval.host_id
                    )
                else:
                    self.logger.debug("No stored authentication data found")
        except Exception as error:
            self.logger.error("Error loading stored auth data: %s", error)

    def _store_auth_data(self, host_id: str, host_token: Optional[str]) -> None:
        """Store authentication data in database."""
        try:
            with get_db_session() as session:
                # DELETE ALL ROWS - no questions asked
                session.execute(text("DELETE FROM host_approval"))

                # Now insert ONE AND ONLY ONE record
                approval = HostApproval(
                    host_id=host_id,
                    host_token=host_token,
                    approval_status="approved",
                )
                session.add(approval)
                session.commit()
                self.logger.info("Stored authentication data for host_id: %s", host_id)
        except Exception as error:
            self.logger.error("Error storing auth data: %s", error)

    def _get_stored_host_id(self) -> Optional[str]:
        """Get host_id from database."""
        try:
            with get_db_session() as session:
                approval = (
                    session.query(HostApproval)
                    .filter(HostApproval.approval_status == "approved")
                    .first()
                )
                return str(approval.host_id) if approval and approval.host_id else None
        except Exception as error:
            self.logger.error("Error getting stored host_id: %s", error)
            return None

    def _get_stored_host_token(self) -> Optional[str]:
        """Get host_token from database."""
        try:
            with get_db_session() as session:
                approval = (
                    session.query(HostApproval)
                    .filter(HostApproval.approval_status == "approved")
                    .first()
                )
                return approval.host_token if approval else None
        except Exception as error:
            self.logger.error(
                "Error retrieving stored approval data: %s", type(error).__name__
            )
            self.logger.debug("Error details: %s", str(error))
            return None
