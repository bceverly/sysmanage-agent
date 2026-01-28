"""
Registration Manager - Handles host registration, approval, and certificate management.

This module manages the registration lifecycle of a host with the server,
including authentication tokens, host approval status, and certificate handling.
"""

import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import aiohttp

from src.database.base import get_database_manager
from src.database.models import HostApproval
from src.i18n import _


class RegistrationManager:
    """Manages host registration, approval, and authentication with the server."""

    def __init__(self, agent_instance):
        """
        Initialize the RegistrationManager.

        Args:
            agent_instance: Reference to the parent SysManageAgent instance
        """
        self.agent = agent_instance
        self.logger = agent_instance.logger
        self.config = agent_instance.config

    async def get_auth_token(self) -> str:
        """Get authentication token for WebSocket connection."""
        return await self.agent.auth_helper.get_auth_token()

    async def fetch_certificates(self, host_id: str) -> bool:
        """Fetch certificates from server after approval."""
        try:
            server_config = self.config.get_server_config()
            hostname = server_config.get("hostname", "localhost")
            port = server_config.get("port", 8000)
            use_https = server_config.get("use_https", False)

            # Build certificate URL - authenticated endpoint requires /api prefix
            protocol = "https" if use_https else "http"
            cert_url = (
                f"{protocol}://{hostname}:{port}/api/certificates/client/{host_id}"
            )

            # Set up SSL context if needed
            ssl_context = None
            if use_https:
                ssl_context = (
                    ssl.create_default_context()
                )  # NOSONAR - SSL verification is intentionally configurable
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = False  # NOSONAR - SSL verification is intentionally configurable
                    ssl_context.verify_mode = (
                        ssl.CERT_NONE
                    )  # NOSONAR - SSL verification is intentionally configurable

            # Get authentication token
            auth_token = await self.get_auth_token()

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                headers = {"Authorization": f"Bearer {auth_token}"}

                async with session.get(cert_url, headers=headers) as response:
                    if response.status == 200:
                        cert_data = await response.json()
                        self.agent.cert_store.store_certificates(cert_data)
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

        except Exception as error:
            self.logger.error("Error fetching certificates: %s", error)
            return False

    async def ensure_certificates(self) -> bool:
        """Ensure agent has valid certificates for mTLS."""
        # Check if we already have valid certificates
        if self.agent.cert_store.has_certificates():
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
                ssl_context = (
                    ssl.create_default_context()
                )  # NOSONAR - SSL verification is intentionally configurable
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = False  # NOSONAR - SSL verification is intentionally configurable
                    ssl_context.verify_mode = (
                        ssl.CERT_NONE
                    )  # NOSONAR - SSL verification is intentionally configurable

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(fingerprint_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        server_fingerprint = data.get("fingerprint")
                        self.logger.info(
                            "Retrieved server fingerprint for validation: %s",
                            "***REDACTED***" if server_fingerprint else "None",
                        )
                        # We'll store it when we get the full cert data

        except Exception as error:
            self.logger.error(
                "Failed to get server fingerprint: %s", type(error).__name__
            )
            return False

        # Check if we can find our host ID from previous registration
        # This is a simplified approach - in a real implementation you might
        # store the host ID during registration
        system_info = self.agent.registration.get_system_info()
        hostname = system_info["hostname"]

        # For now, we'll try to fetch with a known host ID or wait for manual approval
        # This would be improved with a more sophisticated approval checking mechanism
        self.logger.warning(
            "Certificate-based authentication requires manual host approval"
        )
        self.logger.warning("Please approve this host in the SysManage web interface")
        return False

    async def handle_registration_success(self, message: Dict[str, Any]) -> None:
        """Handle registration success notification from server."""
        try:
            self.logger.info(
                _("Received registration success notification from server")
            )

            # Record the registration timestamp
            self.agent.last_registration_time = datetime.now(timezone.utc)

            # Extract host_id and host_token from registration success if available
            host_id = message.get("host_id")
            host_token = message.get("host_token")
            approved = message.get("approved", False)

            if (host_id or host_token) and approved:
                self.logger.info(
                    "Registration approved",
                )

                # Clear any existing host approval and store the new one
                await self.clear_stored_host_id()
                await self.store_host_approval(
                    host_id, "approved", host_token=host_token
                )
                self.logger.info("Host approval stored for host_id: %s", host_id)

                # Mark registration as confirmed and send initial data
                self.agent.registration_confirmed = True
                self.logger.info(
                    "Registration confirmed, sending initial inventory data..."
                )
                await self.agent.send_initial_data_updates()

            elif host_id or host_token:
                self.logger.info(
                    "Registration received but approval pending",
                )
                await self.clear_stored_host_id()
                await self.store_host_approval(
                    host_id, "pending", host_token=host_token
                )
                self.agent.registration_confirmed = True
            else:
                self.logger.info(
                    "Registration success but no host_id provided - approval may come separately"
                )

        except Exception as error:
            self.logger.error(
                _("Error processing registration success notification: %s"), error
            )

    async def handle_host_approval(self, message: Dict[str, Any]) -> None:
        """Handle host approval notification from server."""
        try:
            data = message.get("data", {})
            host_id = data.get("host_id")
            approval_status = data.get("approval_status", "approved")
            certificate = data.get("certificate")

            self.logger.info(
                _("Received host approval notification: host_id=%s, status=%s"),
                host_id,
                approval_status,
            )

            # Store the approval information in the database
            await self.store_host_approval(host_id, approval_status, certificate)

            self.logger.info(
                _("Host approval information stored successfully. Host ID: %s"), host_id
            )

            # Re-send system_info so backend sets connection.host_id
            message = self.agent.create_system_info_message()
            await self.agent.message_handler.queue_outbound_message(message)
            self.logger.info(
                "Queued system_info after approval to update backend connection"
            )

        except Exception as error:
            self.logger.error(
                _("Error processing host approval notification: %s"), error
            )

    async def clear_host_approval(
        self,
    ) -> None:  # NOSONAR - async required by interface
        """Clear all host approval records from local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # Delete all existing host approval records
                session.query(HostApproval).delete()
                session.commit()
                self.logger.debug("Host approval records cleared from database")
            finally:
                session.close()
        except Exception as error:
            self.logger.error(_("Error clearing host approval records: %s"), error)
            raise

    async def store_host_approval(  # NOSONAR - async required by interface
        self,
        host_id: str,
        approval_status: str,
        certificate: str = None,
        host_token: str = None,
    ) -> None:
        """Store host approval information in local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # CRITICAL: Delete ALL existing host approval records first
                # This ensures we only ever have ONE record, preventing old host_id caching issues
                deleted_count = session.query(HostApproval).delete()
                if deleted_count > 0:
                    self.logger.info(
                        _(
                            "Deleted %d old host approval record(s) before storing new approval"
                        ),
                        deleted_count,
                    )

                # Always create fresh new approval record (never update)
                new_approval = HostApproval(
                    host_id=uuid.UUID(host_id) if host_id else None,
                    host_token=host_token,
                    approval_status=approval_status,
                    certificate=certificate,
                    approved_at=(
                        datetime.now(timezone.utc)
                        if approval_status == "approved"
                        else None
                    ),
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                session.add(new_approval)

                session.commit()
                self.logger.info(
                    _("Host approval record stored in database: host_id=%s, status=%s"),
                    host_id,
                    approval_status,
                )

            finally:
                session.close()

        except Exception as error:
            self.logger.error(_("Error storing host approval in database: %s"), error)
            raise

    async def get_stored_host_id(
        self,
    ) -> Optional[str]:  # NOSONAR - async required by interface
        """Get the stored host_id from local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_id.isnot(None),
                    )
                    .first()
                )

                if approval and approval.has_host_id:
                    return str(approval.host_id)

                return None

            finally:
                session.close()

        except Exception as error:
            self.logger.error(_("Error retrieving stored host_id: %s"), error)
            return None

    async def get_stored_host_token(
        self,
    ) -> Optional[str]:  # NOSONAR - async required by interface
        """Get the stored host_token from local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_token.isnot(None),
                    )
                    .first()
                )

                if approval and approval.host_token:
                    return approval.host_token

                return None

            finally:
                session.close()

        except Exception:
            self.logger.error(_("Error retrieving stored credentials"))
            return None

    def get_stored_host_id_sync(self) -> Optional[str]:
        """Get the stored host_id from local database synchronously."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_id.isnot(None),
                    )
                    .order_by(HostApproval.created_at.desc())
                    .first()
                )

                if approval and approval.has_host_id:
                    return str(approval.host_id)

                return None

            finally:
                session.close()

        except Exception as error:
            self.logger.error(
                _("Error retrieving stored host_id synchronously: %s"), error
            )
            return None

    def get_stored_host_token_sync(self) -> Optional[str]:
        """Get the stored host_token from local database synchronously."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_token.isnot(None),
                    )
                    .first()
                )

                if approval and approval.host_token:
                    return approval.host_token

                return None

            finally:
                session.close()

        except Exception:
            self.logger.error(_("Error retrieving stored credentials"))
            return None

    def get_host_approval_from_db(self):
        """Get the host approval record from local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_id.isnot(None),
                    )
                    .first()
                )

                return approval

            finally:
                session.close()

        except Exception as error:
            self.logger.error(
                _("Error retrieving host approval: %s"), type(error).__name__
            )
            return None

    async def clear_stored_host_id(
        self,
    ) -> None:  # NOSONAR - async required by interface
        """Clear the stored host_id from local database and related data."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # Use raw SQL to delete ALL host approval records to avoid UUID parsing errors
                # This is necessary because corrupt UUIDs in the database will cause
                # SQLAlchemy to fail when trying to load them as objects
                session.execute("DELETE FROM host_approval")

                # Clear any pending script executions since they're tied to the old host
                session.execute("DELETE FROM script_execution")

                # Clear any queued messages with host_id data
                session.execute(
                    "DELETE FROM message_queue WHERE message_data LIKE '%host_id%'"
                )

                session.commit()
                self.logger.info(
                    _("Host approval records and related data cleared from database")
                )

            finally:
                session.close()

        except Exception as error:
            self.logger.error(_("Error clearing host approval records: %s"), error)
            # Don't raise - allow the agent to continue even if cleanup fails
            self.logger.warning(_("Continuing despite cleanup error..."))

    def cleanup_corrupt_database_entries(self) -> None:
        """Clean up any corrupt entries from database (e.g., invalid UUIDs)."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # Delete rows with invalid UUIDs using raw SQL
                # Check host_approval table for non-UUID values
                result = session.execute(
                    "SELECT COUNT(*) FROM host_approval WHERE "
                    "LENGTH(host_id) != 36 OR "
                    "host_id NOT LIKE '%-%-%-%-%' OR "
                    "host_id IS NOT NULL"
                ).fetchone()

                if result and result[0] > 0:
                    self.logger.warning(
                        "Found %d corrupt entries in host_approval table, cleaning up...",
                        result[0],
                    )
                    session.execute(
                        "DELETE FROM host_approval WHERE "
                        "LENGTH(host_id) != 36 OR "
                        "host_id NOT LIKE '%-%-%-%-%'"
                    )
                    session.commit()
                    self.logger.info("Corrupt database entries cleaned up")

            finally:
                session.close()

        except Exception as error:
            self.logger.warning("Error during database cleanup: %s", error)
            # Don't raise - this is best-effort cleanup

    async def call_server_api(
        self, endpoint: str, method: str = "POST", data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Centralized method for making API calls to the server.

        Args:
            endpoint: API endpoint (without /api prefix, e.g., "agent/installation-complete")
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request payload (for POST/PUT requests)

        Returns:
            Response data as dictionary, or None if request failed
        """
        try:
            # Get server configuration
            config = self.config
            server_host = config.get("server", {}).get("host", "localhost")
            server_port = config.get("server", {}).get("port", 8080)
            use_ssl = config.get("server", {}).get("ssl", {}).get("enabled", False)

            # Construct full URL with /api prefix
            protocol = "https" if use_ssl else "http"
            url = f"{protocol}://{server_host}:{server_port}/api/{endpoint}"

            # Get authentication token
            host_token = self.get_stored_host_token_sync()
            if not host_token:
                self.logger.error(_("No host token available for API authentication"))
                return None

            # Prepare headers
            headers = {
                "Authorization": f"Bearer {host_token}",
                "Content-Type": "application/json",
            }

            # Create SSL context if needed
            ssl_context = None
            if use_ssl:
                ssl_context = (
                    ssl.create_default_context()
                )  # NOSONAR - SSL verification is intentionally configurable
                if not config.get("server", {}).get("ssl", {}).get("verify", True):
                    ssl_context.check_hostname = False  # NOSONAR - SSL verification is intentionally configurable
                    ssl_context.verify_mode = (
                        ssl.CERT_NONE
                    )  # NOSONAR - SSL verification is intentionally configurable

            # Make the HTTP request
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=data if data else None,
                    ssl=ssl_context,
                ) as response:
                    if response.status == 200:
                        try:
                            return await response.json()
                        except Exception:
                            return {"success": True}
                    else:
                        error_text = await response.text()
                        self.logger.error(
                            _(
                                "API call failed: {} {} - Status: {}, Response: {}"
                            ).format(method, url, response.status, error_text)
                        )
                        return None

        except Exception as error:
            self.logger.error(
                _("Error making API call to {}: {}").format(endpoint, str(error))
            )
            return None
