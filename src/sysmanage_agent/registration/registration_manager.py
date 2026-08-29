# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Registration Manager - Handles host registration, approval, and certificate management.

This module manages the registration lifecycle of a host with the server,
including authentication tokens, host approval status, and certificate handling.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import aiohttp
from sqlalchemy import text

from src.database.base import get_database_manager
from src.database.models import HostApproval
from src.i18n import _
from src.sysmanage_agent.core.server_endpoint import ServerEndpoint

# ONE definition of "corrupt", shared by the count and the delete below.
#
# They used to differ: the count also matched "host_id IS NOT NULL", true of
# every populated row, so a perfectly healthy table reported "Found N corrupt
# entries, cleaning up..." and then deleted nothing -- the delete's predicate was
# the correct one. Worse, NULL comparisons yield NULL rather than true, so the
# one genuinely corrupt row (a NULL host_id) was the only one it did NOT match.
# A NULL host_id IS corrupt: the row identifies no host.
#
# Built by concatenation rather than an f-string so the SQL is provably static
# at module scope -- no interpolation point exists for anything to reach.
_CORRUPT_HOST_ID = " OR ".join(
    (
        "LENGTH(host_id) != 36",
        "host_id NOT LIKE '%-%-%-%-%'",
        "host_id IS NULL",
    )
)
_COUNT_CORRUPT_SQL = "SELECT COUNT(*) FROM host_approval WHERE " + _CORRUPT_HOST_ID
_DELETE_CORRUPT_SQL = "DELETE FROM host_approval WHERE " + _CORRUPT_HOST_ID


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
            # Certificates are an authenticated endpoint, hence the /api prefix.
            endpoint = ServerEndpoint(self.config)
            cert_url = endpoint.rest_url(f"/api/certificates/client/{host_id}")

            # Get authentication token
            auth_token = await self.get_auth_token()

            async with aiohttp.ClientSession(**endpoint.session_kwargs()) as session:
                headers = {"Authorization": f"Bearer {auth_token}"}

                async with session.get(
                    cert_url, headers=headers, proxy=endpoint.proxy()
                ) as response:
                    if response.status == 200:
                        cert_data = await response.json()
                        self.agent.cert_store.store_certificates(cert_data)
                        self.logger.info(
                            "Certificates retrieved and stored successfully"
                        )
                        return True
                    if response.status == 403:
                        self.logger.warning(
                            _("Host not yet approved for certificate retrieval")
                        )
                        return False
                    self.logger.error(
                        _("Failed to fetch certificates: HTTP %s"), response.status
                    )
                    return False

        except Exception as error:
            self.logger.error(_("Error fetching certificates: %s"), error)
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
            endpoint = ServerEndpoint(self.config)
            fingerprint_url = endpoint.rest_url("/api/certificates/server-fingerprint")

            async with aiohttp.ClientSession(**endpoint.session_kwargs()) as session:
                async with session.get(
                    fingerprint_url, proxy=endpoint.proxy()
                ) as response:
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
                _("Failed to get server fingerprint: %s"), type(error).__name__
            )
            return False

        # Dead code removed: this fetched system_info purely to read a hostname
        # that was never used.  It was masked until the URL-building duplication
        # above was folded into ServerEndpoint -- pylint had been seeing the
        # OTHER `hostname` (the one that built the URL) as the used one.
        # For now, we'll try to fetch with a known host ID or wait for manual approval
        # This would be improved with a more sophisticated approval checking mechanism
        self.logger.warning(
            _("Certificate-based authentication requires manual host approval")
        )
        self.logger.warning(
            _("Please approve this host in the SysManage web interface")
        )
        return False

    async def handle_registration_success(self, message: Dict[str, Any]) -> None:
        """Handle registration success notification from server."""
        try:
            self.logger.info("Received registration success notification from server")

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
                "Received host approval notification: host_id=%s, status=%s",
                host_id,
                approval_status,
            )

            # Store the approval information in the database
            await self.store_host_approval(host_id, approval_status, certificate)

            self.logger.info(
                "Host approval information stored successfully. Host ID: %s", host_id
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
        await asyncio.sleep(
            0
        )  # Yield to event loop - async required for interface consistency
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
        await asyncio.sleep(
            0
        )  # Yield to event loop - async required for interface consistency
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # CRITICAL: Delete ALL existing host approval records first
                # This ensures we only ever have ONE record, preventing old host_id caching issues
                deleted_count = session.query(HostApproval).delete()
                if deleted_count > 0:
                    self.logger.info(
                        "Deleted %d old host approval record(s) before storing new approval",
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
                    "Host approval record stored in database: host_id=%s, status=%s",
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
        await asyncio.sleep(
            0
        )  # Yield to event loop - async required for interface consistency
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
        await asyncio.sleep(
            0
        )  # Yield to event loop - async required for interface consistency
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
        await asyncio.sleep(
            0
        )  # Yield to event loop - async required for interface consistency
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # Raw SQL, deliberately: a corrupt UUID in the table makes
                # SQLAlchemy raise while loading the row as an object, which is
                # exactly the situation this cleanup exists to recover from.
                #
                # text() is not optional. SQLAlchemy 2.x refuses a bare string
                # with "Textual SQL expression should be explicitly declared as
                # text(...)", and because the caller swallows the exception,
                # these three statements silently did nothing for weeks -- the
                # agent logged a cleanup it had not performed.
                session.execute(text("DELETE FROM host_approval"))

                # Clear any pending script executions since they're tied to
                # the old host. The table is script_executionS -- the singular
                # name here raised "no such table", and because SQLite aborts
                # the whole transaction on error, it ROLLED BACK the
                # host_approval delete above. The agent then kept its previous
                # host_id across every restart, so the server saw one host and
                # the agent believed it was another. Found 2026-08-28 by a
                # real round-trip, not by a test.
                session.execute(text("DELETE FROM script_executions"))

                # Clear any queued messages with host_id data
                session.execute(
                    text(
                        "DELETE FROM message_queue WHERE message_data LIKE '%host_id%'"
                    )
                )

                session.commit()
                self.logger.info(
                    "Host approval records and related data cleared from database"
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
                # Raw SQL is deliberate here: a corrupt UUID makes SQLAlchemy
                # raise while loading the row as an object, which is the exact
                # situation this cleanup recovers from. SQLAlchemy 2.x requires
                # text() for raw SQL, so the rule cannot be satisfied by writing
                # it differently -- and the statement is a module-level constant
                # with no interpolation point for anything to reach.
                # (Suppression must sit immediately above the finding.)
                # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                result = session.execute(text(_COUNT_CORRUPT_SQL)).fetchone()

                if result and result[0] > 0:
                    self.logger.warning(
                        _(
                            "Found %d corrupt entries in host_approval table, cleaning up..."
                        ),
                        result[0],
                    )
                    # Same static constant, same reasoning as the count above.
                    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    session.execute(text(_DELETE_CORRUPT_SQL))
                    session.commit()
                    self.logger.info("Corrupt database entries cleaned up")

            finally:
                session.close()

        except Exception as error:
            self.logger.warning(_("Error during database cleanup: %s"), error)
            # Don't raise - this is best-effort cleanup
