# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent's registration nonce, in its own database (server Phase 22).

The server hands a host's id and token only to the registration that created
the host.  When that reply was lost -- a timeout on a slow link, the server
restarting at the wrong moment -- the agent's retry was "an existing host",
got no credential, and every session after was refused
``host_credential_required``.  The agent now sends the same random nonce with
every registration attempt; the server recognizes the retry by it and sends
the credential again.  Kept in the database so it survives an agent restart
between the attempts.

Fails open: if the table cannot be read or written, a nonce kept in memory for
this process is used, so retries within this run still match.
"""

import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from src.database.base import get_database_manager
from src.database.models import RegistrationNonce

logger = logging.getLogger(__name__)

_in_memory: dict = {"nonce": None}


def _fallback() -> str:
    if _in_memory["nonce"] is None:
        _in_memory["nonce"] = secrets.token_urlsafe(32)
    return _in_memory["nonce"]


def get_or_create() -> str:
    """This agent's nonce, created (and stored) the first time it is asked for."""
    try:
        session = get_database_manager().get_session()
        try:
            row: Optional[RegistrationNonce] = session.query(RegistrationNonce).first()
            if row is None:
                row = RegistrationNonce(
                    nonce=_in_memory["nonce"] or secrets.token_urlsafe(32),
                    created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                )
                session.add(row)
                session.commit()
            _in_memory["nonce"] = row.nonce
            return row.nonce
        finally:
            session.close()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Registration nonce not stored (%s); using one for this run only", exc
        )
        return _fallback()
