# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The send-on-change memory, in the agent's own database (server Phase 22.2).

Send-on-change (``communication/send_on_change.py``) kept what it last sent in
memory only, so every agent RESTART sent every report again.  At fleet scale
that is the whole fleet's full inventory at once whenever the agents are
upgraded or the machines rebooted -- the burst the server's 10,000-agent storm
could not drain.  Persisted here, a restarted agent sends only what changed.

Fails OPEN: if the table cannot be read the gate starts empty and the agent
sends everything, as it always did; if it cannot be written the gate still
works for this process.  A broken store must never stop the agent reporting.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from src.database.base import get_database_manager
from src.database.models import SentReport

logger = logging.getLogger(__name__)


def _to_epoch(when: datetime) -> float:
    return when.replace(tzinfo=timezone.utc).timestamp()


def _from_epoch(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)


def load() -> Dict[str, Tuple[Optional[str], float]]:
    """``{message_type: (digest, sent_at_epoch)}``, or {} if unreadable."""
    try:
        session = get_database_manager().get_session()
        try:
            return {
                row.message_type: (row.digest, _to_epoch(row.sent_at))
                for row in session.query(SentReport).all()
            }
        finally:
            session.close()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning("Could not read the sent-report memory", exc_info=True)
        return {}


def save(message_type: str, digest: Optional[str], sent_at: float) -> None:
    """Remember that ``message_type`` was sent with ``digest`` at ``sent_at``."""
    try:
        session = get_database_manager().get_session()
        try:
            row = session.get(SentReport, message_type)
            if row is None:
                session.add(SentReport(message_type=message_type, digest=digest,
                                       sent_at=_from_epoch(sent_at)))  # fmt: skip
            else:
                row.digest = digest
                row.sent_at = _from_epoch(sent_at)
            session.commit()
        finally:
            session.close()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning("Could not record the sent %s", message_type, exc_info=True)


def clear() -> None:
    """Forget everything (new identity, or the host was just approved)."""
    try:
        session = get_database_manager().get_session()
        try:
            session.query(SentReport).delete()
            session.commit()
        finally:
            session.close()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning("Could not clear the sent-report memory", exc_info=True)
