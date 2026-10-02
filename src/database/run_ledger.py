# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""When each expensive collection last ran (server Phase 22.1).

Send-on-change keeps an unchanged REPORT from being sent again, but the agent
still RAN the collection behind it -- and the expensive ones (a package
manager refresh, paging through the Windows package catalogs) ran on every
connect, because the tasks that drive them restart with each connection.  A
server restart therefore had the whole fleet hit its package mirrors and the
public catalogs within seconds.

This ledger, in the agent's own database, records when each one last ran, so
a reconnect or an agent restart runs only what is overdue.  It fails OPEN: if
it cannot be read, the collection runs, as it always did -- a broken ledger
must never stop the agent reporting.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.database.base import get_database_manager
from src.database.models import CollectionRun

logger = logging.getLogger(__name__)

UPDATE_CHECK = "update_check"
PACKAGE_COLLECTION = "package_collection"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def last_run(name: str) -> Optional[datetime]:
    """When ``name`` last ran, or None (never, or the ledger is unreadable)."""
    try:
        session = get_database_manager().get_session()
        try:
            row = (
                session.query(CollectionRun).filter(CollectionRun.name == name).first()
            )
            return row.last_run_at if row else None
        finally:
            session.close()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Could not read the collection run ledger for %s", name, exc_info=True
        )
        return None


def mark_run(name: str, when: Optional[datetime] = None) -> None:
    """Record that ``name`` ran (now, unless ``when`` is given)."""
    try:
        session = get_database_manager().get_session()
        try:
            row = (
                session.query(CollectionRun).filter(CollectionRun.name == name).first()
            )
            if row is None:
                session.add(CollectionRun(name=name, last_run_at=when or _now()))
            else:
                row.last_run_at = when or _now()
            session.commit()
        finally:
            session.close()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning("Could not record the run of %s", name, exc_info=True)


def forget(name: str) -> None:
    """Make ``name`` due at once (the host was just approved, or its identity
    changed: what ran before never reached the server as this host)."""
    try:
        session = get_database_manager().get_session()
        try:
            session.query(CollectionRun).filter(CollectionRun.name == name).delete()
            session.commit()
        finally:
            session.close()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning("Could not reset the run of %s", name, exc_info=True)


def is_due(name: str, interval_seconds: float, now: Optional[datetime] = None) -> bool:
    """True when ``name`` has never run, last ran ``interval_seconds`` or
    more ago, or the ledger cannot be read (fail open)."""
    previous = last_run(name)
    if previous is None:
        return True
    current = now or _now()
    if previous > current:  # the clock went backwards: do not wait for it
        return True
    return current - previous >= timedelta(seconds=interval_seconds)
