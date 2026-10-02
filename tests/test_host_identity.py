# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent keeps its credential (server Phase 22.0).

The server now issues the host token once -- to the registration that created
the host -- and never repeats it.  Every place the agent stores its approval
used to overwrite the token with whatever a message carried, including
nothing.  These run against a REAL database (a temp SQLite file): it was
mocks inventing attributes that hid the last round of bugs here.
"""

import os
import tempfile
import uuid
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.database.base import DatabaseManager
from src.database.host_identity import kept_host_token
from src.database.models import HostApproval
from src.sysmanage_agent.core.capabilities import (
    PERSISTENT_TOKEN_CAPABILITY,
    build_capability_report,
)
from src.sysmanage_agent.registration.client_registration import ClientRegistration
from src.sysmanage_agent.registration.registration_manager import RegistrationManager

HOST = str(uuid.uuid4())
TOKEN = "the-real-token"


@pytest.fixture
def dbm():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    manager = DatabaseManager(path)
    manager.create_tables()
    yield manager
    manager.close()
    os.unlink(path)


def _stored(dbm):
    session = dbm.get_session()
    try:
        row = session.query(HostApproval).first()
        return (str(row.host_id), row.host_token) if row else None
    finally:
        session.close()


def _seed(dbm, host_id=HOST, token=TOKEN):
    session = dbm.get_session()
    session.add(
        HostApproval(
            host_id=uuid.UUID(host_id), host_token=token, approval_status="approved"
        )
    )
    session.commit()
    session.close()


def test_kept_token_is_the_stored_one_for_that_host(dbm):
    _seed(dbm)
    session = dbm.get_session()
    try:
        assert kept_host_token(session, HOST) == TOKEN
        assert kept_host_token(session, str(uuid.uuid4())) is None
        assert kept_host_token(session, None) is None
        assert kept_host_token(session, "not-a-uuid") is None
    finally:
        session.close()


@pytest.mark.asyncio
async def test_store_host_approval_keeps_the_token_when_omitted(dbm):
    _seed(dbm)
    manager = RegistrationManager(MagicMock())
    with patch(
        "src.sysmanage_agent.registration.registration_manager.get_database_manager",
        return_value=dbm,
    ):
        await manager.store_host_approval(HOST, "approved", certificate="pem")
    assert _stored(dbm) == (HOST, TOKEN)


@pytest.mark.asyncio
async def test_registration_success_without_a_token_keeps_ours(dbm):
    """The server stopped repeating the token; clearing first used to lose it."""
    _seed(dbm)
    agent = MagicMock()
    agent.send_initial_data_updates = AsyncMock()
    manager = RegistrationManager(agent)
    with patch(
        "src.sysmanage_agent.registration.registration_manager.get_database_manager",
        return_value=dbm,
    ):
        await manager.handle_registration_success({"host_id": HOST, "approved": True})
    assert _stored(dbm) == (HOST, TOKEN)


def test_a_registration_reply_without_a_token_keeps_ours(dbm):
    """Re-registering an existing host returns neither id nor token now; a
    reply WITH the id but no token must not wipe the stored token either."""
    _seed(dbm)

    @contextmanager
    def session_scope():
        session = dbm.get_session()
        try:
            yield session
        finally:
            session.close()

    registration = ClientRegistration.__new__(ClientRegistration)
    registration.logger = MagicMock()
    with patch(
        "src.sysmanage_agent.registration.client_registration.get_db_session",
        session_scope,
    ):
        registration._store_auth_data(HOST, None)
    assert _stored(dbm) == (HOST, TOKEN)


def test_the_agent_advertises_that_it_keeps_its_token():
    assert PERSISTENT_TOKEN_CAPABILITY in build_capability_report({})["capabilities"]
