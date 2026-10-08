# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server Phase 22: idempotent registration, agent side.

The agent sends the same random nonce with every registration attempt, so a
retry whose first reply was lost gets the host's credential instead of being
refused forever.  Real database (a temp SQLite file) for the store.
"""

from contextlib import ExitStack
import logging
import os
import tempfile
from unittest.mock import Mock, patch

import pytest

from src.database import registration_nonce
from src.database.base import DatabaseManager
from src.sysmanage_agent.registration import client_registration as cr

pytestmark = pytest.mark.real_registration_nonce


@pytest.fixture
def dbm():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    manager = DatabaseManager(path)
    manager.create_tables()
    registration_nonce._in_memory["nonce"] = None  # pylint: disable=protected-access
    with patch(
        "src.database.registration_nonce.get_database_manager", return_value=manager
    ):
        yield path
    manager.close()
    os.unlink(path)
    registration_nonce._in_memory["nonce"] = None  # pylint: disable=protected-access


def test_the_nonce_is_created_once_and_kept(dbm):
    first = registration_nonce.get_or_create()
    assert len(first) >= 32
    assert registration_nonce.get_or_create() == first


def test_the_nonce_survives_an_agent_restart(dbm):
    first = registration_nonce.get_or_create()
    registration_nonce._in_memory["nonce"] = None  # pylint: disable=protected-access
    restarted = DatabaseManager(dbm)  # a new process opening the same file
    try:
        with patch(
            "src.database.registration_nonce.get_database_manager",
            return_value=restarted,
        ):
            assert registration_nonce.get_or_create() == first
    finally:
        restarted.close()


def test_a_broken_store_still_gives_one_nonce_per_run():
    registration_nonce._in_memory["nonce"] = None  # pylint: disable=protected-access
    with patch(
        "src.database.registration_nonce.get_database_manager",
        side_effect=RuntimeError("no database"),
    ):
        first = registration_nonce.get_or_create()
        assert registration_nonce.get_or_create() == first
    registration_nonce._in_memory["nonce"] = None  # pylint: disable=protected-access


# -- the registration request --------------------------------------------------


def _registration():
    with patch(
        "src.sysmanage_agent.registration.client_registration.get_db_session"
    ) as session:
        empty = Mock()
        empty.query.return_value.filter.return_value.first.return_value = None
        session.return_value.__enter__.return_value = empty
        return cr.ClientRegistration(Mock())


def test_secret_fields_are_never_logged_as_values():
    loggable = cr._loggable(  # pylint: disable=protected-access
        {"hostname": "h", "registration_key": "rk", "enrollment_token": "sme_x",
         "auto_approve_token": "at", "registration_nonce": "n" * 43}  # fmt: skip
    )
    assert loggable["hostname"] == "h"
    for field in cr.SECRET_REGISTRATION_FIELDS:
        assert loggable[field] == "<redacted>"


class _Response:
    def __init__(self, status, text=""):
        self.status = status
        self._text = text

    async def text(self):
        return self._text

    async def json(self):
        return {"id": "h1", "host_token": "t"}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None


class _Session:
    def __init__(self, responses, bodies):
        self.responses, self.bodies = responses, bodies

    def post(self, _url, json=None, **_kwargs):  # pylint: disable=redefined-outer-name
        self.bodies.append(dict(json))
        return self.responses.pop(0)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None


@pytest.mark.asyncio
async def test_an_older_server_that_rejects_the_nonce_is_retried_without_it(caplog):
    registration = _registration()
    bodies = []
    responses = [
        _Response(422, '{"detail":[{"loc":["body","registration_nonce"]}]}'),
        _Response(200),
    ]
    info = {"hostname": "h", "registration_nonce": "n" * 43}
    endpoint = Mock()
    endpoint.rest_url.return_value = "https://server/api/host/register"
    endpoint.session_kwargs.return_value = {}
    endpoint.proxy.return_value = None
    # ExitStack, not a parenthesized `with`: the agent still supports Python 3.9.
    with ExitStack() as stack:
        stack.enter_context(
            patch(
                "aiohttp.ClientSession",
                side_effect=lambda **_: _Session(responses, bodies),
            )
        )
        stack.enter_context(
            patch.object(
                registration,
                "get_basic_registration_info",
                side_effect=lambda: dict(info),
            )
        )
        stack.enter_context(patch.object(registration, "_store_auth_data"))
        stack.enter_context(patch.object(cr, "ServerEndpoint", return_value=endpoint))
        stack.enter_context(caplog.at_level(logging.INFO))
        assert await registration.register_with_server() is True
    assert "registration_nonce" in bodies[0]
    assert "registration_nonce" not in bodies[1]
    assert "n" * 43 not in caplog.text  # logged as <redacted>, never the value
