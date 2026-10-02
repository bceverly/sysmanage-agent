# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The HTTP fallback must be a transport, not a second implementation.

Verified end to end against the real server endpoint through a real forward
proxy: the agent's heartbeat reached the server's inbound queue, a queued
command came back and was dispatched, and the proxy logged a POST rather than a
CONNECT -- which is the whole reason this path survives where a WebSocket
Upgrade is refused.

These tests pin the behaviors that end-to-end run cannot cheaply cover: what
happens when a poll FAILS.
"""

import json
from unittest.mock import AsyncMock, Mock

import pytest

from src.sysmanage_agent.communication.http_polling import (
    DEFAULT_POLL_INTERVAL,
    ERROR_POLL_INTERVAL,
    HttpPollingTransport,
)


def make_agent(queued=None, host_id="host-42"):
    agent = Mock()
    agent.logger = Mock()
    agent.config.get_server_config.return_value = {"url": "http://s.example:8080"}
    agent.config.should_verify_ssl.return_value = True
    agent.registration_manager.get_stored_host_id_sync.return_value = host_id
    agent.message_handler.queue_manager.dequeue_messages.return_value = queued or []
    # The queue lives on the message handler.  A bare Mock would invent
    # ``agent.queue_manager`` on first touch -- which is how polling once read
    # a queue that does not exist, sent nothing, and still passed these tests.
    del agent.queue_manager
    return agent


def queued_message(mid="out-1", mtype="heartbeat", envelope=None):
    """A queue row as the real queue stores it: the whole envelope, as JSON."""
    envelope = envelope or {
        "message_type": mtype,
        "message_id": "env-" + mid,
        "timestamp": "2026-10-01T00:00:00+00:00",
        "data": {"up": True},
    }
    return Mock(message_id=mid, message_type=mtype, message_data=json.dumps(envelope))


@pytest.mark.asyncio
async def test_messages_are_marked_delivered_only_after_the_server_accepts():
    """Marking before the POST would lose a whole batch whenever a poll failed.

    That is precisely when delivery matters most -- a flaky link is the reason
    the queue exists at all.
    """
    agent = make_agent(queued=[queued_message()])
    transport = HttpPollingTransport(agent)
    transport._post = AsyncMock(side_effect=ConnectionError("HTTP 502"))

    with pytest.raises(ConnectionError):
        await transport.poll_once(Mock(), Mock(), "host-42")

    agent.message_handler.queue_manager.mark_completed.assert_not_called()


@pytest.mark.asyncio
async def test_a_successful_poll_marks_its_batch_delivered():
    agent = make_agent(queued=[queued_message("out-1"), queued_message("out-2")])
    transport = HttpPollingTransport(agent)
    transport._post = AsyncMock(return_value={"messages": [], "poll_interval": 5})

    await transport.poll_once(Mock(), Mock(), "host-42")

    delivered = [
        c.args[0]
        for c in agent.message_handler.queue_manager.mark_completed.call_args_list
    ]
    assert delivered == ["out-1", "out-2"]


@pytest.mark.asyncio
async def test_received_commands_go_through_the_websocket_dispatcher():
    """Same function the receive loop calls, so behavior cannot diverge."""
    agent = make_agent()
    dispatched = []

    async def dispatch(data):
        dispatched.append(data)
        return False

    agent.message_handler._dispatch_received_message = dispatch
    transport = HttpPollingTransport(agent)
    transport._post = AsyncMock(
        return_value={
            "messages": [
                {
                    "message_id": "cmd-1",
                    "message_type": "command",
                    "data": {"command_type": "reboot"},
                }
            ],
            "poll_interval": 5,
        }
    )

    await transport.poll_once(Mock(), Mock(), "host-42")

    assert dispatched[0]["message_type"] == "command"
    assert dispatched[0]["command_type"] == "reboot", "the payload must be flattened"
    assert dispatched[0]["message_id"] == "cmd-1"


@pytest.mark.asyncio
async def test_one_bad_command_does_not_abandon_the_rest_of_the_batch():
    agent = make_agent()
    seen = []

    async def dispatch(data):
        seen.append(data["message_id"])
        if data["message_id"] == "cmd-1":
            raise RuntimeError("handler blew up")
        return False

    agent.message_handler._dispatch_received_message = dispatch
    transport = HttpPollingTransport(agent)
    transport._post = AsyncMock(
        return_value={
            "messages": [
                {"message_id": "cmd-1", "message_type": "command", "data": {}},
                {"message_id": "cmd-2", "message_type": "command", "data": {}},
            ],
            "poll_interval": 5,
        }
    )

    await transport.poll_once(Mock(), Mock(), "host-42")
    assert seen == ["cmd-1", "cmd-2"]


@pytest.mark.asyncio
async def test_the_servers_interval_is_honoured():
    """A backlog asks the agent back sooner; ignoring it would trickle."""
    agent = make_agent()
    transport = HttpPollingTransport(agent)
    transport._post = AsyncMock(return_value={"messages": [], "poll_interval": 1})
    assert await transport.poll_once(Mock(), Mock(), "h") == 1


@pytest.mark.asyncio
async def test_a_missing_interval_falls_back_to_a_sane_default():
    """An older server, or a response that did not parse, must not mean zero."""
    agent = make_agent()
    transport = HttpPollingTransport(agent)
    transport._post = AsyncMock(return_value={"messages": []})
    assert await transport.poll_once(Mock(), Mock(), "h") == DEFAULT_POLL_INTERVAL


@pytest.mark.asyncio
async def test_polling_refuses_to_start_without_a_registered_host_id():
    """The server has no connection object to attribute messages to.

    Registration is plain REST and therefore already proxy-safe, so an agent can
    always get that far first -- but it must, and saying so beats a stream of
    401s nobody can explain.
    """
    agent = make_agent(host_id=None)
    state = Mock()
    transport = HttpPollingTransport(agent)

    await transport.run_until_retest(state)

    agent.logger.error.assert_called()
    state.mark_retested.assert_not_called()


def test_error_backoff_is_longer_than_the_normal_interval():
    """A restarting server must not be polled harder than a healthy one."""
    assert ERROR_POLL_INTERVAL > DEFAULT_POLL_INTERVAL


def _session_returning(status):
    response = Mock(status=status)
    response.text = AsyncMock(return_value="denied")
    response.json = AsyncMock(return_value={"messages": [], "poll_interval": 5})
    ctx = Mock()
    ctx.__aenter__ = AsyncMock(return_value=response)
    ctx.__aexit__ = AsyncMock(return_value=None)
    session = Mock()
    session.post = Mock(return_value=ctx)
    return session


@pytest.mark.asyncio
async def test_a_poll_carries_the_hosts_own_token():
    """The server refuses a poll that cannot prove WHICH host it is."""
    agent = make_agent()
    agent.get_auth_token = AsyncMock(return_value="conn")
    agent.get_stored_host_token = AsyncMock(return_value="host-secret")
    session = _session_returning(200)
    endpoint = Mock()
    endpoint.rest_url.return_value = "http://s/api/agent/poll"

    await HttpPollingTransport(agent)._post(session, endpoint, "host-42", [])

    headers = session.post.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer conn"
    assert headers["X-Host-Token"] == "host-secret"


@pytest.mark.asyncio
async def test_a_rejected_poll_forgets_the_cached_token():
    agent = make_agent()
    agent.get_auth_token = AsyncMock(return_value="stale")
    agent.get_stored_host_token = AsyncMock(return_value="host-secret")
    endpoint = Mock()
    endpoint.rest_url.return_value = "http://s/api/agent/poll"

    with pytest.raises(ConnectionError):
        await HttpPollingTransport(agent)._post(
            _session_returning(401), endpoint, "host-42", []
        )
    agent.auth_helper.invalidate_auth_token.assert_called_once()


def test_a_queued_envelope_is_polled_as_its_type_and_data():
    """The endpoint takes {message_type, data}; the queue holds the envelope."""
    agent = make_agent(queued=[queued_message("out-1", "hardware_update")])
    entries = HttpPollingTransport(agent)._collect_outbound()
    assert entries == [
        {"message_type": "hardware_update", "data": {"up": True}, "message_id": "out-1"}
    ]


def test_top_level_fields_become_the_data():
    """Command acknowledgments and script results carry no ``data`` object."""
    row = queued_message(
        "ack-1",
        "command_acknowledgment",
        envelope={
            "message_type": "command_acknowledgment",
            "message_id": "q-9",
            "timestamp": "2026-10-01T00:00:00+00:00",
            "exit_code": 0,
        },
    )
    entries = HttpPollingTransport(make_agent(queued=[row]))._collect_outbound()
    assert entries[0]["data"] == {"exit_code": 0}


def test_an_unreadable_row_is_skipped_loudly_not_sent():
    bad = Mock(message_id="bad", message_type="heartbeat", message_data="{not json")
    agent = make_agent(queued=[bad, queued_message("ok")])
    entries = HttpPollingTransport(agent)._collect_outbound()
    assert [e["message_id"] for e in entries] == ["ok"]
    agent.logger.error.assert_called_once()
