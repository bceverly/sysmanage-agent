# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Falling back must require evidence, and must be reversible.

Some proxies refuse to tunnel a WebSocket. Measured against a real HTTP CONNECT
proxy returning 403: ``InvalidProxyStatus: proxy rejected connection: HTTP 403``,
no connection at all. Retrying gets the same 403 forever.

But a refused TCP connection is just the server restarting. Treating that as
"this network forbids WebSockets" would drop every agent on a healthy network to
the slower transport during a routine restart -- a far more common event than a
WebSocket-hostile proxy. So the distinction is the whole feature.
"""

import pytest

from src.sysmanage_agent.communication.transport_fallback import (
    TransportState,
    is_structural_websocket_failure,
)


class _Named(Exception):
    """An exception whose class name mimics a websockets library error."""


def named(cls_name, message=""):
    return type(cls_name, (_Named,), {})(message)


# ---------------------------------------------------------------------------
# Structural: retrying cannot help
# ---------------------------------------------------------------------------


def test_the_measured_proxy_refusal_is_structural():
    """The exact error a real refusing CONNECT proxy produced."""
    error = named("InvalidProxyStatus", "proxy rejected connection: HTTP 403")
    assert is_structural_websocket_failure(error) is True


@pytest.mark.parametrize(
    "cls_name,message",
    [
        ("InvalidStatus", "server rejected WebSocket connection: HTTP 200"),
        ("InvalidUpgrade", "missing Upgrade header"),
        ("InvalidHandshake", "malformed handshake"),
        ("InvalidMessage", "did not receive a valid HTTP response"),
    ],
)
def test_middlebox_mangled_handshakes_are_structural(cls_name, message):
    assert is_structural_websocket_failure(named(cls_name, message)) is True


# ---------------------------------------------------------------------------
# Transient: the server is down, not the protocol blocked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError("Connection refused"),
        ConnectionResetError("Connection reset by peer"),
        TimeoutError("timed out"),
        OSError("Network is unreachable"),
    ],
)
def test_ordinary_outages_are_not_structural(error):
    """A restarting server must not demote the whole fleet to polling."""
    assert is_structural_websocket_failure(error) is False


def test_an_unrecognised_failure_defaults_to_transient():
    """Conservative on purpose: over-eager fallback costs everyone latency."""
    assert is_structural_websocket_failure(RuntimeError("something odd")) is False


# ---------------------------------------------------------------------------
# Switching, and switching back
# ---------------------------------------------------------------------------


def test_one_structural_failure_is_not_enough():
    """A single odd response during a proxy reload must not demote a good link."""
    state = TransportState()
    fell_back = state.record_websocket_failure(
        named("InvalidProxyStatus", "proxy rejected connection: HTTP 403"), now=0
    )
    assert fell_back is False
    assert state.using_http_fallback is False


def test_repeated_structural_failures_switch_to_polling():
    state = TransportState()
    error = named("InvalidProxyStatus", "proxy rejected connection: HTTP 403")
    state.record_websocket_failure(error, now=0)
    assert state.record_websocket_failure(error, now=1) is True
    assert state.using_http_fallback is True


def test_a_transient_blip_resets_the_count():
    """Two unrelated failures months apart must not add up to a fallback."""
    state = TransportState()
    state.record_websocket_failure(named("InvalidProxyStatus", "proxy rejected"), now=0)
    state.record_websocket_failure(ConnectionRefusedError("refused"), now=1)
    assert (
        state.record_websocket_failure(
            named("InvalidProxyStatus", "proxy rejected"), now=2
        )
        is False
    ), "the transient failure should have cleared the structural count"


def test_a_working_websocket_restores_the_preferred_transport():
    state = TransportState()
    error = named("InvalidProxyStatus", "proxy rejected")
    state.record_websocket_failure(error, now=0)
    state.record_websocket_failure(error, now=1)
    assert state.using_http_fallback is True

    state.record_websocket_success()
    assert state.using_http_fallback is False


def test_the_websocket_is_retested_so_a_fixed_proxy_is_noticed():
    """Without this an agent stays degraded forever, silently."""
    state = TransportState()
    error = named("InvalidProxyStatus", "proxy rejected")
    state.record_websocket_failure(error, now=0)
    state.record_websocket_failure(error, now=0)

    assert state.should_retest_websocket(now=60) is False
    assert (
        state.should_retest_websocket(now=TransportState.RETEST_AFTER_SECONDS + 1)
        is True
    )

    state.mark_retested(now=TransportState.RETEST_AFTER_SECONDS + 1)
    assert (
        state.should_retest_websocket(now=TransportState.RETEST_AFTER_SECONDS + 2)
        is False
    ), "re-testing must reset the clock, not re-fire every cycle"


def test_a_healthy_agent_never_asks_to_retest():
    assert TransportState().should_retest_websocket(now=10**9) is False
