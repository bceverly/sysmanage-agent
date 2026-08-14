# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Decide when a WebSocket is not merely down, but *unusable on this network*.

WHY THIS DISTINCTION MATTERS
----------------------------
The agent reconnects on failure, which is right: servers restart, laptops sleep,
links flap.  Retrying is the correct response to a transient fault, and falling
back to a slower transport because the server bounced would be a downgrade
nobody asked for.

But some failures are not transient and never will be.  Measured against a real
HTTP CONNECT proxy that refuses the tunnel::

    InvalidProxyStatus: proxy rejected connection: HTTP 403

That is a policy decision by a middlebox.  Retrying it produces the identical
403 forever, and the host stays invisible -- no commands, no inventory, no
heartbeat -- until somebody changes the proxy.  Which, in the estates where this
happens, means a ticket and a wait.

So the agent separates the two.  A transient failure keeps retrying the
WebSocket, because that is the better transport and it will probably come back.
A *structural* one -- the network will not carry this protocol -- switches to
HTTP polling, which any proxy passes, and says so loudly enough that an operator
can see why.

WHY NOT JUST ALWAYS POLL
------------------------
Polling costs latency and requests.  A server-initiated command arrives within
one poll interval instead of immediately, and every idle agent still talks.  The
WebSocket is better whenever it works, so the fallback is a fallback: entered
only on evidence, and re-tested so a fixed proxy is noticed.
"""

from __future__ import annotations

# Failure signatures that mean "this network will not carry a WebSocket".
#
# Matched against the exception TYPE NAME and message rather than by catching
# specific classes, because the websockets library reorganises its exception
# hierarchy between major versions and the agent pins a range (>=15,<16) while
# developers routinely run newer.  A missed signature costs a retry loop, not a
# crash, so breadth beats precision here.
STRUCTURAL_SIGNATURES = (
    "invalidproxystatus",  # proxy refused the CONNECT tunnel outright
    "proxy rejected",  # ... and its message form
    "invalidstatus",  # server/middlebox answered the Upgrade with a plain status
    "invalidupgrade",  # a 200 instead of 101: something terminated the handshake
    "invalidhandshake",  # the handshake itself was mangled in transit
    "invalidmessage",  # a proxy replied with HTML where a 101 belonged
)

# Signatures that are explicitly NOT structural, even though they can look it.
# A refused TCP connection is the server being down; treating that as "the
# network forbids WebSockets" would drop every agent to polling during a restart.
TRANSIENT_SIGNATURES = (
    "connectionrefused",
    "connectionreset",
    "timeout",
    "timeouterror",
    "gaierror",  # DNS not resolving yet
    "oserror",
    "cancellederror",
)


def is_structural_websocket_failure(error: BaseException) -> bool:
    """Is this failure a network policy rather than a transient fault?

    Structural means: retrying changes nothing, because a middlebox has decided
    this protocol does not pass.  Transient means: try again shortly.

    Deliberately conservative -- when a failure matches both, or neither, it is
    treated as TRANSIENT.  Falling back too eagerly costs every agent on a
    healthy network the latency of polling during a server restart, which is a
    far more common event than a WebSocket-hostile proxy.
    """
    name = type(error).__name__.lower()
    message = str(error).lower()
    haystack = f"{name} {message}"

    if any(sig in haystack for sig in TRANSIENT_SIGNATURES):
        return False
    return any(sig in haystack for sig in STRUCTURAL_SIGNATURES)


class TransportState:
    """Tracks which transport the agent is using, and when to re-test.

    The WebSocket is retried periodically even while polling works: a proxy
    policy can be fixed, and an agent that never re-tests would stay on the
    slower transport forever, silently, with nobody aware it had degraded.
    """

    # How many consecutive structural failures before switching.  More than one
    # because a single odd response during a proxy reload should not demote a
    # perfectly good connection.
    STRUCTURAL_FAILURES_BEFORE_FALLBACK = 2

    # How long to stay on HTTP before re-testing the WebSocket.  Fifteen minutes
    # is short enough that a fixed proxy is picked up within a coffee break, and
    # long enough that a permanently hostile network is not re-probed constantly.
    RETEST_AFTER_SECONDS = 900

    def __init__(self):
        self.using_http_fallback = False
        self._structural_failures = 0
        self._fell_back_at = None

    def record_websocket_failure(self, error: BaseException, now: float) -> bool:
        """Note a failed WebSocket attempt; return True if we should now poll."""
        if not is_structural_websocket_failure(error):
            # A transient fault clears the count: two unrelated blips months
            # apart must not add up to a fallback.
            self._structural_failures = 0
            return self.using_http_fallback

        self._structural_failures += 1
        if (
            not self.using_http_fallback
            and self._structural_failures >= self.STRUCTURAL_FAILURES_BEFORE_FALLBACK
        ):
            self.using_http_fallback = True
            self._fell_back_at = now
        return self.using_http_fallback

    def record_websocket_success(self) -> None:
        """The WebSocket works; this is the preferred transport."""
        self.using_http_fallback = False
        self._structural_failures = 0
        self._fell_back_at = None

    def should_retest_websocket(self, now: float) -> bool:
        """Is it time to see whether the network started allowing WebSockets?"""
        if not self.using_http_fallback or self._fell_back_at is None:
            return False
        return (now - self._fell_back_at) >= self.RETEST_AFTER_SECONDS

    def mark_retested(self, now: float) -> None:
        """Record that a re-test just happened, so the next one waits again."""
        self._fell_back_at = now
