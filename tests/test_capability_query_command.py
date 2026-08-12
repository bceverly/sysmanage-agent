# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""``get_capabilities``: answer "what can you do?" on a LIVE agent.

Phase 19 asks for a queryable capability API.  The set already travels with
registration and SYSTEM_INFO, but those are snapshots -- an operator asking
"why is this action unavailable on this host?" needs the answer from the
running build, not from whatever it said when it last enrolled.

It is a command over the existing server-initiated WebSocket rather than a
local listener.  The agent opens one outbound connection and accepts no
inbound ones; adding a socket would change that on every platform it ships to,
and the channel to ask the question already exists.

The property that matters, and what these tests pin: a live query and the
registration payload must come from the SAME handler map, so they cannot drift
apart and tell an operator two different stories.
"""

import asyncio

import pytest

from src.sysmanage_agent.core.capabilities import (
    CAPABILITY_GROUPS,
    build_capability_report,
    ungrouped_commands,
)


class _Logger:
    def error(self, *args, **kwargs):  # pragma: no cover - never expected
        raise AssertionError(f"unexpected error log: {args} {kwargs}")


class _Utils:
    """Minimal stand-in exposing the two methods under test."""

    def __init__(self, handlers):
        self._handlers = handlers
        self.logger = _Logger()

    def _get_command_handlers(self):
        return self._handlers

    # Borrow the real implementation verbatim rather than reimplementing it;
    # a copy here could pass while the shipped method was broken.
    from src.sysmanage_agent.core.agent_utils import (  # noqa: PLC0415
        MessageProcessor as _Real,
    )

    _handle_get_capabilities = _Real._handle_get_capabilities


def _run(coro):
    return asyncio.run(coro)


def test_get_capabilities_is_routable_and_grouped():
    """The command must be dispatchable AND owned by a group.

    An ungrouped command still gates correctly but shows up as drift; the
    suite asserts that list stays empty, so a new handler has to be placed.
    """
    assert "get_capabilities" in CAPABILITY_GROUPS["diagnostics"]
    assert ungrouped_commands(["get_capabilities"]) == []


def test_live_query_matches_what_registration_would_advertise():
    """One handler map, one answer -- the whole point of the feature."""
    handlers = {"execute_shell": object(), "get_system_info": object()}
    utils = _Utils(handlers)

    live = _run(utils._handle_get_capabilities())
    assert live["success"] is True
    assert live["result"] == build_capability_report(handlers)


def test_reports_a_reduced_build_honestly():
    """A build routing only two commands must not claim the full set."""
    utils = _Utils({"get_system_info": object(), "collect_roles": object()})
    report = _run(utils._handle_get_capabilities())["result"]

    assert "inventory" in report["capabilities"]
    assert "packages" not in report["capabilities"]
    assert report["unavailable"]["packages"]
    # inventory is present but incomplete, and says so rather than hiding it
    assert "update_hardware" in report["partial"]["inventory"]


def test_failure_is_reported_not_fabricated():
    """A broken handler map must yield an error, never an invented set.

    Claiming capabilities the build does not have would be worse than saying
    nothing: the server gates dispatch on this.
    """

    class _Boom(_Utils):
        def __init__(self):
            super().__init__({})
            self.logged = []
            self.logger = type("L", (), {"error": lambda _s, *a, **k: None})()

        def _get_command_handlers(self):
            raise RuntimeError("handler table unavailable")

    result = _run(_Boom()._handle_get_capabilities())
    assert result["success"] is False
    assert "handler table unavailable" in result["error"]
    assert "result" not in result


@pytest.mark.parametrize("group", sorted(CAPABILITY_GROUPS))
def test_every_group_is_non_empty(group):
    """A group with no commands can never be reported supported."""
    assert CAPABILITY_GROUPS[group], group
