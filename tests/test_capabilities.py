# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``sysmanage_agent.core.capabilities`` — Phase 19 advertisement.

The load-bearing test here is the DRIFT GUARD: the capability taxonomy is
derived from the agent's real command-handler map, and the entire feature is
worthless if the two ever disagree.  A capability list that lies is worse than
no list, because the server gates dispatch on it — an advertised-but-absent
capability turns a clear "not supported" into the runtime failure this exists
to prevent, and an unadvertised-but-present one silently makes a working
feature unreachable.
"""

import logging
import re
from pathlib import Path

from src.sysmanage_agent.core.capabilities import (
    CAPABILITY_GROUPS,
    CAPABILITY_SCHEMA_VERSION,
    REASON_NO_HANDLER,
    build_capability_report,
    command_to_group,
    ungrouped_commands,
)
from src.sysmanage_agent.registration.client_registration import ClientRegistration

_HANDLER_SRC = "src/sysmanage_agent/core/agent_utils.py"


def _live_command_types():
    """The command types the agent actually routes.

    Read from the source of ``_get_command_handlers`` rather than by
    constructing an agent: the handlers are bound methods on a fully wired
    agent (config, DB, sockets), and none of that is needed to know which
    command TYPES exist.  Parsing keeps the test honest — it fails when a
    handler is added and left ungrouped, which is the drift we care about.
    """
    src = Path(_HANDLER_SRC).read_text(encoding="utf-8")
    block = re.search(r"def _get_command_handlers.*?\n        \}", src, re.S)
    assert block, "could not locate _get_command_handlers — did it move?"
    return re.findall(r'^\s+"([a-z_]+)":', block.group(0), re.M)


def test_every_routable_command_belongs_to_a_group():
    """Drift guard, direction 1: a new handler must be grouped.

    An ungrouped command is still gated correctly (gating reads ``commands``),
    but it is invisible to the operator-facing group list, so a whole feature
    can quietly go unreported.  Add it to CAPABILITY_GROUPS.
    """
    assert ungrouped_commands(_live_command_types()) == []


def test_no_group_claims_a_command_that_does_not_exist():
    """Drift guard, direction 2: a renamed or deleted handler must not linger.

    A group naming a command the agent cannot route would advertise a
    capability that is not there — the server would dispatch and the host
    would answer "Unknown command type".
    """
    live = set(_live_command_types())
    claimed = {c for commands in CAPABILITY_GROUPS.values() for c in commands}
    assert sorted(claimed - live) == []


def test_a_command_belongs_to_exactly_one_group():
    """Two owners would double-count and make 'limited' ambiguous."""
    seen = {}
    for group, commands in CAPABILITY_GROUPS.items():
        for command in commands:
            assert command not in seen, f"{command} in both {seen[command]} and {group}"
            seen[command] = group
    assert command_to_group() == seen


def test_baseline_agent_advertises_everything():
    """Nothing may regress for hosts that already exist (ROADMAP wording)."""
    live = _live_command_types()
    report = build_capability_report({c: None for c in live})
    assert report["schema_version"] == CAPABILITY_SCHEMA_VERSION
    assert sorted(report["capabilities"]) == sorted(CAPABILITY_GROUPS)
    assert report["commands"] == sorted(live)
    assert report["unavailable"] == {}
    assert report["partial"] == {}


def test_a_trimmed_build_advertises_a_strict_subset():
    """The whole point: a build without virtualization must say so."""
    live = _live_command_types()
    trimmed = [c for c in live if c not in CAPABILITY_GROUPS["virtualization"]]
    report = build_capability_report({c: None for c in trimmed})
    assert "virtualization" not in report["capabilities"]
    assert report["unavailable"]["virtualization"] == REASON_NO_HANDLER
    assert set(report["commands"]) < set(live)


def test_partial_support_is_reported_not_hidden():
    """A build missing one of eleven virtualization commands still does
    virtualization; claiming otherwise would be as wrong as claiming full
    support.  It stays in `capabilities` AND names what is missing."""
    live = _live_command_types()
    dropped = CAPABILITY_GROUPS["virtualization"][0]
    report = build_capability_report({c: None for c in live if c != dropped})
    assert "virtualization" in report["capabilities"]
    assert report["partial"]["virtualization"] == [dropped]


def test_reasons_are_codes_not_prose():
    """Translation belongs server-side, where the catalogs are — an agent has
    no business deciding what language an operator reads."""
    report = build_capability_report({})
    for reason in report["unavailable"].values():
        assert re.fullmatch(r"[a-z_]+", reason), reason


def test_unknown_capabilities_do_not_need_a_schema_bump():
    """Adding a capability must not require a server change — only a change of
    SHAPE does.  Guards against someone bumping the version out of habit."""
    assert CAPABILITY_SCHEMA_VERSION == 1


def _bare_registration():
    reg = ClientRegistration.__new__(ClientRegistration)
    reg.logger = logging.getLogger("test")
    return reg


def test_registration_omits_capabilities_when_it_cannot_derive_them():
    """Never fabricate.  With no provider there is no way to know what this
    build routes, and an invented set defeats the feature."""
    reg = _bare_registration()
    reg.capability_provider = None
    assert reg.get_capability_report() is None


def test_a_broken_provider_does_not_break_registration():
    """Capability reporting is not worth failing enrollment over — a host that
    cannot register is strictly worse than one with unknown capabilities."""
    reg = _bare_registration()

    def boom():
        raise RuntimeError("simulated")

    reg.capability_provider = boom
    assert reg.get_capability_report() is None


def test_registration_reports_what_the_provider_offers(monkeypatch):
    """Nothing is dropped or invented between the provider and the report.

    Registration now also applies the runtime probes (see
    capability_probes.py), which legitimately remove commands this HOST cannot
    deliver -- initialize_bhyve off FreeBSD, ubuntu_pro_* without the `pro`
    CLI.  Asserting the raw list would therefore depend on what happens to be
    installed on the machine running the tests, so the probe is neutralised
    here and exercised properly in test_capability_probes.py.  What this test
    still pins is the pass-through: provider in, same set out.
    """
    monkeypatch.setattr(
        "src.sysmanage_agent.registration.client_registration.detect_suppressed",
        lambda handlers, **kwargs: {},
    )
    reg = _bare_registration()
    live = _live_command_types()
    reg.capability_provider = lambda: {c: None for c in live}
    report = reg.get_capability_report()
    assert report["commands"] == sorted(live)


def test_registration_drops_commands_this_host_cannot_deliver(monkeypatch):
    """The probe result must actually reach the advertised command list."""
    monkeypatch.setattr(
        "src.sysmanage_agent.registration.client_registration.detect_suppressed",
        lambda handlers, **kwargs: {"initialize_bhyve": "wrong_platform"},
    )
    reg = _bare_registration()
    reg.capability_provider = lambda: {
        "get_system_info": None,
        "initialize_bhyve": None,
    }
    report = reg.get_capability_report()
    assert report["commands"] == ["get_system_info"]
    assert report["unavailable"]["virtualization"] == "wrong_platform"
