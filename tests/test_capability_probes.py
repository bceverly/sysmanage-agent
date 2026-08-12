# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Reduced-capability reporting: advertise what this HOST can deliver.

Shipping a handler answers "was this code built?", which is not "will it work
here".  Every build carries ``initialize_bhyve`` -- including on Linux, where
it cannot run -- and ``ubuntu_pro_attach`` on Alpine.  Advertising those
invites the server to dispatch work that fails at the far end, which is the
runtime failure the capability feature exists to replace with a clear "not
supported on this agent".

The safety property, pinned below: a probe may only ever REMOVE a capability.
A broken probe therefore degrades to a false negative -- an operator told a
feature is unavailable when it would have worked -- never to claiming
something the agent cannot do, which would put us back where we started.

Build-time trimming is deliberately NOT implemented (no living use case yet),
but the seam is tested: it feeds the same {command: reason} map, so adding it
later needs no new plumbing.
"""

import pytest

from src.sysmanage_agent.core.capabilities import build_capability_report
from src.sysmanage_agent.core.capability_probes import (
    REASON_BUILD_EXCLUDED,
    REASON_MISSING_TOOL,
    REASON_WRONG_PLATFORM,
    build_excluded_from_env,
    detect_suppressed,
)


def ALL_TOOLS_PRESENT(name):  # pylint: disable=invalid-name
    """Stand-in for shutil.which where every tool is installed."""
    return f"/usr/bin/{name}"


def NO_TOOLS_PRESENT(_name):  # pylint: disable=invalid-name
    """Stand-in for shutil.which on a host with none of them."""
    return None


def test_probe_can_only_remove_never_add():
    """The core safety property: output is always a subset of the input."""
    available = ["get_system_info", "initialize_bhyve", "ubuntu_pro_attach"]
    suppressed = detect_suppressed(available, system="Linux", which=NO_TOOLS_PRESENT)
    assert set(suppressed) <= set(available)


def test_bhyve_is_suppressed_off_freebsd():
    """Every build ships it; only FreeBSD can run it."""
    on_linux = detect_suppressed(
        ["initialize_bhyve"], system="Linux", which=ALL_TOOLS_PRESENT
    )
    assert on_linux == {"initialize_bhyve": REASON_WRONG_PLATFORM}

    on_freebsd = detect_suppressed(
        ["initialize_bhyve"], system="FreeBSD", which=ALL_TOOLS_PRESENT
    )
    assert on_freebsd == {}


@pytest.mark.parametrize(
    "command,ok_system",
    [
        ("initialize_bhyve", "FreeBSD"),
        ("disable_bhyve", "FreeBSD"),
        ("initialize_vmm", "OpenBSD"),
        ("enable_wsl", "Windows"),
    ],
)
def test_platform_gated_commands_survive_on_their_own_platform(command, ok_system):
    assert detect_suppressed([command], system=ok_system, which=ALL_TOOLS_PRESENT) == {}


def test_missing_tool_suppresses_ubuntu_pro():
    """Alpine and the BSDs have no `pro` CLI."""
    result = detect_suppressed(
        ["ubuntu_pro_attach"], system="Linux", which=NO_TOOLS_PRESENT
    )
    assert result == {"ubuntu_pro_attach": REASON_MISSING_TOOL}


def test_any_one_alternative_tool_is_enough():
    """Requiring a single name would report a working host as limited.

    KVM networking is virsh on most distros and brctl on older ones.
    """

    def only_brctl(name):
        return "/sbin/brctl" if name == "brctl" else None

    assert (
        detect_suppressed(["setup_kvm_networking"], system="Linux", which=only_brctl)
        == {}
    )


def test_ungoverned_commands_are_never_touched():
    """A command with no declared requirement stays advertised.

    A missing probe must degrade to today's behaviour, not to suppression.
    """
    assert (
        detect_suppressed(
            ["get_system_info", "execute_shell"], system="Linux", which=NO_TOOLS_PRESENT
        )
        == {}
    )


def test_suppressed_commands_leave_the_gate_list():
    """The dispatch gate reads ``commands``; advertising one we would refuse
    is exactly the failure this feature prevents."""
    handlers = {"get_system_info": object(), "initialize_bhyve": object()}
    suppressed = detect_suppressed(handlers, system="Linux", which=ALL_TOOLS_PRESENT)
    report = build_capability_report(handlers, suppressed)

    assert "initialize_bhyve" not in report["commands"]
    assert "get_system_info" in report["commands"]
    assert report["unavailable"]["virtualization"] == REASON_WRONG_PLATFORM


def test_group_reason_falls_back_when_causes_differ():
    """Mixed causes must not claim a single misleading reason."""
    handlers = {"initialize_bhyve": object(), "initialize_lxd": object()}
    suppressed = {
        "initialize_bhyve": REASON_WRONG_PLATFORM,
        "initialize_lxd": REASON_MISSING_TOOL,
    }
    report = build_capability_report(handlers, suppressed)
    assert report["unavailable"]["virtualization"] == "no_handler"


def test_report_without_suppressions_is_unchanged():
    """Baseline agents must advertise exactly what they did before."""
    handlers = {"get_system_info": object(), "execute_shell": object()}
    assert build_capability_report(handlers) == build_capability_report(handlers, {})


class TestBuildTimeSeam:
    """Build-time trimming is not implemented; the seam for it is."""

    def test_env_is_empty_in_the_builds_we_ship(self, monkeypatch):
        monkeypatch.delenv("SYSMANAGE_AGENT_EXCLUDED_COMMANDS", raising=False)
        assert build_excluded_from_env() == {}

    def test_declared_exclusions_flow_through_unchanged(self, monkeypatch):
        monkeypatch.setenv(
            "SYSMANAGE_AGENT_EXCLUDED_COMMANDS", "execute_script, collect_processes"
        )
        assert build_excluded_from_env() == {
            "execute_script": REASON_BUILD_EXCLUDED,
            "collect_processes": REASON_BUILD_EXCLUDED,
        }

    def test_build_exclusion_beats_a_passing_runtime_probe(self):
        """If the artifact shipped without the code, no probe can restore it."""
        result = detect_suppressed(
            ["get_system_info"],
            system="Linux",
            which=ALL_TOOLS_PRESENT,
            build_excluded={"get_system_info": REASON_BUILD_EXCLUDED},
        )
        assert result == {"get_system_info": REASON_BUILD_EXCLUDED}

    def test_exclusions_for_commands_this_build_lacks_are_ignored(self):
        """Nothing invented for a command that was never routable."""
        assert (
            detect_suppressed(
                ["get_system_info"],
                system="Linux",
                which=ALL_TOOLS_PRESENT,
                build_excluded={"something_else": REASON_BUILD_EXCLUDED},
            )
            == {}
        )
