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

from src.sysmanage_agent.core.capabilities import (
    CAPABILITY_GROUPS,
    build_capability_report,
)
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
    # Unavailable because this stub routes no other virtualization handler --
    # NOT because of bhyve, which cannot exist on Linux and is therefore
    # excluded from the analysis entirely.
    assert report["unavailable"]["virtualization"] == "no_handler"
    assert "virtualization" not in report["partial"]


def test_group_reason_falls_back_when_causes_differ():
    """Mixed causes must not claim a single misleading reason.

    Both causes here are APPLICABLE ones.  An inapplicable cause is filtered
    out before this fallback is reached, which the next test pins down.
    """
    handlers = {"initialize_lxd": object(), "initialize_kvm": object()}
    suppressed = {
        "initialize_lxd": REASON_MISSING_TOOL,
        "initialize_kvm": REASON_BUILD_EXCLUDED,
    }
    report = build_capability_report(handlers, suppressed)
    assert report["unavailable"]["virtualization"] == "no_handler"


def test_inapplicable_cause_is_filtered_before_the_reason_is_chosen():
    """An OS-inapplicable command must not muddy an otherwise clear reason.

    bhyve on Linux is not a cause of anything; the only real cause here is the
    missing LXD tool, so that is what an operator should be told.
    """
    handlers = {"initialize_bhyve": object(), "initialize_lxd": object()}
    suppressed = {
        "initialize_bhyve": REASON_WRONG_PLATFORM,
        "initialize_lxd": REASON_MISSING_TOOL,
    }
    report = build_capability_report(handlers, suppressed)
    assert report["unavailable"]["virtualization"] == REASON_MISSING_TOOL


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


# ---------------------------------------------------------------------------
# OS applicability (Phase 19 fix)
#
# The reported symptom: a Linux KVM host showed virtualization as PARTIALLY
# supported because it could not run bhyve, vmm or WSL.  Those are FreeBSD's,
# OpenBSD's and Windows' hypervisors -- absence is not a limitation, it is the
# taxonomy not applying.  The same class of error made every non-Ubuntu host
# "limited" for lacking Ubuntu Pro.
# ---------------------------------------------------------------------------

_ALL_COMMANDS = sorted({c for g in CAPABILITY_GROUPS.values() for c in g})


def _report_for(system, distro_ids, tools):
    handlers = {c: object() for c in _ALL_COMMANDS}
    suppressed = detect_suppressed(
        _ALL_COMMANDS,
        system=system,
        distro_ids=distro_ids,
        which=lambda tool: f"/usr/bin/{tool}" if tool in tools else None,
    )
    return build_capability_report(handlers, suppressed)


_LINUX_VIRT_TOOLS = {"virsh", "qemu-system-x86_64", "modprobe", "ip", "lxd"}


def test_linux_host_is_not_partial_for_lacking_bhyve_vmm_and_wsl():
    """The exact bug: a fully capable KVM host reported as degraded."""
    report = _report_for("Linux", ["ubuntu"], _LINUX_VIRT_TOOLS | {"pro"})
    assert "virtualization" not in report["partial"]
    assert "virtualization" in report["capabilities"]
    assert not report["unavailable"] and not report["partial"]


def test_bsd_host_is_not_partial_for_lacking_kvm_and_lxd():
    """The mirror image -- fixing only the reported direction is half a fix."""
    for system in ("FreeBSD", "OpenBSD"):
        report = _report_for(system, [], {"bhyve"})
        assert "virtualization" not in report["partial"], system
        assert not report["unavailable"], system


def test_ubuntu_pro_is_not_applicable_off_ubuntu():
    """Not a missing tool: the `pro` CLI does not exist outside Ubuntu."""
    report = _report_for("Linux", ["alpine"], _LINUX_VIRT_TOOLS)
    assert report["not_applicable"]["ubuntu_pro"] == REASON_WRONG_PLATFORM
    assert "ubuntu_pro" not in report["unavailable"]
    assert not report["unavailable"] and not report["partial"]


def test_ubuntu_pro_is_still_a_real_gap_on_ubuntu():
    """Applicability must not become a blanket excuse.

    On Ubuntu the `pro` CLI is installable, so its absence is a genuine gap and
    the host SHOULD read as limited.
    """
    report = _report_for("Linux", ["ubuntu"], _LINUX_VIRT_TOOLS)
    assert report["unavailable"]["ubuntu_pro"] == REASON_MISSING_TOOL
    assert "ubuntu_pro" not in report["not_applicable"]


def test_ubuntu_derivatives_count_as_ubuntu():
    """ID_LIKE carries the derivatives; Mint ships `pro` just as Ubuntu does."""
    report = _report_for("Linux", ["linuxmint", "ubuntu"], _LINUX_VIRT_TOOLS)
    assert "ubuntu_pro" not in report["not_applicable"]


def test_inapplicable_groups_never_make_a_host_limited():
    """The server's rule is `limited = unavailable or partial`.

    Anything OS-inapplicable must be outside both, on every platform -- that is
    the entire contract this fix rests on.
    """
    for system, distro, tools in (
        ("Linux", ["ubuntu"], _LINUX_VIRT_TOOLS | {"pro"}),
        ("Linux", ["alpine"], _LINUX_VIRT_TOOLS),
        ("FreeBSD", [], {"bhyve"}),
        ("OpenBSD", [], set()),
        ("Darwin", [], set()),
        ("Windows", [], set()),
    ):
        report = _report_for(system, distro, tools)
        limited = bool(report["unavailable"] or report["partial"])
        assert not limited, f"{system}/{distro} reports limited: {report}"
