# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Runtime detection of capabilities this host cannot actually deliver.

WHY
---
``build_capability_report`` derives what the agent can do from the live command
handler map.  That answers "was this code shipped?", which is not the same
question as "will it work here".  A handler for ``initialize_bhyve`` is present
in every build, including on Linux; a handler for ``ubuntu_pro_attach`` is
present on Alpine.  Reporting those as supported invites the server to dispatch
work that fails at the far end -- exactly the runtime failure the capability
feature exists to replace with a clear "not supported on this agent".

WHAT THIS IS NOT
----------------
Not build-time trimming.  That is a separate, later mechanism for targets where
a dependency cannot even be imported (no wheel for the arch), and it is
deliberately accommodated rather than implemented: it produces the same
``{command: reason}`` mapping this module produces, fed from a build manifest
instead of a probe, and everything downstream is already written against that
shape.  ``REASON_BUILD_EXCLUDED`` is reserved for it.

DESIGN RULES
------------
1. **A probe may only ever REMOVE a capability.**  It can never add one, so a
   broken probe degrades to today's behaviour plus a false negative, never to
   claiming something the agent cannot do.
2. **Be conservative.**  A missing probe is fine (the capability stays
   advertised, as now); a wrong probe silently disables a working feature,
   which is worse than the status quo.  Only requirements that are genuinely
   load-bearing are declared here.
3. **Cheap and side-effect free.**  This runs on every registration and on
   every live query.  Executable lookups only -- no subprocess execution, no
   network, no writes.
"""

import os
import platform
import shutil
from typing import Dict, Iterable, Mapping, Optional, Tuple

# Reason codes.  Codes, not sentences: the SERVER owns the translation, so an
# operator reads them in their own language (see capabilities.py).
REASON_MISSING_TOOL = "missing_tool"
REASON_WRONG_PLATFORM = "wrong_platform"
# Reserved for the build-time mechanism; nothing emits it yet.
REASON_BUILD_EXCLUDED = "build_excluded"

# Reasons that mean "this OS cannot host this capability AT ALL", as opposed to
# "this host is missing something it could have".
#
# The distinction drives the limited/partial analysis, and getting it wrong is
# what made every Linux host report virtualization as PARTIALLY supported: the
# group carries bhyve (FreeBSD), vmm (OpenBSD) and WSL (Windows), so a
# perfectly capable KVM host looked degraded for lacking three hypervisors it
# could never run.  An inapplicable command is not a gap in this agent -- it is
# not part of the taxonomy on this OS -- so it must not count toward "limited".
#
# REASON_MISSING_TOOL is deliberately NOT here: a missing `virsh` on Linux is a
# real gap the operator can close by installing it.
INAPPLICABLE_REASONS = frozenset({REASON_WRONG_PLATFORM})


# command -> ((executable, ...), reason)
#
# The command is unavailable when NONE of the listed executables is on PATH.
# Alternatives are listed where a platform has more than one implementation --
# KVM networking is virsh on most distros and brctl on older ones, so requiring
# a single name would report a working host as limited.
_REQUIRED_TOOLS: Dict[str, Tuple[Tuple[str, ...], str]] = {
    # Virtualization: the initializers shell out to the hypervisor's own tools.
    "initialize_kvm": (
        ("virsh", "qemu-system-x86_64", "qemu-kvm"),
        REASON_MISSING_TOOL,
    ),
    "enable_kvm_modules": (("modprobe",), REASON_MISSING_TOOL),
    "disable_kvm_modules": (("modprobe",), REASON_MISSING_TOOL),
    "setup_kvm_networking": (("virsh", "brctl", "ip"), REASON_MISSING_TOOL),
    "list_kvm_networks": (("virsh",), REASON_MISSING_TOOL),
    "initialize_lxd": (("lxd", "lxc"), REASON_MISSING_TOOL),
    # Ubuntu Pro is the `pro` CLI; without it these are unrunnable anywhere.
    "ubuntu_pro_attach": (("pro", "ua"), REASON_MISSING_TOOL),
    "ubuntu_pro_detach": (("pro", "ua"), REASON_MISSING_TOOL),
    "ubuntu_pro_enable_service": (("pro", "ua"), REASON_MISSING_TOOL),
    "ubuntu_pro_disable_service": (("pro", "ua"), REASON_MISSING_TOOL),
}

# command -> (platform.system() values where it CAN work, reason)
#
# Only where the command is meaningless elsewhere, not merely unusual.  bhyve
# is FreeBSD's hypervisor and vmm is OpenBSD's; WSL is a Windows feature.
_REQUIRED_PLATFORMS: Dict[str, Tuple[Tuple[str, ...], str]] = {
    "initialize_bhyve": (("FreeBSD",), REASON_WRONG_PLATFORM),
    "disable_bhyve": (("FreeBSD",), REASON_WRONG_PLATFORM),
    "initialize_vmm": (("OpenBSD",), REASON_WRONG_PLATFORM),
    "enable_wsl": (("Windows",), REASON_WRONG_PLATFORM),
    # The mirror image of the entries above, and just as necessary.  KVM is a
    # Linux KERNEL feature and LXD is Linux-only, so a FreeBSD host running
    # bhyve was reporting virtualization as PARTIAL for lacking six commands it
    # can never run -- the same bug as Linux-and-bhyve, pointed the other way.
    # Fixing only the direction that was reported would have left every BSD and
    # macOS host wrong.
    "initialize_kvm": (("Linux",), REASON_WRONG_PLATFORM),
    "enable_kvm_modules": (("Linux",), REASON_WRONG_PLATFORM),
    "disable_kvm_modules": (("Linux",), REASON_WRONG_PLATFORM),
    "setup_kvm_networking": (("Linux",), REASON_WRONG_PLATFORM),
    "list_kvm_networks": (("Linux",), REASON_WRONG_PLATFORM),
    "initialize_lxd": (("Linux",), REASON_WRONG_PLATFORM),
}

# command -> (distro IDs where it CAN work, reason)
#
# platform.system() is too coarse for capabilities that are a property of the
# DISTRIBUTION rather than the kernel.  Ubuntu Pro is the example: the `pro`
# CLI is Ubuntu's, so on Alpine or RHEL it is not "a missing tool the operator
# should install", it is a facility that does not exist there -- and treating
# it as a missing tool marked every non-Ubuntu host in the fleet as limited.
#
# On Ubuntu itself an absent `pro` binary stays REASON_MISSING_TOOL via
# _REQUIRED_TOOLS below, because there it genuinely is installable.
_REQUIRED_DISTROS: Dict[str, Tuple[Tuple[str, ...], str]] = {
    "ubuntu_pro_attach": (("ubuntu",), REASON_WRONG_PLATFORM),
    "ubuntu_pro_detach": (("ubuntu",), REASON_WRONG_PLATFORM),
    "ubuntu_pro_enable_service": (("ubuntu",), REASON_WRONG_PLATFORM),
    "ubuntu_pro_disable_service": (("ubuntu",), REASON_WRONG_PLATFORM),
}


def _distro_ids(os_release_path: str = "/etc/os-release") -> frozenset:
    """``{ID}`` plus ``ID_LIKE`` entries from os-release, lowercased.

    A file read, not a subprocess, so it still honours design rule 3.  Empty on
    any platform without the file (macOS, the BSDs, Windows), which makes every
    _REQUIRED_DISTROS entry inapplicable there -- correct, since all of them are
    Linux-distribution facilities.  ID_LIKE is included so Ubuntu derivatives
    (Mint, Pop!_OS) are not told they cannot run a tool they ship.
    """
    ids = set()
    try:
        with open(os_release_path, "r", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.partition("=")
                if key.strip() not in ("ID", "ID_LIKE"):
                    continue
                ids.update(value.strip().strip("\"'").lower().split())
    except OSError:
        return frozenset()
    return frozenset(ids)


def _which(name: str) -> Optional[str]:
    """``shutil.which`` with the service PATH, not the caller's.

    A service started by rc.d/systemd has a narrower PATH than a login shell,
    and probing with the wrong one reports tools the agent could not actually
    invoke.  Callers may override for tests.
    """
    return shutil.which(name)


def _suppression_reason(command, this_system, these_distros, lookup):
    """The reason ``command`` must not be advertised, or None if it is usable.

    Split out of ``detect_suppressed`` so that function stays a flat loop: the
    three checks below were three guard-and-continue blocks inline, which put
    its cognitive complexity over the limit for no gain in clarity.

    ORDER MATTERS between the second and third checks.  A missing ``pro`` on
    Alpine must read as "not applicable here", not as "install it"; reversing
    them would put every non-Ubuntu host back in the limited bucket.
    """
    required, reason = _REQUIRED_PLATFORMS.get(command, ((), ""))
    if required and this_system not in required:
        return reason

    distros, distro_reason = _REQUIRED_DISTROS.get(command, ((), ""))
    if distros and not these_distros.intersection(distros):
        return distro_reason

    tools, tool_reason = _REQUIRED_TOOLS.get(command, ((), ""))
    if tools and not any(lookup(tool) for tool in tools):
        return tool_reason

    return None


def detect_suppressed(
    available: Iterable[str],
    *,
    system: Optional[str] = None,
    which=None,
    build_excluded: Optional[Mapping[str, str]] = None,
    distro_ids: Optional[Iterable[str]] = None,
) -> Dict[str, str]:
    """Map each unusable command to a reason code.

    Args:
        available: command types this build routes (the handler map's keys).
        system: override for ``platform.system()`` (tests).
        which: override for executable lookup (tests).
        build_excluded: commands a future build-time mechanism removed, as
            ``{command: reason}``.  Merged in as-is -- this is the seam that
            keeps build-time trimming from needing any new plumbing.
        distro_ids: override for os-release ID/ID_LIKE lookup (tests).

    Returns:
        ``{command: reason_code}`` for commands that must NOT be advertised.
        Only ever a subset of ``available``.
    """
    lookup = which or _which
    this_system = system or platform.system()
    these_distros = (
        frozenset(str(d).lower() for d in distro_ids)
        if distro_ids is not None
        else _distro_ids()
    )
    suppressed: Dict[str, str] = {}

    for command in available:
        reason = _suppression_reason(command, this_system, these_distros, lookup)
        if reason:
            suppressed[command] = reason

    if build_excluded:
        # Build-time wins: if an artifact shipped without the code, no runtime
        # probe can make it available again.
        available_set = set(available)
        for command, reason in build_excluded.items():
            if command in available_set:
                suppressed[command] = reason

    return dict(sorted(suppressed.items()))


def build_excluded_from_env() -> Dict[str, str]:
    """Commands a trimmed build declared unavailable, from the environment.

    The placeholder for build-time trimming, and the reason this module can
    absorb it later without a redesign: a build that omits code sets
    ``SYSMANAGE_AGENT_EXCLUDED_COMMANDS`` to a comma-separated list, and every
    consumer downstream already handles the result.  Empty in every build we
    currently ship.
    """
    raw = os.environ.get("SYSMANAGE_AGENT_EXCLUDED_COMMANDS", "")
    return {
        command.strip(): REASON_BUILD_EXCLUDED
        for command in raw.split(",")
        if command.strip()
    }
