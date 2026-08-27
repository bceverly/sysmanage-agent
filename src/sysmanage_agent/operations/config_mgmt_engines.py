# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The configuration-management engines this agent can drive (Phase 20.1).

WHY A REGISTRY RATHER THAN A PLATFORM SWITCH
--------------------------------------------
The first cut answered "which executor does this host use?" with a single value
derived from the platform -- ``dsc`` on Windows, ``ansible-core`` everywhere
else.  That was right while there was one engine per platform and wrong the
moment an operator could choose.  A host can have Ansible AND Salt installed,
Puppet and Chef both run on Windows, and which one applies is a property of the
PROFILE, not of the operating system.

So the platform answer survives only as a DEFAULT, and everything else keys off
an engine name.

WHY THE BINARY IS A LIST
------------------------
``chef`` is the engine; ``chef-client`` is the binary that happens to implement
it today.  If licensing ever forces a move to ``cinc-client`` that is a
different distribution of the SAME engine -- stored run rows, profile documents
and the API surface must not change.  Keeping ``binaries`` an ordered tuple
makes that a one-line edit rather than a migration, and mirrors how
``capability_probes._REQUIRED_TOOLS`` already handles alternates.

EVERY FIELD BELOW WAS MEASURED
------------------------------
Nothing here is inferred from documentation; each engine was run on a real box
(2026-08-26/27) and the awkward parts are recorded in ``config_mgmt_runner``
where they are acted on.
"""

import platform
from typing import Dict, Optional, Tuple

# Engine identities.  These strings are the contract: they are what a profile
# names, what `config_profile_run.executor` stores, and what the server's
# prerequisite card reports.  Never put a BINARY name in one of these.
ANSIBLE = "ansible-core"
PUPPET = "puppet"
SALT = "salt"
CHEF = "chef"
DSC = "dsc"


class Engine:  # pylint: disable=too-few-public-methods
    """Static description of one engine."""

    def __init__(
        self,
        name: str,
        binaries: Tuple[str, ...],
        *,
        vendored: bool = False,
        windows_only: bool = False,
    ):
        self.name = name
        # Ordered: the first one found wins.  See the module docstring for why
        # this is a list and not a string.
        self.binaries = binaries
        # Ships with the agent rather than being installed (DSC today), which
        # is why its prerequisite status is "not_required" and not "satisfied".
        self.vendored = vendored
        self.windows_only = windows_only


ENGINES: Dict[str, Engine] = {
    # ansible-playbook, NOT ansible: the pull path runs a playbook against
    # localhost, and some minimal packagings ship the wrapper without the
    # playbook runner.
    ANSIBLE: Engine(ANSIBLE, ("ansible-playbook",)),
    PUPPET: Engine(PUPPET, ("puppet",)),
    # salt-call is the masterless entry point; `salt` is the master CLI and is
    # useless to us.
    SALT: Engine(SALT, ("salt-call",)),
    # cinc-client is deliberately absent today (Bryan chose Chef 2026-08-27);
    # adding it here is the whole escape hatch.
    CHEF: Engine(CHEF, ("chef-client",)),
    DSC: Engine(DSC, ("dsc.exe", "dsc"), vendored=True, windows_only=True),
}

# What a host gets when a profile does not name an engine.  A default, not a
# constraint: Puppet, Salt and Chef all ship Windows agents, so a Windows host
# is perfectly able to run them -- DSC is simply what we vendor there.
DEFAULT_ENGINE_BY_PLATFORM = {"Windows": DSC}
DEFAULT_ENGINE = ANSIBLE


def default_engine(system: Optional[str] = None) -> str:
    """The engine a profile gets when it does not name one."""
    return DEFAULT_ENGINE_BY_PLATFORM.get(system or platform.system(), DEFAULT_ENGINE)


def get(name: Optional[str], system: Optional[str] = None) -> Optional[Engine]:
    """Look up an engine by name, falling back to the platform default.

    Returns ``None`` for a name we do not implement rather than raising: an
    unknown engine in a profile is a bad request to report, not a crash.
    """
    if not name:
        return ENGINES.get(default_engine(system))
    return ENGINES.get(str(name).strip().lower())


def applicable(system: Optional[str] = None) -> Tuple[str, ...]:
    """Engine names that could run on this platform at all.

    Only DSC is genuinely platform-bound; the rest are cross-platform, so this
    filters far less than the old one-per-platform rule did. That is the point.
    """
    this_system = system or platform.system()
    return tuple(
        name
        for name, engine in ENGINES.items()
        if not engine.windows_only or this_system == "Windows"
    )
