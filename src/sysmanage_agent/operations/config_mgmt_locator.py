# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Find this host's configuration-management executor (Phase 20.1).

WHY A SEPARATE MODULE FOR WHAT LOOKS LIKE ONE ``shutil.which`` CALL
-------------------------------------------------------------------
Because it is not one lookup, and because two callers need the SAME answer:

  * the command handler that runs a profile needs the PATH to the executable;
  * ``capability_probes`` needs the yes/no, and it is forbidden from doing
    anything expensive -- its design rules say executable lookups only, no
    subprocess, no network, no writes.

Keeping discovery here means the probe and the executor can never disagree
about whether this host can run a profile, which is the failure that produces
the worst outcome in the whole feature: a host that ADVERTISES config
management and then fails at the far end.

Everything below is a filesystem lookup.  Nothing is executed -- in particular
there is no ``ansible --version`` here, however tempting, because that would
make the capability report shell out on every registration.  Version reporting
is the SERVER's job and it already has the data (see
``backend/services/config_mgmt_prereq.py``).

WINDOWS IS NOT ON PATH, BY DESIGN
---------------------------------
``dsc.exe`` is vendored into the MSI at ``<INSTALLFOLDER>\\dsc\\dsc.exe`` and
deliberately NOT added to the system PATH -- putting a DSC engine on the PATH
of every managed Windows host is a side effect nobody asked for.  So the
Windows branch resolves relative to the installed agent first and only then
falls back to PATH (which covers developers who installed DSC themselves).
"""

import os
import platform
import shutil
from typing import List, Optional

# Matches backend/services/config_mgmt_plan_builder.py.  The two must agree:
# the server decides what to install, this decides what to run.
WINDOWS_EXECUTOR = "dsc"
POSIX_EXECUTOR = "ansible-core"

# The binary each executor is actually invoked as.  Note the POSIX one is
# ansible-PLAYBOOK, not ansible: the pull-style path runs a playbook against
# localhost, and a host can have the `ansible` wrapper without the playbook
# runner in some minimal packagings.
WINDOWS_BINARY = "dsc.exe"
POSIX_BINARY = "ansible-playbook"


def executor_name() -> str:
    """Which executor this platform uses."""
    return WINDOWS_EXECUTOR if platform.system() == "Windows" else POSIX_EXECUTOR


def _agent_install_root() -> Optional[str]:
    """The directory the agent is installed into, or None if undeterminable.

    Derived from this module's own location: the MSI lays the package down
    under ``<INSTALLFOLDER>`` and ``dsc`` is a sibling directory, so walking up
    from here finds it without hardcoding "C:\\Program Files\\SysManage Agent"
    -- which would be wrong for a per-user install, a relocated install, or a
    developer running from a checkout.
    """
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except (OSError, NameError):  # pragma: no cover - __file__ always set
        return None
    # .../<root>/src/sysmanage_agent/operations/this_file.py
    return os.path.abspath(os.path.join(here, "..", "..", ".."))


def _windows_candidates() -> List[str]:
    """Places ``dsc.exe`` may live, most-authoritative first."""
    candidates = []
    root = _agent_install_root()
    if root:
        # The MSI layout.  Checked before PATH so a vendored copy always wins
        # over whatever a developer happens to have installed globally --
        # otherwise a host could run a different DSC version than the one we
        # shipped and tested against.
        candidates.append(os.path.join(root, "dsc", WINDOWS_BINARY))
    return candidates


def find_executor(which=None, system=None) -> Optional[str]:
    """Absolute path to this host's config-management executor, or None.

    ``None`` means the host cannot run profiles.  That is a normal answer, not
    an error: a POSIX host without ansible-core is exactly the case the
    server's prerequisite card exists to surface.

    ``which`` and ``system`` override the executable lookup and the platform.
    They exist so callers that already inject those -- ``detect_suppressed``
    and its tests -- get a deterministic answer instead of one that depends on
    the machine running the tests.  Injecting only ``system`` and leaving this
    reading the real ``platform.system()`` would silently probe the wrong
    branch, which is worse than not injecting at all.
    """
    lookup = which or shutil.which
    if (system or platform.system()) == "Windows":
        for candidate in _windows_candidates():
            if os.path.isfile(candidate):
                return candidate
        # Developer fallback: a self-installed DSC on PATH.
        return lookup(WINDOWS_BINARY) or lookup(WINDOWS_EXECUTOR)

    return lookup(POSIX_BINARY)


def is_available(which=None, system=None) -> bool:
    """Whether this host can run configuration profiles at all."""
    return find_executor(which, system) is not None
