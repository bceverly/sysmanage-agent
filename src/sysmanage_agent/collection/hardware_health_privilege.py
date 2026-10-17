# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Run the read-only Linux health tools as root through ``sudo -n``.

A packaged agent runs as the unprivileged ``sysmanage-agent`` user, and every
drive came back "not judged -- the health log could not be read": the NVMe
log needs the admin ioctl (root), ``smartctl`` cannot open a disk, ``lvs``
cannot take LVM's lock, ``btrfs device stats`` and ``ipmitool`` need root
(beast and nas, 2026-10-16).  The sudoers allowlists grant exactly the
argument forms below; anything else runs as before.  A refused ``sudo``
(older allowlist, no sudo) falls back to the plain call, so a host is never
worse off than without this.
"""

import os
from typing import Callable, Tuple

from src.sysmanage_agent.collection.hardware_identity import _tool

Runner = Callable[[list], Tuple[int, str]]

# Tools whose health reads need root.  Their version probes do not, and stay
# unprivileged so "is it installed?" never depends on the sudo allowlist.
SUDO_TOOLS = frozenset({"smartctl", "btrfs", "lvs", "ipmitool"})
_UNPRIVILEGED_ARGS = frozenset({"--version", "-V"})

# What sudo / sudo-rs print when the allowlist does not cover a command.
_REFUSED = (
    "a password is required",
    "is not allowed to execute",
    "may not run sudo",
    "can't do that",
    "not in the sudoers",
)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def refused(out: str) -> bool:
    """Whether ``out`` is sudo / sudo-rs declining the command (the allowlist
    does not cover it), as opposed to the command itself failing."""
    text = (out or "").lower()
    return text.startswith("sudo") and any(marker in text for marker in _REFUSED)


_refused = refused  # the name the health runner below has always used


def privileged_runner(run: Runner, root=None) -> Runner:
    """``run``, escalating :data:`SUDO_TOOLS` with ``sudo -n`` when not root.

    The returned runner carries ``escalates = True`` so collectors that used
    to skip a read without root (btrfs stats, the BMC) know to try it."""
    if is_root() if root is None else root:
        return run

    def escalated(argv) -> Tuple[int, str]:
        tool = argv[0]
        if tool not in SUDO_TOOLS or (len(argv) > 1 and argv[1] in _UNPRIVILEGED_ARGS):
            return run(argv)
        path = _tool(tool)
        if not os.path.isabs(path):
            return -1, ""  # not installed -- same answer the plain call gives
        rc, out = run(["sudo", "-n", path, *argv[1:]])
        if rc == -1 or (rc != 0 and _refused(out)):
            return run(argv)
        return rc, out

    escalated.escalates = True  # type: ignore[attr-defined]
    return escalated


def escalates(run) -> bool:
    return bool(getattr(run, "escalates", False))
