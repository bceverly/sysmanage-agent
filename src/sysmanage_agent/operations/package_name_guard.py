# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Refuse package names that are not package names (Lucky 13 #1 / #3).

The agent runs package managers as root with argv lists, never a shell, so a
name cannot inject a command.  It can still be read as something other than
a name: ``-o APT::...`` or ``--allow-unauthenticated`` as an OPTION, and
``./evil.deb`` or ``/tmp/x.rpm`` as a local FILE to install (apt, dnf and
zypper all accept paths).  A name arrives from the server, so it is checked
here before any package manager sees it.

Allowed: anything a real package name, id or spec uses -- letters, digits and
``. _ + - : @ = / ~ ,`` (``pkg=1.2``, ``pkg/stable``, ``user/tap/formula``,
``Microsoft.PowerShell``, ``python3.11``) -- up to 256 characters, never
starting with ``-`` or ``.`` or ``/``, and never containing ``..``.
"""

import re
from typing import Any, Optional

MAX_PACKAGE_NAME = 256
_ALLOWED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-:@=/~,]*$")


def package_name_problem(name: Any) -> Optional[str]:
    """Why ``name`` is refused, or None when it is acceptable."""
    if not isinstance(name, str) or not name:
        return "package name is empty or not a string"
    if len(name) > MAX_PACKAGE_NAME:
        return f"package name is longer than {MAX_PACKAGE_NAME} characters"
    if ".." in name:
        return "package name contains '..'"
    if not _ALLOWED.match(name):
        return "package name has characters a package name cannot have"
    return None
