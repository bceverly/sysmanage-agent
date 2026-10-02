# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""MITRE's "Lucky 13" unforgivable vulnerabilities, checked on every push.

Steve Christey (MITRE), "Unforgivable Vulnerabilities", 2007
(https://cwe.mitre.org/documents/unforgivable_vulns/unforgivable.pdf):
thirteen weakness classes so well documented, so obvious and so cheap to
find ("found in five minutes") that shipping one is unforgivable.  Each test
in this package names its number and CWE.  CI runs the package as its own
step (``pytest -m lucky13``; locally ``make test-lucky13``).

The agent runs as root / SYSTEM and takes orders from the server, so here the
checks lean on what a privileged process must never do (#4, #6, #9, #10, #11,
#12) and on refusing hostile values in the server's commands (#1, #3, #5,
#13).  #7 and #8 (direct request, ``authenticated=1``) are server checks --
the agent serves no requests -- and #2 (XSS) only asks that it render no HTML.

    1 buffer overflow (CWE-120)       8 auth bypass: authenticated=1 (CWE-472)
    2 XSS (CWE-79)                    9 grow-your-own crypto (CWE-327)
    3 directory traversal (CWE-23)   10 privilege escalation via Help (CWE-271)
    4 remote file inclusion (CWE-98) 11 symlink following (CWE-61)
    5 SQL injection (CWE-89)         12 hard-coded / default password (CWE-259)
    6 world-writable files (CWE-276) 13 integer overflow (CWE-190)
    7 direct request (CWE-425)
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def pytest_collection_modifyitems(items):
    for item in items:
        if "lucky13" in item.nodeid.split("::")[0]:
            item.add_marker(pytest.mark.lucky13)
