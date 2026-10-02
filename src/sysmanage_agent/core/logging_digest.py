# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Fingerprint of the server-pushed logging config this agent runs with.

Server Phase 22.2: the server pushed the logging config on EVERY reconnect --
after a server restart, ten thousand identical pushes.  The agent now reports
this fingerprint in SYSTEM_INFO and the server pushes only when its own
differs.  The agent keeps the pushed config in memory only, so after an
AGENT restart there is no fingerprint and the push happens, as it must.

Must stay byte-for-byte the server's ``logging_config_service.config_digest``:
SHA-256 of the canonical JSON (sorted keys, no spaces).
"""

import hashlib
import json
from typing import Optional


def config_digest(logging_cfg) -> Optional[str]:
    """The fingerprint of ``logging_cfg``, or None when nothing was pushed."""
    if not isinstance(logging_cfg, dict) or not logging_cfg:
        return None
    canonical = json.dumps(
        logging_cfg, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
