# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent keeps its credential (server Phase 22.0).

The host token is issued ONCE, by the registration that created the host.
The agent used to overwrite its stored token with whatever a later response
carried -- including nothing -- and depended on the server sending it again
on every connect, which is exactly the hand-out the server no longer makes.
Every place that stores the host's approval keeps the existing token when the
new data does not carry one for the same host.
"""

import uuid
from typing import Optional

from src.database.models import HostApproval


def kept_host_token(session, host_id) -> Optional[str]:
    """The token already stored for ``host_id``, if any."""
    if not host_id:
        return None
    try:
        key = uuid.UUID(str(host_id))
    except (ValueError, TypeError):
        return None
    row = (
        session.query(HostApproval)
        .filter(HostApproval.host_id == key, HostApproval.host_token.isnot(None))
        .first()
    )
    return row.host_token if row else None
