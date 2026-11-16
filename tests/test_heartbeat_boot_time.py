# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The heartbeat carries when the host booted, so the server can tell a host
that rebooted and came back from one whose agent never stopped (ROADMAP
26.1: automatic updates that reboot)."""

from datetime import datetime, timezone
from unittest.mock import patch

from src.sysmanage_agent.communication import message_handler


def test_boot_time_is_utc_iso():
    with patch("psutil.boot_time", return_value=1_763_280_000.0):
        value = message_handler._boot_time()  # pylint: disable=protected-access
    assert datetime.fromisoformat(value) == datetime.fromtimestamp(
        1_763_280_000.0, tz=timezone.utc
    )


def test_no_boot_time_is_no_field_not_a_failure():
    with patch("psutil.boot_time", side_effect=OSError("no /proc")):
        assert message_handler._boot_time() is None  # pylint: disable=protected-access
