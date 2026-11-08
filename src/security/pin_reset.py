# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Deliberately forget the pinned server identity (ROADMAP 25.10).

Run from the agent's install directory, as the user the agent runs as, with
the agent's own Python (``.venv/bin/python`` in ``/opt/sysmanage-agent`` for
the Linux packages)::

    .venv/bin/python -m src.security.pin_reset                # forget the pins
    .venv/bin/python -m src.security.pin_reset --certificate  # also this host's certificate

then restart the agent.  With the pins gone, the agent pins the server again
on its next successful connection -- the way to accept a server whose CA
really did change, or that really was replaced.  ``--certificate`` also
removes this host's certificate, key and the SysManage CA, so a new
certificate is requested once the host is approved.

Removing ``server_pins.json`` by hand does the same as the first form.
"""

import argparse
import sys
from typing import List, Optional

from src.i18n import _
from src.security.certificate_store import default_store


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=_("Forget the server identity this agent has pinned.")
    )
    parser.add_argument(
        "--certificate",
        action="store_true",
        help=_("also remove this host's certificate, its key and the CA"),
    )
    args = parser.parse_args(argv)
    store = default_store()
    try:
        if args.certificate:
            store.clear_certificates()
            print(
                _("Removed the server pins and this host's certificate from %s")
                % store.config_dir
            )
        elif store.clear_pins():
            print(_("Removed the server pins: %s") % store.pins_path)
        else:
            print(_("No server pins to remove: %s") % store.pins_path)
    except OSError as error:
        print(_("Could not remove the files: %s") % error, file=sys.stderr)
        return 1
    print(_("Restart the agent; it pins the server again on its next connection."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
