#!/bin/sh
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
#
# ensure-venv.sh APP_DIR PYTHON
#
# Leave APP_DIR/.venv able to run the agent, without ever breaking one that
# already can (2026-11-24, found in the air-gap lab).
#
# The .deb and .rpm are built with every dependency installed into the
# venv from vendored wheels (the build has no network).  The install
# scripts used to DELETE that venv and rebuild it from PyPI -- so on an
# air-gapped host, or with PyPI unreachable, an upgrade left no venv at
# all: the agent could not start and nothing remote could repair it.
#
# Now:
#   1. The shipped venv is kept when every requirement in
#      requirements-prod.txt is installed in it (the normal case: the
#      package was built for this release's Python).
#   2. Otherwise a NEW venv is built beside it -- from APP_DIR/vendor when
#      the package carries wheels, else from whatever pip can reach (an
#      operator's PIP_FIND_LINKS / PIP_INDEX_URL, or PyPI) -- and swapped
#      in only when complete.  If that fails the existing venv is left as
#      it was, so a failed upgrade never takes away a working agent.
set -u

APP_DIR="$1"
PYTHON="$2"
VENV="$APP_DIR/.venv"
NEW="$APP_DIR/.venv.new"
REQS="$APP_DIR/requirements-prod.txt"

complete() {
    # Every requirement installed in the venv at $1?
    [ -x "$1/bin/python3" ] || return 1
    "$1/bin/python3" - "$REQS" <<'PY' >/dev/null 2>&1
import importlib.metadata
import re
import sys

for line in open(sys.argv[1], encoding="utf-8"):
    line = line.split("#", 1)[0].strip()
    if not line:
        continue
    name = re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0]
    importlib.metadata.version(name)  # raises when it is not installed
PY
}

if complete "$VENV"; then
    echo "Python environment: the packaged one is complete; kept"
    exit 0
fi

echo "Python environment: building a new one beside the current one..."
rm -rf "$NEW"
if ! "$PYTHON" -m venv "$NEW"; then
    echo "WARNING: could not create a Python environment; the current one is kept" >&2
    rm -rf "$NEW"
    exit 0
fi
installed=1
if [ -d "$APP_DIR/vendor" ]; then
    "$NEW/bin/pip" install --quiet --no-index --find-links="$APP_DIR/vendor" --upgrade pip \
        && "$NEW/bin/pip" install --quiet --no-index --find-links="$APP_DIR/vendor" -r "$REQS" \
        && installed=0
fi
if [ "$installed" -ne 0 ]; then
    "$NEW/bin/pip" install --quiet --upgrade pip \
        && "$NEW/bin/pip" install --quiet -r "$REQS" \
        && installed=0
fi
if [ "$installed" -eq 0 ] && complete "$NEW"; then
    rm -rf "$VENV"
    mv "$NEW" "$VENV"
    echo "Python environment: rebuilt"
    exit 0
fi
rm -rf "$NEW"
echo "WARNING: the Python dependencies could not be installed (no network or" >&2
echo "  wheels?); the current environment is kept.  Offline, run this again with" >&2
echo "  PIP_NO_INDEX=1 PIP_FIND_LINKS=<a folder of wheels>." >&2
exit 0
