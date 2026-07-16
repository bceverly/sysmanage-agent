#!/bin/sh
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

# Wrapper script for sysmanage-agent to set Python path

export PYTHONPATH="/usr/pkg/lib/sysmanage-agent/src:${PYTHONPATH}"
exec /usr/pkg/bin/python3.12 /usr/pkg/lib/sysmanage-agent/main.py "$@"
