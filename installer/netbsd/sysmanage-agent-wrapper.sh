#!/bin/sh
# Wrapper script for sysmanage-agent to set Python path

export PYTHONPATH="/usr/pkg/lib/sysmanage-agent/src:${PYTHONPATH}"
exec /usr/pkg/bin/python3.12 /usr/pkg/lib/sysmanage-agent/main.py "$@"
