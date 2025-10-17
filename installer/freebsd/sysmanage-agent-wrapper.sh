#!/bin/sh
# Wrapper script for sysmanage-agent to set Python path

export PYTHONPATH="/usr/local/lib/sysmanage-agent/src:${PYTHONPATH}"
exec /usr/local/bin/python3.11 /usr/local/lib/sysmanage-agent/main.py "$@"