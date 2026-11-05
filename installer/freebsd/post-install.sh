#!/bin/sh
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
#
# FreeBSD package post-install (embedded in +MANIFEST by
# build_pkg_manifest.py).  The account must match the rc script's default
# (sysmanage_agent_user="sysmanage-agent"), and it must NOT be the bare
# "sysmanage" account a SysManage SERVER install uses: the sudoers policy
# shipped here is root-equivalent in practice.

if ! pw groupshow sysmanage-agent >/dev/null 2>&1; then
    pw groupadd sysmanage-agent
fi
if ! pw usershow sysmanage-agent >/dev/null 2>&1; then
    pw useradd sysmanage-agent -g sysmanage-agent -h - -s /usr/sbin/nologin \
       -d /nonexistent -c "SysManage Agent"
fi

install -d -o sysmanage-agent -g sysmanage-agent -m 0750 \
    /var/db/sysmanage-agent /var/log/sysmanage-agent /var/run/sysmanage
# The agent's credentials (host token, certificates, server fingerprint):
# security/certificate_store.py writes here and exits at startup without it.
install -d -o sysmanage-agent -g sysmanage-agent -m 0700 /etc/sysmanage-agent

chmod 0440 /usr/local/etc/sudoers.d/sysmanage-agent

CONF=/usr/local/etc/sysmanage-agent/config.yaml
if [ -f /etc/sysmanage-agent.yaml ]; then
    ln -sf /etc/sysmanage-agent.yaml "$CONF"
elif [ ! -f "$CONF" ]; then
    cp /usr/local/etc/sysmanage-agent/config.yaml.example "$CONF"
    chown root:sysmanage-agent "$CONF"
    chmod 0640 "$CONF"
fi

echo "SysManage Agent installed."
echo "  1. Set the server URL in $CONF"
echo "  2. sysrc sysmanage_agent_enable=YES"
echo "  3. service sysmanage_agent start"
