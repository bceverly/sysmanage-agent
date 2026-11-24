# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Compliance evidence on macOS and the BSDs (2026-11-23), parsed from each
tool's own output (as FreeBSD 14.4, OpenBSD 8.0 and NetBSD 10.1 lab hosts
printed it that day)."""

import subprocess
from pathlib import Path
from unittest.mock import patch

from src.sysmanage_agent.collection import compliance_evidence as ce
from src.sysmanage_agent.collection import compliance_evidence_bsd as bsd
from src.sysmanage_agent.collection import compliance_evidence_macos as mac

# -- BSD -------------------------------------------------------------------------


def test_netbsd_defaults_set_several_variables_per_line():
    defaults = 'inetd=YES\t\tinetd_flags="-l"\t# -l logs libwrap\n' \
               'syslogd=YES\t\tsyslogd_flags="-s"\t# -s "secure" unix domain only\n' \
               'if [ -r /etc/defaults/rc.conf ]; then\n'  # fmt: skip
    found = bsd.parse_rc_conf([defaults, "inetd=NO # nothing listens\n"])
    assert found == {
        "inetd": "NO",
        "inetd_flags": "-l",
        "syslogd": "YES",
        "syslogd_flags": "-s",
    }


def test_freebsd_sysrc_listing():
    found = bsd.parse_sysrc(
        "pf_enable: YES\nsyslogd_flags: -s\nntpdate_hosts: \nnot a line\n"
    )
    assert found == {"pf_enable": "YES", "syslogd_flags": "-s", "ntpdate_hosts": ""}


def test_login_conf_default_class_with_continuations():
    conf = ("# comment\ndefault:\\\n\t:passwd_format=sha512:\\\n\t:umask=022:\n"
            "daemon:\\\n\t:passwd_format=md5:\n")  # fmt: skip
    assert bsd.login_class(conf)["passwd_format"] == "sha512"
    openbsd = "default:\\\n\t:path=/usr/bin /bin:\\\n\t:localcipher=blowfish,a:\\\n\t:tc=auth-defaults:\n"
    assert bsd.login_class(openbsd)["localcipher"] == "blowfish,a"


def test_uid0_accounts_besides_root_and_toor():
    passwd = "root:*:0:0:Charlie &:/root:/bin/sh\ntoor:*:0:0:Bourne-again Superuser:/root:\n" \
             "daemon:*:1:1:Owner:/root:/usr/sbin/nologin\nbackdoor:*:0:0::/:/bin/sh\n"  # fmt: skip
    assert bsd.uid0_others(passwd) == 1


def test_sshd_t_goes_through_doas_where_there_is_no_sudo():
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 0, "permitrootlogin no\nmaxauthtries 4\n", ""
        )

    def which(name):
        return "/usr/bin/doas" if name == "doas" else None

    with patch.object(bsd.os, "geteuid", return_value=1000, create=True), \
            patch.object(bsd.shutil, "which", side_effect=which), \
            patch.object(bsd, "_tool", return_value="/usr/sbin/sshd"), \
            patch.object(bsd.subprocess, "run", side_effect=fake_run):  # fmt: skip
        found, status = bsd.ssh_config()
    assert calls == [["doas", "-n", "/usr/sbin/sshd", "-T"]]
    assert status == bsd.RAN and found["PermitRootLogin"] == "no"


def test_a_refused_escalation_is_not_privileged_not_a_failure():
    refused = subprocess.CompletedProcess([], 1, "", "doas: Authorization required\n")
    with patch.object(bsd.os, "geteuid", return_value=1000, create=True), \
            patch.object(bsd.shutil, "which", return_value="/usr/bin/doas"), \
            patch.object(bsd.subprocess, "run", return_value=refused):  # fmt: skip
        assert bsd._privileged(["/usr/sbin/sshd", "-T"]) == (None, bsd.NOT_PRIVILEGED)


def test_each_bsd_reports_ssh_and_settings():
    for system in ("FreeBSD", "OpenBSD", "NetBSD"):
        with patch.object(
            bsd, "SECTIONS", {n: (lambda: ({}, bsd.RAN)) for n in bsd.SECTIONS}
        ):
            report = ce.collect_compliance_evidence(system)
        assert report["platform"] == system
        assert set(report["sections"]) == {"ssh_config", "bsd_settings"}


def test_the_bsd_allowlists_name_exactly_sshd_t():
    root = Path(__file__).resolve().parent.parent / "installer"
    assert (
        "/usr/sbin/sshd ^-T$" in (root / "freebsd/sysmanage-agent.sudoers").read_text()
    )
    assert (
        "NOPASSWD: /usr/sbin/sshd -T\n"
        in (root / "netbsd/sysmanage_agent.sudoers").read_text()
    )
    assert ("permit nopass _sysmanage as root cmd /usr/sbin/sshd args -T"
            in (root / "openbsd/files/sysmanage_agent.doas").read_text())  # fmt: skip


# -- macOS -------------------------------------------------------------------------

ACCOUNT_POLICIES = """Getting global account policies
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>policyCategoryAuthentication</key><array><dict>
  <key>policyContent</key><string>(policyAttributeFailedAuthentications &lt; policyAttributeMaximumFailedAuthentications)</string>
  <key>policyIdentifier</key><string>com.apple.policy.legacy.maxFailedLoginAttempts</string>
  <key>policyParameters</key><dict><key>policyAttributeMaximumFailedAuthentications</key><integer>5</integer></dict>
</dict></array>
<key>policyCategoryPasswordContent</key><array><dict>
  <key>policyContent</key><string>policyAttributePassword matches '.{15,}+'</string>
  <key>policyIdentifier</key><string>com.apple.policy.legacy.minChars</string>
  <key>policyParameters</key><dict><key>minimumLength</key><integer>15</integer></dict>
</dict></array>
<key>policyCategoryPasswordChange</key><array><dict>
  <key>policyIdentifier</key><string>Change every 365 days</string>
  <key>policyParameters</key><dict><key>policyAttributeExpiresEveryNDays</key><integer>365</integer></dict>
</dict></array>
</dict></plist>
"""  # noqa: E501


def test_account_policies_by_parameter_with_expiry_in_minutes_too():
    found = mac.parse_account_policies(ACCOUNT_POLICIES)
    assert found["pwpolicy_account:policyattributemaximumfailedauthentications"] == 5
    assert found["pwpolicy_account:minimumlength"] == 15
    assert found["pwpolicy_account:policyattributeexpireseverynminutes"] == 365 * 1440


def test_global_policy_pairs():
    found = mac.parse_global_policy(
        "maxFailedLoginAttempts=5 minChars=15 usingHistory=15\n"
    )
    assert found == {"pwpolicy_global:maxfailedloginattempts": 5,
                     "pwpolicy_global:minchars": 15, "pwpolicy_global:usinghistory": 15}  # fmt: skip


def test_audit_control_flags_and_retention_in_either_unit():
    text = "dir:/var/audit\nflags:-fm,ad,-ex,aa,-fr,lo,-fw\nexpire-after:60d OR 5G\n"
    found = mac.parse_audit_control(text)
    assert found["audit_flags"] == "-fm,ad,-ex,aa,-fr,lo,-fw"
    assert found["audit_expire_after_days"] == 60
    assert found["audit_expire_after_bytes"] == 5 * 1024**3


def test_install_log_retention():
    text = "# comment\n? [= Sender installd] file /var/log/install.log format=bsd ttl=365\n"
    assert mac.parse_asl_install(text) == {"install_log_ttl_days": 365}
    capped = "* file /var/log/install.log ttl=365 all_max=50M\n"
    assert mac.parse_asl_install(capped)["install_log_all_max"] is True


def test_pmset_sudo_and_launchd():
    assert mac.parse_pmset(
        "Battery Power:\n powernap 0\nAC Power:\n powernap 1\n womp 0\n"
    ) == {"pmset_powernap": 1, "pmset_womp": 0}
    sudo = ("Authentication timestamp timeout: 0.0 minutes\n"
            "Type of authentication timestamp record: tty\n")  # fmt: skip
    assert mac.parse_sudo_defaults(sudo) == {
        "sudo_timestamp_timeout_minutes": 0.0,
        "sudo_timestamp_type": "tty",
    }
    listing = "PID\tStatus\tLabel\n-\t0\tcom.apple.auditd\n123\t0\tcom.apple.smbd\n"
    facts = mac.launchd_facts(listing)
    assert (
        facts["launchd:com.apple.smbd"] is True
        and facts["launchd:org.apache.httpd"] is False
    )


def test_preferences_come_back_lower_cased_from_one_osascript():
    out = '{"com.apple.SoftwareUpdate/AutomaticCheckEnabled":true,"com.apple.loginwindow/GuestEnabled":0}\n'
    with patch.object(mac, "_run", return_value=(0, out)):
        found = mac.read_prefs()
    assert found == {"pref:com.apple.softwareupdate/automaticcheckenabled": True,
                     "pref:com.apple.loginwindow/guestenabled": 0}  # fmt: skip


def test_macos_reports_its_settings():
    with patch.object(mac, "SECTIONS", {"macos_settings": lambda: ({"x": 1}, mac.RAN)}):
        report = ce.collect_compliance_evidence("Darwin")
    assert report["platform"] == "Darwin" and report["sections"] == {
        "macos_settings": {"x": 1}
    }


def test_a_minimum_length_written_only_as_a_pattern_is_read():
    """macOS 15.6.1's default (macbookair, 2026-11-24): no parameter, just
    ``policyAttributePassword matches '^$|.{4,}+'``."""
    text = ACCOUNT_POLICIES.replace(
        "<key>policyParameters</key><dict><key>minimumLength</key><integer>15</integer></dict>",
        "",
    ).replace(
        "policyAttributePassword matches '.{15,}+'",
        "policyAttributePassword matches '^$|.{4,}+'",
    )
    assert mac.parse_account_policies(text)["pwpolicy_account:minimumlength"] == 4


def test_a_plist_followed_by_the_tools_own_status_line_still_parses():
    """``security authorizationdb read`` prints "YES (0)" on stderr after the
    plist; stdout and stderr together failed to parse (macbookair)."""
    out = ACCOUNT_POLICIES + "YES (0)\n"
    assert mac.parse_account_policies(out)["pwpolicy_account:minimumlength"] == 15
    assert mac._plist_text("no plist here") is None  # pylint: disable=protected-access
