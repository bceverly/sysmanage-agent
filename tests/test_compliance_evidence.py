# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Compliance evidence (server ROADMAP 24.4): the inputs the benchmark
checks read, in the compliance engine's shapes, collected without root
except through the exact sudo forms the allowlists name."""

import asyncio
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.sysmanage_agent.collection import compliance_evidence as ce
from src.sysmanage_agent.collection import compliance_evidence_parsers as parse
from src.sysmanage_agent.collection.hardware_health_privilege import refused
from src.sysmanage_agent.communication import send_on_change

SSHD_T = """\
port 22
permitrootlogin no
maxauthtries 4
logingracetime 60
banner /etc/issue
macs hmac-sha2-512,hmac-sha2-256
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ed25519_key
someunknownkeyword value
"""


# -- parsers ------------------------------------------------------------------


def test_sshd_t_keywords_take_the_catalogs_spelling():
    parsed = parse.parse_sshd_t(SSHD_T)
    assert parsed["PermitRootLogin"] == "no"
    assert parsed["MaxAuthTries"] == "4"
    assert parsed["MACs"] == "hmac-sha2-512,hmac-sha2-256"
    assert parsed["Banner"] == "/etc/issue"
    # A repeated keyword keeps every value; an unknown one is kept, lowercase.
    assert parsed["HostKey"].count(",") == 1
    assert parsed["someunknownkeyword"] == "value"


def test_login_defs_last_setting_wins_and_comments_are_ignored():
    parsed = parse.parse_login_defs(
        [
            "# PASS_MAX_DAYS 1\nPASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\n",
            "PASS_MAX_DAYS 365\n",
        ]
    )
    assert parsed == {"PASS_MAX_DAYS": "365", "PASS_MIN_DAYS": "0"}


def test_auditd_keywords_are_case_insensitive_but_paths_are_not():
    parsed = parse.parse_eq_conf(
        "max_log_file_action = ROTATE\nlog_file = /var/log/Audit.log\n",
        lower_words=True,
    )
    assert parsed == {"max_log_file_action": "rotate", "log_file": "/var/log/Audit.log"}


def test_module_lists_carry_both_spellings():
    assert "usb-storage" in parse.parse_proc_modules("usb_storage 81920 0 - Live\n")
    disabled = parse.parse_modprobe(
        ["blacklist cramfs\ninstall usb-storage /bin/false\n# blacklist hfs\n"]
    )
    assert {"cramfs", "usb-storage", "usb_storage"} <= set(disabled)
    assert "hfs" not in disabled


def test_pam_modules_are_found_in_bracketed_and_pathed_lines():
    text = (
        "password [success=1 default=ignore] pam_unix.so obscure\n"
        "password requisite /usr/lib/security/pam_pwquality.so retry=3\n"
        "# password required pam_cracklib.so\n"
    )
    assert parse.parse_pam([text]) == ["pam_pwquality.so", "pam_unix.so"]


def test_no_pam_faillock_means_nothing_locks():
    assert parse.faillock_settings(["auth required pam_unix.so\n"], "deny = 5\n") == {}


def test_faillock_defaults_then_conf_then_pam_arguments():
    pam = ["auth required pam_faillock.so preauth\n"]
    assert parse.faillock_settings(pam, None) == {"deny": 3, "unlock_time": 600}
    assert parse.faillock_settings(pam, "deny = 5\nunlock_time = 900\n") == {
        "deny": 5,
        "unlock_time": 900,
    }
    pam = ["auth required pam_faillock.so authfail deny=4 unlock_time=0\n"]
    assert parse.faillock_settings(pam, "deny = 5\n") == {"deny": 4, "unlock_time": 0}


def test_the_weakest_umask_any_login_path_sets_is_reported():
    assert (
        parse.weakest_umask(["umask 027\n", "if x; then umask 002; fi\n"], {}) == "002"
    )
    assert parse.weakest_umask([], {"UMASK": "077"}) == "077"
    assert parse.weakest_umask([], {}) == "022"


def test_chrony_and_aide_and_auditctl():
    chrony = parse.parse_chrony(["! comment\npool a.example\npool b.example\nport 0\n"])
    assert chrony == {"pool": "a.example,b.example", "port": "0"}
    aide = parse.parse_aide(["/sbin/auditctl p+i+n\n=/etc CONTENT\n!/var/log\n"])
    assert aide == {"/sbin/auditctl": "p+i+n", "/etc": "CONTENT"}
    assert parse.parse_auditctl("No rules\n") == []
    assert parse.parse_auditctl("-w /etc/sudoers -p wa -k scope\n") == [
        "-w /etc/sudoers -p wa -k scope"
    ]


# -- collector ------------------------------------------------------------------


class FakeHost:
    """Files, commands and modes the collector's seams read."""

    def __init__(self, files=None, commands=None, modes=None, root=False, dirs=()):
        self.files = files or {}
        self.commands = commands or {}
        self.modes = modes or {}
        self.root = root
        self.dirs = set(dirs)
        self.ran = []

    def read(self, path):
        value = self.files.get(path)
        if value is PermissionError:
            return None, ce.NOT_PRIVILEGED
        return (value, ce.RAN) if value is not None else (None, ce.ABSENT)

    def run(self, argv):
        self.ran.append(argv)
        return self.commands.get(tuple(argv), (-1, ""))

    def glob(self, pattern):
        prefix = pattern.rstrip("*")
        return sorted(p for p in self.files if p.startswith(prefix) and p != prefix)

    def stat(self, path):
        if path not in self.modes:
            raise FileNotFoundError(path)
        return SimpleNamespace(
            st_mode=stat.S_IFREG | self.modes[path], st_uid=0, st_gid=0
        )


@pytest.fixture
def host(monkeypatch):
    fake = FakeHost()
    monkeypatch.setattr(ce, "_read", fake.read)
    monkeypatch.setattr(ce, "_run", fake.run)
    monkeypatch.setattr(ce, "_glob", fake.glob)
    monkeypatch.setattr(ce, "_stat", fake.stat)
    monkeypatch.setattr(ce, "_root", lambda: fake.root)
    monkeypatch.setattr(ce, "_isdir", lambda path: path in fake.dirs)
    monkeypatch.setattr(ce, "_tool", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(ce.shutil, "which", lambda name: f"/usr/bin/{name}")
    return fake


def test_sshd_t_goes_through_sudo_when_not_root(host):
    host.commands[("sudo", "-n", "/usr/sbin/sshd", "-T")] = (0, SSHD_T)
    value, status = ce.ssh_config()
    assert status == ce.RAN and value["PermitRootLogin"] == "no"


def test_a_refused_sudo_is_not_collected_never_empty(host):
    host.commands[("sudo", "-n", "/usr/sbin/sshd", "-T")] = (
        1,
        "sudo: interactive authentication is required\n",
    )
    assert ce.ssh_config() == (None, ce.NOT_PRIVILEGED)


def test_root_runs_sshd_t_directly(host):
    host.root = True
    host.commands[("/usr/sbin/sshd", "-T")] = (0, SSHD_T)
    assert ce.ssh_config()[1] == ce.RAN
    assert host.ran == [["/usr/sbin/sshd", "-T"]]


def test_no_sshd_installed_means_no_ssh_evidence(host, monkeypatch):
    monkeypatch.setattr(ce, "_tool", lambda name: name)
    assert ce.ssh_config() == (None, ce.ABSENT)


def test_root_only_auditd_conf_is_read_with_sudo_cat(host):
    host.files[ce.AUDITD_CONF] = PermissionError
    host.commands[("sudo", "-n", "/usr/sbin/cat", ce.AUDITD_CONF)] = (
        0,
        "max_log_file_action = ROTATE\n",
    )
    assert ce.auditd_config() == ({"max_log_file_action": "rotate"}, ce.RAN)


def test_no_auditd_is_nothing_configured(host):
    assert ce.auditd_config() == ({}, ce.RAN)


def test_auditd_conf_behind_a_refused_sudo_is_not_collected(host):
    host.files[ce.AUDITD_CONF] = PermissionError
    host.commands[("sudo", "-n", "/usr/sbin/cat", ce.AUDITD_CONF)] = (
        1,
        "sudo: a password is required\n",
    )
    assert ce.auditd_config() == (None, ce.NOT_PRIVILEGED)


def test_sysctl_reads_only_what_proc_has(host):
    host.files["/proc/sys/net/ipv4/ip_forward"] = "0\n"
    value, status = ce.sysctl()
    assert status == ce.RAN and value == {"net.ipv4.ip_forward": "0"}


def test_file_modes_and_the_grub2_alias(host):
    host.modes = {"/etc/shadow": 0o640, "/boot/grub2/grub.cfg": 0o600}
    value, _ = ce.file_permissions()
    assert value["/etc/shadow"]["mode"] == "0640"
    assert value["/boot/grub/grub.cfg"] == {
        "mode": "0600", "uid": 0, "gid": 0, "path": "/boot/grub2/grub.cfg"
    }  # fmt: skip
    assert "/etc/gshadow" not in value  # absent: the rule says "file not found"


def test_services_take_the_first_unit_that_exists(host):
    host.commands[("/usr/sbin/systemctl", "is-enabled", "cron.service")] = (
        4,
        "not-found\n",
    )
    host.commands[("/usr/sbin/systemctl", "is-enabled", "crond.service")] = (
        0,
        "enabled\n",
    )
    host.commands[("/usr/sbin/systemctl", "is-enabled", "auditd.service")] = (
        1,
        "disabled\n",
    )
    value, _ = ce.services()
    assert value["cron"] == {"enabled": True, "unit": "crond"}
    assert value["auditd"]["enabled"] is False
    assert "rsyslog" not in value


def test_pam_and_faillock_and_login_defs_and_umask(host):
    host.dirs = {"/etc/pam.d"}
    host.files.update({
        "/etc/pam.d/common-auth": "auth required pam_faillock.so preauth deny=5\n",
        "/etc/pam.d/common-password": "password requisite pam_pwquality.so\n",
        "/etc/login.defs": "PASS_MAX_DAYS 90\nUMASK 027\n",
        "/etc/profile": "umask 022\n",
    })  # fmt: skip
    assert "pam_pwquality.so" in ce.pam_modules()[0]
    assert ce.faillock_config()[0] == {"deny": 5, "unlock_time": 600}
    assert ce.login_defs()[0]["PASS_MAX_DAYS"] == "90"
    assert ce.umask()[0] == "022"


def test_no_pam_directory_is_not_collected(host):
    assert ce.pam_modules() == (None, ce.ABSENT)
    assert ce.faillock_config() == (None, ce.ABSENT)


def test_fips_flag(host):
    assert ce.fips_enabled() == (False, ce.RAN)  # no FIPS support at all
    host.files[ce.FIPS_FLAG] = "1\n"
    assert ce.fips_enabled() == (True, ce.RAN)


def test_no_chrony_is_not_collected_but_no_aide_is_no_rules(host):
    assert ce.chrony_config() == (None, ce.ABSENT)
    assert ce.aide_rules() == ({}, ce.RAN)


def test_a_root_only_aide_conf_that_sudo_refuses_is_not_collected(host):
    host.files["/etc/aide.conf"] = PermissionError
    host.commands[("sudo", "-n", "/usr/sbin/cat", "/etc/aide.conf")] = (
        1,
        "sudo: a password is required\n",
    )
    assert ce.aide_rules() == (None, ce.NOT_PRIVILEGED)


def test_no_audit_tools_means_no_rules_loaded(host, monkeypatch):
    monkeypatch.setattr(ce, "_tool", lambda name: name)
    assert ce.audit_rules() == ([], ce.RAN)


def test_one_failing_section_does_not_lose_the_rest(host, monkeypatch):
    def boom():
        raise RuntimeError("broken")

    monkeypatch.setitem(ce.SECTIONS, "sysctl", boom)
    report = ce.collect_compliance_evidence("Linux")
    assert report["sections"]["sysctl"] is None
    assert report["sources"]["sysctl"] == ce.FAILED
    assert set(report["sections"]) == set(ce.SECTIONS)
    assert report["platform"] == "Linux"


def test_nothing_is_collected_off_linux():
    assert ce.collect_compliance_evidence("FreeBSD") is None
    assert ce.collect_compliance_evidence("Windows") is None


def test_newer_sudo_refusal_wording_is_recognized():
    assert refused("sudo: interactive authentication is required")


# -- sending --------------------------------------------------------------------


def test_compliance_evidence_is_a_send_on_change_snapshot():
    assert "compliance_evidence_update" in send_on_change.SNAPSHOT_TYPES
    first = {"message_type": "compliance_evidence_update",
             "data": {"sections": {"umask": "022"}, "collected_at": "a"}}  # fmt: skip
    again = {"message_type": "compliance_evidence_update",
             "data": {"sections": {"umask": "022"}, "collected_at": "b"}}  # fmt: skip
    assert send_on_change.digest(first) == send_on_change.digest(again)


def _sender(payload):
    from src.sysmanage_agent.communication.data_collector_senders import (  # pylint: disable=import-outside-toplevel
        DataCollectorSendersMixin,
    )

    sender = DataCollectorSendersMixin.__new__(DataCollectorSendersMixin)
    sender.logger = MagicMock()
    sender.agent = MagicMock()
    sender.agent.registration_manager.get_host_approval_from_db.return_value = (
        SimpleNamespace(host_id="h1")
    )
    sender.agent.create_message.side_effect = lambda kind, data: {
        "message_type": kind, "data": data
    }  # fmt: skip
    sender.agent.send_message = AsyncMock(return_value=True)
    return sender


def test_the_sender_sends_the_report_with_the_host_id(monkeypatch):
    from src.sysmanage_agent.communication import (  # pylint: disable=import-outside-toplevel
        data_collector_senders as senders,
    )

    monkeypatch.setattr(
        senders, "collect_compliance_evidence", lambda: {"sections": {}}
    )
    sender = _sender(None)
    asyncio.run(
        sender._send_compliance_evidence_update()
    )  # pylint: disable=protected-access
    sent = sender.agent.send_message.await_args.args[0]
    assert sent["message_type"] == "compliance_evidence_update"
    assert sent["data"]["host_id"] == "h1"


def test_the_sender_sends_nothing_off_linux(monkeypatch):
    from src.sysmanage_agent.communication import (  # pylint: disable=import-outside-toplevel
        data_collector_senders as senders,
    )

    monkeypatch.setattr(senders, "collect_compliance_evidence", lambda: None)
    sender = _sender(None)
    asyncio.run(
        sender._send_compliance_evidence_update()
    )  # pylint: disable=protected-access
    sender.agent.send_message.assert_not_awaited()


# -- sudoers ----------------------------------------------------------------------


@pytest.mark.parametrize("distro", ["ubuntu", "centos", "opensuse"])
def test_every_linux_sudoers_allows_exactly_the_compliance_reads(distro):
    text = Path(f"installer/{distro}/sysmanage-agent.sudoers").read_text(
        encoding="utf-8"
    )
    assert "NOPASSWD: SYSMANAGE_COMPLIANCE_READ" in text
    for form in (
        "/usr/sbin/sshd -T",
        "/usr/sbin/auditctl -l",
        "/usr/bin/cat /etc/audit/auditd.conf",
        "/usr/bin/cat /etc/aide.conf",
    ):
        assert form in text
    assert "sshd -T *" not in text and "auditctl *" not in text  # exact forms only


def test_the_real_reader_reports_absent_and_unreadable(tmp_path):
    present = tmp_path / "f"
    present.write_text("x", encoding="utf-8")
    assert ce._read(str(present)) == ("x", ce.RAN)  # pylint: disable=protected-access
    assert (
        ce._read(str(tmp_path / "missing"))[1] == ce.ABSENT
    )  # pylint: disable=protected-access
    if os.name == "posix" and os.geteuid() != 0:
        present.chmod(0)
        assert (
            ce._read(str(present))[1] == ce.NOT_PRIVILEGED
        )  # pylint: disable=protected-access
