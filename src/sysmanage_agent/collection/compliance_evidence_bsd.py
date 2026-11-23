# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Compliance evidence on FreeBSD, OpenBSD and NetBSD (2026-11-23).

CIS and DISA publish no benchmark for the BSDs; the server's SysManage BSD
baseline carries over the controls that have a BSD form.  This reads what
it checks, in two sections:

``ssh_config``    the effective sshd settings (``sshd -T``), as on Linux.
                  sshd -T needs root (it loads the host keys): through
                  ``sudo -n`` on FreeBSD and NetBSD, ``doas -n`` on OpenBSD,
                  each allowlisted for exactly ``/usr/sbin/sshd -T``.
``bsd_settings``  a flat map: ``sysctl:<name>``, ``rc:<variable>`` (FreeBSD
                  and NetBSD rc.conf with its defaults), ``service:<name>``
                  and ``flags:<name>`` (OpenBSD rcctl), ``file_mode:<path>``
                  ("0644") and ``file_owner:<path>`` (a uid), and named
                  facts (``uid0_other_accounts``, ``pf_running``, the
                  password hashing in login.conf / passwd.conf).

Everything but sshd -T and OpenBSD's ``pfctl -s info`` is world-readable.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import stat
import subprocess  # nosec B404 -- fixed argv, no shell
from typing import Any, Dict, List, Optional, Tuple

from src.sysmanage_agent.collection import compliance_evidence_parsers as parse

logger = logging.getLogger(__name__)

RAN = "ran"
ABSENT = "absent"
NOT_PRIVILEGED = "not_privileged"
FAILED = "failed"
_TIMEOUT = 30

SYSCTLS = {
    "FreeBSD": (
        "kern.securelevel", "security.bsd.see_other_uids", "security.bsd.see_other_gids",
        "security.bsd.see_jail_proc", "security.bsd.unprivileged_read_msgbuf",
        "security.bsd.unprivileged_proc_debug", "security.bsd.hardlink_check_uid",
        "security.bsd.hardlink_check_gid", "kern.randompid", "kern.elf64.aslr.enable",
        "net.inet.ip.forwarding", "net.inet6.ip6.forwarding", "net.inet.ip.redirect",
        "net.inet.ip.sourceroute", "net.inet.ip.accept_sourceroute",
        "net.inet.icmp.drop_redirect", "net.inet.tcp.blackhole", "net.inet.udp.blackhole",
        "net.inet.ip.random_id",
    ),
    "OpenBSD": (
        "kern.securelevel", "kern.allowkmem", "kern.nosuidcoredump", "ddb.panic",
        "machdep.allowaperture", "hw.smt", "kern.audio.record", "kern.video.record",
        "net.inet.ip.forwarding", "net.inet6.ip6.forwarding", "net.inet.ip.redirect",
        "net.inet.icmp.rediraccept", "net.inet.ip.sourceroute",
    ),
    "NetBSD": (
        "kern.securelevel", "security.pax.aslr.global", "security.pax.mprotect.global",
        "security.curtain", "net.inet.ip.forwarding", "net.inet6.ip6.forwarding",
        "net.inet.ip.redirect", "net.inet.ip.allowsrcrt", "net.inet.ip.forwsrcrt",
        "net.inet.icmp.rediraccept",
    ),
}  # fmt: skip

FILES = (
    "/etc/master.passwd", "/etc/spwd.db", "/etc/passwd", "/etc/group",
    "/etc/ssh/sshd_config", "/etc/crontab", "/etc/rc.conf", "/etc/login.conf",
)  # fmt: skip

OPENBSD_SERVICES = ("ntpd", "syslogd", "inetd", "pf", "sshd")

Section = Tuple[Optional[Any], str]


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for directory in (
        "/sbin",
        "/usr/sbin",
        "/usr/bin",
        "/bin",
        "/usr/pkg/bin",
        "/usr/local/bin",
    ):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return name


def _run(argv: List[str]) -> Tuple[int, str]:
    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv
            argv, capture_output=True, text=True, timeout=_TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _privileged(argv: List[str]) -> Tuple[Optional[str], str]:
    """A root-only read: directly as root, else ``sudo -n`` or ``doas -n``."""
    if os.geteuid() == 0:
        code, out = _run(argv)
    else:
        escalate = next((t for t in ("sudo", "doas") if shutil.which(t)), None)
        if escalate is None:
            return None, NOT_PRIVILEGED
        code, out = _run([escalate, "-n", *argv])
        lowered = out.lower()
        if (
            code != 0
            and lowered.startswith(("sudo", "doas"))
            and any(
                word in lowered for word in ("password", "not permitted", "not allowed",
                                         "authorization required", "may not run")  # fmt: skip
            )
        ):
            return None, NOT_PRIVILEGED
    return (out, RAN) if code == 0 else (None, FAILED)


def ssh_config() -> Section:
    sshd = _tool("sshd")
    if not os.path.isabs(sshd):
        return None, ABSENT
    out, status = _privileged([sshd, "-T"])
    return (parse.parse_sshd_t(out), RAN) if status == RAN else (None, status)


def parse_rc_conf(texts: List[str]) -> Dict[str, str]:
    """Shell ``name=value`` assignments, later files winning (defaults first)."""
    found: Dict[str, str] = {}
    for text in texts:
        for raw in text.splitlines():
            # NetBSD's defaults set several per line: syslogd=YES  syslogd_flags="-s"
            line = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0]
            if re.match(r"\s*(if|then|else|fi|case|esac|for|do|done)\b", line):
                continue
            for m in re.finditer(
                r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s;]*)", line
            ):
                found[m.group(1)] = m.group(2).strip("\"'")
    return found


def parse_sysrc(text: str) -> Dict[str, str]:
    """``sysrc -A``: ``name: value`` per line."""
    found = {}
    for line in text.splitlines():
        name, sep, value = line.partition(": ")
        if sep and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            found[name] = value.strip()
    return found


def login_class(text: str, name: str = "default") -> Dict[str, str]:
    """One login.conf class's capabilities (continuation lines joined)."""
    joined = re.sub(r"\\\n\s*", "", text)
    for entry in joined.splitlines():
        names = entry.split(":", 1)[0].split("|")
        if entry and not entry.startswith("#") and name in names:
            caps = {}
            for cap in entry.split(":")[1:]:
                key, _, value = cap.strip().partition("=")
                if key:
                    caps[key] = value
            return caps
    return {}


def uid0_others(passwd: str) -> int:
    """UID 0 accounts besides root (and FreeBSD's disabled ``toor``)."""
    count = 0
    for line in passwd.splitlines():
        fields = line.split(":")
        if len(fields) > 2 and fields[2] == "0" and fields[0] not in ("root", "toor"):
            count += 1
    return count


def _read(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _sysctls(system: str, found: Dict[str, Any]) -> None:
    sysctl = _tool("sysctl")
    for name in SYSCTLS.get(system, ()):
        code, out = _run([sysctl, "-n", name])
        value = out.strip()
        if code == 0 and value:
            found["sysctl:" + name] = (
                int(value) if re.fullmatch(r"-?\d+", value) else value
            )


def _rc(system: str, found: Dict[str, Any]) -> None:
    if system == "FreeBSD":
        code, out = _run([_tool("sysrc"), "-A"])
        values = parse_sysrc(out) if code == 0 else {}
    elif system == "NetBSD":
        values = parse_rc_conf([t for t in (_read("/etc/defaults/rc.conf"),
                                            _read("/etc/rc.conf")) if t])  # fmt: skip
    else:
        values = {}
        code, out = _run([_tool("rcctl"), "ls", "on"])
        if code == 0:
            enabled = set(out.split())
            for name in OPENBSD_SERVICES:
                found["service:" + name] = name in enabled
        code, out = _run([_tool("rcctl"), "get", "syslogd", "flags"])
        if code == 0:
            found["flags:syslogd"] = out.strip()
    for name, value in values.items():
        found["rc:" + name.lower()] = value


def _files(found: Dict[str, Any]) -> None:
    for path in FILES:
        try:
            info = os.stat(path)
        except OSError:
            continue
        found["file_mode:" + path] = format(stat.S_IMODE(info.st_mode), "04o")
        found["file_owner:" + path] = info.st_uid
    passwd = _read("/etc/passwd")
    if passwd is not None:
        found["uid0_other_accounts"] = uid0_others(passwd)


def _passwords(system: str, found: Dict[str, Any]) -> None:
    conf = _read("/etc/login.conf")
    if conf is not None and system in ("FreeBSD", "OpenBSD"):
        caps = login_class(conf)
        for cap in ("passwd_format", "localcipher", "minpasswordlen", "passwordtime"):
            if cap in caps:
                found["login_conf:" + cap] = caps[cap]
    if system == "NetBSD":
        text = _read("/etc/passwd.conf") or ""
        m = re.search(r"^\s*localcipher\s*=\s*(\S+)", text, re.M)
        if m:
            found["passwd_conf:localcipher"] = m.group(1)


def _firewall(system: str, found: Dict[str, Any]) -> None:
    if system != "OpenBSD":
        return
    out, status = _privileged([_tool("pfctl"), "-s", "info"])
    if status == RAN and out:
        found["pf_running"] = "Status: Enabled" in out


def bsd_settings(system: Optional[str] = None) -> Section:
    system = system or platform.system()
    found: Dict[str, Any] = {}
    for collect in (_sysctls, _rc, _passwords, _firewall):
        try:
            collect(system, found)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("BSD compliance facts: %s failed: %s", collect.__name__, exc)
    try:
        _files(found)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.debug("BSD compliance facts: files failed: %s", exc)
    return (found, RAN) if found else (None, FAILED)


SECTIONS = {"ssh_config": ssh_config, "bsd_settings": bsd_settings}
