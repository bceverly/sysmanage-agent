# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Compliance evidence (server ROADMAP 24.4): what the benchmark checks read.

THE DEFECT THIS FIXES
---------------------
The server's compliance scan judged every host against EMPTY sshd, sysctl,
PAM, auditd... data -- nothing collected it -- so every host scored the same
and setting ``PermitRootLogin no`` could not change its result (2026-10-18).
This collects each input the rule catalog reads, in the engine's shapes
(``compliance_evidence_parsers``), and the server hands it to the scan.

WHAT IS SENT
------------
``{"platform", "sections": {name: value-or-None}, "sources": {name: status}}``.
A section is ``None`` when this host could not answer it -- the read needs
root and the sudo allowlist refused it (``not_privileged``), the tool failed
-- and the server then scores its rules "not applicable (not collected)",
never "fail".  A section that answered "nothing" is real evidence: no
pam_faillock line is ``{}`` (nothing locks accounts), no auditd is ``{}``.

PRIVILEGE
---------
A packaged agent runs as the unprivileged ``sysmanage-agent`` user.  Only
three reads need root, and the sudoers allowlists name exactly these forms:
``sshd -T`` (it loads the host keys), ``auditctl -l``, and ``cat`` of
``/etc/audit/auditd.conf`` and ``/etc/aide.conf``.  Everything else -- the
login.defs, PAM, modprobe and chrony files, /proc, ``stat`` of the catalog's
paths, ``systemctl is-enabled`` -- is world-readable and read directly.

Linux only in this slice: elsewhere nothing is sent and every rule stays
"not collected".
"""

from __future__ import annotations

import glob
import logging
import os
import platform
import shutil
import stat
import subprocess  # nosec B404 -- fixed argv, no shell
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.sysmanage_agent.collection import compliance_evidence_parsers as parse
from src.sysmanage_agent.collection.hardware_health_privilege import is_root, refused
from src.sysmanage_agent.collection.hardware_identity import _tool

logger = logging.getLogger(__name__)

RAN = "ran"
ABSENT = "absent"
NOT_PRIVILEGED = "not_privileged"
FAILED = "failed"
_TIMEOUT = 30

# The sysctl keys the rule catalog checks, plus the rest of the CIS network
# and kernel set, so a custom rule on one of them has evidence too.
SYSCTL_KEYS = (
    "fs.suid_dumpable",
    "kernel.randomize_va_space",
    "kernel.dmesg_restrict",
    "kernel.kptr_restrict",
    "kernel.yama.ptrace_scope",
    "net.ipv4.ip_forward",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.secure_redirects",
    "net.ipv4.conf.default.secure_redirects",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.conf.default.log_martians",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.default.accept_ra",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.default.accept_redirects",
    "net.ipv6.conf.all.forwarding",
)

# The catalog's paths (and the rest of the CIS file set).
FILE_PATHS = (
    "/boot/grub/grub.cfg",
    "/var/log",
    "/etc/crontab",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/cron.d",
    "/etc/ssh/sshd_config",
    "/etc/passwd",
    "/etc/passwd-",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/group",
    "/etc/group-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/issue",
    "/etc/issue.net",
    "/etc/motd",
)
# Where non-Debian distributions keep the file a catalog path names.
_PATH_ALIASES = {"/boot/grub/grub.cfg": ("/boot/grub2/grub.cfg",)}

# The services a rule may require, and each one's unit names across distros.
SERVICE_UNITS = {
    "cron": ("cron", "crond", "cronie"),
    "auditd": ("auditd",),
    "chrony": ("chronyd", "chrony"),
    "rsyslog": ("rsyslog",),
    "sshd": ("ssh", "sshd"),
    "apparmor": ("apparmor",),
    "firewalld": ("firewalld",),
    "ufw": ("ufw",),
}
_ENABLED = frozenset({"enabled", "enabled-runtime", "alias"})
_NOT_ENABLED = frozenset(
    {"disabled", "masked", "masked-runtime", "static", "indirect", "linked",
     "linked-runtime", "generated", "transient"}
)  # fmt: skip

_PROFILES = ("/etc/profile", "/etc/bash.bashrc", "/etc/bashrc")
_LOGIN_DEFS = ("/etc/login.defs", "/usr/etc/login.defs")
_PAM_DIRS = ("/etc/pam.d", "/usr/lib/pam.d", "/usr/etc/pam.d")
_MODPROBE_GLOBS = (
    "/etc/modprobe.d/*.conf",
    "/run/modprobe.d/*.conf",
    "/usr/lib/modprobe.d/*.conf",
    "/lib/modprobe.d/*.conf",
)
_CHRONY_FILES = ("/etc/chrony/chrony.conf", "/etc/chrony.conf")
_CHRONY_GLOBS = ("/etc/chrony/conf.d/*.conf", "/etc/chrony.d/*.conf")
_AIDE_FILES = ("/etc/aide/aide.conf", "/etc/aide.conf")
_AIDE_GLOBS = ("/etc/aide/aide.conf.d/*",)
AUDITD_CONF = "/etc/audit/auditd.conf"
FAILLOCK_CONF = "/etc/security/faillock.conf"
FIPS_FLAG = "/proc/sys/crypto/fips_enabled"

Section = Tuple[Any, str]  # (value or None, source status)


# -- input/output seams (tests replace these) ---------------------------------


def _read(path: str) -> Tuple[Optional[str], str]:
    """A file's text and RAN, or None and ABSENT / NOT_PRIVILEGED / FAILED."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(), RAN
    except FileNotFoundError:
        return None, ABSENT
    except PermissionError:
        return None, NOT_PRIVILEGED
    except OSError:
        return None, FAILED


def _run(argv: List[str]) -> Tuple[int, str]:
    """``(returncode, stdout + stderr)``; -1 when it could not run at all."""
    try:
        result = subprocess.run(  # nosec B603 -- fixed argv, no shell
            argv, capture_output=True, text=True, timeout=_TIMEOUT, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("compliance evidence: %s failed: %s", argv[0], exc)
        return -1, ""
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _glob(pattern: str) -> List[str]:
    return sorted(glob.glob(pattern))


def _stat(path: str):
    return os.stat(path)


def _root() -> bool:
    return is_root()


def _isdir(path: str) -> bool:
    return os.path.isdir(path)


# -- privileged reads ---------------------------------------------------------


def _privileged(argv: List[str]) -> Tuple[Optional[str], str]:
    """Run a root-only read, through ``sudo -n`` when not root."""
    if _root():
        rc, out = _run(argv)
    elif not shutil.which("sudo"):
        return None, NOT_PRIVILEGED
    else:
        rc, out = _run(["sudo", "-n", *argv])
        if rc != 0 and refused(out):
            return None, NOT_PRIVILEGED
    if rc == 0:
        return out, RAN
    if "no such file" in out.lower():
        return None, ABSENT
    return None, FAILED


def _root_read(path: str) -> Tuple[Optional[str], str]:
    """A file that may be root-only: read directly, else ``sudo -n cat``."""
    text, status = _read(path)
    if status != NOT_PRIVILEGED:
        return text, status
    cat = _tool("cat")
    if not os.path.isabs(cat):
        return None, NOT_PRIVILEGED
    return _privileged([cat, path])


def _texts(paths) -> List[str]:
    return [text for text, status in map(_read, paths) if status == RAN and text]


def _glob_texts(patterns) -> List[str]:
    return _texts([path for pattern in patterns for path in _glob(pattern)])


# -- sections -------------------------------------------------------------------


def ssh_config() -> Section:
    """The EFFECTIVE sshd settings (``sshd -T``, includes and defaults
    resolved), not a grep of sshd_config.  No sshd: no SSH rules apply."""
    sshd = _tool("sshd")
    if not os.path.isabs(sshd):
        return None, ABSENT
    out, status = _privileged([sshd, "-T"])
    return (parse.parse_sshd_t(out), RAN) if status == RAN else (None, status)


def sysctl() -> Section:
    values = {}
    for key in SYSCTL_KEYS:
        text, status = _read("/proc/sys/" + key.replace(".", "/"))
        if status == RAN and text is not None:
            values[key] = " ".join(text.split())
    return (values, RAN) if values else (None, FAILED)


def kernel_modules() -> Section:
    text, status = _read("/proc/modules")
    if status in (NOT_PRIVILEGED, FAILED):
        return None, status
    blacklisted = parse.parse_modprobe(_glob_texts(_MODPROBE_GLOBS))
    loaded = parse.parse_proc_modules(text or "")  # no /proc/modules: none loadable
    return {"loaded": loaded, "blacklisted": blacklisted}, RAN


def _mode(path: str) -> Optional[Dict[str, Any]]:
    try:
        info = _stat(path)
    except OSError:
        return None  # absent or not stat-able: the rule says "file not found"
    return {"mode": format(stat.S_IMODE(info.st_mode), "04o"),
            "uid": info.st_uid, "gid": info.st_gid}  # fmt: skip


def file_permissions() -> Section:
    modes = {}
    for path in FILE_PATHS:
        found = _mode(path)
        for alias in _PATH_ALIASES.get(path, ()) if found is None else ():
            found = _mode(alias)
            if found is not None:
                found["path"] = alias
                break
        if found is not None:
            modes[path] = found
    return modes, RAN


def _unit_state(systemctl: str, unit: str) -> Optional[str]:
    _rc, out = _run([systemctl, "is-enabled", unit + ".service"])
    state = (out.strip().splitlines() or [""])[0].strip()
    return state if state in _ENABLED or state in _NOT_ENABLED else None


def services() -> Section:
    """``{"cron": {"enabled": True}, ...}`` for the services found; a
    service with no unit at all is left out ("service not found")."""
    systemctl = _tool("systemctl")
    if not os.path.isabs(systemctl):
        return None, ABSENT  # not systemd (OpenRC, runit): not collected yet
    found = {}
    for name, units in SERVICE_UNITS.items():
        for unit in units:
            state = _unit_state(systemctl, unit)
            if state is not None:
                found[name] = {"enabled": state in _ENABLED, "unit": unit}
                break
    return found, RAN


def fips_enabled() -> Section:
    text, status = _read(FIPS_FLAG)
    if status == ABSENT:
        return False, RAN  # the kernel offers no FIPS mode: not enabled
    if status != RAN:
        return None, status
    return (text or "").strip() == "1", RAN


def _login_defs_texts() -> List[str]:
    """/etc/login.defs, else the vendor copy (openSUSE: /usr/etc), then any
    drop-ins."""
    base = _texts(_LOGIN_DEFS[:1]) or _texts(_LOGIN_DEFS[1:])
    return base + _glob_texts(("/etc/login.defs.d/*.defs",))


def login_defs() -> Section:
    texts = _login_defs_texts()
    return (parse.parse_login_defs(texts), RAN) if texts else (None, ABSENT)


def umask() -> Section:
    profiles = _texts(_PROFILES) + _glob_texts(("/etc/profile.d/*.sh",))
    defs_texts = _login_defs_texts()
    if not profiles and not defs_texts:
        return None, ABSENT
    return parse.weakest_umask(profiles, parse.parse_login_defs(defs_texts)), RAN


def _pam_texts() -> Optional[List[str]]:
    dirs = [d for d in _PAM_DIRS if _isdir(d)]
    if not dirs:
        return None
    return _texts([p for d in dirs for p in _glob(os.path.join(d, "*"))])


def pam_modules() -> Section:
    texts = _pam_texts()
    return (None, ABSENT) if texts is None else (parse.parse_pam(texts), RAN)


def faillock_config() -> Section:
    texts = _pam_texts()
    if texts is None:
        return None, ABSENT
    conf, _status = _read(FAILLOCK_CONF)
    return parse.faillock_settings(texts, conf), RAN


def auditd_config() -> Section:
    text, status = _root_read(AUDITD_CONF)
    if status == ABSENT:
        return {}, RAN  # no auditd: nothing is configured
    if status != RAN:
        return None, status
    return parse.parse_eq_conf(text, lower_words=True), RAN


def audit_rules() -> Section:
    auditctl = _tool("auditctl")
    if not os.path.isabs(auditctl):
        return [], RAN  # no audit tools: no rules are loaded
    out, status = _privileged([auditctl, "-l"])
    return (parse.parse_auditctl(out), RAN) if status == RAN else (None, status)


def chrony_config() -> Section:
    texts = _texts(_CHRONY_FILES) + _glob_texts(_CHRONY_GLOBS)
    return (parse.parse_chrony(texts), RAN) if texts else (None, ABSENT)


def aide_rules() -> Section:
    texts, refusals = [], 0
    for path in _AIDE_FILES:
        text, status = _root_read(path)
        if status == RAN and text:
            texts.append(text)
        refusals += status == NOT_PRIVILEGED
    texts += _glob_texts(_AIDE_GLOBS)
    if not texts and refusals:
        return None, NOT_PRIVILEGED
    return parse.parse_aide(texts), RAN  # no AIDE configuration: no rules


SECTIONS: Dict[str, Callable[[], Section]] = {
    "ssh_config": ssh_config,
    "sysctl": sysctl,
    "kernel_modules": kernel_modules,
    "file_permissions": file_permissions,
    "services": services,
    "fips_enabled": fips_enabled,
    "login_defs": login_defs,
    "umask": umask,
    "pam_modules": pam_modules,
    "faillock_config": faillock_config,
    "auditd_config": auditd_config,
    "audit_rules": audit_rules,
    "chrony_config": chrony_config,
    "aide_rules": aide_rules,
}


def _one(name: str, collect: Callable[[], Section]) -> Section:
    try:
        return collect()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.debug("compliance evidence: %s failed: %s", name, exc)
        return None, FAILED


def collect_compliance_evidence(
    system: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """The report, or None on an OS this slice does not collect for."""
    if (system or platform.system()) != "Linux":
        return None
    sections, sources = {}, {}
    for name, collect in SECTIONS.items():
        sections[name], sources[name] = _one(name, collect)
    return {
        "platform": "Linux",
        "sections": sections,
        "sources": sources,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
