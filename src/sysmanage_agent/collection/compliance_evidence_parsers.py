# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Parsers for the compliance evidence collector (server ROADMAP 24.4).

Pure functions, text in and the compliance engine's ``host_data`` shapes out,
so every format is tested without a host.  The shapes are the engine's
(``compliance_engine/checks.pxi``):

* ``ssh_config`` ...... ``{"PermitRootLogin": "no", "MACs": "a,b", ...}`` --
                        the catalog's spelling of each keyword
* ``login_defs`` ...... ``{"PASS_MAX_DAYS": "365", ...}``
* ``kernel_modules`` .. ``{"loaded": [...], "blacklisted": [...]}``
* ``pam_modules`` ..... ``["pam_unix.so", "pam_pwquality.so", ...]``
* ``faillock_config`` . ``{"deny": 3, "unlock_time": 600}``
* ``auditd_config`` ... ``{"max_log_file_action": "rotate", ...}``
* ``audit_rules`` ..... ``["-a always,exit -F path=... -F key=...", ...]``
* ``umask`` ........... ``"027"``
* ``chrony_config`` ... ``{"port": "0", "server": "a,b", ...}``
* ``aide_rules`` ...... ``{"/sbin/auditctl": "p+i+n+u+g+s+b+acl+xattrs+sha512"}``
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

# ``sshd -T`` prints every keyword in lower case; the rule catalog (and
# sshd_config(5)) spells them in CamelCase.  A keyword missing here is kept
# in lower case rather than dropped.
_SSHD_KEYWORDS = (
    "AcceptEnv AddressFamily AllowAgentForwarding AllowGroups "
    "AllowStreamLocalForwarding AllowTcpForwarding AllowUsers "
    "AuthenticationMethods AuthorizedKeysCommand AuthorizedKeysCommandUser "
    "AuthorizedKeysFile AuthorizedPrincipalsCommand "
    "AuthorizedPrincipalsCommandUser AuthorizedPrincipalsFile Banner "
    "CASignatureAlgorithms ChallengeResponseAuthentication ChannelTimeout "
    "ChrootDirectory Ciphers ClientAliveCountMax ClientAliveInterval "
    "Compression DenyGroups DenyUsers DisableForwarding ExposeAuthInfo "
    "FingerprintHash ForceCommand GatewayPorts GSSAPIAuthentication "
    "GSSAPICleanupCredentials GSSAPIStrictAcceptorCheck "
    "HostbasedAcceptedAlgorithms HostbasedAuthentication "
    "HostbasedUsesNameFromPacketOnly HostCertificate HostKey HostKeyAgent "
    "HostKeyAlgorithms IgnoreRhosts IgnoreUserKnownHosts IPQoS "
    "KbdInteractiveAuthentication KerberosAuthentication KerberosGetAFSToken "
    "KerberosOrLocalPasswd KerberosTicketCleanup KexAlgorithms ListenAddress "
    "LoginGraceTime LogLevel LogVerbose MACs MaxAuthTries MaxSessions "
    "MaxStartups ModuliFile PasswordAuthentication PermitEmptyPasswords "
    "PermitListen PermitOpen PermitRootLogin PermitTTY PermitTunnel "
    "PermitUserEnvironment PermitUserRC PerSourceMaxStartups "
    "PerSourceNetBlockSize PidFile Port PrintLastLog PrintMotd Protocol "
    "PubkeyAcceptedAlgorithms PubkeyAuthOptions PubkeyAuthentication "
    "RekeyLimit RequiredRSASize RevokedKeys SecurityKeyProvider SetEnv "
    "StreamLocalBindMask StreamLocalBindUnlink StrictModes Subsystem "
    "SyslogFacility TCPKeepAlive TrustedUserCAKeys UnusedConnectionTimeout "
    "UseDNS UsePAM VersionAddendum X11DisplayOffset X11Forwarding "
    "X11UseLocalhost XAuthLocation"
).split()
_SSHD_NAMES = {name.lower(): name for name in _SSHD_KEYWORDS}

_COMMENT = re.compile(r"^\s*(#|$)")
_LOGIN_DEFS = re.compile(r"^\s*([A-Z_][A-Z0-9_]*)\s+(\S+)")
# Key prefixes only: the value is the rest of the line, stripped.  The old
# ``\s*(.*?)\s*$`` tails backtracked super-linearly (Sonar S5852).
_EQ_SETTING = re.compile(r"\s*([A-Za-z_][\w.-]*)\s*=")
_BARE_FLAG = re.compile(r"^\s*([A-Za-z_]\w*)\s*$")
_BLACKLIST = re.compile(r"^\s*blacklist\s+(\S+)")
_INSTALL_FALSE = re.compile(r"^\s*install\s+(\S+)\s+(?:/usr)?/bin/(?:true|false)\b")
_PAM_MODULE = re.compile(r"(?:^|[\s/])(pam_[\w-]+\.so)\b")
_PAM_ARG = re.compile(r"\b(deny|unlock_time)=(\d+)\b")
_UMASK = re.compile(r"(?:^|[;&|\s])umask\s+(?:-S\s+)?(0?[0-7]{3})\b")
_CHRONY = re.compile(r"\s*([A-Za-z]\w*)")
_AIDE = re.compile(r"^\s*=?(/\S*)\s+(\S+)")
_WORD = re.compile(r"^[A-Za-z_]+$")
# The umask every Linux login inherits when nothing sets one (a umask, not a
# file mode: it REMOVES write for group and other).
DEFAULT_UMASK = "022"


def _lines(text: Optional[str]) -> Iterable[str]:
    for line in (text or "").splitlines():
        if not _COMMENT.match(line):
            yield line


def module_names(name: str) -> List[str]:
    """Both spellings of a kernel module name: the kernel treats ``-`` and
    ``_`` alike (``usb-storage`` is listed as ``usb_storage``)."""
    return sorted({name, name.replace("_", "-"), name.replace("-", "_")})


def parse_sshd_t(text: str) -> Dict[str, str]:
    """``sshd -T`` output: one ``keyword value`` per line, some repeated
    (``hostkey``, ``port``, ``listenaddress``); repeats are joined with ``,``."""
    settings: Dict[str, str] = {}
    for line in _lines(text):
        keyword, _, value = line.strip().partition(" ")
        name = _SSHD_NAMES.get(keyword.lower(), keyword.lower())
        value = value.strip()
        settings[name] = f"{settings[name]},{value}" if name in settings else value
    return settings


def parse_login_defs(texts: Iterable[Optional[str]]) -> Dict[str, str]:
    """``/etc/login.defs`` (then any ``login.defs.d`` drop-ins): the last
    setting of a key wins, as in shadow-utils."""
    settings: Dict[str, str] = {}
    for text in texts:
        for line in _lines(text):
            match = _LOGIN_DEFS.match(line)
            if match:
                settings[match.group(1)] = match.group(2)
    return settings


def parse_eq_conf(text: Optional[str], lower_words: bool = False) -> Dict[str, object]:
    """``key = value`` files (auditd.conf, faillock.conf); a bare word is a
    flag (``even_deny_root``).  auditd reads its keywords case-insensitively
    (``ROTATE`` == ``rotate``): ``lower_words`` lower-cases one-word values."""
    settings: Dict[str, object] = {}
    for line in _lines(text):
        match = _EQ_SETTING.match(line)
        if match:
            value = line[match.end() :].strip()
            if lower_words and _WORD.match(value):
                value = value.lower()
            settings[match.group(1)] = value
            continue
        flag = _BARE_FLAG.match(line)
        if flag:
            settings[flag.group(1)] = True
    return settings


def parse_proc_modules(text: str) -> List[str]:
    """``/proc/modules``: the module name is the first field."""
    names = set()
    for line in (text or "").splitlines():
        fields = line.split()
        if fields:
            names.update(module_names(fields[0]))
    return sorted(names)


def parse_modprobe(texts: Iterable[Optional[str]]) -> List[str]:
    """Modules ``blacklist``-ed or disabled with ``install <m> /bin/false``
    (or ``/bin/true``) in modprobe.d."""
    names = set()
    for text in texts:
        for line in _lines(text):
            match = _BLACKLIST.match(line) or _INSTALL_FALSE.match(line)
            if match:
                names.update(module_names(match.group(1)))
    return sorted(names)


def parse_pam(texts: Iterable[Optional[str]]) -> List[str]:
    """Every PAM module the stacks name (``pam_pwquality.so``...)."""
    names = set()
    for text in texts:
        for line in _lines(text):
            names.update(_PAM_MODULE.findall(line))
    return sorted(names)


def faillock_settings(
    pam_texts: Iterable[Optional[str]], conf_text: Optional[str]
) -> Dict[str, int]:
    """The effective account lockout: ``{}`` when no PAM stack uses
    pam_faillock (nothing locks), else its defaults (deny 3, unlock_time
    600), overridden by faillock.conf, overridden by arguments on the
    pam_faillock lines.  ``unlock_time`` 0 means "never unlock"."""
    lines = [line for text in pam_texts for line in _lines(text)]
    faillock_lines = [line for line in lines if "pam_faillock.so" in line]
    if not faillock_lines:
        return {}
    settings = {"deny": 3, "unlock_time": 600}
    for key, value in parse_eq_conf(conf_text).items():
        if key in settings and isinstance(value, str) and value.isdigit():
            settings[key] = int(value)
    for line in faillock_lines:
        for key, value in _PAM_ARG.findall(line):
            settings[key] = int(value)
    return settings


def weakest_umask(texts: Iterable[Optional[str]], login_defs: Dict[str, str]) -> str:
    """The most permissive default umask any login path sets: login.defs
    ``UMASK`` and every ``umask`` in the shell profiles.  None set: 022, the
    default every Linux login inherits."""
    found = [value for text in texts for value in _UMASK.findall(text or "")]
    if "UMASK" in login_defs:
        found.append(login_defs["UMASK"])
    values = []
    for value in found:
        try:
            values.append(int(value, 8))
        except ValueError:
            continue
    return format(min(values), "03o") if values else DEFAULT_UMASK


def parse_chrony(texts: Iterable[Optional[str]]) -> Dict[str, str]:
    """chrony.conf directives; repeated ones (``server``, ``pool``) joined
    with ``,``.  chrony comments start with ``#``, ``!``, ``;`` or ``%``."""
    settings: Dict[str, str] = {}
    for text in texts:
        for line in (text or "").splitlines():
            if line.lstrip()[:1] in ("#", "!", ";", "%", ""):
                continue
            match = _CHRONY.match(line)
            if match:
                key, value = match.group(1).lower(), line[match.end() :].strip()
                settings[key] = f"{settings[key]},{value}" if key in settings else value
    return settings


def parse_aide(texts: Iterable[Optional[str]]) -> Dict[str, str]:
    """AIDE selection lines (``/path RULE`` or ``=/path RULE``); exclusions
    (``!/path``) select nothing."""
    rules: Dict[str, str] = {}
    for text in texts:
        for line in _lines(text):
            match = _AIDE.match(line)
            if match:
                rules[match.group(1)] = match.group(2)
    return rules


def parse_auditctl(text: str) -> List[str]:
    """``auditctl -l``: one loaded rule per line ("No rules" when none)."""
    return [
        line.strip()
        for line in (text or "").splitlines()
        if line.strip() and line.strip().lower() != "no rules"
    ]
