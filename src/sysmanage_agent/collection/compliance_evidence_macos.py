# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Compliance evidence on macOS (2026-11-23): what the CIS Apple macOS 15
Sequoia benchmark reads, as one flat ``macos_settings`` map.

FACT NAMES (lower-case)
-----------------------
``pref:<domain>/<key>``  a preference as the system resolves it for the
                         agent (root): a configuration profile's managed
                         value first, then ``/Library/Preferences``.  Read
                         in one ``osascript`` call through NSUserDefaults,
                         exactly as the benchmark's audit does.
``launchd:<label>``      True when the job is loaded (``launchctl list``).
everything else          one named fact per command the benchmark reads:
                         ``filevault_on`` (fdesetup), ``gatekeeper_enabled``
                         (spctl), ``sip_enabled`` (csrutil), the
                         ``pwpolicy_global:*`` / ``pwpolicy_account:*``
                         password policy, the audit_control flags...

A fact this host could not read is simply absent; each rule says what an
absent fact means.  Any failure of the whole read sends None ("not
collected"), never a guess.
"""

from __future__ import annotations

import json
import logging
import os
import plistlib
import re
import stat
import subprocess  # nosec B404 -- fixed argv, no shell
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

RAN = "ran"
FAILED = "failed"
_TIMEOUT = 30

_SU = "com.apple.SoftwareUpdate"
_LW = "com.apple.loginwindow"
_SYSTEMSETUP = "/usr/sbin/systemsetup"

# (domain, key) pairs the rules read.
PREFS = (
    (_SU, "AutomaticCheckEnabled"),
    (_SU, "AutomaticDownload"),
    (_SU, "AutomaticallyInstallMacOSUpdates"),
    (_SU, "ConfigDataInstall"),
    (_SU, "CriticalUpdateInstall"),
    ("com.apple.commerce", "AutoUpdate"),
    ("com.apple.applicationaccess", "enforcedSoftwareUpdateDelay"),
    ("com.apple.applicationaccess", "allowContentCaching"),
    ("com.apple.MCX", "forceInternetSharingOff"),
    ("com.apple.MCX", "DisableGuestAccount"),
    ("com.apple.AssetCache", "Activated"),
    ("com.apple.TimeMachine", "AutoBackup"),
    ("com.apple.TimeMachine", "LastDestinationID"),
    (_LW, "LoginwindowText"),
    (_LW, "SHOWFULLNAME"),
    (_LW, "RetriesUntilHint"),
    (_LW, "GuestEnabled"),
    (_LW, "com.apple.login.mcx.DisableAutoLoginClient"),
    (_LW, "autoLoginUser"),
    ("com.apple.mDNSResponder", "NoMulticastAdvertisements"),
)

# launchd labels the rules ask about.
LAUNCHD_LABELS = (
    "com.apple.ODSAgent",
    "com.apple.screensharing",
    "com.apple.smbd",
    "com.apple.auditd",
    "org.apache.httpd",
    "com.apple.XProtect.daemon.scan",
    "com.apple.XProtect.daemon.scan.startup",
)

_JXA = """
ObjC.import('Foundation');
var pairs = %s;
var out = {};
pairs.forEach(function (p) {
  var v = $.NSUserDefaults.alloc.initWithSuiteName(p[0]).objectForKey(p[1]);
  var u = ObjC.deepUnwrap(v);
  if (u !== undefined && u !== null) { out[p[0] + '/' + p[1]] = u; }
});
JSON.stringify(out);
"""

_SIZE_UNITS = {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
_TIME_DAYS = {"s": 1 / 86400, "h": 1 / 24, "d": 1, "y": 365}

Section = Tuple[Optional[Any], str]


def _run(argv: List[str]) -> Tuple[int, str]:
    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv
            argv, capture_output=True, text=True, timeout=_TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def read_prefs() -> Dict[str, Any]:
    code, out = _run(["osascript", "-l", "JavaScript", "-e", _JXA % json.dumps(PREFS)])
    if code != 0:
        return {}
    try:
        values = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {}
    return {"pref:" + name.lower(): value for name, value in values.items()}


def launchd_facts(listing: str) -> Dict[str, bool]:
    """``launchctl list`` output -> ``launchd:<label>`` loaded or not."""
    loaded = {line.split("\t")[-1].strip().lower() for line in listing.splitlines()}
    return {
        "launchd:" + label.lower(): label.lower() in loaded for label in LAUNCHD_LABELS
    }


def parse_global_policy(text: str) -> Dict[str, Any]:
    """``pwpolicy -getglobalpolicy``: ``key=value key=value``."""
    found = {}
    for token in text.split():
        key, sep, value = token.partition("=")
        if sep and key and value and (key.replace("_", "").isalnum()):
            found["pwpolicy_global:" + key.lower()] = _number(value)
    return found


def _policies(data: Any) -> List[Dict[str, Any]]:
    """Every policy dict in an account-policies plist."""
    if not isinstance(data, dict):
        return []
    return [policy for policies in data.values() if isinstance(policies, list)
            for policy in policies if isinstance(policy, dict)]  # fmt: skip


def _content_limits(content: str) -> List[Tuple[str, int]]:
    """``policyAttributeX < 5`` / ``>= 15`` pairs in a policyContent
    string, read token by token (no backtracking regex)."""
    tokens = content.replace("(", " ").replace(")", " ").split()
    limits = []
    for index, token in enumerate(tokens[:-2]):
        if token.startswith("policyAttribute") and tokens[index + 1] in (
            "<",
            "<=",
            ">",
            ">=",
        ):
            if tokens[index + 2].isdigit():
                limits.append((token, int(tokens[index + 2])))
    return limits


def _pattern_min_length(content: str) -> Optional[int]:
    """The N of a ``policyAttributePassword matches '...{N,}...'`` rule."""
    if "policyAttributePassword" not in content or "matches" not in content:
        return None
    start = content.find(".{")
    if start < 0:
        return None
    digits = content[start + 2 :].split(",", 1)[0]
    return int(digits) if digits.isdigit() else None


def parse_account_policies(text: str) -> Dict[str, Any]:
    """``pwpolicy -getaccountpolicies`` plist: each policy's parameters, and
    the limits written into its policyContent ("policyAttributeMaximum
    FailedAuthentications < 5"), by attribute name.  An expiry in days is
    also given in minutes, so either form compares."""
    plist = _plist_text(text)
    if plist is None:
        return {}
    try:
        data = plistlib.loads(plist.encode())
    except ValueError:  # plistlib.InvalidFileException is a ValueError
        return {}
    found: Dict[str, Any] = {}
    for policy in _policies(data):
        for key, value in (policy.get("policyParameters") or {}).items():
            found["pwpolicy_account:" + key.lower()] = _number(value)
        content = policy.get("policyContent") or ""
        for attr, value in _content_limits(content):
            found.setdefault("pwpolicy_account:" + attr.lower(), value)
        length = _pattern_min_length(content)
        if length is not None:
            # macOS 15's own default: "policyAttributePassword matches
            # '^$|.{4,}+'" -- a minimum length with no parameter (2026-11-24).
            found.setdefault("pwpolicy_account:minimumlength", length)
    days = found.get("pwpolicy_account:policyattributeexpireseveryndays")
    if isinstance(days, (int, float)):
        found.setdefault(
            "pwpolicy_account:policyattributeexpireseverynminutes", days * 1440
        )
    return found


def _amounts(text: str) -> List[Tuple[int, str]]:
    """``60d OR 5G`` -> [(60, "d"), (5, "g")] (lower-cased first)."""
    found = []
    for token in text.split():
        digits = token.rstrip("smhdybkg")
        unit = token[len(digits) :]
        if digits.isdigit() and len(unit) == 1:
            found.append((int(digits), unit))
    return found


def parse_audit_control(text: str) -> Dict[str, Any]:
    """/etc/security/audit_control: ``flags`` and ``expire-after`` (as days
    and as bytes, whichever units it names)."""
    found: Dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("flags:"):
            found["audit_flags"] = line.split(":", 1)[1].strip()
        elif line.startswith("expire-after:"):
            for number, unit in _amounts(line.split(":", 1)[1].lower()):
                if unit in _SIZE_UNITS:
                    found["audit_expire_after_bytes"] = int(number) * _SIZE_UNITS[unit]
                else:
                    found["audit_expire_after_days"] = int(number) * _TIME_DAYS[unit]
    return found


def parse_asl_install(text: str) -> Dict[str, Any]:
    """/etc/asl/com.apple.install: the shortest ``ttl=`` and any ``all_max=``."""
    found: Dict[str, Any] = {}
    ttls = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ttls += [int(v) for v in re.findall(r"\bttl=(\d+)", line)]
        if re.search(r"\ball_max=", line):
            found["install_log_all_max"] = True
    if ttls:
        found["install_log_ttl_days"] = min(ttls)
    return found


def parse_pmset(text: str) -> Dict[str, int]:
    """``pmset -g custom``: the highest powernap / womp over every source."""
    found: Dict[str, int] = {}
    for name in ("powernap", "womp"):
        values = [int(v) for v in re.findall(rf"^\s*{name}\s+(\d+)", text, re.M)]
        if values:
            found["pmset_" + name] = max(values)
    return found


def parse_sudo_defaults(text: str) -> Dict[str, Any]:
    found: Dict[str, Any] = {}
    m = re.search(r"Authentication timestamp timeout:\s*(-?[\d.]+)\s*minutes", text)
    if m:
        found["sudo_timestamp_timeout_minutes"] = float(m.group(1))
    m = re.search(r"Type of authentication timestamp record:\s*(\S+)", text)
    if m:
        found["sudo_timestamp_type"] = m.group(1).lower()
    return found


def _number(value: Any) -> Any:
    try:
        return int(str(value))
    except ValueError:
        try:
            return float(str(value))
        except ValueError:
            return value


def _read(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _plist_text(out: str) -> Optional[str]:
    """The plist in a command's output: ``security authorizationdb`` prints
    "YES (0)" on stderr after it, which broke the parse (macbookair,
    2026-11-24)."""
    start, end = out.find("<?xml"), out.rfind("</plist>")
    if start < 0 or end < start:
        return None
    return out[start : end + len("</plist>")]


def _authdb(right: str) -> Optional[Dict[str, Any]]:
    code, out = _run(["security", "authorizationdb", "read", right])
    text = _plist_text(out)
    if code != 0 or text is None:
        return None
    try:
        return plistlib.loads(text.encode())
    except ValueError:  # plistlib.InvalidFileException is a ValueError
        return None


def _status_facts(found: Dict[str, Any]) -> None:
    """Firewall, time, sharing, Gatekeeper, FileVault, SIP."""
    checks = (
        (["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
         "firewall_enabled", r"(enabled|state = [12])"),
        (["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
         "firewall_stealth", r"(stealth mode is on|mode enabled|state = [12])"),
        ([_SYSTEMSETUP, "-getusingnetworktime"], "network_time", r"Network Time:\s*On"),
        ([_SYSTEMSETUP, "-getremotelogin"], "remote_login", r"Remote Login:\s*On"),
        ([_SYSTEMSETUP, "-getremoteappleevents"], "remote_apple_events",
         r"Remote Apple Events:\s*On"),
        (["/usr/sbin/spctl", "--status"], "gatekeeper_enabled", r"assessments enabled"),
        (["/usr/bin/fdesetup", "status"], "filevault_on", r"FileVault is On"),
        (["/usr/bin/csrutil", "status"], "sip_enabled", r"status: enabled\."),
        (["/usr/bin/csrutil", "authenticated-root", "status"], "authenticated_root_enabled",
         r"Authenticated Root status: enabled"),
        (["/usr/sbin/sysadminctl", "-smbGuestAccess", "status"], "smb_guest_access",
         r"SMB guest access enabled"),
        (["/sbin/nfsd", "status"], "nfsd_running", r"nfsd is running"),
    )  # fmt: skip
    for argv, fact, pattern in checks:
        code, out = _run(argv)
        if out.strip() and (code == 0 or fact in ("smb_guest_access", "nfsd_running")):
            found[fact] = re.search(pattern, out, re.I) is not None
    code, out = _run([_SYSTEMSETUP, "-getnetworktimeserver"])
    m = re.search(r"Network Time Server:\s*(\S+)", out)
    if code == 0 and m:
        found["network_time_server"] = m.group(1)
    code, out = _run(["/usr/sbin/cupsctl"])
    m = re.search(r"_share_printers=(\d)", out)
    if code == 0 and m:
        found["cups_share_printers"] = int(m.group(1))


def _account_facts(found: Dict[str, Any]) -> None:
    """Password policy, hints, root, sudo, authorization rights."""
    code, out = _run(["/usr/bin/pwpolicy", "-n", "/Local/Default", "-getglobalpolicy"])
    if code == 0:
        found.update(parse_global_policy(out))
    code, out = _run(["/usr/bin/pwpolicy", "-getaccountpolicies"])
    if code == 0:
        found.update(parse_account_policies(out))
    code, out = _run(["/usr/bin/dscl", ".", "-list", "/Users", "hint"])
    if code == 0:
        found["users_with_password_hint"] = sum(
            1 for line in out.splitlines() if len(line.split(None, 1)) > 1
        )
    code, out = _run(
        ["/usr/bin/dscl", ".", "-read", "/Users/root", "AuthenticationAuthority"]
    )
    found["root_enabled"] = code == 0 and "No such key" not in out
    code, out = _run(["/usr/bin/sudo", "-V"])
    if code == 0:
        found.update(parse_sudo_defaults(out))
    prefs = _authdb("system.preferences")
    if prefs is not None:
        found["authdb_system_preferences_shared"] = bool(prefs.get("shared", True))
    saver = _authdb("system.login.screensaver")
    if saver is not None:
        found["authdb_screensaver_rule"] = " ".join(
            str(r) for r in saver.get("rule") or []
        )


def _file_facts(found: Dict[str, Any]) -> None:
    """Audit, install.log retention, power, Time Machine, banners, NFS."""
    for path, parse in (("/etc/security/audit_control", parse_audit_control),
                        ("/etc/asl/com.apple.install", parse_asl_install)):  # fmt: skip
        text = _read(path)
        if text is not None:
            found.update(parse(text))
    code, out = _run(["/usr/bin/pmset", "-g", "custom"])
    if code == 0:
        found.update(parse_pmset(out))
    tm_plist = _read("/Library/Preferences/com.apple.TimeMachine.plist")
    if tm_plist is not None:
        code, out = _run(
            ["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.TimeMachine"]
        )
        found["timemachine_unencrypted_destinations"] = out.count("NotEncrypted")
    nat = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
    try:
        with open(nat, "rb") as fh:
            found["internet_sharing"] = bool(
                plistlib.load(fh).get("NAT", {}).get("Enabled")
            )
    except (OSError, ValueError, AttributeError):
        pass
    banners = [n for n in _listdir("/Library/Security") if n.startswith("PolicyBanner")]
    found["policy_banner_readable"] = any(
        os.stat(os.path.join("/Library/Security", n)).st_mode & stat.S_IROTH
        for n in banners
    )
    found["guest_home_exists"] = os.path.isdir("/Users/Guest")
    found["exports_file"] = os.path.exists("/etc/exports")
    code, out = _run(["/usr/sbin/nvram", "boot-args"])
    found["nvram_boot_args"] = out.split("\t", 1)[-1].strip() if code == 0 else ""
    code, out = _run(["/bin/ps", "-axo", "comm"])
    if code == 0:
        found["ard_agent_running"] = "ARDAgent" in out


def _listdir(path: str) -> List[str]:
    try:
        return os.listdir(path)
    except OSError:
        return []


def macos_settings() -> Section:
    found: Dict[str, Any] = {}
    found.update(read_prefs())
    code, out = _run(["/bin/launchctl", "list"])
    if code == 0:
        found.update(launchd_facts(out))
    for collect in (_status_facts, _account_facts, _file_facts):
        try:
            collect(found)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("macOS compliance facts: %s failed: %s", collect.__name__, exc)
    return (found, RAN) if found else (None, FAILED)


SECTIONS = {"macos_settings": macos_settings}
