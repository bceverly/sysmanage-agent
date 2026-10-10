#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""SysManage domain glossary for the translation service.

WHY THIS EXISTS
---------------
The system prompt protects brand and protocol names, but it never said what
the product's own nouns MEAN, so the model took the everyday sense and the
result passed every gate.  Measured against the live service on 2026-09-20,
all gate-green: ``Inventories`` came back as warehouse stock in seven of eight
languages (ja 在庫, ko 재고, nl Voorraden, de Bestände, zh_CN 库存,
ar المخزونات), ``Fleet`` as a navy or a motorcade in all eight,
``Configuration Drift`` as ja 構成の漂白 -- configuration *bleaching* --
``Job templates`` as de Arbeitsplatzvorlagen (templates for job VACANCIES),
and, inverted, ``Hosts`` as ar الضيوف and ``Every host`` as nl "Elke gast",
both meaning GUESTS.

No completeness, placeholder, markup or English-identity check can catch a
fluent translation of the wrong sense; only reading it can, which cost 403
frontend values and 114 docs paragraphs of hand correction in Phase 20.

WHY IT IS FILTERED PER BATCH RATHER THAN PASTED INTO THE PROMPT
---------------------------------------------------------------
The vocabulary below spans all four repositories and is far too long to sit in
every request: a system prompt that dwarfs the payload degrades
instruction-following and costs tokens on every call.  ``relevant()`` selects
only the terms that actually OCCUR in the batch being translated, so a batch
of five strings carries five-ish definitions and the dictionary can keep
growing without making any single request worse.

Terms are curated, not exhaustive: a word earns an entry only when its
everyday sense would mislead, or when it must not be translated at all.
Adding a term that has no trap just spends prompt on nothing.
"""

import re
from typing import Dict, Iterable, List, Sequence, Tuple

# TERMS (canonical / measured-wrong renderings) and ALIASES (inflections) live
# in i18n_glossary_terms.py, split out at the 1000-line limit; re-exported
# here so every caller keeps importing this one module.
from i18n_glossary_terms import ALIASES, TERMS  # noqa: F401

# ---------------------------------------------------------------------------
# Names that must survive untouched.  Rule 2 of the system prompt carries the
# short list; these are the rest, harvested from the four repositories.
# ---------------------------------------------------------------------------
NEVER_TRANSLATE: Tuple[str, ...] = (
    "SysManage",
    "OpenBAO",
    "osquery",
    "YARA",
    "Ansible",
    "Puppet",
    "Salt",
    "Chef",
    "DSC",
    "bootc",
    "rpm-ostree",
    "OSTree",
    "Snap",
    "Snapcraft",
    "Flatpak",
    "AppImage",
    "Homebrew",
    "winget",
    "Chocolatey",
    "APT",
    "DNF",
    "YUM",
    "Zypper",
    "pkg",
    "pkgin",
    "APK",
    "Portage",
    "Ubuntu Pro",
    "Landscape",
    "Oracle Linux",
    "Rocky Linux",
    "AlmaLinux",
    "openSUSE",
    "Tumbleweed",
    "Alpine",
    "Active Directory",
    "Entra ID",
    "Okta",
    "Keycloak",
    "SCIM",
    "OIDC",
    "LDAP",
    "TOTP",
    "FIDO2",
    "WebAuthn",
    "CVE",
    "CVSS",
    "NVD",
    "SBOM",
    "CycloneDX",
    "OVAL",
    "SCAP",
    "CIS",
    "STIG",
    "FIPS",
    "Semgrep",
    "SonarQube",
    "CodeQL",
    "Playwright",
    "Vite",
    "FastAPI",
    "SQLAlchemy",
    "Alembic",
    "Cython",
    "Podman",
    "containerd",
    "skopeo",
    "libvirt",
    "QEMU",
    "Vagrant",
    "poudriere",
    "systemd",
    "launchd",
    "rc.d",
    "PXE",
    "iPXE",
    "DHCP",
    "TFTP",
    "cloud-init",
    "Autounattend",
    "Kickstart",
    "AutoYaST",
    "preseed",
)

# ---------------------------------------------------------------------------
# term -> what it means here, and the everyday sense it must NOT become.
# ---------------------------------------------------------------------------
GLOSSARY: Dict[str, str] = {
    # -- the managed estate ------------------------------------------------
    "host": "a managed computer or server. NOT a guest, and NOT a person who "
    "receives visitors",
    "child host": "a virtual machine or container running on a managed host",
    "parent host": "the machine a child host runs on",
    "fleet": "all the machines under management, taken as a group. NOT ships, "
    "and NOT a convoy of vehicles",
    "agent": "the SysManage program installed on a managed host. NOT a person "
    "or a representative",
    "inventory": "a NAMED SET OF HOSTS selected for work. NOT warehouse "
    "stock, goods, or supplies on hand",
    "tag": "a label attached to hosts for grouping. NOT a price tag",
    "site": "a location that groups hosts. NOT a building plot, and NOT a " "web site",
    "tenant": "one customer's isolated data within a shared installation. NOT "
    "someone who rents property",
    "access group": "a set of hosts and users that share permissions",
    "heartbeat": "the periodic signal proving an agent is still alive",
    "enrollment": "the act of registering an agent with the server",
    "approval": "an operator accepting a newly registered host",
    "discovery": "finding devices on the network that are not yet managed",
    "asset": "a device present on the network",
    "sweep": "actively probing every address in a network range to find "
    "devices. NOT cleaning or brushing",
    "exclusion": "an operator's recorded decision that a discovered device is "
    "known and needs no management. NOT a ban or an expulsion",
    # -- configuration management -----------------------------------------
    "profile": "a stored configuration definition applied to hosts. NOT a "
    "person's biography or account details",
    "drift": "a host's configuration diverging from its intended state. NOT "
    "floating, bleaching, or physical movement",
    "baseline": "the reference state a host is compared against",
    "golden host": "a reference host other hosts are compared against",
    "job": "one bounded unit of scheduled work the server performs. NOT "
    "employment, an occupation, or a job vacancy",
    "job template": "a saved definition a job is launched from. NOT a "
    "template for a job application",
    "run": "a single execution of a job, profile or scan",
    "target": "a host a job acts upon. NOT a goal or an aim",
    "dry run": "a SIMULATION that reports what WOULD change while changing "
    "nothing. NOT operating something while dry",
    "check mode": "a dry run: report what would change, change nothing",
    "playbook": "a reusable automation script",
    "remediation": "an action that repairs a detected problem",
    "assignment": "binding a profile to the hosts it applies to",
    "wave": "one batch of hosts a job works through at a time",
    "concurrency": "how many hosts a job works on at once",
    # -- packages and content ---------------------------------------------
    "package": "an installable software package. NOT a parcel",
    "repository": "a server holding software packages",
    "mirror": "a local copy of a software repository. NOT a reflective " "surface",
    "snapshot": "a point-in-time copy of a repository or machine state",
    "channel": "a release stream software is published on",
    "upstream": "the original source a mirror copies from",
    "update": "a newer version of installed software",
    "patch": "a fix applied to installed software. NOT a piece of cloth",
    "upgrade": "moving to a newer release",
    "rollback": "returning to the previous version",
    "image": "a bootable or container filesystem image. NOT a picture",
    "container": "an isolated process environment. NOT a shipping box",
    "content view": "a curated, versioned selection of packages",
    "bundle": "a single file packaging content for transfer",
    # -- security ----------------------------------------------------------
    "vulnerability": "a known security weakness in software",
    "advisory": "a published security notice",
    "erratum": "an official patch notice for an operating-system release "
    "(OpenBSD and Red Hat publish errata). NOT an error, a mistake or a bug",
    "finding": "one detected problem",
    "severity": "how serious a finding is",
    "compliance": "conformance to a security standard",
    "scan": "an automated inspection of a host",
    "antivirus": "malware protection software",
    "malware": "hostile software",
    "signature": "a detection pattern for malware. NOT a handwritten name",
    "quarantine": "isolating a suspect file so it cannot run",
    "firewall": "software controlling network traffic",
    "role": "a named set of permissions. NOT a part in a play",
    "policy": "a set of rules the product enforces on hosts or users. NOT an "
    "insurance policy, and NOT a political program",
    "permission": "the right to perform one action",
    "secret": "a stored credential such as a password or key",
    "vault": "the encrypted store holding secrets. NOT a bank vault",
    "lease": "time-limited access to a secret. NOT a rental agreement",
    "seal": "locking the vault so secrets cannot be read",
    "certificate": "a cryptographic identity document",
    "key": "a cryptographic key. NOT a door key",
    "token": "a string proving identity or authorization",
    "threat model": "the operator's description of their installation -- its "
    "data, obligations, exposure and tolerances -- from which the applicable "
    "security checks are chosen. NOT a model of an attacker's behavior",
    "punch list": "the set of outstanding items still to be completed. NOT "
    "anything to do with striking or hole-punching",
    "waiver": "an operator's audited, recorded acceptance of one specific "
    "risk, with a reason. NOT a legal release of liability, and NOT a "
    "postponement",
    "hardening": "reducing a system's attack surface",
    # -- operations --------------------------------------------------------
    "queue": "stored messages waiting to be delivered",
    "dispatch": "sending a command to an agent",
    "alert": "a notification that a condition was met",
    "alert rule": "the condition that raises an alert",
    "maintenance window": "a period when changes are allowed",
    "blackout": "a period when changes are forbidden. NOT a power cut",
    "reboot orchestration": "restarting machines in a safe order",
    "provisioning": "creating and installing a new machine",
    "federation": "linked SysManage servers sharing data",
    "air-gap": "a deployment with no network path to the internet",
    "collection": "gathering content for transfer to an air-gapped site",
    "ingestion": "importing collected content at the air-gapped site",
    "telemetry": "operational measurements emitted by the software",
    "metric": "one measured value over time",
    "report": "a generated document summarizing data",
    "dashboard": "a screen summarizing status",
    "recommendation": "prescriptive guidance the product derives",
    "advisor": "the component that produces recommendations",
    "rule pack": "a named, versioned set of advisor rules that can be switched "
    "on or off as a unit. NOT a physical package",
    "proposed fix": "a change the advisor suggests and an operator must approve "
    "before anything runs. NOT a fix that was already applied",
    "lens": "one category of recommendations: security, performance, "
    "availability or stability. NOT an optical lens",
    "risk score": "impact multiplied by likelihood; withheld when the host "
    "could not be assessed",
    "peer group": "the hosts compared with each other, e.g. those on the same "
    "operating system release",
    "evidence": "the data a rule reads before it can reach a verdict",
    "query pack": "a bundle of osquery queries collected together",
    "live query": "a query run across hosts right now, with results arriving "
    "as they come in. NOT a query that is alive",
    "fact table": "one of the osquery-schema tables the agent answers queries "
    "from (data-warehousing sense). NOT a table of trivia",
    "not assessable": "we could not measure this host, so there is no verdict "
    "to give. NOT a passing result, NOT a failing one, and NOT the same as "
    "finding nothing wrong",
    "not evaluated": "this host was neither selected nor ruled out, because a "
    "field the filter tests was never reported by it",
    "watch list": "the set of file paths a host checks each collection. NOT a "
    "list of people being observed, and NOT a wish list",
    "watched file": "a file on a host whose checksum is collected so changes "
    "to it can be detected",
    "blind spot": "something we could not measure, so no verdict about it "
    "exists. NOT a fault in the thing, and NOT a clean result",
    "not compared": "we did not examine this, so we cannot say whether it "
    "matches. NOT a statement that it differs, and NOT that it agrees",
    # -- 21.4 threat model and posture --------------------------------------
    "posture": "the installation's overall security and resilience state. NOT "
    "a person's body posture, and NOT an attitude or opinion",
    "posture item": "one installation-wide check on the punch list, with its " "state",
    "remedy": "the action that fixes a posture item. NOT a medicine or a "
    "legal remedy",
    "regressed": "was satisfied, and is open again because the fleet changed",
    # -- 21.5 built-in host metrics -----------------------------------------
    "series": "the values of one metric over time, as drawn on a chart. NOT "
    "a TV series, a product line or a mathematical series",
    "sample": "one recorded value of a metric at one moment. NOT a product "
    "sample, a specimen or a statistical survey",
    "built-in": "defined by the product itself rather than by an operator. "
    "NOT physically built into a wall or a device",
    "load average": "the operating system's count of runnable processes, "
    "averaged. NOT a physical weight or cargo",
    # -- product shape ------------------------------------------------------
    "edition": "which product variant is licensed: Community, Professional "
    "or Enterprise",
    "tier": "the licensing level a feature belongs to",
    "module": "a licensed component of the product",
    "engine": "a licensed component implementing one feature area. NOT a " "motor",
    "plugin": "a front-end bundle a licensed module supplies",
    "license": "the entitlement to use licensed components",
    # -- computing words whose everyday sense misleads ----------------------
    # Each of these is frequent in our own strings (measured over all four
    # repositories); rarer false friends are deliberately left out, because an
    # entry for a word we never ship is prompt spent on nothing.
    "service": "a background program managed by the operating system. NOT "
    "customer service or a favor",
    "default": "the preset value used when none is given. NOT failing to pay " "a debt",
    "log": "a record of events the software writes. NOT a piece of wood",
    "load": "how busy a machine is. NOT cargo or freight",
    "health": "whether a system is operating correctly. NOT bodily health",
    "path": "a location in the filesystem. NOT a walkway",
    "process": "a running program. NOT a procedure or a method",
    "build": "a compiled version of the software. NOT construction, and NOT "
    "a person's physique",
    "port": "a numbered network endpoint. NOT a harbour",
    "interface": "a network interface, or the screens a user works in",
    "schema": "the structure of the database",
    "ISO": "a disc image FILE used to install an operating system. NOT the "
    "standards body",
    # -- found by the translation verifier, 2026-10-09/10 --------------------
    # Each of these came back from the service in its everyday sense and was
    # caught only by the verifier plus a human review of its rejects (ROADMAP
    # 23.4).  The wrong renderings measured are in TERMS below.
    "canary": "a small first deployment that proves a change before it reaches "
    "everything, or a separate watcher program that checks a server from "
    "outside. NOT the bird",
    "cascade": "a database change propagating to the records that depend on it. "
    "NOT a waterfall",
    "idempotent": "safe to repeat: running it twice has the same effect as "
    "running it once",
    "thundering herd": "many clients acting at the same instant and overloading "
    "a server. NOT animals",
    "jitter": "a small random delay added so clients do not act in step. NOT "
    "trembling or nervousness",
    "backoff": "waiting progressively longer between retries. NOT retreating",
    "circuit breaker": "a guard that stops calling a failing service for a "
    "while. NOT an electrical breaker",
    "throughput": "how much work a system completes per unit of time. NOT a "
    "move or a transfer",
    "handshake": "the opening exchange in which two programs establish a "
    "connection. NOT shaking hands",
    "capture": "recording a host's current state so it can be compared later. "
    "NOT catching or seizing something",
    "grade": "a letter or number scoring a result. NOT product quality, and NOT "
    "a school year",
    "silo": "one tenant's fully separate database and secrets. NOT a grain silo",
    "failover": "switching automatically to a standby server when the primary "
    "fails. NOT making a backup copy",
    "reconciliation": "bringing the actual state back in line with the "
    "intended state. NOT harmony or making peace",
    "marked down": "flagged as offline or unreachable. NOT reduced in price, "
    "and NOT a subscript",
    "privileged": "running with root or administrator rights. NOT socially "
    "privileged or distinguished",
    "pruning": "deleting old entries that are no longer needed. NOT trimming "
    "plants or harvesting",
    "polling": "asking repeatedly whether there is new work. NOT voting or an "
    "opinion poll",
}


# A batch that mentions half the product should not ship half the dictionary;
# past this many definitions the prompt is doing more harm than the glossary
# does good.  Longest terms win, because "job template" is more specific --
# and more often mistranslated -- than "job".
MAX_ENTRIES = 25


def _patterns() -> List[Tuple[str, re.Pattern]]:
    """(term, compiled matcher) for every term and its aliases."""
    out: List[Tuple[str, re.Pattern]] = []
    for term in GLOSSARY:
        forms = [term, *ALIASES.get(term, ())]
        # Plain plural unless an explicit alias already supplies one.
        if not any(f.endswith("s") for f in forms):
            forms.append(term + "s")
        alts = sorted(
            {re.escape(f).replace(r"\ ", r"[\s\-]+") for f in forms},
            key=len,
            reverse=True,
        )
        alternation = "|".join(alts)
        out.append((term, re.compile(rf"\b(?:{alternation})\b", re.I)))
    return out


_PATTERNS = _patterns()


# Word characters for forbidden-form boundaries: \w plus the Devanagari and
# Arabic blocks, which include their combining marks.
_WORDCHAR = r"[\w\u0900-\u097F\u0600-\u06FF\u0750-\u077F]"
_CJK = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af]")


def forbidden_matcher(form: str) -> re.Pattern:
    """Matcher for one forbidden rendering.

    Word-boundary for everything with spaces between words -- Latin, Cyrillic
    AND Arabic.  Python's \\b is Unicode-aware, which is what saves Arabic:
    the correct word for host, مضيف, CONTAINS the word for guest, ضيف, so a
    substring test flags all 403 correct Arabic values.  With a boundary there
    is none between م and ض, so only the standalone word matches.  German is
    the same story from the other side: "bereitstellen" contains "stellen".

    CJK has no boundaries to find, so those fall back to substring -- safe
    there, because 在庫 and 艦隊 are not morphemes of anything we ship.
    """
    if _CJK.search(form):
        return re.compile(re.escape(form))
    # Not \b: Python treats combining marks (Devanagari vowel signs, Arabic
    # diacritics) as NON-word characters, so \b fell inside words -- the
    # forbidden Hindi टेंट (a camping tent) matched the middle of कंटेंट,
    # "content" (2026-10-10).  A letter OR mark of the same scripts on
    # either side means we are inside a word.
    return re.compile(rf"(?<!{_WORDCHAR}){re.escape(form)}(?!{_WORDCHAR})", re.I)


def patterns() -> List[Tuple[str, re.Pattern]]:
    """(term, matcher) pairs -- the gate walks these to find terms in sources."""
    return _PATTERNS


# Brand/protocol names are matched literally (no plural, no case folding):
# "Salt" the configuration tool must stay, but "salt" in a password-hashing
# sentence is an ordinary English word and is none of our business.
_PROTECTED = [(n, re.compile(rf"\b{re.escape(n)}\b")) for n in NEVER_TRANSLATE]


def protected(texts: Iterable[str]) -> List[str]:
    """Names from NEVER_TRANSLATE that occur in ``texts``, in listed order."""
    blob = "\n".join(t for t in texts if isinstance(t, str))
    if not blob:
        return []
    return [name for name, pat in _PROTECTED if pat.search(blob)]


def relevant(texts: Iterable[str], limit: int = MAX_ENTRIES) -> List[Tuple[str, str]]:
    """The glossary entries whose terms actually appear in ``texts``.

    Longest term first, so a batch that trips the cap keeps the specific
    entries ("maintenance window") over the generic ones ("window").
    """
    blob = "\n".join(t for t in texts if isinstance(t, str))
    if not blob:
        return []
    hits = [(term, GLOSSARY[term]) for term, pat in _PATTERNS if pat.search(blob)]
    # Terms in TERMS come FIRST, whatever their length.  Sorting purely by
    # length looks tidy and is wrong: the words that actually get
    # mistranslated are the short ones -- fleet, host, job, drift -- so a
    # batch matching more than `limit` terms dropped exactly the entries that
    # matter and kept "reboot orchestration".  Measured: a docs run
    # retranslated 66 zh_TW values straight back to 艦隊 (a navy) while the
    # same sentence sent alone came back correct.  Within each group, longer
    # first, so "job template" still outranks "job".
    hits.sort(key=lambda kv: (kv[0] not in TERMS, -len(kv[0]), kv[0]))
    return hits[:limit]


def render(
    entries: Sequence[Tuple[str, str]],
    language: str,
    lang_code: str = "",
    names: Sequence[str] = (),
) -> str:
    """The system message defining ``entries`` for this batch and locale.

    A term with a canonical rendering for ``lang_code`` is given as an
    INSTRUCTION ("use X"), not a definition, because a definition only steers
    and we want the same word every time -- the gate checks for exactly this.
    Terms without one fall back to the gloss, which still rules out the
    everyday sense.  Measured wrong renderings are named explicitly: telling
    the model what NOT to say fixed more of them than the gloss alone.

    Returns "" when nothing matched, so the caller can skip the message.
    """
    if not entries and not names:
        return ""
    lines = []
    for term, gloss in entries:
        spec = TERMS.get(term, {})
        canonical = spec.get("canonical", {}).get(lang_code) if spec else None
        forbid = spec.get("forbid", {}).get(lang_code) if spec else None
        if canonical:
            line = f"  - {term} -> use \u201c{canonical}\u201d ({gloss})"
        else:
            line = f"  - {term} = {gloss}"
        if forbid:
            line += " NEVER render it as: " + ", ".join(forbid)
        lines.append(line)
    block = (
        "DOMAIN GLOSSARY for this batch. These words appear in the strings "
        "below and are this product's own technical terms. Where a rendering "
        f"is given, use EXACTLY that {language} word so the product stays "
        "consistent; otherwise use the sense given, never the everyday one:\n"
        + "\n".join(lines)
        + f"\nIf {language} has no established IT rendering for one of these, "
        "keep the English word rather than translate it literally into "
        "something that means the wrong thing."
    )
    if names:
        block += (
            "\nKeep these names EXACTLY as written, untranslated: "
            + ", ".join(names)
            + "."
        )
    return block
