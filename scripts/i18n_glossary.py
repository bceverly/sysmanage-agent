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
    "permission": "the right to perform one action",
    "secret": "a stored credential such as a password or key",
    "vault": "the encrypted store holding secrets. NOT a bank vault",
    "lease": "time-limited access to a secret. NOT a rental agreement",
    "seal": "locking the vault so secrets cannot be read",
    "certificate": "a cryptographic identity document",
    "key": "a cryptographic key. NOT a door key",
    "token": "a string proving identity or authorization",
    "threat model": "an analysis of what an attacker could do",
    "punch list": "the set of outstanding items still to be completed. NOT "
    "anything to do with striking or hole-punching",
    "waiver": "a recorded, deliberate decision to accept a risk",
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
    "query pack": "a bundle of osquery queries collected together",
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
    "customer service or a favour",
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
}

# ---------------------------------------------------------------------------
# CANONICAL RENDERINGS.  The glosses above steer the model; this table decides.
#
# Two fields, and the distinction matters:
#
#   canonical  the agreed term for that locale.  Present ONLY where an
#              established IT rendering exists and I am confident in it.  Where
#              a language has no settled native term, the canonical form is the
#              ENGLISH WORD -- consistent, checkable, and better than inventing
#              a native phrase nobody uses.  Absent means "no opinion": the
#              gloss still steers the model, and the gate does not require
#              anything.
#
#   forbid     renderings MEASURED coming back wrong from the service on
#              2026-09-20.  These are the high-precision half: a translation of
#              a string containing this term must never contain these.
#
# Grow this table as terms become widespread.  Adding a term costs one entry;
# the service and the gate both pick it up with no further change.
# ---------------------------------------------------------------------------
TERMS: Dict[str, Dict[str, Dict[str, object]]] = {
    "host": {
        "canonical": {
            "de": "Host",
            "nl": "host",
            "fr": "hôte",
            "es": "host",
            "it": "host",
            "pt": "host",
            "ru": "хост",
            "ja": "ホスト",
            "ko": "호스트",
            "zh_CN": "主机",
            "zh_TW": "主機",
            "hi": "होस्ट",
            "ar": "مضيف",
        },
        # Every one of these means a GUEST or a party host -- the inversion
        # that shipped in Phase 20.
        "forbid": {
            "nl": ["gast", "gasten"],
            "ar": ["الضيوف", "ضيوف"],
            "de": ["Gastgeber"],
            "fr": ["animateur", "invité"],
            # NOT "anfitrión"/"anfitrião": Spanish and Portuguese genuinely
            # use them for a host SYSTEM (sistema anfitrión). Only the guest
            # words are the inversion.
            "es": ["invitado"],
            "it": ["ospite"],
            "pt": ["convidado"],
        },
    },
    "inventory": {
        "canonical": {
            "ja": "インベントリ",
            "ko": "인벤토리",
            "zh_CN": "清单",
            "zh_TW": "清單",
            "de": "Inventar",
            "nl": "inventaris",
            "fr": "inventaire",
            "es": "inventario",
            "it": "inventario",
            "pt": "inventário",
            # No settled Arabic IT term; describe it instead of reaching for
            # جرد/مخزون, which are both stock-taking.
            "ar": "قائمة مضيفات",
        },
        # Warehouse stock, in seven of eight languages measured.
        "forbid": {
            "ja": ["在庫"],
            "ko": ["재고"],
            "zh_CN": ["库存"],
            "zh_TW": ["庫存"],
            "de": ["Bestand", "Bestände", "Lagerbestand"],
            "nl": ["voorraad", "voorraden"],
            "ar": ["المخزونات", "مخزون"],
            "ru": ["запасы", "склад"],
        },
    },
    "agent": {
        # The product's most central noun, and it was NOT glossed until
        # 2026-09-22. Asked cold, the service renders it 代理人 -- an agent in
        # the HUMAN sense, a representative or broker -- which is the same
        # everyday-meaning trap as inventory->warehouse stock.
        #
        # The canonicals below are what the catalogs ALREADY use (measured:
        # zh_CN 代理 x53, zh_TW 代理 x41, ja エージェント x52, ko 에이전트 x48),
        # so this pins existing wording rather than churning ~50 strings per
        # locale to satisfy a preference.
        "canonical": {
            "de": "Agent",
            "nl": "agent",
            "fr": "agent",
            "es": "agente",
            "it": "agente",
            "pt": "agente",
            "ru": "агент",
            "ja": "エージェント",
            "ko": "에이전트",
            "zh_CN": "代理",
            "zh_TW": "代理",
            "hi": "एजेंट",
            "ar": "وكيل",
        },
        "forbid": {
            # A person acting on someone's behalf, not a program.
            "zh_CN": ["代理人"],
            "zh_TW": ["代理人"],
        },
    },
    # ---- Phase 21.1 vocabulary -------------------------------------------
    # The phase plan called for these ("the glossary now carries the
    # vocabulary"), and without them each string was translated in isolation:
    # the same concept came back worded differently across the UI, and short
    # mostly-placeholder strings had no domain anchor at all.
    "query pack": {
        "canonical": {
            "de": "Abfragepaket",
            # Dutch uses "query" as the ordinary word for a database query --
            # the same reason queryPacks.query is blessed for nl.
            "nl": "query-pakket",
            "fr": "pack de requêtes",
            "es": "paquete de consultas",
            "it": "pacchetto di query",
            "pt": "pacote de consultas",
            "ru": "пакет запросов",
            "ja": "クエリパック",
            "ko": "쿼리 팩",
            "zh_CN": "查询包",
            "zh_TW": "查詢包",
            "hi": "क्वेरी पैक",
            "ar": "حزمة استعلامات",
        },
        "forbid": {},
    },
    "live query": {
        # "Live" here means run-right-now, NOT alive. The forbids below are
        # the readings that make it mean a query that is breathing.
        "canonical": {
            "de": "Live-Abfrage",
            "nl": "live query",
            "fr": "requête en direct",
            "es": "consulta en vivo",
            "it": "query in tempo reale",
            "pt": "consulta ao vivo",
            "ru": "запрос в реальном времени",
            "ja": "ライブクエリ",
            "ko": "라이브 쿼리",
            "zh_CN": "实时查询",
            "zh_TW": "即時查詢",
            "hi": "लाइव क्वेरी",
            "ar": "استعلام مباشر",
        },
        "forbid": {
            "zh_CN": ["活查询"],
            "zh_TW": ["活查詢"],
        },
    },
    "fact table": {
        # The osquery-schema tables the agent serves. "Fact table" is settled
        # data-warehousing vocabulary, so these are the established renderings
        # rather than anything invented here.
        "canonical": {
            "de": "Faktentabelle",
            "nl": "feitentabel",
            "fr": "table de faits",
            "es": "tabla de hechos",
            "it": "tabella dei fatti",
            "pt": "tabela de fatos",
            "ru": "таблица фактов",
            "ja": "ファクトテーブル",
            "ko": "팩트 테이블",
            "zh_CN": "事实表",
            "zh_TW": "事實表",
            "hi": "तथ्य तालिका",
            "ar": "جدول الحقائق",
        },
        "forbid": {},
    },
    "not assessable": {
        # The single most dangerous phrase in Phase 21.1 to get wrong. It must
        # not come back meaning "compliant", "clean", "passed", "none found",
        # "not applicable" or "failed" -- every one of those is a VERDICT, and
        # the whole point of the phrase is that no verdict was reached. The
        # canonical forms below all mean "could not be assessed/evaluated".
        "canonical": {
            "de": "nicht bewertbar",
            "nl": "niet te beoordelen",
            "fr": "non \u00e9valuable",
            "es": "no evaluable",
            "it": "non valutabile",
            "pt": "n\u00e3o avali\u00e1vel",
            "ru": "\u043d\u0435\u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e \u043e\u0446\u0435\u043d\u0438\u0442\u044c",
            "ja": "\u8a55\u4fa1\u4e0d\u80fd",
            "ko": "\ud3c9\uac00 \ubd88\uac00",
            "zh_CN": "\u65e0\u6cd5\u8bc4\u4f30",
            "zh_TW": "\u7121\u6cd5\u8a55\u4f30",
            "hi": "\u0906\u0915\u0932\u0928 \u0938\u0902\u092d\u0935 \u0928\u0939\u0940\u0902",
            "ar": "\u063a\u064a\u0631 \u0642\u0627\u0628\u0644 \u0644\u0644\u062a\u0642\u064a\u064a\u0645",
        },
        # Renderings that turn "we do not know" into an all-clear, which is the
        # exact failure this phase exists to prevent.
        "forbid": {
            "de": ["konform", "sauber", "bestanden"],
            "nl": ["conform", "schoon", "geslaagd"],
            "fr": ["conforme", "propre"],
            "es": ["conforme", "limpio", "sin problemas"],
            "it": ["conforme", "pulito"],
            "pt": ["conforme", "limpo"],
            "ru": [
                "\u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0443\u0435\u0442",
                "\u0447\u0438\u0441\u0442\u043e",
            ],
            "ja": [
                "\u9069\u5408",
                "\u554f\u984c\u306a\u3057",
                "\u8a72\u5f53\u306a\u3057",
            ],
            "ko": [
                "\uc900\uc218",
                "\ubb38\uc81c \uc5c6\uc74c",
                "\ud574\ub2f9 \uc5c6\uc74c",
            ],
            "zh_CN": ["\u5408\u89c4", "\u65e0\u95ee\u9898", "\u4e0d\u9002\u7528"],
            "zh_TW": ["\u5408\u898f", "\u7121\u554f\u984c", "\u4e0d\u9069\u7528"],
        },
    },
    "blind spot": {
        # The phrase an operator reads next to a drift result, so getting it
        # wrong reverses the meaning of the whole report. It must not come
        # back as "fault", "defect", "error" or "problem" -- a blind spot is
        # not a finding ABOUT the thing, it is the absence of one.
        "canonical": {
            "de": "nicht einsehbarer Bereich",
            "nl": "blinde vlek",
            "fr": "angle mort",
            "es": "punto ciego",
            "it": "punto cieco",
            "pt": "ponto cego",
            "ru": "\u0441\u043b\u0435\u043f\u0430\u044f \u0437\u043e\u043d\u0430",
            "ja": "\u672a\u78ba\u8a8d\u7bc4\u56f2",
            "ko": "\ud655\uc778 \ubd88\uac00 \uc601\uc5ed",
            "zh_CN": "\u76d1\u63a7\u76f2\u533a",
            "zh_TW": "\u76e3\u63a7\u76f2\u5340",
            "hi": "\u0905\u0928\u0926\u0947\u0916\u093e \u0915\u094d\u0937\u0947\u0924\u094d\u0930",
            "ar": "\u0645\u0646\u0637\u0642\u0629 \u063a\u064a\u0631 \u0645\u0631\u0626\u064a\u0629",
        },
        "forbid": {
            "de": ["Fehler", "Defekt"],
            "nl": ["fout", "defect"],
            "fr": ["erreur", "d\u00e9faut"],
            "es": ["error", "fallo"],
            "it": ["errore", "difetto"],
            "pt": ["erro", "falha"],
            "ru": ["\u043e\u0448\u0438\u0431\u043a\u0430"],
            "ja": ["\u30a8\u30e9\u30fc", "\u6b20\u9665"],
            "ko": ["\uc624\ub958", "\uacb0\ud568"],
            "zh_CN": ["\u9519\u8bef", "\u7f3a\u9677"],
            "zh_TW": ["\u932f\u8aa4", "\u7f3a\u9677"],
        },
    },
    "watch list": {
        # "Watch list" in the surveillance sense is the wrong register in
        # every one of these; what is meant is a monitored SET OF FILES.
        "canonical": {
            "de": "\u00dcberwachungsliste",
            "nl": "bewakingslijst",
            "fr": "liste de surveillance",
            "es": "lista de vigilancia",
            "it": "elenco di controllo",
            "pt": "lista de monitoramento",
            "ru": "\u0441\u043f\u0438\u0441\u043e\u043a \u043d\u0430\u0431\u043b\u044e\u0434\u0435\u043d\u0438\u044f",
            "ja": "\u76e3\u8996\u30ea\u30b9\u30c8",
            "ko": "\uac10\uc2dc \ubaa9\ub85d",
            "zh_CN": "\u76d1\u63a7\u5217\u8868",
            "zh_TW": "\u76e3\u63a7\u6e05\u55ae",
            "hi": "\u0928\u093f\u0917\u0930\u093e\u0928\u0940 \u0938\u0942\u091a\u0940",
            "ar": "\u0642\u0627\u0626\u0645\u0629 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629",
        },
        "forbid": {},
    },
    "fleet": {
        # No settled native term in most of these; the English word is the
        # canonical form rather than a naval one.
        "canonical": {
            "ja": "フリート",
            "ko": "플릿",
            "zh_CN": "主机群",
            "zh_TW": "主機群",
            "ru": "парк",
            # Dutch says -park for a fleet of machines (serverpark,
            # machinepark); vloot is ships.
            "nl": "machinepark",
            # أسطول is the ordinary Arabic fleet-of-vehicles word -- the same
            # metaphor English uses -- not the naval-ONLY sense that makes
            # ja 艦隊 and zh 车队 wrong. Canonical, not forbidden.
            "ar": "أسطول",
        },
        "forbid": {
            "ja": ["艦隊"],
            "ko": ["함대"],
            "zh_CN": ["车队", "舰队"],
            "zh_TW": ["車隊", "艦隊"],
            "ru": ["флот"],
            "nl": ["vloot"],
        },
    },
    "drift": {
        "canonical": {
            "de": "Konfigurationsabweichung",
            "nl": "afwijking",
            "fr": "dérive",
            "es": "desviación",
            "it": "deviazione",
            "pt": "desvio",
            "ru": "отклонение",
            "ja": "構成ドリフト",
            "ko": "구성 이탈",
            "zh_CN": "配置漂移",
            "zh_TW": "配置漂移",
        },
        # 漂白 is BLEACHING; the rest are physical floating.
        "forbid": {
            "ja": ["漂白", "浮遊"],
            "de": ["treiben", "Treibgut"],
            "nl": ["drijven"],
        },
    },
    "job": {
        "canonical": {
            "de": "Auftrag",
            "nl": "taak",
            "fr": "tâche",
            "es": "tarea",
            "it": "processo",
            "pt": "tarefa",
            "ru": "задача",
            "ja": "ジョブ",
            "ko": "작업",
            "zh_CN": "作业",
            "zh_TW": "作業",
            # مهمة = task. وظيفة leans to employment or a code function.
            "ar": "مهمة",
        },
        # Employment, occupations and job VACANCIES.
        "forbid": {
            "de": ["Arbeitsplatz", "Arbeitsplätze", "Stelle", "Stellen"],
            "fr": ["emploi", "emplois"],
            "es": ["empleo"],
            "it": ["impiego"],
            "pt": ["emprego"],
            "ar": ["الوظائف", "وظيفة"],
            "hi": ["नौकरी", "नौकरियाँ"],
            "ru": ["работа по найму"],
        },
    },
    "profile": {
        "canonical": {
            "de": "Profil",
            "nl": "profiel",
            "fr": "profil",
            "es": "perfil",
            "it": "profilo",
            "pt": "perfil",
            "ru": "профиль",
            "ja": "プロファイル",
            "ko": "프로필",
            "zh_CN": "配置文件",
            "zh_TW": "設定檔",
        },
        # A personal bio.
        "forbid": {"zh_CN": ["个人资料"], "zh_TW": ["個人資料"]},
    },
    "dry run": {
        "canonical": {
            "de": "Simulationslauf",
            "nl": "simulatie",
            "fr": "simulation",
            "es": "simulación",
            "it": "simulazione",
            "pt": "simulação",
            "ru": "тестовый запуск",
            "ja": "ドライラン",
            "ko": "시뮬레이션 실행",
            "zh_CN": "模拟运行",
            "zh_TW": "模擬執行",
        },
        # Literally "running while dry".
        "forbid": {
            "de": ["Trockenlauf", "Trockener Lauf"],
            "nl": ["droogloop"],
            "zh_CN": ["干跑"],
            "fr": ["exécution sèche", "course sèche"],
            "ar": ["تجربة جافة"],
            "it": ["corsa a secco"],
        },
    },
}


# Inflections a trailing "s" does not cover.
ALIASES: Dict[str, Tuple[str, ...]] = {
    "vulnerability": ("vulnerabilities",),
    "policy": ("policies",),
    "inventory": ("inventories",),
    "severity": ("severities",),
    "dry run": ("dry-run", "dry runs", "dry-runs"),
    "air-gap": ("air gap", "air-gapped", "air gapped"),
    "rollback": ("roll back", "rolled back"),
    "quarantine": ("quarantined",),
    "hardening": ("harden", "hardened"),
    "dispatch": ("dispatched", "dispatching"),
    "ingestion": ("ingest", "ingested"),
    "provisioning": ("provision", "provisioned"),
    "enrollment": ("enroll", "enrolled", "enrolment"),
    "discovery": ("discover", "discovered"),
    "remediation": ("remediate", "remediated"),
    "compliance": ("compliant", "non-compliant"),
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
    return re.compile(rf"\b{re.escape(form)}\b", re.I)


def patterns() -> List[Tuple[str, re.Pattern]]:
    """(term, matcher) pairs — the gate walks these to find terms in sources."""
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
