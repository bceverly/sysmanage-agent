#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
"""Per-locale renderings for the SysManage domain glossary.

Split out of ``i18n_glossary.py`` on 2026-10-10, when the glossary grew past
the 1000-line module limit.  The definitions (``GLOSSARY``) and the matching
logic stay there; this module holds the two data tables that grow fastest:
``TERMS`` (canonical and measured-wrong renderings per locale) and
``ALIASES`` (inflections).  ``i18n_glossary`` re-exports both, so every
caller keeps importing from one place.

Shared verbatim by sysmanage, sysmanage-agent, sysmanage-professional-plus and
sysmanage-docs (scripts/sync_i18n_tooling.py); only the license header differs.
"""

from typing import Dict, Tuple

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
            "hi": "जॉब",  # 63 uses; नौकरी is employment
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
        # The user's own profile page: there it IS a person's details.
        "except_keys": ["userProfile.*"],
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
    "erratum": {
        # An erratum is a PATCH NOTICE. Every forbidden form below means
        # "error"/"bug" -- the sense the translator reached for on 2026-09-23,
        # producing "5 of 10 security errors are not applied".
        "canonical": {
            "de": "Errata",
            "nl": "errata",
            "fr": "errata",
            "es": "erratas",
            "it": "errata",
            "pt": "erratas",
            "ru": "исправлени",
            "ja": "エラータ",
            "ko": "에라타",
            "zh_CN": "勘误",
            "zh_TW": "勘誤",
            "hi": "इराटा",
            "ar": "تصحيحات",
        },
        "forbid": {
            "de": ["Fehler"],
            "nl": ["fouten"],
            "fr": ["erreurs"],
            "es": ["errores"],
            "it": ["errori"],
            "pt": ["erros"],
            "ru": ["ошибки", "ошибок"],
            "ja": ["エラー"],
            "ko": ["오류"],
            "zh_CN": ["错误"],
            "zh_TW": ["錯誤"],
            "hi": ["त्रुटि", "त्रुटियों"],
            "ar": ["أخطاء", "الأخطاء"],
        },
    },
    # -- measured 2026-10-09/10 by the translation verifier ----------------
    # Every forbidden form below was written by the service and found by the
    # verifier's human review; none has an innocent reading when the English
    # contains the term.
    "advisory": {
        # A published SECURITY notice, measured 2026-10-10 rendered as
        # "warnings" / "alerts" in the sysmanage frontend navigation.
        "canonical": {"zh_CN": "安全公告", "zh_TW": "安全公告"},
        "forbid": {"de": ["Warnungen"], "zh_CN": ["预警"], "zh_TW": ["警示"]},
    },
    "idempotent": {
        "canonical": {"zh_CN": "幂等", "zh_TW": "冪等", "ja": "冪等"},
        # The SIMPLIFIED character in a Traditional Chinese catalog.
        "forbid": {"zh_TW": ["幂等"]},
    },
    "tenant": {
        "canonical": {"hi": "टेनेंट"},  # 246 uses across the catalogs
        "forbid": {"hi": ["टेंट"]},  # a camping tent
    },
    "repository": {"forbid": {"ar": ["الجمهورية"]}},  # a republic
    "target": {
        "canonical": {"nl": "doel"},
        "forbid": {"nl": ["doelwit"]},  # the target of an attack
    },
    "engine": {
        # движок: 51 uses in the catalogs against 7 for the motor word.
        "canonical": {"ru": "движок"},
        "forbid": {"ru": ["двигатель", "двигателя", "двигатели", "двигателей"]},
    },
    "cascade": {"forbid": {"ko": ["폭포수"]}},  # a waterfall
    "reconciliation": {
        "canonical": {"ko": "조정"},
        "forbid": {"ko": ["조화"]},  # harmony
    },
    "handshake": {"forbid": {"fr": ["serre-main"]}},  # an invented calque
    "capture": {
        "canonical": {"nl": "vastleggen"},
        "forbid": {"nl": ["vangen"]},  # catching an animal
    },
    "marked down": {"forbid": {"zh_TW": ["下標"]}},  # a subscript
    "canary": {
        "canonical": {"ko": "카나리", "zh_CN": "金丝雀", "zh_TW": "金絲雀"},
        # 캔리: misspelled; 金鑰鳥: "key bird".
        "forbid": {"ko": ["캔리"], "zh_TW": ["金鑰鳥"]},
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
    "enrollment": ("enroll", "enrolled", "enrollment"),
    "discovery": ("discover", "discovered"),
    "sweep": ("sweeps", "swept"),
    "exclusion": ("exclusions",),
    "remediation": ("remediate", "remediated"),
    "compliance": ("compliant", "non-compliant"),
    "erratum": ("errata",),
    "threat model": ("threat-model", "threat models"),
    "waiver": ("waive", "waived", "waivers"),
    "remedy": ("remedies",),
    "posture item": ("posture items",),
    "sample": ("samples",),
    "canary": ("canaries",),
    "backoff": ("back-off", "back off"),
    "capture": ("captured", "captures", "capturing"),
    "failover": ("fail over", "failed over", "fail-over"),
    "reconciliation": ("reconcile", "reconciled", "reconciles"),
    "marked down": ("mark down", "marks down"),
    "pruning": ("prune", "pruned", "prunes"),
    "polling": ("poll", "polled", "polls"),
    "jitter": ("jittered",),
    "privileged": ("privilege", "privileges"),
}
