# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Lucky 13 source checks for the privileged agent: #2 XSS (CWE-79), #4
remote file inclusion (CWE-98), #5 SQL injection (CWE-89), #6 world-writable
files (CWE-276), #9 grow-your-own crypto (CWE-327), #10 privilege escalation
via Help (CWE-271), #11 symlink following (CWE-61) and #12 hard-coded /
default passwords (CWE-259).

These are patterns a reviewer can see in five minutes, so a scan can too.
A hit is either fixed or added to ``ALLOWED`` below with the reason it is
safe -- the allow-list is the reviewed record, so keep the reasons honest.
"""

import re

import yaml

from tests.lucky13.conftest import REPO

# (check, repo-relative path) -> why this occurrence is safe.
ALLOWED = {
    ("4", "scripts/translate_i18n.py"): (
        "developer translation tool loading this repository's own i18n_strict.py; "
        "never shipped in the agent"
    ),
    ("4", "src/sysmanage_agent/operations/config_mgmt_readers.py"): (
        "yaml.load with _TagTolerantLoader, a SafeLoader subclass that drops "
        "tags: nothing is ever constructed from the document"
    ),
    ("5", "src/sysmanage_agent/core/fact_store.py"): (
        "DDL interpolates IDENTIFIERS only, both contract constants (table is "
        "checked against FACT_TABLES first); untrusted pack SQL goes to query() "
        "behind the sqlite authorizer"
    ),
    ("9", "src/sysmanage_agent/core/schedule_jitter.py"): (
        "timer jitter and connect splay only (Phase 22.1): spreads load, guards "
        "no secret, so predictability costs nothing"
    ),
}

SKIP_DIRS = {"node_modules", "__pycache__", "tests", ".venv", "dist", "build",
             "htmlcov", "sbom", "logs"}  # fmt: skip
PY = {".py"}
SHELL = {".sh", ".ps1", ".spec", ".bat", ".wxs", ".nsi", ".service", ".plist",
         "postinst", "postrm", "preinst", "prerm", "Makefile", "+INSTALL",
         "+DEINSTALL", "+MANIFEST", "postinstall", "preinstall", "APKBUILD",
         "PKGBUILD", "rc"}  # fmt: skip
CODE = ["src", "main.py"]


def _files(roots, suffixes):
    for root in roots:
        base = REPO / root
        if not base.exists():
            continue
        paths = [base] if base.is_file() else base.rglob("*")
        for path in paths:
            if not path.is_file() or SKIP_DIRS & set(path.relative_to(REPO).parts):
                continue
            if suffixes is None or path.suffix in suffixes or path.name in suffixes:
                yield path


def _hits(check, roots, suffixes, pattern, line_ok=None):
    regex = re.compile(pattern)
    found = []
    for path in _files(roots, suffixes):
        rel = path.relative_to(REPO).as_posix()
        if (check, rel) in ALLOWED:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if regex.search(line) and not (line_ok and line_ok(line)):
                found.append(f"{rel}:{number}: {line.strip()[:120]}")
    return found


def _report(found, what):
    return (
        f"{what} -- fix, or allow in test_source_hygiene.ALLOWED with the reason:\n  "
        + "\n  ".join(found)
    )


def test_2_the_agent_renders_no_html():
    found = _hits("2", CODE, PY, r"<html|text/html|HTMLResponse|\.innerHTML")
    assert not found, _report(found, "#2 HTML produced by the agent (XSS)")


def test_4_no_code_loaded_from_server_data():
    found = _hits("4", CODE + ["scripts"], PY,
                  r"(^|[^.\w])(eval|exec)\(|__import__\(|import_module\("
                  r"|spec_from_file_location|SourceFileLoader|pickle\.loads?\("
                  r"|yaml\.load\((?!.*Loader=yaml\.SafeLoader)")  # fmt: skip
    assert not found, _report(found, "#4 dynamic code loading (file inclusion)")


def test_5_no_sql_built_from_strings():
    found = _hits("5", CODE, PY,
                  r"(execute|text)\(\s*f[\"']|(execute|text)\(.*[\"']\s*%\s"
                  r"|(execute|text)\(.*[\"']\.format\(")  # fmt: skip
    assert not found, _report(found, "#5 SQL built from strings")


def test_6_nothing_is_made_world_writable():
    octal = r"[0-7]?[0-7][0-7][2367]\b"
    found = _hits("6", CODE + ["scripts", "installer", "packaging", "Makefile"],
                  PY | SHELL,
                  rf"chmod\s+(-\w+\s+)*{octal}|chmod\s+(-\w+\s+)*[ugoa]*[oa][ugoa]*\+[rxX]*w"
                  rf"|0o{octal}|S_IWOTH|os\.umask\(0\)",
                  # 0o7777 as a mask or range bound is not a mode being set
                  line_ok=lambda line: re.search(r"(<=|&)\s*0o7777", line))  # fmt: skip
    assert not found, _report(found, "#6 world-writable files")


def test_9_no_home_grown_or_broken_crypto():
    found = _hits("9", CODE + ["scripts"], PY,
                  r"hashlib\.(md5|sha1)\(|hashlib\.new\(['\"](md5|sha1)|\bfrom Crypto\b"
                  r"|\bimport Crypto\b|\bARC4\b|\bBlowfish\b|TripleDES|modes\.ECB|rot13",
                  line_ok=lambda line: "usedforsecurity=False" in line)  # fmt: skip
    assert not found, _report(found, "#9 weak or home-grown crypto")


def test_9_identity_and_security_code_use_secrets_not_random():
    found = _hits("9", CODE, PY, r"^\s*(import random\b|from random import)")
    assert not found, _report(found, "#9 predictable randomness")


def test_10_the_privileged_agent_never_launches_a_ui():
    found = _hits("10", CODE + ["scripts"], PY,
                  r"\bwebbrowser\b|os\.startfile|xdg-open|ShellExecute|\bhh\.exe"
                  r"|winhlp32|explorer\.exe")  # fmt: skip
    assert not found, _report(found, "#10 launching a browser/help viewer")


def test_11_no_predictable_temporary_files():
    found = _hits("11", CODE + ["scripts"], PY,
                  r"tempfile\.mktemp\(|['\"]/(var/)?tmp/")  # fmt: skip
    assert not found, _report(found, "#11 predictable /tmp paths (symlink following)")


# -- #12 -----------------------------------------------------------------------

CREDENTIAL_KEYS = re.compile(
    r"(password|passwd|secret|token|api_key|private_key)$", re.I
)
PLACEHOLDER = re.compile(r"^(|<.*>|\$\{.*\}|changeme|change_me.*|your[_-].*)$", re.I)


def _walk(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")
    else:
        yield path, node


def _agent_configs():
    return [path for path in (REPO / "installer").rglob("*.yaml.example")
            if not SKIP_DIRS & set(path.relative_to(REPO).parts)] + [
        REPO / "sysmanage-agent-system.yaml"]  # fmt: skip


def test_12_the_scan_sees_the_shipped_configs():
    assert len(_agent_configs()) > 3


def test_12_no_credential_ships_in_an_agent_config():
    found = []
    for path in _agent_configs():
        if not path.exists():
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for key, value in _walk(data):
            leaf = key.rsplit(".", 1)[-1]
            if CREDENTIAL_KEYS.search(leaf) and value not in (None, False):
                if not PLACEHOLDER.match(str(value).strip()):
                    found.append(f"{path.relative_to(REPO)}: {key} = {value!r}")
    assert not found, "#12 credentials in shipped configs:\n  " + "\n  ".join(found)


def test_12_no_hard_coded_password_in_code():
    found = _hits("12", CODE, PY,
                  r"(password|passwd|secret|api_key)\s*=\s*[\"'][^\"'{}%\s]{4,}[\"']",
                  line_ok=lambda line: "nosec" in line)  # fmt: skip
    assert not found, _report(found, "#12 hard-coded password in code")
