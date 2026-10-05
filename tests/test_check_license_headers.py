# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for the license-header gate (scripts/check_license_headers.py).

The same script runs in all four repositories with one line changed
(``LICENSE_KIND``); a header naming the wrong license is a licensing problem.
"""

import importlib.util
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "check_license_headers.py"
_SIBLINGS = (
    "sysmanage",
    "sysmanage-agent",
    "sysmanage-docs",
    "sysmanage-professional-plus",
)


def _load(path=_SCRIPT, name="check_license_headers"):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod():
    return _load()


AGPL = (
    "# Copyright (c) 2024-2026 Bryan Everly\n"
    "# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).\n"
    "# See the LICENSE file in the project root for the full terms.\n\nx = 1\n"
)
PROPRIETARY = (
    "# Copyright (c) 2024-2026 Bryan Everly. All rights reserved.\n"
    "# PROPRIETARY AND CONFIDENTIAL commercial software - NOT open source, NOT\n"
    "# licensed under the AGPL. Unauthorized copying, distribution, or use is\n"
    "# prohibited. See the LICENSE file in the project root for the full terms.\n"
    "\nx = 1\n"
)


def test_this_repository_uses_its_own_license(mod):
    assert mod.LICENSE_KIND == "agpl"


@pytest.mark.parametrize("kind, text", [("agpl", AGPL), ("proprietary", PROPRIETARY)])
def test_the_right_header_passes(mod, kind, text):
    assert mod.problems(text, kind, 2026) == []


def test_crossed_licenses_are_caught_both_ways(mod):
    assert any("WRONG license" in p for p in mod.problems(PROPRIETARY, "agpl", 2026))
    assert any("WRONG license" in p for p in mod.problems(AGPL, "proprietary", 2026))


def test_missing_header_and_stale_year(mod):
    assert mod.problems("x = 1\n", "agpl", 2026) == ["no copyright header"]
    stale = AGPL.replace("2024-2026", "2024-2025")
    assert mod.problems(stale, "agpl", 2026) == ["copyright year ends 2025, not 2026"]


def test_fix_adds_the_header_after_shebang_and_coding_cookie(mod):
    text = "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\nx = 1\n"
    new = mod.fixed(text, "a.py", "agpl", 2026)
    lines = new.splitlines()
    assert lines[:2] == text.splitlines()[:2]
    assert lines[2].startswith("# Copyright (c) 2024-2026 Bryan Everly")
    assert mod.problems(new, "agpl", 2026) == []
    assert mod.fixed(new, "a.py", "agpl", 2026) == new  # idempotent


def test_fix_uses_slash_comments_and_keeps_crlf(mod):
    new = mod.fixed("const a = 1;\r\n", "a.ts", "agpl", 2026)
    assert new.startswith("// Copyright (c) 2024-2026 Bryan Everly")
    assert "\n" not in new.replace("\r\n", "")


def test_fix_moves_a_stale_year_and_never_rewrites_a_wrong_license(mod):
    stale = AGPL.replace("2024-2026", "2024-2025")
    assert "2024-2027" in mod.fixed(stale, "a.py", "agpl", 2027)
    wrong = PROPRIETARY
    assert mod.fixed(wrong, "a.py", "agpl", 2026) == wrong


def test_vendored_and_generated_files_are_exempt(mod):
    files = [
        "frontend/public/mockServiceWorker.js",
        "frontend/node_modules/x/index.js",
        "frontend/playwright-report/trace/sw.bundle.js",
        "src/app.min.js",
        "src/app.ts",
    ]
    assert mod.source_files(files, walk=False) == ["src/app.ts"]


@pytest.mark.parametrize("sibling", _SIBLINGS)
def test_copies_in_sibling_repositories_match(sibling):
    """One script, four copies: only the header and LICENSE_KIND may differ."""
    other = _REPO.parent / sibling / "scripts" / "check_license_headers.py"
    if not other.is_file():
        pytest.skip(f"{sibling} is not checked out next to this repository")

    def body(path):
        text = path.read_text(encoding="utf-8")
        text = text[text.index('"""License-header gate') :]
        return text.replace('LICENSE_KIND = "proprietary"', 'LICENSE_KIND = "agpl"')

    assert body(other) == body(_SCRIPT)
