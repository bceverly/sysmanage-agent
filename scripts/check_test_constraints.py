#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Test-toolchain pin gate (2026-10-28).

On 2026-10-28 pytest 9.2.0 and pytest-asyncio 1.4.1 were released, CI
installed them unpinned, and a startup deprecation notice -- made fatal by
our ``filterwarnings = error`` -- took out every repo's CI at once.  The test
toolchain is now pinned in ``constraints-test.txt``, and this gate keeps it
that way:

1. ``constraints-test.txt`` exists and pins pytest and pytest-asyncio.
2. Every ``pip install`` in ``.github/workflows/`` that installs pytest (or a
   pytest plugin) or a requirements file passes ``-c``/``--constraint``.
   Production, semgrep and safety requirement files are exempt (no test
   tools), and so is ``latest-deps-canary.yml``, which tests the newest
   releases on purpose.
3. The canary workflow exists.
4. When sibling repos are checked out next to this one, their
   ``constraints-test.txt`` is identical (bump all three together).

Run with paths to check just those workflow files (used by the tests).
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSTRAINTS = "constraints-test.txt"
CANARY = "latest-deps-canary.yml"
SIBLINGS = ("sysmanage", "sysmanage-agent", "sysmanage-professional-plus")

PIP_INSTALL = re.compile(r"(?:\bpip3?|-m pip)\s+install\b")
TEST_TOOLS = re.compile(
    r"\bpytest[\w-]*|-r\s+\S*requirements(?!-(?:prod|semgrep|safety))[\w./-]*\.txt"
)
CONSTRAINED = re.compile(r"(?:^|\s)(?:-c|--constraint)[\s=]")


def logical_lines(text):
    """(line number, text) with backslash continuations joined."""
    out, start, buf = [], None, ""
    for number, line in enumerate(text.split("\n"), 1):
        if start is None:
            start = number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        out.append((start, buf + line))
        start, buf = None, ""
    return out


def unconstrained_installs(path):
    """[(line, command)] for test-tool installs without a constraints file."""
    found = []
    for number, line in logical_lines(path.read_text(encoding="utf-8")):
        text = line.strip()
        if text.startswith("#") or not PIP_INSTALL.search(text):
            continue
        tail = PIP_INSTALL.split(text, maxsplit=1)[1]
        if TEST_TOOLS.search(tail) and not CONSTRAINED.search(tail):
            found.append((number, text))
    return found


def constraints_problems(root):
    path = root / CONSTRAINTS
    if not path.is_file():
        return [f"{CONSTRAINTS} is missing"]
    text = path.read_text(encoding="utf-8")
    return [
        f"{CONSTRAINTS} does not pin {name}"
        for name in ("pytest", "pytest-asyncio")
        if not re.search(rf"^{re.escape(name)}==", text, re.M)
    ]


def sibling_drift(root):
    mine = (root / CONSTRAINTS).read_bytes() if (root / CONSTRAINTS).is_file() else None
    drift = []
    for name in SIBLINGS:
        other = root.parent / name / CONSTRAINTS
        if name == root.name or not other.is_file() or mine is None:
            continue
        if other.read_bytes() != mine:
            drift.append(name)
    return drift


def main(argv):
    workflows = [Path(a) for a in argv] or sorted(
        (ROOT / ".github" / "workflows").glob("*.yml")
    )
    problems = []
    if not argv:
        problems += constraints_problems(ROOT)
        if not (ROOT / ".github" / "workflows" / CANARY).is_file():
            problems.append(f".github/workflows/{CANARY} is missing")
    bad = []
    for path in workflows:
        if path.name == CANARY:
            continue
        bad += [(path, n, cmd) for n, cmd in unconstrained_installs(path)]
    drift = sibling_drift(ROOT) if not argv else []

    if not (problems or bad or drift):
        print("[OK] Test toolchain is pinned (constraints-test.txt)")
        return 0
    print("[FAIL] The test toolchain must be pinned (constraints-test.txt).")
    for problem in problems:
        print(f"  - {problem}")
    for path, number, cmd in bad:
        try:
            shown = path.relative_to(ROOT)
        except ValueError:
            shown = path
        print(f"  - {shown}:{number}: pip install without -c: {cmd[:120]}")
    for name in drift:
        print(f"  - ../{name}/{CONSTRAINTS} differs from this repo's copy")
    print("How to fix:")
    step = 0
    if bad:
        step += 1
        print(
            f"  {step}. Add '-c {CONSTRAINTS}' right after 'pip install' on each line above"
        )
        print("     (the path is relative to the step's directory; a step running in a")
        print(f"     sysmanage-agent checkout uses the agent's {CONSTRAINTS}).")
    if any(CANARY in p for p in problems):
        step += 1
        print(
            f"  {step}. Restore .github/workflows/{CANARY} (copy it from a sibling repo"
        )
        print("     and adjust its install and test steps to this repo).")
    if drift or any(CONSTRAINTS in p for p in problems):
        step += 1
        print(
            f"  {step}. Make {CONSTRAINTS} identical in sysmanage, sysmanage-agent and"
        )
        print(
            "     sysmanage-professional-plus: copy the newest one to the other two and"
        )
        print(
            "     commit it in each repo.  To move to a newer pytest or plugin, change"
        )
        print("     the pin there, once the latest-deps canary is green.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
