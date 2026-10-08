#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Dependency gate for ``make security``: is THIS environment safe and current?

Two checks, in order; either one failing fails ``make security``:

1. **Freshness.**  Every requirement in the repository's requirements files
   (``-r`` includes followed, environment markers honored) must be satisfied
   by what is installed.  A raised floor -- ``urllib3>=2.8.0`` after an
   advisory -- does nothing until someone reinstalls; until then the venv
   still holds the vulnerable version and every local tool runs against it.
   The fix is always the same: ``make install-dev``.

2. **pip-audit against the installed environment.**  Every installed
   package, pinned or not, checked against the PyPI advisory database.  This
   is what catches a vulnerable TRANSITIVE dependency that no requirements
   file names (found 2026-10-07: pyasn1 via ldap3, starlette via semgrep).

The escape hatch is ``.pip-audit-ignore.yml`` at the repository root, the
same file in every SysManage repository::

    vulnerabilities:
      - id: CVE-2026-12345
        reason: "why it does not apply here, or why it cannot be fixed yet"
        expires: 2026-12-31      # optional; the ignore FAILS after this date

An entry without a reason is refused, and an expired one fails the gate:
an ignore is a reviewed decision with a date on it, not a way to make a
finding go away.

Shared verbatim by sysmanage, sysmanage-agent and sysmanage-professional-plus;
keep the copies identical.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import subprocess  # nosec B404 -- runs pip-audit, fixed argv, no shell
import sys
from importlib import metadata
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

try:
    from packaging.requirements import InvalidRequirement, Requirement
except ImportError:  # pragma: no cover - pip always carries a copy
    from pip._vendor.packaging.requirements import (  # type: ignore
        InvalidRequirement,
        Requirement,
    )

REPO = Path(__file__).resolve().parent.parent
DEFAULT_REQUIREMENTS = ("requirements.txt", "requirements-dev.txt")
DEFAULT_IGNORE_FILE = ".pip-audit-ignore.yml"


def _requirement_lines(path: Path, seen: Set[Path]) -> Iterable[Tuple[Path, str]]:
    """Requirement strings in ``path`` and the files it ``-r``-includes."""
    path = path.resolve()
    if path in seen or not path.is_file():
        return
    seen.add(path)
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        include = re.match(r"^(?:-r|--requirement)\s+(\S+)", line)
        if include:
            yield from _requirement_lines(path.parent / include.group(1), seen)
            continue
        if line.startswith("-"):
            continue  # --index-url, -e, --find-links ...: not a version claim
        yield path, line


def stale_requirements(files: Iterable[Path]) -> List[str]:
    """Human-readable problems: requirements the environment does not meet."""
    problems: List[str] = []
    seen: Set[Path] = set()
    for path in files:
        for source, line in _requirement_lines(path, seen):
            try:
                req = Requirement(line)
            except InvalidRequirement:
                continue  # a URL or local path; nothing to compare
            if req.marker is not None and not req.marker.evaluate():
                continue  # applies to another platform / Python version
            try:
                installed = metadata.version(req.name)
            except metadata.PackageNotFoundError:
                problems.append(
                    f"{req.name}: not installed (wants {req}; {source.name})"
                )
                continue
            if req.specifier and not req.specifier.contains(
                installed, prereleases=True
            ):
                problems.append(
                    f"{req.name}: {installed} installed, {source.name} wants {req.specifier}"
                )
    return problems


def load_ignores(
    path: Path, today: Optional[_dt.date] = None
) -> Tuple[List[str], List[str]]:
    """``(ids to ignore, problems)`` from the ignore file (absent = none)."""
    if not path.is_file():
        return [], []
    import yaml  # pylint: disable=import-outside-toplevel

    today = today or _dt.date.today()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    ids: List[str] = []
    problems: List[str] = []
    for entry in data.get("vulnerabilities") or []:
        vid = str((entry or {}).get("id") or "").strip()
        if not vid:
            problems.append(f"{path.name}: an entry has no id")
            continue
        if not str(entry.get("reason") or "").strip():
            problems.append(
                f"{path.name}: {vid} has no reason -- every ignore must say why"
            )
            continue
        expires = entry.get("expires")
        if expires is not None:
            if isinstance(expires, str):
                try:
                    expires = _dt.date.fromisoformat(expires)
                except ValueError:
                    problems.append(
                        f"{path.name}: {vid} has an unreadable expires date"
                    )
                    continue
            if expires < today:
                problems.append(
                    f"{path.name}: the ignore for {vid} expired on {expires}; "
                    "re-check it and remove it or extend it with a new reason"
                )
                continue
        ids.append(vid)
    return ids, problems


def run_pip_audit(ignores: List[str], strict: bool) -> int:
    """pip-audit over the installed environment; its exit status."""
    try:
        import pip_audit  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import
    except ImportError:
        print(
            "ERROR: pip-audit is not installed in this environment; run `make install-dev`."
        )
        return 1
    argv = [sys.executable, "-m", "pip_audit"]
    if strict:
        argv.append("--strict")
    for vid in ignores:
        argv += ["--ignore-vuln", vid]
    return subprocess.call(argv)  # nosec B603 -- fixed argv, no shell


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--requirements",
        nargs="*",
        default=list(DEFAULT_REQUIREMENTS),
        help="requirements files to check (relative to the repository root)",
    )
    parser.add_argument("--ignore-file", default=DEFAULT_IGNORE_FILE)
    parser.add_argument("--strict", action="store_true", help="pip-audit --strict")
    args = parser.parse_args(argv)
    # pip-audit writes straight to the terminal; keep this script's lines in order.
    sys.stdout.reconfigure(line_buffering=True)

    print("Checking that the environment meets the requirements files...")
    stale = stale_requirements(REPO / name for name in args.requirements)
    if stale:
        print("ERROR: this environment does not match the requirements files:")
        for line in stale:
            print(f"  - {line}")
        print(
            "Run `make install-dev` to bring it up to date, then re-run `make security`."
        )
        return 1
    print("[OK] every requirement is satisfied")

    ignores, problems = load_ignores(REPO / args.ignore_file)
    if problems:
        print(f"ERROR: {args.ignore_file} needs attention:")
        for line in problems:
            print(f"  - {line}")
        return 1
    if ignores:
        print(
            f"pip-audit ignoring {len(ignores)} reviewed advisory(ies) from {args.ignore_file}"
        )
    print("Running pip-audit against the installed environment...")
    status = run_pip_audit(ignores, args.strict)
    if status:
        print(
            "Upgrade the package (add a floor to the requirements file when it is "
            "transitive), or record a reviewed exception in "
            f"{args.ignore_file} with a reason and an expires date."
        )
    return status


if __name__ == "__main__":
    sys.exit(main())
