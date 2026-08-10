#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Static validation of the FreeBSD port skeleton — ROADMAP Phase 19.

WHY THIS EXISTS
---------------
The port has never been built by a real ports tree: CI renders it and tarballs
it, and that is all.  Reviewing it on 2026-08-07 ahead of a possible ports-tree
submission turned up three defects that only a build would otherwise have
caught, and a committer would have bounced on sight:

* ``# $FreeBSD$`` and ``# Created by:`` — removed when FreeBSD moved to git in
  2021, and still present here.
* ``USE_PYTHON=autoplist`` on a ``NO_BUILD`` port with a hand-written
  ``do-install``.  autoplist generates the packing list for setuptools-
  installed modules; this port has no setup.py at all.  The two mechanisms
  together produce a wrong plist.
* ``pkg-plist`` listed 3 files while ``do-install`` staged ~290 — every
  unlisted staged file fails stage-qa.
* ``MASTER_SITES``/``DISTFILES``/``DIST_SUBDIR`` declared alongside
  ``USE_GITHUB=yes``, which derives all three.

Shared with the sysmanage repo, which has the same skeleton and had the same
defects; keep the two copies in step.

This is NOT a substitute for ``portlint -AC`` and ``poudriere testport``, which
need an actual FreeBSD host; it catches the classes above cheaply, on Linux, in
CI, so they cannot come back.  A real build remains the bar before submission.

Exit status: 0 clean, 1 problems found.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PORT_DIR = Path("packaging/freebsd-ports/sysutils/sysmanage-agent")

# Keywords FreeBSD removed with the git migration.  A port carrying them is
# immediately dated to pre-2021 in a reviewer's eyes.
DEAD_KEYWORDS = ("$FreeBSD$", "# Created by:")

REQUIRED_VARS = ("PORTNAME", "CATEGORIES", "MAINTAINER", "COMMENT", "WWW", "LICENSE")


# Substitutions bsd.port.mk performs on USE_RC_SUBR scripts without the port
# asking.  Anything else in %%...%% has to come from SUB_LIST, or it is
# installed verbatim.
FRAMEWORK_SUBS = frozenset(
    {
        "PREFIX",
        "LOCALBASE",
        "PORTNAME",
        "DATADIR",
        "DOCSDIR",
        "ETCDIR",
        "EXAMPLESDIR",
        "WWWDIR",
        "PYTHON_INCLUDEDIR",
        "PYTHON_LIBDIR",
        "PYTHON_PLATFORM",
        "PYTHON_SITELIBDIR",
        "PYTHON_SUFFIX",
        "PYTHON_VER",
        "PYTHON_VERSION",
    }
)


def _rc_script_problems(path: Path, body: str, makefile: str) -> list[str]:
    """Defects that only bite when the SERVICE IS STARTED.

    Everything else this checker looks at — and portlint, check-plist,
    stage-qa and poudriere too — inspects a package at rest.  All of them
    passed a sysmanage package that could not start.  The two rules here are
    the two failures that cost the most to find, each reduced to the textual
    signature that would have caught it.
    """
    found: list[str] = []
    if not path.name.endswith(".in") or ". /etc/rc.subr" not in body:
        return found

    # Scan the CODE, not the prose.  The comment explaining why -u must not be
    # there necessarily quotes ``-u ${name}_user``, so matching raw text reports
    # the fixed script as broken — the mirror image of the ${TMPPLIST} check
    # below, where a comment made a dead check look alive.  Either way the rule
    # has to read what the shell reads.
    code = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )

    name_match = re.search(r"^name=(\S+)", code, re.M)

    # ``${name}_user`` belongs to rc.subr, not to the port.  Setting it makes
    # run_rc_command wrap the command in ``su -m <user> -c ...``, so a
    # ``daemon -u`` further down runs unprivileged and dies in initgroups():
    #     daemon[85969]: initgroups(sysmanage,253): Operation not permitted
    # Both drops are no-ops when the user is root, so this hides completely
    # until someone runs the service as anyone else.  Found 2026-08-10, and
    # only because daemon(8) logs to syslog by default — ``service onestart``
    # itself said nothing but "failed to start".
    if name_match:
        user_var = f"{name_match.group(1)}_user"
        declares_user = re.search(rf"^:\s*\$\{{{re.escape(user_var)}:", code, re.M)
        drops_again = re.search(r"(^|\s)-u\s+\$?\{?\w", code, re.M)
        if declares_user and drops_again:
            found.append(
                f"files/{path.name}: sets ${{{user_var}}} (an rc.subr knob that "
                "already runs the command under su) AND passes -u to daemon; the "
                "second drop fails in initgroups() for any non-root user — drop "
                "the -u"
            )

    # A %%TOKEN%% with no SUB_LIST entry is installed literally.  The rc script
    # then execs the string "%%PYTHON_CMD%%", which is not a program, and the
    # service fails with nothing useful anywhere.  The port builds, packages,
    # passes check-plist and stage-qa, and installs — found 2026-08-10 only by
    # running ``sh -x`` on the INSTALLED rc script.
    declared = set(re.findall(r"SUB_LIST\s*[+?]?=\s*([^\n]*)", makefile))
    provided = set()
    for chunk in declared:
        provided.update(re.findall(r"(\w+)=", chunk))
    for token in sorted(set(re.findall(r"%%(\w+)%%", code))):
        if token not in provided and token not in FRAMEWORK_SUBS:
            found.append(
                f"files/{path.name}: uses %%{token}%% but the Makefile's SUB_LIST "
                f"does not define {token}; it installs verbatim and the service "
                "fails at exec"
            )

    return found


def _problems(port_dir: Path) -> list[str]:
    found: list[str] = []
    makefile = port_dir / "Makefile"
    plist = port_dir / "pkg-plist"

    if not makefile.is_file():
        return [f"{makefile}: missing"]
    text = makefile.read_text(encoding="utf-8")

    for dead in DEAD_KEYWORDS:
        if dead in text:
            found.append(
                f"Makefile: contains '{dead}', removed when FreeBSD moved to git "
                "in 2021 — a committer will reject this"
            )

    # files/ TOO, not just the Makefile.  ``$FreeBSD$`` sat in both rc scripts
    # for months while this checker passed the ports, because it only ever read
    # Makefile — a gate that inspects one file cannot speak for a directory.
    # Found 2026-08-09 in a committer's own triage diff, which is the expensive
    # way to learn it.
    files_dir = port_dir / "files"
    if files_dir.is_dir():
        for extra in sorted(files_dir.iterdir()):
            if not extra.is_file():
                continue
            try:
                body = extra.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for dead in DEAD_KEYWORDS:
                if dead in body:
                    found.append(
                        f"files/{extra.name}: contains '{dead}', removed when "
                        "FreeBSD moved to git in 2021"
                    )
            found.extend(_rc_script_problems(extra, body, text))

    for var in REQUIRED_VARS:
        if not re.search(rf"^{var}\s*[?+]?=", text, re.M):
            found.append(f"Makefile: no {var}= (required by the ports framework)")

    # autoplist only makes sense for a setuptools build.  Flag it when the port
    # also hand-installs, which is the combination that silently mis-stages.
    if re.search(r"^USE_PYTHON\s*=.*autoplist", text, re.M):
        if re.search(r"^NO_BUILD\s*=\s*yes", text, re.M) or "do-install:" in text:
            found.append(
                "Makefile: USE_PYTHON=autoplist together with NO_BUILD/do-install "
                "— autoplist is for setuptools-installed modules; a hand-staged "
                "tree needs an explicit plist (or a TMPPLIST append)"
            )

    # The plist must account for everything do-install stages.  We cannot run
    # the install, so check the weaker but decisive property: if do-install
    # copies a TREE, something must generate plist entries for it.
    if "do-install:" in text:
        # Strip comments first.  Checking the raw text let the explanatory
        # COMMENT about ${TMPPLIST} satisfy the check while the actual append
        # was gone — a gate that cannot fail for the right reason is worse than
        # no gate, so match the redirect in real recipe lines only.
        code = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        # \}? matters: the recipe writes ${COPYTREE_SHARE}, so a pattern
        # demanding whitespace straight after SHARE matches nothing and the
        # whole check silently passes.  It did, until a deliberately-broken
        # fixture proved the check was inert.
        copies_tree = re.search(r"COPYTREE_(SHARE|BIN)\}?\s+\S+", code)
        appends_plist = re.search(r">>\s*\$\{TMPPLIST\}", code) is not None
        if copies_tree and not appends_plist:
            tree = copies_tree.group(0)
            found.append(
                f"Makefile: do-install stages a tree ({tree}) but nothing appends "
                "those files to ${TMPPLIST}; pkg-plist cannot list them by hand "
                "and stage-qa fails on every unlisted file"
            )

    # USE_GITHUB derives MASTER_SITES/DISTFILES/DISTNAME itself.  Declaring
    # them alongside it is redundant, portlint warns, and the two can disagree
    # about what actually gets fetched.
    if re.search(r"^USE_GITHUB\s*=\s*yes", text, re.M):
        for var in ("MASTER_SITES", "DISTFILES", "DIST_SUBDIR"):
            if re.search(rf"^{var}\s*[?+]?=", text, re.M):
                found.append(
                    f"Makefile: {var}= is set alongside USE_GITHUB=yes, which "
                    "derives it — remove one or they can disagree about the "
                    "fetched distfile"
                )

    # A dependency version FLOOR is a trap in a port.  FreeBSD ships exactly ONE
    # version of each port, so `py312-alembic>=1.16.5` against a tree carrying
    # 1.16.2 makes this port permanently unbuildable for everyone: the floor is
    # unmet, the framework falls back to a source build, and that build still
    # produces 1.16.2.  Found on a real ports tree on 2026-08-08 — portlint
    # passes it, because portlint does not resolve versions.  Floors are
    # meaningful in requirements.txt and meaningless-to-harmful in a port; the
    # right way to require a newer dependency is to update THAT port in the
    # tree, not to declare a bound this port cannot satisfy.
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#") and ">=" in stripped and ":" in stripped:
            match = re.search(r"(\S+)>=([^:\s]+):(\S+)", stripped)
            if match:
                found.append(
                    f"Makefile: dependency '{match.group(1)}' declares a version "
                    f"floor (>={match.group(2)}); FreeBSD carries one version per "
                    "port, so an unmet floor makes the port unbuildable — use >0"
                )

    if plist.is_file():
        raw = [
            line.strip()
            for line in plist.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        # pkg-plist has NO comment syntax.  Every line is an entry, so a '#'
        # line becomes a file path: check-plist reports "Missing: # ..." and
        # pkg-create fails with "Unable to access file .../usr/local/# ...".
        # This checker used to skip '#' lines as comments, which is what let
        # six of them reach a real build on 2026-08-10 — a gate that shares the
        # bug it is meant to catch is worse than no gate.  Use @comment if a
        # note really has to live in the plist.
        for entry in raw:
            if entry.startswith("#"):
                found.append(
                    f"pkg-plist: '{entry[:50]}' starts with '#', but pkg-plist "
                    "has no comment syntax — it will be treated as a file path "
                    "(use @comment, or move the note to the Makefile)"
                )
        entries = [e for e in raw if not e.startswith("#")]
        if not entries:
            found.append("pkg-plist: empty")
        for entry in entries:
            # Keyword lines (@dir, @sample, @owner, ...) legitimately carry
            # absolute paths: /var and /etc are outside ${PREFIX} and cannot be
            # expressed any other way.  Only plain file entries are relative.
            if entry.startswith("@"):
                continue
            if entry.startswith("/"):
                found.append(
                    f"pkg-plist: '{entry}' is absolute; entries are relative to "
                    "${PREFIX}"
                )
    else:
        found.append("pkg-plist: missing")

    return found


def _release_readiness(port_dir: Path) -> list[str]:
    """Checks that only matter when SUBMITTING, not in day-to-day CI."""
    notes: list[str] = []
    distinfo = port_dir / "distinfo"
    if not distinfo.is_file():
        return ["distinfo: missing"]
    text = distinfo.read_text(encoding="utf-8")
    if re.search(r"SHA256 .*= 0{64}", text) or "SIZE (" in text and "= 0\n" in text:
        notes.append(
            "distinfo still holds the release-time placeholder (zeros). Run "
            "`make makesum` against the published tarball before submitting."
        )
    return notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port-dir", default=str(PORT_DIR), type=Path)
    parser.add_argument(
        "--submission",
        action="store_true",
        help="also apply checks that only matter when submitting upstream",
    )
    args = parser.parse_args()

    problems = _problems(args.port_dir)
    if args.submission:
        problems += _release_readiness(args.port_dir)

    if problems:
        print(f"FAIL: {len(problems)} problem(s) in {args.port_dir}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nNote: this is a static check.  `portlint -AC` and "
            "`poudriere testport` on a real FreeBSD host remain the bar before "
            "a ports-tree submission.",
            file=sys.stderr,
        )
        return 1

    print(f"[OK] FreeBSD port skeleton at {args.port_dir} passes static checks.")
    if not args.submission:
        print("     (run with --submission before sending it upstream)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
