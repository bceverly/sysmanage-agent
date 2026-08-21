#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Cut a release: bump version markers, COMMIT, then TAG, then push.

The ordering is the entire point.  The old ritual was `git tag` first (because
``check_version_drift.py`` resolved the version from an already-existing tag),
then bump, then commit -- which leaves the tag pointing at the commit BEFORE the
one carrying the work.  CI checks out the tag and faithfully rebuilds the old
tree.  That is how v3.5.1.24 shipped with broken OpenBSD and Flatpak jobs whose
fixes were already on main, and v3.5.1.25 the same way for the Windows ARM64
MSI.  Tagging last makes that impossible.

This is Python rather than Makefile shell on purpose: these repos are built on
Windows too, where make drives cmd.exe and ``test`` / ``grep`` / ``sed`` do not
exist.  Every git call here goes through subprocess with an argument LIST and no
shell, so quoting behaves the same on Windows, Linux, macOS and the BSDs.

Identical file in all four repos.  Everything repo-specific is discovered:
version markers are bumped only when ``scripts/check_version_drift.py`` exists,
so a docs-only repo just gets a tag.

    python scripts/release.py --version 3.5.1.26 --message "..."
    python scripts/release.py --version 3.5.1.26 --dry-run
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess  # nosec B404 - git plumbing, argument lists only, never shell
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories whose contents ship.  An untracked file in one of these would be
# absent from the release commit -- `git commit -a` stages modified TRACKED
# files and silently skips untracked ones -- while code importing it ships.
# Only those that exist in this repo are checked.
CANDIDATE_SRC_DIRS = (
    "src",
    "backend",
    "frontend/src",
    "alembic",
    "scripts",
    "installer",
    "packaging",
    ".githooks",
)

VERSION_RE = re.compile(r"^\d+(\.\d+){3}$")
TAG_RE = re.compile(r"^refs/tags/v?(\d+(?:\.\d+){3})(?:\^\{\})?$")


def git(
    *args: str, check: bool = True, timeout: int = 120
) -> subprocess.CompletedProcess:
    """Run a git command in the repo root.  Never uses a shell."""
    return (
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no user interpolation
            ["git", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )
    )


def fail(*lines: str) -> int:
    """Print an error block and return the failing exit code."""
    print("ERROR: " + lines[0], file=sys.stderr)
    for line in lines[1:]:
        print("       " + line, file=sys.stderr)
    return 1


def parse_version(text: str):
    """``"v3.5.1.26"`` -> ``(3, 5, 1, 26)``; None when not four numeric parts."""
    bare = text.lstrip("v")
    if not VERSION_RE.match(bare):
        return None
    return tuple(int(p) for p in bare.split("."))


def known_tags() -> set:
    """Four-part version tags known locally AND on origin.

    Origin matters: a version can be released while its local tag has been
    deleted, and re-cutting it would collide only at push time -- after the
    commit and tag already exist locally.
    """
    tags = set()
    local = git("tag", "--list", check=False)
    if local.returncode == 0:
        for line in local.stdout.splitlines():
            parsed = parse_version(line.strip())
            if parsed:
                tags.add(parsed)
    try:
        remote = git("ls-remote", "--tags", "origin", check=False, timeout=60)
    except subprocess.TimeoutExpired:
        print(
            "WARNING: `git ls-remote` timed out; checked local tags only",
            file=sys.stderr,
        )
        return tags
    if remote.returncode != 0:
        print(
            "WARNING: could not reach origin; checked local tags only", file=sys.stderr
        )
        return tags
    for line in remote.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        match = TAG_RE.match(parts[1].strip())
        if match:
            parsed = parse_version(match.group(1))
            if parsed:
                tags.add(parsed)
    return tags


def untracked_source_files() -> list:
    """Non-ignored untracked files under the directories that ship."""
    dirs = [d for d in CANDIDATE_SRC_DIRS if (REPO_ROOT / d).exists()]
    if not dirs:
        return []
    result = git("ls-files", "--others", "--exclude-standard", "--", *dirs, check=False)
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def dirty_paths() -> set:
    """Paths of tracked files that currently differ from HEAD."""
    result = git("status", "--porcelain", "--untracked-files=no", check=False)
    if result.returncode != 0:
        return set()
    return {line[3:].strip() for line in result.stdout.splitlines() if line.strip()}


def restore_markers(paths) -> None:
    """Undo the version bump.  Safe because check_guards already proved the
    tree was clean, so nothing of yours can be inside these files."""
    if not paths:
        return
    git("checkout", "--", *sorted(paths), check=False)
    print(f"Restored {len(paths)} version-marker file(s) to their pre-release state.")


def modified_tracked_files() -> list:
    """Tracked files with staged or unstaged modifications."""
    result = git("status", "--porcelain", "--untracked-files=no", check=False)
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def check_guards(version: str, want, allow_untracked: bool, allow_dirty: bool):
    """Every refusal happens here, BEFORE anything is modified."""
    tags = known_tags()
    if tags:
        highest = max(tags)
        if want <= highest:
            highest_str = ".".join(str(p) for p in highest)
            relation = "the same as" if want == highest else "older than"
            return fail(
                f"v{version} is {relation} the highest existing tag v{highest_str}.",
                "Releases only move forward -- pick a higher version.",
            )
        if want in tags:
            return fail(f"tag v{version} already exists.", "Pick a higher version.")
        print(
            f"Version check: v{version} > highest existing tag "
            f"v{'.'.join(str(p) for p in highest)}"
        )
    else:
        print(
            "WARNING: no version tags resolvable; skipping newer-than check",
            file=sys.stderr,
        )

    if not allow_untracked:
        stray = untracked_source_files()
        if stray:
            return fail(
                "untracked file(s) under the shipping source tree:",
                *[f"  {s}" for s in stray],
                "'git commit -a' skips untracked files, so these would be MISSING",
                "from the release while code that imports them ships.",
                "Run: git add <file>   (or .gitignore them), then re-run.",
                "Deliberate?  make release ALLOW_UNTRACKED=1 ...",
            )

    # A release commit should contain the version bump and NOTHING else.
    # `git commit -a` below stages every modified tracked file, so unrelated
    # work-in-progress would be swept into "Release vX.Y.Z.W" and the tag would
    # then name a commit that is not what it claims to be.
    if not allow_dirty:
        dirty = modified_tracked_files()
        if dirty:
            return fail(
                "uncommitted change(s) to tracked files:",
                *[f"  {d}" for d in dirty],
                "`make release` commits with `git commit -a`, so these would be",
                'swept into the "Release v..." commit next to the version bump,',
                "leaving a tag that does not describe what it contains.",
                "Commit or stash them first, then re-run.",
                "Deliberate?  make release ALLOW_DIRTY=1 ...",
            )
    return 0


def bump_markers(version: str, dry_run: bool) -> int:
    """Bump on-disk version markers when this repo tracks any."""
    drift = REPO_ROOT / "scripts" / "check_version_drift.py"
    if not drift.exists():
        print("No check_version_drift.py in this repo - nothing to bump, tag only.")
        return 0
    args = [sys.executable, str(drift), "--version", version]
    if not dry_run:
        args.append("--fix")
    # The child writes straight to the inherited stdout; flush ours first or
    # our buffered prints surface AFTER its output and the log reads backwards.
    sys.stdout.flush()
    # Semgrep flags this as a subprocess call reachable from the environment,
    # which is true of the ORIGIN of `version` and not of its VALUE: main()
    # rebuilds it from parsed integers, so it can only ever be four
    # dot-separated numbers.  argv is a fixed list and shell=False, so even a
    # hostile value would be one argv element, never a command.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args
    result = subprocess.run(  # nosec B603 - fixed argv from this repo, no shell
        args, cwd=REPO_ROOT, check=False
    )
    # Without --fix the script reports drift as a non-zero exit; before a
    # release that drift is EXPECTED, so it is informational here.
    if dry_run:
        return 0
    return result.returncode


def run_lint(version: str) -> int:
    """Run the repo's own `make lint` gate, matching the pre-push hook.

    Deliberately BEFORE the commit.  The hook runs this at PUSH time, which in a
    release is after the commit and tag already exist -- so a `format-python`
    failure (black had to reformat) would strand a tagged commit that cannot be
    pushed.  Running it first means reformatted files land IN the release commit,
    and any other gate failure aborts with nothing committed and nothing tagged.

    Mirrors the hook's shell selection: gmake on the BSDs, and SHELL=cmd.exe on
    Windows so make does not switch to Unix-shell mode just because MSYS put
    sh.exe on PATH.
    """
    if not (REPO_ROOT / "Makefile").exists():
        return 0
    if sys.platform.startswith("win"):
        cmd = ["make", "SHELL=cmd.exe", "lint"]
    elif sys.platform.startswith(("freebsd", "openbsd", "netbsd")):
        cmd = ["gmake", "lint"]
    else:
        cmd = ["make", "lint"]
    print(f"=== running '{' '.join(cmd)}' before committing ===")
    sys.stdout.flush()
    # The markers were just bumped to the version we are ABOUT to tag, but
    # lint-version resolves the expected version from the highest PUBLISHED
    # tag -- which is still the previous release, because this one is not
    # pushed yet.  Left alone the two disagree by construction and every
    # release fails its own lint.  make picks env vars up as variables, and
    # lint-version forwards this one to check_version_drift.py --version.
    env = dict(os.environ, SYSMANAGE_RELEASE_VERSION=version)
    try:
        result = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            cmd, cwd=REPO_ROOT, check=False, env=env
        )
    except FileNotFoundError:
        print("WARNING: make not found; skipping the lint gate", file=sys.stderr)
        return 0
    return result.returncode


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Cut a release (bump, commit, tag, push)."
    )
    parser.add_argument(
        "--version",
        default=None,
        metavar="X.Y.Z.W",
        help=(
            "Explicit version.  Omit to auto-increment the LAST component of "
            "the highest existing tag (3.5.1.26 -> 3.5.1.27), which is the "
            "normal case; pass it to start a new series at a phase boundary."
        ),
    )
    parser.add_argument("--message", default=None, help="Commit and tag message.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Run guards, change nothing."
    )
    parser.add_argument("--allow-untracked", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument(
        "--skip-lint", action="store_true", help="Skip the pre-commit `make lint` gate."
    )
    parser.add_argument(
        "--yes", action="store_true", help="Do not confirm an auto-derived version."
    )
    args = parser.parse_args()

    skip_lint = args.skip_lint
    derived = False
    if args.version:
        version = args.version.lstrip("v")
        want = parse_version(version)
        if want is None:
            return fail(
                f"VERSION must be four numeric parts, e.g. 3.5.1.26 (got: {args.version}).",
                "Every tag in these repos is four-part; a short version would rewrite",
                "the .spec/APKBUILD markers to a value CI never builds.",
            )
        # Rebuild from the parsed INTEGERS rather than reusing the input
        # string.  Both are equal here by construction, but only this one is
        # provably four numeric parts at the point it is handed to a
        # subprocess and written into a git tag -- "it was validated earlier"
        # is exactly the reasoning that stops holding after the next edit.
        version = ".".join(str(part) for part in want)
    else:
        tags = known_tags()
        if not tags:
            return fail(
                "no existing version tag to increment from.",
                "Pass an explicit version: make release VERSION=1.0.0.0",
            )
        highest = max(tags)
        want = highest[:-1] + (highest[-1] + 1,)
        version = ".".join(str(p) for p in want)
        derived = True
        print(
            f"Auto-increment: v{'.'.join(str(p) for p in highest)} -> v{version}  "
            f"(pass VERSION=x.y.z.w to start a new series)"
        )

    tag = f"v{version}"
    message = args.message or f"Release {tag}"

    guard = check_guards(version, want, args.allow_untracked, args.allow_dirty)
    if guard:
        return guard

    # A bare `make release` now publishes.  Confirm the derived number when a
    # human is watching -- one keystroke, and it makes a mistyped/tab-completed
    # `make release` recoverable instead of a pushed tag and a full CI run.
    if derived and not args.dry_run and not args.yes and sys.stdin.isatty():
        answer = input(f"Release v{version} from this branch? [Y/n] ").strip().lower()
        if answer and not answer.startswith("y"):
            print("Aborted; nothing was changed.")
            return 1

    if args.dry_run:
        has_markers = (REPO_ROOT / "scripts" / "check_version_drift.py").exists()
        if has_markers:
            print(
                "--- version markers that WOULD be bumped (drift here is expected) ---"
            )
        bump_markers(version, dry_run=True)
        bump = "bump the version markers, " if has_markers else ""
        lint = "" if skip_lint else "run `make lint`, "
        print(
            f"[dry-run] all guards passed.  A real run would {bump}{lint}commit "
            f'the version-marker bump as "{message}", tag {tag} on THAT commit, then push '
            f"the branch and the tag.  Nothing was changed."
        )
        return 0

    bumped = dirty_paths()
    if bump_markers(version, dry_run=False):
        return fail("version-marker bump failed; nothing committed or tagged.")
    bumped = [p for p in dirty_paths() if p not in bumped]

    if not skip_lint and run_lint(version):
        restore_markers(bumped)
        return fail(
            "`make lint` failed -- NOTHING was committed, tagged or left bumped.",
            "The version markers were restored, so the tree is as you left it.",
            "Fix the gate and re-run; if black reformatted files, those changes",
            "are yours to commit first.",
        )

    dirty = git("diff", "--quiet", "HEAD", check=False).returncode != 0
    if dirty:
        git("commit", "-a", "-m", message)
        print(f'Committed: "{message}"')
    else:
        print("Nothing to commit - tagging the current HEAD.")

    head = git("rev-parse", "--short", "HEAD").stdout.strip()
    git("tag", "-a", tag, "-m", message)
    print(f"=== {tag} tagged at {head} - pushing ===")

    for push in (["push"], ["push", "origin", tag]):
        result = git(*push, check=False, timeout=900)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            return fail(
                f"`git {' '.join(push)}` failed.",
                f"The commit and tag {tag} exist LOCALLY; fix the cause and re-push.",
                f"To undo the tag:  git tag -d {tag}",
            )

    print(f"[OK] {tag} pushed; the tag contains the commit it names.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
