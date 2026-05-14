# Git hooks

This directory holds the project's shareable git hooks.  They're
activated by pointing `core.hooksPath` at this directory (instead of
the default `.git/hooks/` which is not version-controlled).

## Installation

Run `make install-hooks` from the repo root once after cloning.  It
sets `core.hooksPath = .githooks` for this clone — idempotent, safe to
re-run.  `make install-dev` runs `make install-hooks` automatically as
its last step, so for most contributors there's nothing to do beyond
the normal setup workflow.

## Active hooks

### `pre-push`

Runs `make lint` before allowing a push to remote.  If linting fails,
the push is blocked with an error pointing at the failing tool
(Black, pylint, eslint, i18n validator, etc).  In a genuine emergency
the hook can be bypassed with `git push --no-verify`, but the next CI
run will fail the same way so the bypass only delays the fix.

## Bypassing the install (not recommended)

If for any reason you don't want the hooks active in your clone, run
`git config --unset core.hooksPath` — but please don't push without
running `make lint` first, or CI will reject the change anyway.
