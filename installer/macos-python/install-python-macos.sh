#!/bin/sh
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

# install-python-macos.sh -- find (or install) the Python the SysManage
# agent's virtual environment is built from on macOS, and print its path.
#
# The agent needs Python 3.10 or newer: its dependencies ship their security
# fixes only for 3.10+ (aiohttp 3.14, urllib3 2.7).  A stock Mac's python3 is
# Apple's (Xcode Command Line Tools), Python 3.9.  So where the Mac's Python is
# too old, the agent brings its own: a pinned python-build-standalone build,
# installed under /opt/sysmanage-agent/python.  The same approach as the
# SysManage server's installer/python/install-python-linux.sh.
#
# Usage:
#   install-python-macos.sh [--prefix DIR] [--keep-archive DIR]
#
#   Prints the absolute path of the interpreter to use on stdout; everything
#   else goes to stderr.  Exits nonzero when no suitable Python can be had.
#
# Order:
#   1. python3 (or python3.N) on PATH when it is 3.10 or newer -> use it
#   2. a Python this script installed earlier, still the pinned build
#   3. the pinned archive from $SYSMANAGE_PYTHON_BUNDLE
#   4. the pinned archive downloaded from python-build-standalone's
#      GitHub release
#   An archive is installed only when its sha256 matches the value pinned
#   below, wherever it came from.  Never pipes a download into a shell.

PBS_TAG="20261110"
PBS_PYTHON="3.12.16"
PBS_URL="${SYSMANAGE_PYTHON_URL:-https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}}"
MIN_MINOR=10

PREFIX="/opt/sysmanage-agent/python"
KEEP_DIR=""
BUNDLE_DIR="${SYSMANAGE_PYTHON_BUNDLE:-/opt/sysmanage-agent/installer/python}"

say() { printf '%s\n' "$*" >&2; }
warn() { printf '[!] %s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
	case "$1" in
		--prefix) PREFIX="$2"; shift 2 ;;
		--keep-archive) KEEP_DIR="$2"; shift 2 ;;
		-h|--help) say "usage: $0 [--prefix DIR] [--keep-archive DIR]"; exit 0 ;;
		*) say "usage: $0 [--prefix DIR] [--keep-archive DIR]"; exit 2 ;;
	esac
done

# The pinned archive and its sha256 for this machine's architecture.
# From SHA256SUMS of release $PBS_TAG.
case "$(uname -m)" in
	arm64|aarch64)
		TRIPLE="aarch64-apple-darwin"
		SHA256="2f11b8aa3726bdbd87dd9eb76568412faddf4f47e26913fa45d6a2e424972acd" ;;
	x86_64)
		TRIPLE="x86_64-apple-darwin"
		SHA256="b78a4c479f1964ec484880bee567568266f68da102269fb93a05fe8716b45f91" ;;
	*)
		TRIPLE=""
		SHA256="" ;;
esac
ARCHIVE="cpython-${PBS_PYTHON}+${PBS_TAG}-${TRIPLE}-install_only_stripped.tar.gz"
STAMP="$PREFIX/.sysmanage-agent-python"

# 1. A new enough system Python.
for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
	path="$(command -v "$candidate" 2>/dev/null)" || continue
	if "$path" -c "import sys; sys.exit(sys.version_info < (3, $MIN_MINOR))" 2>/dev/null; then
		printf '%s\n' "$path"
		exit 0
	fi
done

if [ -z "$TRIPLE" ]; then
	warn "this system's Python is older than 3.$MIN_MINOR, and there is no"
	warn "bundled Python for the $(uname -m) architecture."
	warn "Install Python 3.$MIN_MINOR or newer as python3, then reinstall the agent."
	exit 1
fi

# 2. Installed earlier, and still the pinned build.
if [ -x "$PREFIX/bin/python3" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$ARCHIVE" ]; then
	printf '%s\n' "$PREFIX/bin/python3"
	exit 0
fi

sha256_of() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		return 1
	fi
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -T 20 -t 3 -O "$2" "$1"
	else
		warn "neither curl nor wget is installed; cannot download Python"
		return 1
	fi
}

WORK="$(mktemp -d)" || exit 1
trap 'rm -rf "$WORK"' EXIT

# 3. The air-gap bundle's copy, else 4. the release download.
if [ -f "$BUNDLE_DIR/$ARCHIVE" ]; then
	say "Using the bundled Python $PBS_PYTHON ($BUNDLE_DIR)"
	cp "$BUNDLE_DIR/$ARCHIVE" "$WORK/$ARCHIVE" || exit 1
else
	say "This system's Python is older than 3.$MIN_MINOR; downloading Python $PBS_PYTHON"
	if ! download "$PBS_URL/$ARCHIVE" "$WORK/$ARCHIVE"; then
		warn "could not download $PBS_URL/$ARCHIVE"
		warn "On a Mac without internet access, use the air-gap bundle, or"
		warn "copy that file into $BUNDLE_DIR and reinstall the agent."
		exit 1
	fi
fi

actual="$(sha256_of "$WORK/$ARCHIVE")" || {
	warn "no sha256 tool (shasum, sha256sum or openssl) available; refusing to install Python unverified"
	exit 1
}
if [ "$actual" != "$SHA256" ]; then
	warn "$ARCHIVE has sha256 $actual, expected $SHA256; refusing to install it"
	exit 1
fi

# Unpack beside the prefix, then swap it in, so a failure halfway never
# leaves a broken interpreter where a working one was.
parent="$(dirname "$PREFIX")"
mkdir -p "$parent" || exit 1
NEW="$(mktemp -d "$parent/.python-new.XXXXXX")" || exit 1
if ! tar -xzf "$WORK/$ARCHIVE" -C "$NEW" || [ ! -x "$NEW/python/bin/python3" ]; then
	warn "could not unpack $ARCHIVE"
	rm -rf "$NEW"
	exit 1
fi
printf '%s\n' "$ARCHIVE" > "$NEW/python/.sysmanage-agent-python"
rm -rf "$PREFIX.old"
[ -e "$PREFIX" ] && mv "$PREFIX" "$PREFIX.old"
if ! mv "$NEW/python" "$PREFIX"; then
	warn "could not install Python in $PREFIX"
	[ -e "$PREFIX.old" ] && mv "$PREFIX.old" "$PREFIX"
	rm -rf "$NEW"
	exit 1
fi
rm -rf "$NEW" "$PREFIX.old"

if [ -n "$KEEP_DIR" ]; then
	mkdir -p "$KEEP_DIR" && cp "$WORK/$ARCHIVE" "$KEEP_DIR/" || exit 1
fi

say "Installed Python $PBS_PYTHON in $PREFIX"
printf '%s\n' "$PREFIX/bin/python3"
