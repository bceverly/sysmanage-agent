#!/bin/sh
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
#
# link-openbsd-package.sh VENV_PYTHON PACKAGE...
#
# A PACKAGE written ?NAME is optional: linked only where this OpenBSD release
# packages it (py3-grpcio exists on 8.0, not 7.9), otherwise left to pip.
#
# Use OpenBSD's own build of a Python package inside a venv instead of letting
# pip build it from source.  Each PACKAGE (an OpenBSD package name such as
# py3-cryptography) is installed with pkg_add if missing, and ONLY its own
# files are linked into the venv's site-packages -- no other system package
# leaks in -- so pip then sees it as installed.  The packaged distribution's
# declared runtime dependencies are installed into the venv with pip.
#
# Why: some packages cannot be built from source on OpenBSD at all, or only
# slowly.  OpenBSD 8.0's LibreSSL 4.4.0 is newer than the Rust openssl-sys
# crate accepts (LibreSSL <= 4.3.x), so `pip install cryptography` fails
# there; the py3-cryptography package is patched by OpenBSD ports.  grpcio
# (py3-grpcio, 8.0+) otherwise takes a 5-10 minute patched source build.
#
# Each linked distribution is pinned at its packaged version in
# <venv>/openbsd-constraints.txt; installers pass it to pip (-c), so an
# --upgrade cannot replace the package with a source build.
#
# The venv's Python must be the system's (the package is built for it).
set -e

PY="$1"
shift
if [ -z "$PY" ] || [ $# -eq 0 ]; then
	echo "usage: link-openbsd-package.sh VENV_PYTHON PACKAGE..." >&2
	exit 2
fi

SITE=$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
SYS=$("$PY" -c 'import sys, sysconfig; print(sysconfig.get_paths(vars={"base": sys.base_prefix, "platbase": sys.base_prefix})["purelib"])')
CONSTRAINTS=$("$PY" -c 'import os, sys; print(os.path.join(sys.prefix, "openbsd-constraints.txt"))')
DISTS=""
: >"$CONSTRAINTS"

for pkg in "$@"; do
	case "$pkg" in
	\?*)
		pkg=${pkg#?}
		if ! pkg_info -e "${pkg}-*" >/dev/null 2>&1 &&
			! pkg_info -Q "$pkg" 2>/dev/null | grep -q "^${pkg}-[0-9]"; then
			echo "[INFO] This OpenBSD release does not package ${pkg} -- pip builds it"
			continue
		fi
		;;
	esac
	if ! pkg_info -e "${pkg}-*" >/dev/null 2>&1; then
		echo "[INFO] Installing the OpenBSD package ${pkg}..."
		doas pkg_add "$pkg" || {
			echo "[ERROR] Could not install ${pkg}. Run:  doas pkg_add ${pkg}  and re-run this make target." >&2
			exit 1
		}
	fi
	# Top-level entries of the package under the system site-packages:
	# package directories, .dist-info, and single-file modules.
	entries=$(pkg_info -L "$pkg" | sed -n "s|^${SYS}/\([^/]*\).*|\1|p" | sort -u)
	if [ -z "$entries" ]; then
		echo "[ERROR] ${pkg} installs nothing under ${SYS} -- is it built for this Python?" >&2
		exit 1
	fi
	for entry in $entries; do
		case "$entry" in
		*.dist-info)
			name=${entry%.dist-info}
			version=${name##*-}
			name=${name%-*}
			"$PY" -m pip uninstall -y -q "$name" >/dev/null 2>&1 || true
			DISTS="$DISTS $name"
			echo "${name}==${version}" >>"$CONSTRAINTS"
			;;
		esac
	done
	for entry in $entries; do
		ln -sfn "${SYS}/${entry}" "${SITE}/${entry}"
	done
	echo "[OK] ${pkg} linked into the venv"
done

# The linked distributions' own runtime requirements (markers are evaluated
# by pip; extras are left out).
[ -n "$DISTS" ] || exit 0
# shellcheck disable=SC2086
"$PY" -c '
import sys
from importlib.metadata import requires
for name in sys.argv[1:]:
    for req in requires(name) or []:
        if "extra ==" not in req:
            print(req)
' $DISTS | "$PY" -m pip install -q -r /dev/stdin
