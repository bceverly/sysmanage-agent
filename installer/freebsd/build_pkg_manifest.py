#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Write +COMPACT_MANIFEST and +MANIFEST for the FreeBSD agent package.

The release builds the FreeBSD .pkg on a Linux runner with bsdtar, so it
cannot run FreeBSD's ``pkg create``.  It has to write the manifests itself,
and until 2026-11-05 it got four things wrong, so the package installed
nothing a fresh FreeBSD host could run (found by installing 3.12.1.4 on a
new FreeBSD 14.5 VM):

  * no ``files`` section -- ``pkg`` registers and extracts only the files
    the manifest lists, so the package installed 0 bytes;
  * Python 3.11 dependencies (``py311-*``) -- FreeBSD's repository now
    builds these modules for Python 3.12 only, so ``pkg add`` stopped at
    "Missing dependency";
  * five runtime modules not declared at all (psutil, bcrypt, aiofiles,
    defusedxml, packaging);
  * a post-install that created a ``sysmanage`` account while the rc script
    runs the agent as ``sysmanage-agent``.

This script lists every staged file with its SHA-256 (``1$<hex>``, a
checksum form ``pkg`` accepts), declares the dependencies the agent imports,
and runs the post-install from ``post-install.sh`` beside it.  The archive
must then be packed with ABSOLUTE member paths (``bsdtar -P -s ',^usr,/usr,'``):
``pkg`` matches archive entries to the manifest by their full path, and a
relative ``usr/...`` entry matches nothing.

Usage: build_pkg_manifest.py <staging dir> <version>
"""

import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The agent's runtime imports (requirements-prod.txt) as FreeBSD packages.
# FreeBSD's default Python flavor is 3.12; every name here was checked
# against the FreeBSD 14.5 repository on 2026-11-05 (`pkg rquery`).
DEPS = {
    "python312": "lang/python312",
    "py312-websockets": "devel/py-websockets",
    "py312-pyyaml": "devel/py-pyyaml",
    "py312-aiohttp": "www/py-aiohttp",
    "py312-cryptography": "security/py-cryptography",
    "py312-psutil": "sysutils/py-psutil",
    "py312-bcrypt": "security/py-bcrypt",
    "py312-aiofiles": "devel/py-aiofiles",
    "py312-defusedxml": "devel/py-defusedxml",
    "py312-sqlalchemy20": "databases/py-sqlalchemy20",
    "py312-alembic": "databases/py-alembic",
    "py312-packaging": "devel/py-packaging",
    "py312-netifaces": "net/py-netifaces",
    # The agent's local queue is SQLite; Python's sqlite3 module is its own
    # package on FreeBSD.
    "py312-sqlite3": "databases/py-sqlite3",
    # The agent runs as sysmanage-agent and reaches privileged commands
    # through the sudoers file this package ships.
    "sudo": "security/sudo",
}

# Files that need something other than 0644 / 0755.
PERMS = {"/usr/local/etc/sudoers.d/sysmanage-agent": "0440"}

COMMON = {
    "name": "sysmanage-agent",
    "origin": "sysutils/sysmanage-agent",
    "comment": "System management agent for SysManage",
    "arch": "FreeBSD:*:amd64",
    "maintainer": "bryan@theeverlys.com",
    "prefix": "/usr/local",
    "www": "https://github.com/bceverly/sysmanage-agent",
}


def file_entries(staging: Path) -> dict:
    """Every staged file, keyed by its installed path."""
    entries = {}
    for path in sorted((staging / "usr").rglob("*")):
        if not path.is_file():
            continue
        installed = "/" + str(path.relative_to(staging))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        perm = PERMS.get(installed) or ("0755" if os.access(path, os.X_OK) else "0644")
        # pkg extracts each file with the mode the ARCHIVE carries, so make
        # the staged file match what the manifest says (a builder's umask
        # would otherwise leave group-writable files owned by root).
        path.chmod(int(perm, 8))
        entries[installed] = {
            "sum": f"1${digest}",
            "uname": "root",
            "gname": "wheel",
            "perm": perm,
        }
    return entries


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-1])
        return 2
    staging, version = Path(sys.argv[1]), sys.argv[2]
    files = file_entries(staging)
    if not files:
        print(
            f"ERROR: no files under {staging}/usr -- refusing to build an empty package"
        )
        return 1
    flatsize = sum((staging / path.lstrip("/")).stat().st_size for path in files)
    compact = {**COMMON, "version": version, "flatsize": flatsize}
    full = {
        **compact,
        "desc": "SysManage Agent: inventory, updates, monitoring, security policy, "
        "certificates, firewall and remote commands, managed from a SysManage server.",
        "categories": ["sysutils", "python"],
        "licenselogic": "single",
        "licenses": ["AGPLv3"],
        "deps": {name: {"origin": origin} for name, origin in DEPS.items()},
        "files": files,
        "scripts": {
            "post-install": (HERE / "post-install.sh").read_text(encoding="utf-8"),
            "pre-deinstall": "#!/bin/sh\nservice sysmanage_agent stop 2>/dev/null || true\n",
        },
    }
    (staging / "+COMPACT_MANIFEST").write_text(
        json.dumps(compact, indent=2) + "\n", encoding="utf-8"
    )
    (staging / "+MANIFEST").write_text(
        json.dumps(full, indent=2) + "\n", encoding="utf-8"
    )
    print(f"+MANIFEST: {len(files)} files, {len(DEPS)} dependencies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
