"""
Per-directory pytest config for tests/integration/.

Some files in this folder only make sense on a specific OS family.  We
``collect_ignore`` them on platforms where they would otherwise have
to be skipped at collection or runtime — this keeps the default test
run "passed only / 0 skipped" on every platform while still letting
the dedicated BSD VM workflow run them by setting ``BSD_VM_TESTS=1``.
"""

import os
import platform

# Files in this directory that are only meaningful on a BSD host (their
# assertions check for BSD-only paths and binaries).  On non-BSD we
# refuse to collect them so they don't show up as skipped.
_BSD_ONLY_FILES = ("test_bsd_specific.py",)

_BSD_NAMES = {"FreeBSD", "OpenBSD", "NetBSD"}

collect_ignore = []

# If we're not running on a BSD AND the BSD VM workflow hasn't asked
# to include them explicitly, drop the BSD-only files from collection.
if platform.system() not in _BSD_NAMES and not os.environ.get("BSD_VM_TESTS"):
    collect_ignore.extend(_BSD_ONLY_FILES)
