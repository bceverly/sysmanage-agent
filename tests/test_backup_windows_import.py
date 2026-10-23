# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The backup modules must import where grp / pwd do not exist (Windows):
main.py imports them on every platform, and the Windows CI leg failed to load
conftest when storage_audit imported grp at module level (2026-10-23)."""

import importlib
import subprocess  # nosec B404
import sys

import pytest

MODULES = (
    "src.sysmanage_agent.backup.storage_audit",
    "src.sysmanage_agent.backup.storage_prepare",
    "src.sysmanage_agent.operations.backup_operations",
)


@pytest.mark.parametrize("module", MODULES)
def test_imports_without_unix_only_modules(module):
    # A fresh interpreter: hiding grp / pwd in this one would leak.
    code = (
        "import sys; sys.modules['grp'] = None; sys.modules['pwd'] = None; "
        f"import importlib; importlib.import_module({module!r})"
    )
    done = subprocess.run(  # nosec B603
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr


def test_the_modules_still_have_grp_and_pwd_where_they_exist():
    if sys.platform == "win32":
        pytest.skip("Unix only")
    audit = importlib.import_module(MODULES[0])
    assert audit.grp is not None and audit.pwd is not None
