# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The FreeBSD package manifest lists every file and installable dependencies.

3.12.1.4's package installed 0 bytes (no ``files`` section), depended on
``py311-*`` packages FreeBSD no longer builds, and its post-install created
an account the rc script does not run as (found on a fresh FreeBSD 14.5 VM,
2026-11-05).
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "installer"
    / "freebsd"
    / "build_pkg_manifest.py"
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file modes; the package is built on Linux"
)


def _load():
    spec = importlib.util.spec_from_file_location("build_pkg_manifest", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stage(root: Path) -> Path:
    lib = root / "usr/local/lib/sysmanage-agent"
    lib.mkdir(parents=True)
    (lib / "main.py").write_text("print('agent')\n")
    wrapper = lib / "sysmanage-agent-wrapper.sh"
    wrapper.write_text("#!/bin/sh\n")
    wrapper.chmod(0o775)
    sudoers = root / "usr/local/etc/sudoers.d/sysmanage-agent"
    sudoers.parent.mkdir(parents=True)
    sudoers.write_text("sysmanage-agent ALL=(ALL) NOPASSWD: /usr/sbin/pkg update\n")
    return root


def test_every_file_is_listed_with_its_checksum_and_mode(tmp_path, monkeypatch):
    staging = _stage(tmp_path / "staging")
    monkeypatch.setattr(sys, "argv", ["x", str(staging), "3.12.1.99"])
    assert _load().main() == 0
    manifest = json.loads((staging / "+MANIFEST").read_text())
    files = manifest["files"]
    main = "/usr/local/lib/sysmanage-agent/main.py"
    assert set(files) == {
        main,
        "/usr/local/lib/sysmanage-agent/sysmanage-agent-wrapper.sh",
        "/usr/local/etc/sudoers.d/sysmanage-agent",
    }
    digest = hashlib.sha256((staging / main.lstrip("/")).read_bytes()).hexdigest()
    assert files[main]["sum"] == f"1${digest}"
    assert files[main]["perm"] == "0644"
    assert (
        files["/usr/local/lib/sysmanage-agent/sysmanage-agent-wrapper.sh"]["perm"]
        == "0755"
    )
    assert files["/usr/local/etc/sudoers.d/sysmanage-agent"]["perm"] == "0440"
    # The archive carries the staged modes, so they must match the manifest.
    wrapper = staging / "usr/local/lib/sysmanage-agent/sysmanage-agent-wrapper.sh"
    assert oct(wrapper.stat().st_mode & 0o777) == "0o755"
    compact = json.loads((staging / "+COMPACT_MANIFEST").read_text())
    assert "files" not in compact and compact["flatsize"] > 0


def test_dependencies_are_the_current_python_flavor(tmp_path, monkeypatch):
    staging = _stage(tmp_path / "staging")
    monkeypatch.setattr(sys, "argv", ["x", str(staging), "3.12.1.99"])
    assert _load().main() == 0
    deps = json.loads((staging / "+MANIFEST").read_text())["deps"]
    assert "python312" in deps and "sudo" in deps
    assert not [name for name in deps if name.startswith(("py311-", "python311"))]
    # Every runtime import the old manifest left out.
    for module in (
        "psutil",
        "bcrypt",
        "aiofiles",
        "defusedxml",
        "packaging",
        "sqlite3",
    ):
        assert f"py312-{module}" in deps


def test_the_post_install_creates_the_account_the_rc_script_uses(tmp_path, monkeypatch):
    staging = _stage(tmp_path / "staging")
    monkeypatch.setattr(sys, "argv", ["x", str(staging), "3.12.1.99"])
    assert _load().main() == 0
    script = json.loads((staging / "+MANIFEST").read_text())["scripts"]["post-install"]
    rc = (SCRIPT.parent / "sysmanage-agent.rc").read_text()
    assert ': ${sysmanage_agent_user:="sysmanage-agent"}' in rc
    assert "pw useradd sysmanage-agent" in script
    assert "/etc/sysmanage-agent" in script
    assert "-P ${sysmanage_agent_pidfile}" in rc


def test_an_empty_staging_directory_is_refused(tmp_path, monkeypatch):
    (tmp_path / "staging" / "usr").mkdir(parents=True)
    monkeypatch.setattr(sys, "argv", ["x", str(tmp_path / "staging"), "3.12.1.99"])
    assert _load().main() == 1
