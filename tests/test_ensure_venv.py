# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""installer/common/ensure-venv.sh (2026-11-24): the .deb / .rpm install
scripts deleted the agent's venv and rebuilt it from PyPI, so on an
air-gapped host an upgrade left no agent.  A complete venv is kept now,
and a rebuild that cannot finish never touches the current one."""

import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parent.parent / "installer" / "common" / "ensure-venv.sh"
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="a POSIX install script",
)


def _app(tmp_path, requirements):
    app = tmp_path / "opt"
    app.mkdir()
    (app / "requirements-prod.txt").write_text(requirements, encoding="utf-8")
    venv.EnvBuilder(with_pip=True).create(app / ".venv")
    (app / ".venv" / "marker").write_text("the old environment", encoding="utf-8")
    return app


def _run(app):
    env = dict(os.environ, PIP_NO_INDEX="1", PIP_FIND_LINKS=str(app / "nowhere"))
    return subprocess.run(["sh", str(SCRIPT), str(app), sys.executable], capture_output=True,
                          text=True, env=env, timeout=600, check=False)  # fmt: skip


def test_a_complete_packaged_venv_is_kept(tmp_path):
    app = _app(tmp_path, "pip>=1\n# a comment\n")
    done = _run(app)
    assert done.returncode == 0 and "kept" in done.stdout
    assert (app / ".venv" / "marker").exists()


def test_a_rebuild_that_cannot_reach_any_index_leaves_the_old_venv(tmp_path):
    app = _app(tmp_path, "websockets-not-installed-anywhere>=1\n")
    done = _run(app)
    assert done.returncode == 0
    assert "current environment is kept" in done.stderr
    assert (app / ".venv" / "marker").read_text(
        encoding="utf-8"
    ) == "the old environment"
    assert not (app / ".venv.new").exists()
