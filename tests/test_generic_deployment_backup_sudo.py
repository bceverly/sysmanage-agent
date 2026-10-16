# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A packaged agent runs unprivileged, so backing up and restoring a file in
a root-owned directory must go through ``sudo install`` like the write does.
Production, 2026-10-16: every antivirus plan failed with "Could not back up
existing '/etc/clamav/clamd.conf' before deploy: Permission denied"."""

from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.generic_deployment import GenericDeployment


def _deployment():
    agent = Mock()
    agent.send_message = AsyncMock()
    return GenericDeployment(agent)


@pytest.mark.asyncio
async def test_an_unwritable_backup_goes_through_sudo_install(tmp_path):
    original = tmp_path / "clamd.conf"
    original.write_text("old\n")
    original.chmod(0o640)
    deployment = _deployment()
    with patch(
        "src.sysmanage_agent.operations.generic_deployment.shutil.copy2",
        side_effect=PermissionError("denied"),
    ), patch.object(deployment, "_run_sudo", new=AsyncMock()) as sudo:
        backup, error = await deployment._maybe_backup(str(original), True)
    assert error is None
    assert backup == str(original) + ".sysmanage.bak"
    argv = sudo.await_args.args[0]
    assert argv[:4] == ["sudo", "-n", "install", "-p"]
    assert argv[argv.index("-m") + 1] == "640"  # the original's mode, kept
    assert argv[-2:] == [str(original), backup]


@pytest.mark.asyncio
async def test_a_failed_sudo_backup_is_reported_not_raised(tmp_path):
    original = tmp_path / "clamd.conf"
    original.write_text("old\n")
    deployment = _deployment()
    with patch(
        "src.sysmanage_agent.operations.generic_deployment.shutil.copy2",
        side_effect=PermissionError("denied"),
    ), patch.object(
        deployment,
        "_run_sudo",
        new=AsyncMock(side_effect=PermissionError("sudo install failed (rc=1)")),
    ):
        backup, error = await deployment._maybe_backup(str(original), True)
    assert backup is None
    assert "Could not back up" in error["error"]


@pytest.mark.asyncio
async def test_a_writable_backup_needs_no_sudo(tmp_path):
    original = tmp_path / "clamd.conf"
    original.write_text("old\n")
    deployment = _deployment()
    with patch.object(deployment, "_run_sudo", new=AsyncMock()) as sudo:
        backup, error = await deployment._maybe_backup(str(original), True)
    assert error is None
    assert Path(backup).read_text(encoding="utf-8") == "old\n"
    sudo.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_rollback_into_a_root_owned_directory_uses_sudo(tmp_path):
    target = tmp_path / "clamd.conf"
    target.write_text("bad\n")
    backup = tmp_path / "clamd.conf.sysmanage.bak"
    backup.write_text("old\n")
    deployment = _deployment()
    with patch(
        "src.sysmanage_agent.operations.generic_deployment.os.replace",
        side_effect=PermissionError("denied"),
    ), patch.object(deployment, "_run_sudo", new=AsyncMock()) as sudo:
        message = await deployment._rollback_file(str(target), str(backup))
    assert "Restored from backup" in message
    assert sudo.await_args.args[0][-2:] == [str(backup), str(target)]
