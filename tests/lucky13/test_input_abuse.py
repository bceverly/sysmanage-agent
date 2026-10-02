# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Lucky 13 #1 buffer overflow (CWE-120), #3 directory traversal (CWE-23),
#5 injection (CWE-89), #6 / #11 file permissions and symlinks (CWE-276,
CWE-61) and #13 integer overflow (CWE-190) -- on what the server sends.

The paper's attacks, verbatim: ``AAA...AAA``, ``../..`` and ``/full/path``,
``' OR 1=1`` and ``0xffffffff``.  The agent runs as root and obeys the
server, so every hostile value in a command must be refused cleanly -- never
crash the agent, never become an option or a file path to a package manager,
never land a file other than where and how it was asked.
"""

import asyncio
import os
import stat
import sys
from unittest.mock import AsyncMock, Mock

import pytest

from src.sysmanage_agent.core.agent_utils import MessageProcessor
from src.sysmanage_agent.operations.generic_deployment import (
    GenericDeployment,
    _mode_to_permissions,
)
from src.sysmanage_agent.operations.hostname_operations import HostnameOperations
from src.sysmanage_agent.operations.package_installation_helpers import (
    validate_packages,
)
from src.sysmanage_agent.operations.package_name_guard import package_name_problem

LONG = "A" * 100_000
HOSTILE = {
    "#1 long string": LONG,
    "#3 traversal": "../../../../etc/passwd",
    "#3 full path": "/etc/passwd",
    "#3 local package file": "./evil.deb",
    "#5 SQL injection": "' OR 1=1 --",
    "#5 shell metacharacters": "nginx; rm -rf /",
    "#5 option injection": "-o APT::Get::AllowUnauthenticated=true",
    "#5 long option": "--allow-unauthenticated",
    "#13 NUL byte": "nginx\x00evil",
}
REAL_NAMES = ["nginx", "python3.11", "libstdc++6", "pkg=1.2-3ubuntu1",
              "pkg/bookworm-backports", "user/tap/formula", "Microsoft.PowerShell",
              "openssl:amd64", "py3-pip", "gcc-c++", "R-base", "perl-JSON-PP"]  # fmt: skip
POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")


@pytest.mark.parametrize("label", sorted(HOSTILE))
def test_1_3_5_13_hostile_package_names_are_refused(label):
    assert package_name_problem(HOSTILE[label]) is not None, label


@pytest.mark.parametrize("value", [0xFFFFFFFF, 2**63, -1, None, ["nginx"], {"a": 1}])
def test_13_non_string_package_names_are_refused(value):
    assert package_name_problem(value) is not None


@pytest.mark.parametrize("name", REAL_NAMES)
def test_real_package_names_still_pass(name):
    assert package_name_problem(name) is None, name


def test_1_3_5_the_install_validator_refuses_hostile_names():
    packages = [{"package_name": value} for value in HOSTILE.values()]
    packages.append({"package_name": "nginx"})
    valid, failed = validate_packages(packages, Mock())
    assert [p["package_name"] for p in valid] == ["nginx"]
    assert len(failed) == len(HOSTILE)


@pytest.mark.parametrize("label", sorted(HOSTILE))
def test_1_3_5_hostile_hostnames_are_refused(label):
    operations = HostnameOperations.__new__(HostnameOperations)
    # pylint: disable-next=protected-access
    assert operations._validate_hostname(HOSTILE[label]) is False


@pytest.mark.parametrize(
    "mode", [0xFFFFFFFF, 2**63, -1, "0xffffffff", "9999", LONG, True, 3.5, None]
)
def test_13_absurd_file_modes_fall_back_to_0644(mode):
    assert _mode_to_permissions(mode) == "0644"


def test_6_a_plan_mode_is_honored():
    assert _mode_to_permissions(0o700) == "0700"
    assert _mode_to_permissions("0600") == "0600"


def _deployment():
    agent = Mock()
    agent.send_message = AsyncMock()
    return GenericDeployment(agent)


@POSIX
@pytest.mark.asyncio
async def test_6_11_a_script_lands_owner_only_and_never_through_a_symlink(tmp_path):
    """The shape the server's script_plan_builder sends: a uuid4 path in a
    shared temp directory and ``mode`` 0o700, no owner.  A symlink planted at
    the path must be replaced, not followed, and the script must not be
    readable by other local users (it can carry secrets)."""
    victim = tmp_path / "victim"
    victim.write_text("untouched", encoding="utf-8")
    dest = tmp_path / "sysmanage_script_0123.sh"
    os.symlink(victim, dest)
    result = await _deployment().deploy_files(
        {"files": [{"path": str(dest), "content": "echo hi", "mode": 0o700}]}
    )
    assert result["success"], result
    assert victim.read_text(encoding="utf-8") == "untouched"
    assert not dest.is_symlink()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700


@POSIX
@pytest.mark.asyncio
async def test_6_no_deployed_file_is_world_writable_by_default(tmp_path):
    dest = tmp_path / "conf"
    result = await _deployment().deploy_files(
        {"files": [{"path": str(dest), "content": "x=1"}]}
    )
    assert result["success"], result
    assert not stat.S_IMODE(dest.stat().st_mode) & stat.S_IWOTH


# -- the command dispatcher ------------------------------------------------------


def _processor():
    agent = Mock()
    agent.create_message = Mock(return_value={})
    agent.send_message = AsyncMock()
    return MessageProcessor(agent, Mock())


def _nested(depth):
    command = {"command_type": "no_such_command", "parameters": {}}
    for _ in range(depth):
        command = {"command_type": "generic_command", "parameters": command}
    return command


HOSTILE_MESSAGES = {
    "#1 data is a long string": {"message_id": "m", "data": LONG},
    "#1 data is null": {"message_id": "m", "data": None},
    "#1 data is a list": {"message_id": "m", "data": ["x"] * 10_000},
    "#1 long command type": {"message_id": "m",
                             "data": {"command_type": LONG, "parameters": {}}},
    "#1 parameters not a mapping": {"message_id": "m", "data": {
        "command_type": "apply_deployment_plan", "parameters": ["x"]}},
    "#13 parameters a huge number": {"message_id": "m", "data": {
        "command_type": "no_such_command", "parameters": 2**63}},
    "#1 generic_command nested 5,000 deep": {"message_id": "m",
                                             "data": _nested(5_000)},
}  # fmt: skip


@pytest.mark.parametrize("label", sorted(HOSTILE_MESSAGES))
@pytest.mark.asyncio
async def test_1_13_hostile_commands_are_answered_not_crashed_on(label):
    processor = _processor()
    await asyncio.wait_for(processor.handle_command(HOSTILE_MESSAGES[label]), 30)
    processor.agent.send_message.assert_awaited()  # an answer went back
