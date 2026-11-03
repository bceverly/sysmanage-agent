# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""iCloud Photos to local (server ROADMAP 24.12), driven against a FAKE
icloudpd that prompts the way the real one does: the password goes in on
stdin only when asked (never argv, environment, a file or the kept output),
the two-factor code is relayed from the server, an authentication failure is
"needs sign-in" (never "no new photos"), and the files are counted."""

import asyncio
import hashlib
import json
import os
import re
import stat
import sys
import textwrap
import uuid
from types import SimpleNamespace

import pytest

from src.sysmanage_agent.backup import self_backup
from src.sysmanage_agent.cloud_backup import layout, operations, runner, tool
from src.sysmanage_agent.core import capabilities, capability_probes

# icloudpd is offered only on Linux and FreeBSD storage hosts; these tests run a
# shebang script as the tool and check POSIX modes and paths.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")

PASSWORD = "correct-horse-battery-staple"  # nosec B105  # a test value
CODE = "123456"
SUDOERS = os.path.join(
    os.path.dirname(__file__), "..", "installer", "freebsd", "sysmanage-agent.sudoers"
)

FAKE = textwrap.dedent(r'''
    #!PYTHON
    """A stand-in for icloudpd 1.32.3's console prompts and log lines."""
    import json, os, sys, time

    def log(level, message):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{stamp} {level:<8} {message}", flush=True)

    args = sys.argv[1:]
    cookie = args[args.index("--cookie-directory") + 1]
    with open(os.path.join(cookie, "scenario.json")) as handle:
        scenario = json.load(handle)
    with open(os.path.join(cookie, "seen.json"), "w") as handle:
        json.dump({"argv": sys.argv, "env": dict(os.environ)}, handle)
    log("DEBUG", "Authenticating...")
    if scenario.get("ask_password", True):
        sys.stderr.write("iCloud Password for x:")
        sys.stderr.flush()
        given = sys.stdin.readline().rstrip("\n")
        if scenario.get("echo_password"):
            log("INFO", "debug echo " + given)
        if given != scenario["password"]:
            log("INFO", "Invalid email/password combination.")
            sys.exit(1)
    if scenario.get("mfa"):
        log("INFO", "Two-factor authentication is required (2fa)")
        print("  a: (***) ***-**12")
        sys.stdout.write("Please enter two-factor authentication code or device "
                         "index (a) to send SMS with a code: ")
        sys.stdout.flush()
        code = sys.stdin.readline().strip()
        if code != scenario["code"]:
            log("INFO", "Failed to verify two-factor authentication code")
            sys.exit(1)
        log("INFO", "Great, you're all set up.")
    if scenario.get("two_step"):
        log("INFO", "Two-step authentication is required (2sa)")
        sys.stdout.write("Please choose an option: [0]: ")
        sys.stdout.flush()
        sys.stdin.readline()
        sys.exit(1)
    if "--auth-only" in args:
        log("INFO", "Authentication completed successfully")
        sys.exit(0)
    if "--list-libraries" in args:
        print("PrimarySync")
        print("SharedSync-ABCDEF")
        sys.exit(0)
    directory = args[args.index("--directory") + 1]
    for index in range(scenario.get("new", 0)):
        path = os.path.join(directory, "2026", "11", "03", f"IMG_{index}.HEIC")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as out:
            out.write(b"x" * 100)
        log("INFO", f"Downloaded {path}")
    for index in range(scenario.get("present", 0)):
        log("DEBUG", f"/photos/IMG_old{index}.HEIC already exists")
    for index in range(scenario.get("failed", 0)):
        log("ERROR", f"Could not download IMG_bad{index}.HEIC. Please try again later.")
    sys.exit(scenario.get("exit", 0))
    ''').lstrip()


@pytest.fixture
def fake(tmp_path):
    path = tmp_path / "icloudpd"
    path.write_text(FAKE.replace("PYTHON", sys.executable))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def _job(tmp_path, action="download", **extra):
    session = tmp_path / "sessions" / "icloud-0000abcd"
    session.mkdir(parents=True, exist_ok=True)
    directory = tmp_path / "photos"
    directory.mkdir(exist_ok=True)
    job = {
        "run_id": str(uuid.uuid4()), "action": action, "apple_id": "a@example.com",
        "library": "PrimarySync", "dir_name": "icloud-0000abcd",
        "storage_path": str(tmp_path), "directory": str(directory),
        "session_dir": str(session), "auto_delete": False,
        "until_found": 50 if action == "download" else None,
    }  # fmt: skip
    job.update(extra)
    return job


def _scenario(job, **values):
    values.setdefault("password", PASSWORD)
    values.setdefault("code", CODE)
    with open(
        os.path.join(job["session_dir"], "scenario.json"), "w", encoding="utf-8"
    ) as handle:
        json.dump(values, handle)


class _Server:
    def __init__(self, codes=(CODE,)):
        self.password_asks = 0
        self.codes = list(codes)
        self.code_asks = 0
        self.progress = []

    async def password(self):
        self.password_asks += 1
        return PASSWORD

    async def code(self):
        self.code_asks += 1
        if self.code_asks < 2:
            return None  # the operator has not typed it yet
        return self.codes.pop(0) if self.codes else None

    async def report(self, data):
        self.progress.append(data)


def _run(fake, job, server):
    return asyncio.run(runner.run(
        layout.argv(fake, job), action=job["action"], session_dir=job["session_dir"],
        password=server.password, code=server.code, progress=server.report,
        cwd=job["session_dir"],
    ))  # fmt: skip


def _seen(job):
    with open(
        os.path.join(job["session_dir"], "seen.json"), encoding="utf-8"
    ) as handle:
        return json.load(handle)


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    monkeypatch.setattr(runner, "CODE_POLL_SECONDS", 0.05)
    monkeypatch.setattr(runner, "PROGRESS_SECONDS", 0)


# --- runs ---------------------------------------------------------------------


def test_a_download_counts_files_and_the_password_only_goes_on_stdin(fake, tmp_path):
    job = _job(tmp_path)
    _scenario(job, new=3, present=4, failed=1, echo_password=True)
    server = _Server()
    outcome = _run(fake, job, server)
    assert outcome["status"] == "ok" and outcome["reason"] == "some_failed"
    assert (outcome["downloaded"], outcome["present"], outcome["failed"]) == (3, 4, 1)
    assert server.password_asks == 1  # asked once, when prompted
    seen = _seen(job)
    assert PASSWORD not in json.dumps(seen["argv"])
    assert PASSWORD not in json.dumps(seen["env"])
    assert seen["env"]["HOME"] == job["session_dir"]
    # Even a tool that echoed it: what is kept is scrubbed.
    assert PASSWORD not in json.dumps(outcome)
    assert PASSWORD not in json.dumps(server.progress)
    assert "--until-found" in seen["argv"] and "50" in seen["argv"]
    for absent in ("--auto-delete", "--keep-icloud-recent-days", "webui", "--password"):
        assert absent not in seen["argv"]


def test_debug_lines_are_counted_never_kept(fake, tmp_path):
    job = _job(tmp_path)
    _scenario(job, present=2)
    outcome = _run(fake, job, _Server())
    assert outcome["present"] == 2
    assert "already exists" not in outcome["detail"]
    assert "Authenticating" not in outcome["detail"]


def test_a_wrong_password_is_needs_sign_in_not_no_new_photos(fake, tmp_path):
    job = _job(tmp_path)
    _scenario(job, password="something else")
    outcome = _run(fake, job, _Server())
    assert outcome["status"] == "needs_sign_in"
    assert outcome["reason"] == "auth_failed"
    assert outcome["exit_code"] == 1 and outcome["downloaded"] == 0


def test_a_two_factor_prompt_in_a_download_stops_it_as_needs_sign_in(fake, tmp_path):
    job = _job(tmp_path)
    _scenario(job, mfa=True, new=5)
    server = _Server()
    outcome = _run(fake, job, server)
    assert outcome["status"] == "needs_sign_in"
    assert outcome["reason"] == "session_expired"
    assert outcome["downloaded"] == 0 and server.code_asks == 0


def test_connect_relays_the_operators_code(fake, tmp_path):
    job = _job(tmp_path, action="connect")
    _scenario(job, mfa=True)
    server = _Server()
    outcome = _run(fake, job, server)
    assert outcome["status"] == "ok", outcome
    assert server.code_asks >= 2  # it waited for the operator
    assert any(p["phase"] == "waiting_code" for p in server.progress)
    assert "--auth-only" in _seen(job)["argv"]
    assert CODE not in json.dumps(_seen(job))


def test_a_rejected_code_is_needs_sign_in(fake, tmp_path):
    job = _job(tmp_path, action="connect")
    _scenario(job, mfa=True, code="654321")
    outcome = _run(fake, job, _Server())
    assert outcome["status"] == "needs_sign_in"


def test_no_code_in_time_is_needs_sign_in(fake, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "CODE_WAIT_SECONDS", 0.3)
    job = _job(tmp_path, action="connect")
    _scenario(job, mfa=True)
    outcome = _run(fake, job, _Server(codes=()))
    assert (outcome["status"], outcome["reason"]) == ("needs_sign_in", "no_code")


def test_two_step_verification_is_said_plainly(fake, tmp_path):
    job = _job(tmp_path, action="connect")
    _scenario(job, two_step=True)
    outcome = _run(fake, job, _Server())
    assert (outcome["status"], outcome["reason"]) == ("needs_sign_in", "two_step")


def test_libraries_are_listed(fake, tmp_path):
    job = _job(tmp_path, action="libraries")
    _scenario(job, ask_password=False)
    outcome = _run(fake, job, _Server())
    assert outcome["libraries"] == ["PrimarySync", "SharedSync-ABCDEF"]


def test_the_password_server_refusing_fails_cleanly(fake, tmp_path):
    job = _job(tmp_path)
    _scenario(job)

    class Refusing(_Server):
        async def password(self):
            raise PermissionError("HTTP 409: already released")

    outcome = _run(fake, job, Refusing())
    assert (outcome["status"], outcome["reason"]) == ("failed", "password_unavailable")


def test_a_web_access_problem_says_what_to_turn_on():
    outcome = runner.Outcome()
    outcome.exit_code = 1
    outcome.tail.append("2026-11-03 10:00:00 ERROR    Webservice not available")
    runner.judge(outcome, "download")
    assert outcome.reason == "web_access_off"
    assert "Access iCloud Data on the Web" in outcome.message


# --- layout -------------------------------------------------------------------------


def _policies(tmp_path, mount_point):
    (tmp_path / "backup").mkdir(exist_ok=True)
    (tmp_path / "backup" / "policies.json").write_text(
        json.dumps(
            {"p1": {"role": "storage", "mount_point": mount_point},
         "p2": {"role": "host", "mount_point": "/mnt/elsewhere"}}  # fmt: skip
        )
    )


def _read(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def test_only_a_storage_path_this_host_serves_is_accepted(tmp_path):
    _policies(tmp_path, "/srv/backups/restate")
    state = str(tmp_path)
    assert (
        layout.storage_path("/srv/backups/restate", state, _read)
        == "/srv/backups/restate"
    )
    for bad in (
        "/mnt/elsewhere",
        "/etc",
        "relative",
        "/srv/backups/restate/../x",
        None,
    ):
        with pytest.raises(layout.LayoutError):
            layout.storage_path(bad, state, _read)


def test_an_account_job_is_checked_and_placed(tmp_path):
    _policies(tmp_path, "/srv/backups/restate")
    params = {
        "run_id": str(uuid.uuid4()), "action": "download", "apple_id": "a@example.com",
        "library": "PrimarySync", "dir_name": "icloud-0000abcd",
        "storage_path": "/srv/backups/restate", "until_found": 50, "auto_delete": True,
    }  # fmt: skip
    job = layout.account_job(params, str(tmp_path), _read)
    assert job["directory"] == "/srv/backups/restate/cloud-photos/icloud-0000abcd"
    assert job["session_dir"].startswith(str(tmp_path))  # never on the storage
    assert "--auto-delete" in layout.argv("/x/icloudpd", job)
    for key, bad in (("dir_name", "../etc"), ("apple_id", "x; rm"),
                     ("library", "-rf"), ("until_found", 0), ("action", "shell")):  # fmt: skip
        with pytest.raises(layout.LayoutError):
            layout.account_job(dict(params, **{key: bad}), str(tmp_path), _read)


def test_a_reconcile_is_a_full_pass():
    job = dict(_job_dict(), action="reconcile", until_found=None)
    assert "--until-found" not in layout.argv("/x/icloudpd", job)


def _job_dict():
    return {"apple_id": "a@example.com", "session_dir": "/s", "directory": "/d",
            "library": "PrimarySync", "auto_delete": False, "until_found": 50}  # fmt: skip


# --- the tool --------------------------------------------------------------------------


def test_the_install_method_by_platform():
    assert tool.method("Linux", "x86_64", exists=lambda _p: False) == tool.BINARY
    assert tool.method("Linux", "aarch64", exists=lambda _p: False) == tool.BINARY
    assert tool.method("Linux", "x86_64", exists=lambda _p: True) == tool.VENV  # Alpine
    assert tool.method("Linux", "riscv64", exists=lambda _p: False) == tool.VENV
    assert tool.method("FreeBSD", "amd64") == tool.VENV
    assert tool.method("Darwin", "arm64") is None
    assert tool.method("Windows", "AMD64") is None
    assert tool.enable_unavailable_reason(None, "Windows") == "wrong_platform"


def test_a_binary_install_is_checked_against_its_pin(tmp_path, monkeypatch):
    body = b"#!/bin/sh\necho version:1.32.3, commit sha:x\n"
    monkeypatch.setitem(tool.BINARIES, "x86_64",
                        ("icloudpd-test", hashlib.sha256(body).hexdigest()))  # fmt: skip

    def run(argv, _timeout):
        return 0, "version:1.32.3, commit sha:2035bb1"

    found = tool.install(str(tmp_path), run, get=lambda _n: body,
                         system="Linux", machine="x86_64")  # fmt: skip
    assert found["method"] == "binary" and found["version"] == "1.32.3"
    assert stat.S_IMODE(os.stat(tool.tool_dir(str(tmp_path))).st_mode) == 0o700
    assert tool.installed(str(tmp_path), _read)["path"] == found["path"]
    with pytest.raises(tool.ToolError) as caught:
        tool.install(str(tmp_path), run, get=lambda _n: body + b"tampered",
                     system="Linux", machine="x86_64")  # fmt: skip
    assert caught.value.reason == "checksum_mismatch"


def test_a_venv_install_uses_the_pinned_wheel(tmp_path, monkeypatch):
    body = b"wheel"
    monkeypatch.setattr(
        tool, "WHEEL", ("icloudpd-test.whl", hashlib.sha256(body).hexdigest())
    )
    calls = []

    def run(argv, _timeout):
        calls.append(argv)
        if argv[1:] == ["--version"]:
            return 0, "version:1.32.3,"
        if argv[1:3] == ["-m", "venv"]:
            os.makedirs(os.path.join(argv[-1], "bin"), exist_ok=True)
            script = os.path.join(argv[-1], "bin", "icloudpd")
            with open(script, "w", encoding="utf-8") as out:
                out.write("#!/bin/sh\n")
            os.chmod(script, 0o700)
        return 0, ""

    found = tool.install(str(tmp_path), run, get=lambda _n: body, system="FreeBSD",
                         which=lambda name: "/usr/local/bin/" + name)  # fmt: skip
    assert found["method"] == "venv"
    assert calls[1][0].endswith("/bin/pip") and calls[1][-1].endswith(
        "icloudpd-test.whl"
    )
    assert not os.path.exists(
        os.path.join(tool.tool_dir(str(tmp_path)), "icloudpd-test.whl")
    )


def test_the_version_line_is_read():
    assert tool.parse_version("version:1.32.3, commit sha:2035bb1") == "1.32.3"
    assert tool.parse_version("nothing") is None


# --- capabilities, the self-backup and sudoers --------------------------------------


def test_the_capability_groups_and_probes(tmp_path, monkeypatch):
    assert capabilities.CAPABILITY_GROUPS["cloud_backup"] == ("cloud_backup_run",)
    assert (
        "cloud_backup_enable" in capabilities.CAPABILITY_GROUPS["cloud_backup_enable"]
    )
    assert tool.run_unavailable_reason(str(tmp_path), _read, "Linux") == "missing_tool"
    assert (
        tool.run_unavailable_reason(str(tmp_path), _read, "Darwin") == "wrong_platform"
    )
    monkeypatch.setenv("SYSMANAGE_BACKUP_STATE_DIR", str(tmp_path))
    assert (
        capability_probes._cloud_run_reason("Linux") == "missing_tool"
    )  # pylint: disable=protected-access


def test_the_self_backup_leaves_the_sessions_out():
    points = self_backup.leave_out([], "/srv/backups", exists=lambda _p: False,
                                   private=("/var/lib/sysmanage-agent/cloud_backup/sessions",))  # fmt: skip
    assert "/var/lib/sysmanage-agent/cloud_backup/sessions" in points


def test_the_freebsd_sudoers_rule_admits_exactly_the_cloud_datasets():
    with open(SUDOERS, encoding="utf-8") as handle:
        rules = handle.read()
    patterns = [rx for rx in re.findall(r"/sbin/zfs (\^\S.*\$)$", rules, re.M)
                if "cloud-photos" in rx]  # fmt: skip
    assert len(patterns) == 1
    rx = patterns[0]
    assert re.fullmatch(rx, "create tank/backups/cloud-photos")
    assert re.fullmatch(rx, "create tank/backups/cloud-photos/icloud-0000abcd")
    for bad in ("create -o mountpoint=/ tank/backups/cloud-photos",
                "create tank/backups/x", "destroy tank/backups/cloud-photos",
                "create tank/backups/cloud-photos/icloud-zz"):  # fmt: skip
        assert not re.fullmatch(rx, bad), bad


# --- the handlers ----------------------------------------------------------------------


class _Agent:
    def __init__(self):
        self.sent = []
        self.registration_manager = SimpleNamespace(
            get_host_approval_from_db=lambda: SimpleNamespace(host_id="h1")
        )

    def create_message(self, message_type, data):
        return {"message_type": message_type, "data": data}

    async def send_message(self, message):
        self.sent.append(message)
        return True


def test_enable_refuses_a_path_it_does_not_serve(tmp_path):
    ops = operations.CloudBackupOperations(_Agent(), str(tmp_path))
    answer = asyncio.run(ops.cloud_backup_enable(
        {"run_id": str(uuid.uuid4()), "storage_path": "/etc"}))  # fmt: skip
    assert answer["success"] is False and answer["reason"] == "invalid_request"


def test_enable_installs_prepares_and_reports(tmp_path, monkeypatch):
    _policies(tmp_path, "/srv/backups/restate")
    agent = _Agent()
    ops = operations.CloudBackupOperations(agent, str(tmp_path))
    # icloudpd is offered only on Linux and FreeBSD; this runs on every CI OS.
    monkeypatch.setattr(tool, "method", lambda *_a, **_k: "venv")
    monkeypatch.setattr(tool, "install", lambda *_a, **_k: {
        "version": "1.32.3", "method": "venv", "path": "/x"})  # fmt: skip
    made = []

    async def make(path, storage):
        made.append((path, storage))
        return "zfs"

    monkeypatch.setattr(ops, "_make", make)
    run_id = str(uuid.uuid4())

    async def go():
        answer = await ops.cloud_backup_enable(
            {"run_id": run_id, "storage_path": "/srv/backups/restate"}
        )
        await asyncio.gather(*list(ops._tasks))  # pylint: disable=protected-access
        return answer

    assert asyncio.run(go())["started"] is True
    assert made == [("/srv/backups/restate/cloud-photos", "/srv/backups/restate")]
    result = agent.sent[-1]
    assert result["message_type"] == "cloud_backup_result"
    assert (
        result["data"]["status"] == "ok" and result["data"]["tool_version"] == "1.32.3"
    )
    sessions = layout.sessions_root(str(tmp_path))
    assert stat.S_IMODE(os.stat(sessions).st_mode) == 0o700


def test_a_run_needs_the_tool_and_remove_keeps_the_photos(tmp_path):
    _policies(tmp_path, str(tmp_path / "store"))
    ops = operations.CloudBackupOperations(_Agent(), str(tmp_path))
    params = {"run_id": str(uuid.uuid4()), "action": "connect",
              "apple_id": "a@example.com", "dir_name": "icloud-0000abcd",
              "storage_path": str(tmp_path / "store")}  # fmt: skip
    answer = asyncio.run(ops.cloud_backup_run(params))
    assert answer["reason"] == "missing_tool"
    session = layout.session_dir(str(tmp_path), "icloud-0000abcd")
    os.makedirs(session)
    photos = tmp_path / "store" / "cloud-photos" / "icloud-0000abcd"
    photos.mkdir(parents=True)
    (photos / "IMG_1.HEIC").write_bytes(b"x")
    done = asyncio.run(ops.cloud_backup_remove(
        {"run_id": str(uuid.uuid4()), "dir_name": "icloud-0000abcd"}))  # fmt: skip
    assert done["success"] and not os.path.exists(session)
    assert (photos / "IMG_1.HEIC").exists()


def test_the_library_is_measured(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "IMG.HEIC").write_bytes(b"x" * 10)
    (tmp_path / "a" / "IMG.HEIC.xmp").write_bytes(b"y" * 5)
    assert operations.library_size(str(tmp_path)) == (1, 15)


def noop(text):
    return text


def test_a_dumped_response_never_hides_or_leaks_the_failure():
    outcome = runner.Outcome()
    runner.classify_line(
        outcome,
        "2026-11-03 10:00:00 INFO     Invalid email/password combination.",
        "connect",
        noop,
    )
    runner.classify_line(
        outcome, "2026-11-03 10:00:00 DEBUG    response:", "connect", noop
    )
    for index in range(200):
        runner.classify_line(
            outcome, f'  "token{index}" : "secret-cookie"', "connect", noop
        )
    outcome.exit_code = 1
    runner.judge(outcome, "connect")
    assert outcome.status == "needs_sign_in"
    assert "secret-cookie" not in "\n".join(outcome.tail)
