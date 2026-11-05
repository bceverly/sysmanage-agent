# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Drive one icloudpd run (server ROADMAP 24.12).

icloudpd runs as the agent's own account in a session of its own, with no
controlling terminal, its output read as it comes:

* the PASSWORD -- icloudpd prompts for it (``--password-provider console``)
  only when it needs it.  Only then does the runner ask the server for it
  (``password()``, one release per run), write it to icloudpd's stdin and
  drop it.  It is never in argv, the environment, a file or a log, and any
  line that should somehow carry it is scrubbed before it is kept;
* the TWO-FACTOR CODE -- on a sign-in (``connect``), the prompt puts the job
  in "waiting for code"; the runner asks the server for the code the
  operator types (``code()``, polled) and writes it the same way.  Anywhere
  else the prompt means Apple wants a new sign-in: the run stops at once as
  ``needs_sign_in``, never as "no new photos";
* two-step verification (Apple's older scheme) is not supported: also
  ``needs_sign_in``, saying so.

Output is read into counts: "Downloaded ..." (downloaded), "... already
exists" / "... deduplicated" (present), "Could not download ..." (failed).
What is kept for the operator is the tail of the INFO-and-above lines and
icloudpd's own messages -- never its debug lines, which can dump Apple's
responses.
"""

import asyncio
import os
import re
import signal
import time
from collections import deque
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional

OK, FAILED, NEEDS_SIGN_IN = "ok", "failed", "needs_sign_in"
TAIL_LINES = 60
CODE_POLL_SECONDS = 3
CODE_WAIT_SECONDS = 15 * 60
PROGRESS_SECONDS = 30
READ_SIZE = 4096

PASSWORD_PROMPT = re.compile(r"iCloud Password for [^\n]*:\s*$")
MFA_PROMPT = re.compile(r"Please enter two-factor authentication code[^\n]*:\s*$")
TWO_STEP_PROMPT = re.compile(
    r"(Please choose an option:|Please enter two-step authentication code)[^\n]*$"
)
_LOG_LINE = re.compile(
    # ``(\S.*|)`` rather than ``(.*)``: the message cannot start with the
    # whitespace ``\s+`` takes, so the split is unique and matching linear.
    r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:,\d+)? (DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+(\S.*|)$"
)
_DOWNLOADED = re.compile(r"^Downloaded ")
_PRESENT = re.compile(r" (already exists|deduplicated)$")
_FAILED_FILE = re.compile(r"^Could not download ")
# Apple refused the credentials or the session: sign in again.
SIGN_IN_MARKERS = (
    "Invalid email/password combination",
    "Failed to initiate srp authentication",
    "Invalid authentication token",
    "Authentication required for Account",
    "Failed to verify two-factor authentication code",
    "Failed to verify two-step authentication code",
    "Two-factor authentication is required",
    "Two-step authentication is required",
    "Missing X-APPLE-WEBAUTH-TOKEN",
    "PyiCloudFailedLoginException",
    "PyiCloudFailedMFAException",
    "PyiCloud2SARequiredException",
)
# iCloud data is not reachable from the web for this account: Advanced Data
# Protection without "Access iCloud Data on the Web", or setup unfinished.
WEB_ACCESS_MARKERS = (
    "iCloud setup is not complete",
    "Webservice not available",
    "ZONE_NOT_FOUND",
    "PyiCloudServiceNotActivatedException",
)
# Apple answered 503: it limits how fast one account downloads.  The server
# waits it out and tries again by itself (cloud_backup_tick, "apple_busy").
APPLE_BUSY_MARKERS = ("Apple iCloud is temporary refusing to serve icloudpd",)


class Outcome:
    """What one run did; ``as_dict`` is what the server is told."""

    def __init__(self) -> None:
        self.status: Optional[str] = None
        self.reason: Optional[str] = None
        self.message: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.downloaded = 0
        self.present = 0
        self.failed = 0
        self.libraries: List[str] = []
        self.tail: Deque[str] = deque(maxlen=TAIL_LINES)
        self.authenticated = False
        self.last_level: Optional[str] = None
        # Every line read, not only the kept tail: a long run's failure
        # line must not scroll out before it is judged.
        self.sign_in_refused = False
        self.web_access_off = False
        self.started = time.monotonic()

    def stop(self, status: str, reason: str, message: str) -> None:
        if self.status is None:
            self.status, self.reason, self.message = status, reason, message

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "message": self.message,
            "exit_code": self.exit_code,
            "downloaded": self.downloaded,
            "present": self.present,
            "failed": self.failed,
            "libraries": list(self.libraries),
            "detail": "\n".join(self.tail),
            "duration": int(time.monotonic() - self.started),
        }


class _Scrubber:
    """Removes the password from any text kept, should it ever appear."""

    def __init__(self) -> None:
        self._secrets: List[str] = []

    def add(self, secret: str) -> None:
        if secret:
            self._secrets.append(secret)

    def __call__(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[redacted]")
        return text


def classify_line(outcome: Outcome, line: str, action: str, scrub) -> None:
    """Count one complete output line, and keep it when it is worth keeping."""
    line = scrub(line.rstrip("\r"))
    match = _LOG_LINE.match(line)
    if match:
        level, message = match.groups()
        if _DOWNLOADED.match(message):
            outcome.downloaded += 1
        elif _PRESENT.search(message):
            outcome.present += 1
        elif _FAILED_FILE.match(message):
            outcome.failed += 1
        if message.startswith("Authentication completed successfully"):
            outcome.authenticated = True
        outcome.last_level = level
        if level != "DEBUG":
            outcome.sign_in_refused |= any(m in message for m in SIGN_IN_MARKERS)
            outcome.web_access_off |= any(m in message for m in WEB_ACCESS_MARKERS)
        if level != "DEBUG":
            outcome.tail.append(line)
        return
    stripped = line.strip()
    if not stripped:
        return
    if action == "libraries" and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}", stripped
    ):
        outcome.libraries.append(stripped)
        return
    # A line that continues a DEBUG message (a dumped Apple response runs
    # over many lines) is dropped with it.
    if outcome.last_level != "DEBUG":
        outcome.tail.append(stripped)


def judge(outcome: Outcome, action: str) -> None:
    """The run's status from its exit and output, unless already decided.
    A good exit is judged first: a sign-in that worked logs "Two-factor
    authentication is required" on its way."""
    if outcome.status is not None:
        return
    if outcome.exit_code == 0:
        if action == "connect" and not outcome.authenticated:
            outcome.stop(FAILED, "no_confirmation",
                         "icloudpd ended without confirming the sign-in")  # fmt: skip
        elif outcome.failed:
            outcome.stop(OK, "some_failed",
                         f"{outcome.failed} file(s) could not be downloaded; "
                         "they are tried again next time")  # fmt: skip
        else:
            outcome.stop(OK, None, None)
        return
    text = "\n".join(outcome.tail)
    if outcome.sign_in_refused or any(marker in text for marker in SIGN_IN_MARKERS):
        outcome.stop(
            NEEDS_SIGN_IN,
            "auth_failed",
            "Apple did not accept the sign-in for this account. Check the "
            "password, then press Connect and enter the two-factor code.",
        )
    elif outcome.web_access_off or any(marker in text for marker in WEB_ACCESS_MARKERS):
        outcome.stop(
            FAILED,
            "web_access_off",
            "iCloud data is not reachable from the web for this account. With "
            'Advanced Data Protection on, turn on "Access iCloud Data on the '
            'Web" on the iPhone (Settings, your name, iCloud), then try again.',
        )
    elif any(marker in text for marker in APPLE_BUSY_MARKERS):
        outcome.stop(
            FAILED,
            "apple_busy",
            "Apple is limiting downloads for this account. Nothing is lost: "
            "the download is tried again after a cooldown.",
        )
    else:
        outcome.stop(FAILED, "tool_failed",
                     f"icloudpd exited with status {outcome.exit_code}")  # fmt: skip


def child_env(session_dir: str) -> Dict[str, str]:
    """A plain environment: no password, no proxy secrets from the agent."""
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": session_dir,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
    }
    for name in ("TMPDIR", "TZ", "HTTPS_PROXY", "https_proxy", "SSL_CERT_FILE"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


class _Run:  # pylint: disable=too-many-instance-attributes
    """One run's state while it is read."""

    def __init__(self, process, action: str, password, code, progress) -> None:
        self.process = process
        self.action = action
        self.password = password
        self.code = code
        self.progress = progress
        self.outcome = Outcome()
        self.scrub = _Scrubber()
        self.password_given = False
        self.code_given = False
        self.last_progress = 0.0

    def kill(self) -> None:
        if self.process.returncode is not None:
            return
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            try:
                self.process.kill()
            except ProcessLookupError:
                pass

    async def _write(self, text: str) -> None:
        self.process.stdin.write((text + "\n").encode("utf-8"))
        await self.process.stdin.drain()

    async def _report(
        self, phase: str, line: Optional[str] = None, force=False
    ) -> None:
        now = time.monotonic()
        if not force and now - self.last_progress < PROGRESS_SECONDS:
            return
        self.last_progress = now
        try:
            await self.progress({
                "phase": phase, "downloaded": self.outcome.downloaded,
                "present": self.outcome.present, "failed": self.outcome.failed,
                "line": line,
            })  # fmt: skip
        except Exception:  # pylint: disable=broad-except
            pass  # progress is a courtesy; the run goes on

    async def answer_password(self) -> bool:
        if self.password_given:
            self.outcome.stop(NEEDS_SIGN_IN, "auth_failed",
                              "Apple did not accept the password for this account.")  # fmt: skip
            return False
        self.password_given = True
        await self._report("signing_in", force=True)
        try:
            secret = await self.password()
        except Exception as error:  # pylint: disable=broad-except
            self.outcome.stop(FAILED, "password_unavailable",
                              f"The password could not be had from the server: {error}")  # fmt: skip
            return False
        self.scrub.add(secret)
        await self._write(secret)
        del secret
        return True

    async def answer_code(self) -> bool:
        if self.action != "connect":
            self.outcome.stop(NEEDS_SIGN_IN, "session_expired",
                              "Apple wants a new sign-in for this account. Press "
                              "Connect and enter the two-factor code.")  # fmt: skip
            return False
        if self.code_given:
            self.outcome.stop(NEEDS_SIGN_IN, "code_rejected",
                              "Apple did not accept the two-factor code.")  # fmt: skip
            return False
        await self._report("waiting_code", force=True)
        deadline = time.monotonic() + CODE_WAIT_SECONDS
        while time.monotonic() < deadline:
            try:
                value = await self.code()
            except Exception as error:  # pylint: disable=broad-except
                self.outcome.stop(NEEDS_SIGN_IN, "no_code", str(error))
                return False
            if value:
                self.code_given = True
                await self._write(value)
                await self._report("signing_in", force=True)
                return True
            await asyncio.sleep(CODE_POLL_SECONDS)
        self.outcome.stop(NEEDS_SIGN_IN, "no_code",
                          "No two-factor code was entered in time.")  # fmt: skip
        return False

    async def prompt(self, pending: str) -> Optional[bool]:
        """Answer a prompt at the end of the unread text; None when there is
        none, False when the run must stop."""
        if PASSWORD_PROMPT.search(pending):
            return await self.answer_password()
        if MFA_PROMPT.search(pending):
            return await self.answer_code()
        if TWO_STEP_PROMPT.search(pending):
            self.outcome.stop(NEEDS_SIGN_IN, "two_step",
                              "This Apple ID uses Apple's older two-step verification, "
                              "which is not supported. Turn on two-factor authentication "
                              "for it, then press Connect.")  # fmt: skip
            return False
        return None

    async def read(self) -> None:
        pending = ""
        while True:
            chunk = await self.process.stdout.read(READ_SIZE)
            if not chunk:
                break
            pending += chunk.decode("utf-8", "replace")
            *lines, pending = pending.split("\n")
            for line in lines:
                classify_line(self.outcome, line, self.action, self.scrub)
            if lines and self.action in ("download", "reconcile"):
                await self._report("downloading", self.scrub(lines[-1])[-300:])
            answered = await self.prompt(pending)
            if answered is False:
                self.kill()
                break
            if answered:
                pending = ""
        if pending.strip():
            classify_line(self.outcome, pending, self.action, self.scrub)


async def run(
    argv: List[str],
    *,
    action: str,
    session_dir: str,
    password: Callable[[], Awaitable[str]],
    code: Callable[[], Awaitable[Optional[str]]],
    progress: Callable[[Dict[str, Any]], Awaitable[None]],
    cwd: str = "/",
) -> Dict[str, Any]:
    """Run icloudpd once; the outcome as a dict (see ``Outcome``)."""
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,  # no controlling terminal: prompts use stdin
        env=child_env(session_dir),
        cwd=cwd,
    )
    state = _Run(process, action, password, code, progress)
    try:
        await state.read()
    finally:
        if state.outcome.status is not None:
            state.kill()
        state.outcome.exit_code = await process.wait()
    judge(state.outcome, action)
    return state.outcome.as_dict()
