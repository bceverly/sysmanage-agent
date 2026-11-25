# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Upload caps by hour of day (server ROADMAP 27.3).

The schedule is the storage host's LOCAL time, as the operator thinks of
"business hours" there::

    {"rules": [{"days": [0, 1, 2, 3, 4], "start": "08:00", "end": "18:00",
                "kbps": 20000}],
     "default_kbps": 0}

``days`` are 0 (Monday) to 6; ``end`` before ``start`` runs past midnight
(into the next day); ``kbps`` is kilobits per second, 0 for no cap.  The
first rule that covers the moment wins, else ``default_kbps``.  The cap is
looked up again as the upload runs, so an upload that starts at night slows
down at eight in the morning.
"""

import datetime
import time
from typing import Any, BinaryIO, Callable, Dict, List, Optional

BURST_SECONDS = 1.0


class ScheduleError(ValueError):
    """A schedule the agent will not apply."""


def _minutes(text: Any) -> int:
    try:
        hours, minutes = str(text).split(":")
        value = int(hours) * 60 + int(minutes)
    except (ValueError, AttributeError) as error:
        raise ScheduleError(f"bad time {text!r}") from error
    if not 0 <= int(hours) <= 24 or not 0 <= int(minutes) < 60 or value > 1440:
        raise ScheduleError(f"bad time {text!r}")
    return value


def _kbps(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ScheduleError(f"bad cap {value!r}")
    return value


def validate(schedule: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The schedule, checked; an absent one means no cap at all."""
    if not schedule:
        return {"rules": [], "default_kbps": 0}
    if not isinstance(schedule, dict):
        raise ScheduleError("the bandwidth schedule is not an object")
    rules: List[Dict[str, Any]] = []
    for rule in schedule.get("rules") or []:
        if not isinstance(rule, dict):
            raise ScheduleError("a bandwidth rule is not an object")
        days = rule.get("days")
        if (
            not isinstance(days, list)
            or not days
            or any(
                isinstance(d, bool) or not isinstance(d, int) or not 0 <= d <= 6
                for d in days
            )
        ):
            raise ScheduleError("a bandwidth rule's days must be 0 (Monday) to 6")
        rules.append({
            "days": sorted(set(days)), "start": _minutes(rule.get("start")),
            "end": _minutes(rule.get("end")), "kbps": _kbps(rule.get("kbps")),
        })  # fmt: skip
    return {"rules": rules, "default_kbps": _kbps(schedule.get("default_kbps", 0))}


def cap_at(schedule: Dict[str, Any], moment: datetime.datetime) -> int:
    """Bytes per second allowed at ``moment`` (local time); 0 = no cap."""
    day = moment.weekday()
    minute = moment.hour * 60 + moment.minute
    for rule in schedule["rules"]:
        start, end = rule["start"], rule["end"]
        if start <= end:
            hit = day in rule["days"] and start <= minute < end
        else:  # past midnight: the evening of a listed day, or the morning after
            hit = (day in rule["days"] and minute >= start) or (
                (day - 1) % 7 in rule["days"] and minute < end
            )
        if hit:
            return rule["kbps"] * 1000 // 8
    return schedule["default_kbps"] * 1000 // 8


class Throttle:
    """A token bucket whose rate follows the schedule."""

    def __init__(
        self,
        schedule: Dict[str, Any],
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime.datetime] = datetime.datetime.now,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.schedule = schedule
        self._clock = clock
        self._now = now
        self._sleep = sleep
        self._tokens = 0.0
        self._last = clock()

    def consume(self, size: int) -> None:
        while size > 0:
            rate = cap_at(self.schedule, self._now())
            if rate <= 0:
                self._tokens = 0.0
                self._last = self._clock()
                return
            moment = self._clock()
            self._tokens = min(
                rate * BURST_SECONDS, self._tokens + (moment - self._last) * rate
            )
            self._last = moment
            if self._tokens >= 1:
                taken = min(size, int(self._tokens))
                self._tokens -= taken
                size -= taken
                continue
            self._sleep(min(1.0, (1 - self._tokens) / rate + 0.001))


class ThrottledReader:  # pylint: disable=too-few-public-methods
    """A file whose reads wait for the throttle (an upload's body)."""

    def __init__(self, handle: BinaryIO, throttle: Throttle):
        self._handle = handle
        self._throttle = throttle

    def read(self, size: int = -1) -> bytes:
        data = self._handle.read(size)
        if data:
            self._throttle.consume(len(data))
        return data
