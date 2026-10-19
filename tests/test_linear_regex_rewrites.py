# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The linear rewrites of patterns SonarCloud flagged as super-linear
(S5852, 2026-10-19) capture exactly what the originals did.

Each original pattern is kept here as the oracle, and the new code is checked
against it on real tool output and on a seeded random corpus built from the
characters that pattern cares about.
"""

import random
import re

from src.sysmanage_agent.collection import compliance_evidence_parsers as cep
from src.sysmanage_agent.collection import hardware_events as he
from src.sysmanage_agent.collection import hardware_health as hh
from src.sysmanage_agent.collection import hardware_health_bsd as bsd
from src.sysmanage_agent.collection import hardware_health_linux as hl
from src.sysmanage_agent.collection import hardware_health_linux_storage as hls
from src.sysmanage_agent.collection import hardware_health_mce as mce
from src.sysmanage_agent.collection import hardware_health_vendor as hv

# pylint: disable=protected-access

RNG_SEED = 20261019
CASES = 2000


def _corpus(alphabet, real, length=24):
    rng = random.Random(RNG_SEED)
    out = list(real)
    for _ in range(CASES):
        out.append("".join(rng.choice(alphabet) for _ in range(rng.randint(0, length))))
    return out


def _tokens(*words):
    """An alphabet of whole words and single characters."""
    return list(words)


# -- compliance parsers ------------------------------------------------------

OLD_EQ = re.compile(r"^\s*([A-Za-z_][\w.-]*)\s*=\s*(.*?)\s*$")
OLD_CHRONY = re.compile(r"^\s*([A-Za-z]\w*)\s*(.*?)\s*$")


def test_eq_setting():
    for line in _corpus(
        _tokens(" ", "\t", "=", "a", "B", "_", ".", "-", "1", "x y", "#"),
        [
            "max_log_file = 8",
            "  deny=5  ",
            "even_deny_root",
            "space_left_action = SYSLOG ",
        ],
    ):
        old = OLD_EQ.match(line)
        new = cep._EQ_SETTING.match(line)
        assert (old and (old.group(1), old.group(2))) == (
            new and (new.group(1), line[new.end() :].strip())
        )


def test_chrony():
    for line in _corpus(
        _tokens(" ", "\t", "a", "Z", "_", "1", "-", "pool", ".", "iburst"),
        ["pool 2.ubuntu.pool.ntp.org iburst maxsources 2", "makestep 1 3", "rtcsync"],
    ):
        old = OLD_CHRONY.match(line)
        new = cep._CHRONY.match(line)
        assert (old and (old.group(1), old.group(2))) == (
            new and (new.group(1), line[new.end() :].strip())
        )


# -- hardware events ---------------------------------------------------------


def test_key_value_fields():
    for line in _corpus(
        _tokens(" ", "=", '"', "'", "a", "1", "_", ".", "x", "!"),
        [
            '!system=CAM subsystem=periph type=error device=ada0 serial="WD-1 2"',
            "class=ereport.fs.zfs.checksum pool='tank' vdev_path=/dev/da0",
        ],
    ):
        assert re.findall(r'(\w+)=("[^"]*"|\S+)', line) == he._DEVD_FIELD.findall(line)
        assert re.findall(r"(\w+)=('[^']*'|\S+)", line) == he._ZED_FIELD.findall(line)


# -- smartctl / FreeBSD ------------------------------------------------------


def test_smart_celsius():
    for value in _corpus(
        _tokens(" ", "C", "-", ".", "1", "9", "a", "(", "/"),
        ["36 C", "40 C (Min/Max 20/45)", "-5 C", "5-3 C", "1.2.3 C", "a.5 C"],
    ):
        old = re.search(r"(-?[\d.]+) C", value)
        new = hh._SMART_CELSIUS.search(value)
        assert (old and old.group(1)) == (new and new.group(1))


def test_nvme_devlist():
    for line in _corpus(
        _tokens(" ", "\t", "nvme", "0", "1", ":", "x", "Samsung"),
        ["   nvme0: Samsung SSD 970 EVO Plus 1TB", "nvme1:", "nvd0 (953869MB)"],
    ):
        old = re.match(r"^\s*(nvme\d+):\s*(.*)$", line)
        new = bsd._NVME_DEVLIST.match(line)
        assert (old and (old.group(1), old.group(2).strip())) == (
            new and (new.group(1), line[new.end() :].strip())
        )


def test_acpi_thermal():
    for line in _corpus(
        _tokens(
            " ",
            "\t",
            "hw.acpi.thermal.tz0.temperature:",
            "hw.acpi.thermal.tz1._CRT:",
            "27.9C",
            "x",
            ":",
            "1",
        ),
        ["hw.acpi.thermal.tz0.temperature: 27.9C", "hw.acpi.thermal.tz0._PSV: -1"],
        length=6,
    ):
        old = re.match(
            r"^hw\.acpi\.thermal\.(tz\d+)\.(temperature|_CRT|_PSV):\s*(.+)$", line
        )
        new = bsd._ACPI_THERMAL.match(line)
        got = bsd._rest_after(line, new)
        assert (old and (old.group(1), old.group(2), old.group(3))) == (
            got is not None and (new.group(1), new.group(2), got) or None
        )


# -- Linux md / btrfs / MCE --------------------------------------------------

OLD_MD = re.compile(
    r"^(md\S+)\s*:\s*(\w+)\s+(?:\((\w+)\)\s+)?(raid\d+|linear)?\s*(.*)$"
)


def _new_md(line):
    head = hl._MD_HEAD.match(line)
    if not head:
        return None
    level = hl._MD_LEVEL.match(line, head.end())
    return head.group(1), head.group(2), level.group(2), line[level.end() :].split()


def test_mdstat_line():
    for line in _corpus(
        _tokens(
            " ",
            "md0",
            "md127",
            ":",
            "active",
            "(auto)",
            "raid1",
            "linear",
            "sda1[0]",
            "sdb1[1](F)",
            "x",
        ),
        [
            "md0 : active raid1 sdb1[1] sda1[0]",
            "md127 : active (auto-read-only) raid1 sdb[1] sda[0]",
            "md1 : inactive sdc1[0](S)",
        ],
        length=8,
    ):
        old = OLD_MD.match(line)
        assert (
            old and (old.group(1), old.group(2), old.group(4), old.group(5).split())
        ) == (_new_md(line))


OLD_BTRFS = re.compile(r"^\s*devid\s+(\d+)\s+size\s+.*?\spath\s+(.+?)\s*$")


def test_btrfs_device():
    for line in _corpus(
        _tokens(
            " ", "  ", "devid", "1", "size", "path", "/dev/sda", "used", "x", "MISSING"
        ),
        [
            "\tdevid    1 size 1.82TiB used 1.20TiB path /dev/sda",
            "\tdevid    2 size 0 used 0 path <missing disk> MISSING",
            "devid 1 size path /dev/x",
            "devid 1 size  path /dev/x",
        ],
        length=10,
    ):
        old = OLD_BTRFS.match(line)
        assert (old and (old.group(1), old.group(2))) == hls._btrfs_device_fields(line)


def test_mce_record():
    for line in _corpus(
        _tokens(" ", "1", "2026-10-18 21:04:05", "+0000", "error:", "Uncorrected", "x"),
        [
            "1 2026-10-18 21:04:05 -0400 error: Corrected error, no action required.",
            "  12 2026-10-18 21:04:05 error:   Uncorrected error",
        ],
        length=8,
    ):
        old = re.match(
            r"^\s*\d+\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?: [+-]\d{4})?)\s+error:\s*(.*)$",
            line,
        )
        new = mce._MCE_RECORD.match(line)
        assert (old and (old.group(1), old.group(2))) == (
            new and (new.group(1), line[new.end() :].lstrip())
        )


# -- vendor tools ------------------------------------------------------------


def test_percent_and_sel_clock():
    for text in _corpus(
        _tokens(" ", "%", ".", "1", "9", "a", "/", ":"),
        ["Rebuild 45% done", "12.5 %", "1.2.3 %", "07/14/2026 21:04:05"],
    ):
        old = re.search(r"(\d+(?:\.\d+)?)\s*%", text)
        new = hv._PERCENT.search(text)
        assert (old and old.group(1)) == (new and new.group(1))
        old = re.search(r"(\d+/\d+/\d+)\s+(\d+:\d+:\d+)", text)
        new = hv._SEL_CLOCK.search(text)
        assert (old and old.groups()) == (new and new.groups())


def test_arc_key():
    for line in _corpus(
        _tokens(" ", "\t", ":", "a", "Key", "b", "x y"),
        ["  Controller Status    : Optimal", "Name: x", " : y", "a :b : c"],
    ):
        old = re.match(r"^\s*(.+?)\s+:\s?(.*)$", line)
        assert (old and (old.group(1).strip(), old.group(2).strip())) == hv._arc_key(
            line
        )


def test_sdr_reading():
    for reading in [
        r.strip()
        for r in _corpus(
            _tokens(" ", "-", "1", ".", "5", "degrees", "C"),
            ["45 degrees C", "-1.5 Volts", "0x00", "no reading"],
        )
    ]:
        old = re.match(r"^(-?\d+(?:\.\d+)?)\s+(.+)$", reading)
        new = hv._SDR_READING.match(reading)
        assert (old and (old.group(1), old.group(2).strip())) == (
            new and (new.group(1), new.group(2).strip())
        )
