# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
ARP listening on the BSDs and macOS through BPF -- Phase 21.6 S6.

Linux captures with an AF_PACKET socket; every other Unix the agent runs on
has the Berkeley Packet Filter instead: open ``/dev/bpf`` (or the first free
``/dev/bpfN``), bind it to one interface, and read buffers of captured frames.
Root is required, as it is for AF_PACKET.  ARP listening found 26 of 31 devices
on a live LAN (21.6 S0), so without this the BSDs and macOS would see only a
fraction of their networks.

THE ONE THING THAT DIFFERS BETWEEN THEM
---------------------------------------
Each captured frame is preceded by a ``struct bpf_hdr`` whose first member is
a timestamp, and its size decides where the lengths are and how records are
aligned:

  macOS    timeval32 (8 bytes)          records aligned to 4
  OpenBSD  bpf_timeval, 2 x u_int32 (8) records aligned to 4
  FreeBSD  struct timeval, 2 x long     records aligned to sizeof(long)
  NetBSD   bpf_timeval, 2 x long        records aligned to sizeof(long)

After the timestamp come ``caplen`` (u32), ``datalen`` (u32) and ``hdrlen``
(u16); the frame starts ``hdrlen`` bytes into the record and the next record
starts at ``BPF_WORDALIGN(hdrlen + caplen)``.  Get the layout wrong and every
frame is garbage, so ``layout()`` is chosen by platform and ``records()`` is
pure and tested against synthetic buffers for each one.
"""

import os
import platform
import re
import select
import shutil
import struct
import subprocess  # nosec B404 - fixed argv, absolute path, no shell
import threading
from typing import Callable, Dict, Iterator, List, Optional, Tuple

# ioctl requests: _IOW/_IOR('B', n, ...) -- identical across the 4.4BSD family.
BIOCGBLEN = 0x40044266
BIOCSETIF = 0x8020426C
BIOCIMMEDIATE = 0x80044270
_IFREQ_SIZE = 32
_MAX_DEVICES = 256


def layout(system: Optional[str] = None) -> Tuple[int, int]:
    """``(timestamp_size, alignment)`` of ``struct bpf_hdr`` on this platform."""
    system = system or platform.system()
    long_size = struct.calcsize("l")
    if system in ("Darwin", "OpenBSD"):
        return 8, 4
    return 2 * long_size, long_size  # FreeBSD, NetBSD, DragonFly


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def records(buffer: bytes, stamp: int, alignment: int) -> Iterator[bytes]:
    """The frames in one BPF read buffer.  Pure: no I/O, no platform calls."""
    offset = 0
    header = stamp + 10  # caplen u32, datalen u32, hdrlen u16
    while offset + header <= len(buffer):
        caplen, _datalen, hdrlen = struct.unpack_from("=IIH", buffer, offset + stamp)
        if hdrlen < header or caplen == 0:
            return  # a malformed record: stop rather than read garbage
        start = offset + hdrlen
        yield buffer[start : start + caplen]
        offset += _align(hdrlen + caplen, alignment)


def open_device(
    interface: str, opener: Callable[[str, int], int] = os.open
) -> Tuple[int, int]:
    """``(fd, buffer_length)`` for a BPF device bound to ``interface``."""
    fd = None
    for path in ["/dev/bpf"] + [f"/dev/bpf{n}" for n in range(_MAX_DEVICES)]:
        try:
            fd = opener(path, os.O_RDONLY)
            break
        except FileNotFoundError:
            continue
        except OSError as error:
            if error.errno == 16:  # EBUSY: that unit is taken, try the next
                continue
            raise
    if fd is None:
        raise OSError("no free BPF device")
    # Imported here, not at module load: fcntl does not exist on Windows, and
    # the collector imports this module on every platform.
    import fcntl  # pylint: disable=import-outside-toplevel

    try:
        ifreq = struct.pack(f"{_IFREQ_SIZE}s", interface.encode()[:15])
        fcntl.ioctl(fd, BIOCSETIF, ifreq)
        fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
        blen = struct.unpack("I", fcntl.ioctl(fd, BIOCGBLEN, struct.pack("I", 0)))[0]
    except OSError:
        os.close(fd)
        raise
    return fd, blen


class BpfListener(threading.Thread):
    """Captures on every monitored interface and hands frames to ``parse``.

    ``parse(frame, interface)`` is the collector's shared frame parser.  Frames
    this host sent come back through BPF too; they are dropped by source MAC.
    """

    def __init__(self, interfaces: List[Dict[str, str]], parse, opener=os.open):
        super().__init__(name="netdisc-bpf", daemon=True)
        self.parse = parse
        self.stop_event = threading.Event()
        self.stamp, self.alignment = layout()
        self.own_macs = {i["mac"].lower() for i in interfaces if i.get("mac")}
        self.devices: Dict[int, Tuple[str, int]] = {}
        for iface in interfaces:
            fd, blen = open_device(iface["name"], opener)
            self.devices[fd] = (iface["name"], blen)
        if not self.devices:
            raise OSError("no interface to capture on")

    def run(self):
        try:
            while not self.stop_event.is_set():
                ready, _w, _x = select.select(list(self.devices), [], [], 1.0)
                for fd in ready:
                    name, blen = self.devices[fd]
                    self._drain(os.read(fd, blen), name)
        except OSError:
            return
        finally:
            for fd in self.devices:
                os.close(fd)

    def _drain(self, buffer: bytes, interface: str) -> None:
        for frame in records(buffer, self.stamp, self.alignment):
            if len(frame) >= 12 and frame[6:12].hex(":") not in self.own_macs:
                self.parse(frame, interface)


# ---------------------------------------------------------------------------
# Bridges that are only VM / jail plumbing (the BSD half of the S5 rule)
# ---------------------------------------------------------------------------

# Member interfaces that are virtual by what they are: bhyve/QEMU taps, jail
# epairs, macOS vmnet, tunnels, loopbacks, other bridges.  A bridge whose
# members are ALL of these carries the host's own guests, not a network the
# operator means -- Bryan's FreeBSD box reported its `bridge1` (10.0.100.0/24)
# as a network the day BPF first ran on it.
_VIRTUAL_MEMBERS = (
    "tap", "epair", "vnet", "vmenet", "tun", "lo", "bridge", "veb", "vether",
    "pair", "vport", "feth", "utun",
)  # fmt: skip
_BRIDGE_NAMES = ("bridge", "veb")
# FreeBSD/macOS: "member: tap0 flags=..."; OpenBSD/NetBSD: "\ttap0 flags=..."
_MEMBER = re.compile(r"^\s+(?:member:\s+)?([A-Za-z][\w.]*)\s+flags=", re.MULTILINE)
_IFCONFIG_TIMEOUT = 5


def bridge_members(ifconfig_text: str) -> List[str]:
    """Member interfaces named in ``ifconfig <bridge>`` output.  Pure."""
    return _MEMBER.findall(ifconfig_text or "")


def virtual_only_bridge(name: str, run=None) -> bool:
    """BSDs / macOS: a bridge all of whose members are virtual.

    A bridge with any physical member (``bridge0`` over ``em0``) is a real
    network and is kept.  Anything that is not a bridge, or whose members
    cannot be read, is kept too: skipping a real network silently is worse
    than reporting a VM bridge.
    """
    if not name.lower().startswith(_BRIDGE_NAMES):
        return False
    text = (run or _ifconfig)(name)
    if text is None:
        return False
    return all(m.lower().startswith(_VIRTUAL_MEMBERS) for m in bridge_members(text))


def _ifconfig(name: str) -> Optional[str]:
    binary = shutil.which("ifconfig") or next(
        (p for p in ("/sbin/ifconfig", "/usr/sbin/ifconfig") if os.path.exists(p)),
        None,
    )
    if binary is None:
        return None
    try:
        result = subprocess.run(  # nosec B603 - fixed argv, absolute path
            [binary, name],
            capture_output=True,
            text=True,
            timeout=_IFCONFIG_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None
