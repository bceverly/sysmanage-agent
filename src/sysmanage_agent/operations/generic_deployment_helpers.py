# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Shared module-level helpers for the generic deployment operations module.

These functions are imported by BOTH ``generic_deployment`` (the main
handler class + file-deploy code) and ``generic_deployment_plan`` (the
plan-execution mixin), so they live here to avoid a circular import
between those two modules.  ``generic_deployment`` additionally
re-exports ``_decode_command_output`` from its own namespace because
``src.sysmanage_agent.wsl.capability`` imports it from there.
"""

from __future__ import annotations

from typing import List, Optional

# wsl.exe outputs UTF-16LE on Windows; subprocess returns raw bytes which we
# must decode with the right encoding or we get garbled / null-byte-dotted
# strings.  Originally lived in ``_virtualization_windows.WindowsVirtualizationMixin``
# (legacy child-host path); promoted here so the generic apply_deployment_plan
# handler decodes wsl.exe output correctly even when the legacy WSL handlers
# are not in the import graph (post-cutover).
_UTF16LE_BOM = b"\xff\xfe"


def _argv_is_wsl_exe(argv: Optional[List[str]]) -> bool:
    """Return True if argv[0] basename is ``wsl.exe`` or ``wsl``."""
    if not argv:
        return False
    head = argv[0]
    if not isinstance(head, str):
        return False
    base = head.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    return base in ("wsl.exe", "wsl")


def _decoded_looks_like_utf16le(decoded: str) -> bool:
    """High-density-NUL heuristic: ``UTF-16LE-as-UTF-8`` smoking gun.

    UTF-16LE bytes that happen to be ASCII-mappable decode as UTF-8 with
    one NUL between every printable character.  If >= 5 % of the result
    is NULs, treat it as misdecoded UTF-16LE.
    """
    null_count = decoded.count("\x00")
    return bool(null_count) and null_count * 20 >= len(decoded)


def _decode_utf16le(stream: bytes) -> Optional[str]:
    """Strip BOM (if any) and decode as UTF-16LE; return None on failure."""
    body = stream[2:] if stream.startswith(_UTF16LE_BOM) else stream
    try:
        return body.decode("utf-16-le").replace("\x00", "")
    except (UnicodeDecodeError, LookupError):
        return None


def _decode_command_output(stream: bytes, argv: Optional[List[str]] = None) -> str:
    """Decode subprocess stdout/stderr bytes into a string.

    Tries UTF-8 first.  Falls back to UTF-16LE when the bytes look like
    UTF-16LE output (argv[0] is ``wsl.exe`` / ``wsl``, the bytes start
    with the UTF-16LE BOM, or the UTF-8 decode produced a string littered
    with null characters — the smoking-gun signature of UTF-16LE bytes
    decoded as UTF-8).  Last resort is latin-1, which never fails.

    Args:
        stream: Raw bytes from ``proc.stdout`` or ``proc.stderr``.
        argv: The argv list of the spawned command (for the wsl.exe
            heuristic).  Optional; pass None when not available.

    Returns:
        Decoded string.  Empty input returns an empty string.
    """
    if not stream:
        return ""

    looks_utf16 = stream.startswith(_UTF16LE_BOM) or _argv_is_wsl_exe(argv)

    if not looks_utf16:
        try:
            decoded = stream.decode("utf-8")
        except UnicodeDecodeError:
            decoded = None
        if decoded is not None:
            if _decoded_looks_like_utf16le(decoded):
                looks_utf16 = True
            else:
                return decoded

    if looks_utf16:
        utf16 = _decode_utf16le(stream)
        if utf16 is not None:
            return utf16

    try:
        return stream.decode("utf-8", errors="replace")
    except Exception:  # pylint: disable=broad-exception-caught
        return stream.decode("latin-1")
