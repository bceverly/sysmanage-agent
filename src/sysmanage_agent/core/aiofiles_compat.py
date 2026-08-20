# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Drop-in stand-in for the parts of ``aiofiles`` this agent actually uses.

``aiofiles`` is a hard dependency of the agent's async file helpers, but it has
NO port in the OpenBSD ports tree in any category (checked through 7.9), so the
packaged ``.tgz`` -- which runs against the system ``python3`` with dependencies
supplied only by the port's ``RUN_DEPENDS``, no venv and no pip -- would die at
import time on ``import aiofiles``.  A developer checkout is unaffected because
``make install-dev`` pip-installs ``requirements.txt`` into ``.venv``, which is
exactly why this never showed up locally.

So: use the real ``aiofiles`` whenever it is importable, and otherwise fall back
to running the blocking call in a worker thread.  Same shape as the optional
``packaging`` import in ``operations/package_compliance_operations.py``.

Only ``open()`` is provided, and only the surface the agent uses -- ``read()``,
``readlines()``, ``write()``, and ``async with``.  Anything else should be added
here deliberately rather than discovered at runtime on the one platform that
lacks the real library.  Import it aliased so call sites read unchanged::

    from src.sysmanage_agent.core import aiofiles_compat as aiofiles

``asyncio.to_thread`` is 3.9+, matching this project's floor.
"""

import asyncio
import builtins

try:
    import aiofiles as _aiofiles
except ImportError:  # pragma: no cover - exercised only where aiofiles is absent
    _aiofiles = None


class _ThreadedFile:
    """Async wrapper over a blocking file object."""

    def __init__(self, handle):
        self._handle = handle

    async def read(self, *args):
        """Read the file contents."""
        return await asyncio.to_thread(self._handle.read, *args)

    async def readlines(self, *args):
        """Read the file as a list of lines."""
        return await asyncio.to_thread(self._handle.readlines, *args)

    async def write(self, data):
        """Write ``data`` to the file."""
        return await asyncio.to_thread(self._handle.write, data)

    async def close(self):
        """Close the underlying file object."""
        await asyncio.to_thread(self._handle.close)


class _ThreadedOpen:
    """Async context manager mirroring ``aiofiles.open``."""

    def __init__(self, *args, **kwargs):
        self._args = args
        self._kwargs = kwargs
        self._file = None

    async def __aenter__(self):
        # builtins.open, NOT the module-level open() below, which would recurse.
        handle = await asyncio.to_thread(builtins.open, *self._args, **self._kwargs)
        self._file = _ThreadedFile(handle)
        return self._file

    async def __aexit__(self, exc_type, exc, traceback):
        if self._file is not None:
            await self._file.close()
        return False


def open(*args, **kwargs):  # pylint: disable=redefined-builtin
    """``aiofiles.open`` when available, else a thread-backed equivalent."""
    if _aiofiles is not None:
        return _aiofiles.open(*args, **kwargs)
    return _ThreadedOpen(*args, **kwargs)


def using_real_aiofiles() -> bool:
    """True when the real ``aiofiles`` backs this module (for diagnostics)."""
    return _aiofiles is not None
