"""
Agent version detection module.
Provides the running agent version for heartbeat and registration messages.
"""

import logging
import subprocess
from importlib.metadata import version as pkg_version

logger = logging.getLogger(__name__)

_CACHED_VERSION: dict[str, str] = {}


def get_agent_version() -> str:
    """
    Get the sysmanage-agent version string.

    Resolution order:
    1. importlib.metadata (installed package)
    2. git describe --tags --abbrev=0 with '-dev' suffix (running from source)
    3. "unknown" fallback

    The result is cached after the first call.
    """
    if "value" in _CACHED_VERSION:
        return _CACHED_VERSION["value"]

    # Try installed package metadata first
    try:
        _CACHED_VERSION["value"] = pkg_version("sysmanage-agent")
        logger.info("Agent version from package metadata: %s", _CACHED_VERSION["value"])
        return _CACHED_VERSION["value"]
    except Exception:  # pylint: disable=broad-except
        pass  # nosec B110 - expected fallthrough to git detection

    # Try git describe for development builds
    try:
        result = subprocess.run(  # nosec B603, B607
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            _CACHED_VERSION["value"] = result.stdout.strip() + "-dev"
            logger.info("Agent version from git: %s", _CACHED_VERSION["value"])
            return _CACHED_VERSION["value"]
    except Exception:  # pylint: disable=broad-except
        pass  # nosec B110 - expected fallthrough to "unknown"

    _CACHED_VERSION["value"] = "unknown"
    logger.warning("Could not determine agent version, using 'unknown'")
    return _CACHED_VERSION["value"]
