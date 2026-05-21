"""
Phase 12.7: Public-IP fetcher for the agent.

Fetches the host's public-facing IP from a small allowlist of public
echo endpoints, validates it as a syntactically-valid IPv4 / IPv6
address, and caches the result in memory for re-use by subsequent
heartbeats.  The server uses this IP for GeoLite2 geo-resolution
(see ``backend/services/geolocation_service.py`` and the Phase 12.7
section in ROADMAP.md).

Design:
  * **Three-endpoint fallback** — try each in order until one returns
    a valid IP string.  Each request gets a tight 5s timeout so a
    slow or hung endpoint can't stall the agent.
  * **Module-level cache** — a single ``PublicIPCache`` instance with
    an async refresh + a sync read.  Refresh is called once at agent
    startup (so the first heartbeat carries a value) and then by a
    background task every ``DEFAULT_REFRESH_INTERVAL_SECONDS`` (24h).
  * **Silent skip when unreachable** — air-gapped agents legitimately
    can't reach the echo endpoints; we log and leave the cache empty.
    The heartbeat payload simply omits ``public_ip`` in that case and
    the server's geo-resolver leaves the host's geo columns alone.
  * **Re-validates each fetch** — even from trusted endpoints, we
    parse the response body with ``ipaddress.ip_address`` and reject
    anything that doesn't validate as IPv4 or IPv6.  Defends against
    a malicious or compromised echo endpoint returning garbage.

Public surface:
  * ``async refresh()`` — refetch from the endpoints, update cache,
    log result.  Safe to call concurrently (internal lock).
  * ``get()`` — synchronous read of the cached value (or None).
    Heartbeat construction is sync, so this is what the
    ``create_heartbeat_message`` payload uses.
  * ``public_ip_refresh_service()`` — async loop that calls
    ``refresh()`` at startup and then every refresh interval.
    Launched as an ``asyncio.create_task`` by the agent's run loop.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)

# Three echo endpoints with mutual fallback.  Order matters: ipify is
# the canonical / most-uptime; ifconfig.co and icanhazip are well-known
# secondaries with independent operators.  All return a plain-text
# response body containing the public IP.
_ECHO_ENDPOINTS: Tuple[str, ...] = (
    "https://api.ipify.org",
    "https://ifconfig.co/ip",
    "https://icanhazip.com",
)

# Per-request timeout.  5 s is plenty for an HTTP GET that returns
# ~16 bytes; if any single endpoint is slower than that, we move on
# rather than block the agent's startup or background refresh tick.
_HTTP_TIMEOUT_SECONDS = 5.0

# How often the background refresh task re-checks.  Public IP is stable
# on most hosts (NAT egress, fixed ISP allocation); refreshing once a
# day is enough to catch the occasional dynamic-IP rotation.
DEFAULT_REFRESH_INTERVAL_SECONDS = 24 * 60 * 60


class PublicIPCache:
    """Thread-safe-ish in-memory cache for the agent's public IP.

    The async refresh is single-flight via an ``asyncio.Lock`` so two
    overlapping refreshes (startup + first scheduled tick racing) can't
    each hit the echo endpoints.  The sync ``get`` reads the current
    value with no lock — Python attribute reads are atomic for a single
    string reference, and stale-by-one-cycle is fine.
    """

    def __init__(self) -> None:
        self._ip: Optional[str] = None
        self._lock = asyncio.Lock()

    def get(self) -> Optional[str]:
        """Return the last successfully-fetched public IP (or None)."""
        return self._ip

    async def refresh(self) -> Optional[str]:
        """Fetch the public IP from the echo endpoints, update the cache.

        Returns the new IP on success, or the previous cached value
        (possibly None) if all endpoints failed.  Never raises.
        """
        async with self._lock:
            new_ip = await _fetch_from_endpoints()
            if new_ip is not None and new_ip != self._ip:
                logger.info(
                    "Public IP refreshed: %s -> %s",
                    self._ip or "(unset)",
                    new_ip,
                )
                self._ip = new_ip
            elif new_ip is None and self._ip is None:
                # Quiet at debug — happens every refresh on airgapped
                # agents and we don't want to spam the log.
                logger.debug(
                    "Public IP fetch returned no result from any echo "
                    "endpoint; cache remains empty"
                )
            return self._ip


# Module-level singleton — the agent has one public IP.
_cache = PublicIPCache()


def get() -> Optional[str]:
    """Module-level convenience: return the cached public IP (or None)."""
    return _cache.get()


async def refresh() -> Optional[str]:
    """Module-level convenience: force a refresh + return the new value."""
    return await _cache.refresh()


async def _fetch_from_endpoints() -> Optional[str]:
    """Try each echo endpoint until one returns a valid IP.

    Returns None if every endpoint times out, errors, or returns a
    response body that doesn't parse as IPv4 or IPv6.
    """
    timeout = aiohttp.ClientTimeout(total=_HTTP_TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for url in _ECHO_ENDPOINTS:
            try:
                async with session.get(url) as response:
                    if response.status != 200:
                        logger.debug(
                            "Echo endpoint %s returned HTTP %d", url, response.status
                        )
                        continue
                    body = await response.text()
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.debug("Echo endpoint %s unreachable: %s", url, exc)
                continue
            candidate = body.strip()
            # Reject anything that doesn't validate as a real IP.  This
            # protects against compromised endpoints injecting garbage
            # or unrelated text (e.g. a captive-portal HTML page).
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                logger.debug(
                    "Echo endpoint %s returned non-IP body %r", url, candidate[:60]
                )
                continue
            return candidate
    return None


async def public_ip_refresh_service(
    refresh_interval_seconds: int = DEFAULT_REFRESH_INTERVAL_SECONDS,
) -> None:
    """Background task: refresh the public-IP cache on a schedule.

    Calls ``refresh()`` immediately so the first heartbeat after
    startup carries the IP, then sleeps for ``refresh_interval_seconds``
    between refreshes.  Cancellation-safe: ``await asyncio.sleep`` is
    the only blocking point and it propagates ``CancelledError``
    naturally.
    """
    while True:
        try:
            await _cache.refresh()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning("public_ip_refresh_service iteration failed: %s", exc)
        await asyncio.sleep(max(1, refresh_interval_seconds))
