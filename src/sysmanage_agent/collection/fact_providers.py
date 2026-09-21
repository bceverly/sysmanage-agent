# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Fact provider bootstrap — ROADMAP Phase 21.1, slice S3.

The registry in ``fact_schema`` starts EMPTY, and an empty registry is not a
neutral state: ``build_fact_coverage`` correctly reports every table as
``no_provider``, so an agent that never bootstraps advertises a host with no
facts at all.  That is the honest answer to "who registered?", which makes it
exactly the wrong thing to leave to chance.  One function, called from one
place, is what keeps the advertisement true.

ORDER MATTERS, ONCE
-------------------
Native registers first and unconditionally -- it is the floor, and it is what
OpenBSD and NetBSD have.  osquery registers second and only on the operator's
say-so.  Preference is decided by ``PROVIDER_ORDER``, not by registration
order, so this is about WHAT exists rather than what wins; registering native
first simply means a host is never briefly factless while osquery is probed.
"""

import logging
from typing import Any, Optional

from src.sysmanage_agent.collection import fact_native, fact_osquery
from src.sysmanage_agent.core.fact_schema import clear_providers

logger = logging.getLogger(__name__)

# Opt-in, per ROADMAP 21.1 S3.  Default OFF: a host that merely happens to
# have osquery installed keeps using the native provider until an operator
# says otherwise, so enabling this is a decision with a date on it rather
# than a side effect of some unrelated package install.
OSQUERY_ENABLED_KEY = "facts.osquery.enabled"

_bootstrapped = False


def osquery_enabled(config: Optional[Any]) -> bool:
    """Has the operator opted this host into osquery?

    A config object that cannot answer is not an error and is not a yes: some
    call paths (a capability report built during early startup) have no config
    at all, and the safe reading of "I don't know" is the floor provider.
    """
    if config is None:
        return False
    try:
        return bool(config.get(OSQUERY_ENABLED_KEY, False))
    except Exception:  # pylint: disable=broad-except
        logger.debug("could not read %s; leaving osquery off", OSQUERY_ENABLED_KEY)
        return False


def bootstrap_fact_providers(config: Optional[Any] = None, force: bool = False) -> None:
    """Register the fact providers for this host. Idempotent.

    Idempotent because the capability report is built on more than one path --
    at registration and on a live query -- and re-registering on each would
    re-probe osquery every time.  ``force`` re-runs it for tests and for a
    config reload that could have flipped the opt-in.
    """
    global _bootstrapped  # pylint: disable=global-statement
    if _bootstrapped and not force:
        return
    if force:
        clear_providers()
        fact_osquery.reset_cache()

    fact_native.register_native_provider()

    if osquery_enabled(config):
        # Deliberately not guarded by a try/except that swallows: a failure
        # here would be a bug in registration itself, not the field condition
        # of a broken port.  A broken port is already handled where it belongs
        # -- the probe answers no, and _choose_provider walks on to native.
        fact_osquery.register_osquery_provider(enabled=True)
        logger.info("osquery fact provider enabled by configuration")

    _bootstrapped = True
