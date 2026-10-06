# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Phase 22.1: the public winget / Chocolatey catalogs are fetched politely.

Every Windows agent paged through both public catalogs (~460 requests) with
no pause and no rate-limit handling, and stored whatever part it had when a
page failed.  Now: paced, 429/503 honored (Retry-After), a partial fetch is
a failure that keeps the previous catalog, and a catalog fetched within
PUBLIC_CATALOG_MAX_AGE is reused.
"""

import io
import json
import urllib.error
from datetime import datetime, timedelta, timezone
from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from src.sysmanage_agent.collection import package_collector_windows as pcw

WINGET = "https://api.winget.run/v2/packages"


def _http_error(code, retry_after=None):
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(WINGET, code, "x", headers, io.BytesIO(b""))


def _response(body: bytes):
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def _winget_page(ids, total):
    return json.dumps(
        {
            "Packages": [
                {"Id": f"p{i}", "Latest": {"Name": f"P{i}", "PackageVersion": "1"}}
                for i in ids
            ],
            "Total": total,
        }
    ).encode()


@pytest.fixture
def collector():
    with patch(
        "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
    ):
        yield pcw.WindowsPackageCollector()


@pytest.fixture(autouse=True)
def no_sleep():
    with patch.object(pcw.time, "sleep") as sleep:
        yield sleep


class TestFetchPublic:
    def test_rate_limit_waits_for_retry_after_then_succeeds(self, no_sleep):
        with patch.object(
            pcw.urllib.request,
            "urlopen",
            side_effect=[_http_error(429, "42"), _response(b"ok")],
        ):
            assert pcw._fetch_public(WINGET) == b"ok"
        no_sleep.assert_called_once_with(42.0)

    def test_retry_after_is_capped(self):
        error = _http_error(503, "86400")
        wait = pcw._retry_after_seconds(error, 0)
        error.close()
        assert wait == pcw.MAX_RETRY_WAIT_SECONDS

    def test_backoff_without_retry_after(self):
        error = _http_error(429, "Wed, 21 Oct 2026 07:28:00 GMT")
        wait = pcw._retry_after_seconds(error, 1)
        error.close()
        assert 15 * 2 * 0.75 <= wait <= 15 * 2 * 1.25

    def test_persistent_rate_limit_is_incomplete(self):
        with patch.object(
            pcw.urllib.request, "urlopen", side_effect=_http_error(429, "1")
        ) as urlopen:
            with pytest.raises(pcw.CatalogIncomplete):
                pcw._fetch_public(WINGET)
        assert urlopen.call_count == pcw.MAX_ATTEMPTS

    def test_other_http_errors_are_not_retried(self):
        with patch.object(
            pcw.urllib.request, "urlopen", side_effect=_http_error(404)
        ) as urlopen:
            with pytest.raises(pcw.CatalogIncomplete):
                pcw._fetch_public(WINGET)
        assert urlopen.call_count == 1

    def test_dropped_connection_is_retried(self):
        with patch.object(
            pcw.urllib.request,
            "urlopen",
            side_effect=[urllib.error.URLError("reset"), _response(b"ok")],
        ):
            assert pcw._fetch_public(WINGET) == b"ok"

    def test_https_only(self):
        with pytest.raises(ValueError):
            pcw._fetch_public("http://api.winget.run/v2/packages")


class TestCatalogFetch:
    def test_pages_are_paced(self, collector, no_sleep):
        pages = [_winget_page(range(0, 12), 24), _winget_page(range(12, 24), 24)]
        with patch.object(
            pcw.urllib.request, "urlopen", side_effect=[_response(p) for p in pages]
        ):
            packages = collector._collect_winget_pages(WINGET)
        assert len(packages) == 24
        # One pause between the two pages, inside PAGE_DELAY_SECONDS.
        assert no_sleep.call_count == 1
        low = pcw.PAGE_DELAY_SECONDS * (1 - pcw.PAGE_DELAY_SPREAD)
        high = pcw.PAGE_DELAY_SECONDS * (1 + pcw.PAGE_DELAY_SPREAD)
        assert low <= no_sleep.call_args[0][0] <= high

    def test_a_failed_page_fails_the_catalog(self, collector):
        with patch.object(
            pcw.urllib.request,
            "urlopen",
            side_effect=[_response(_winget_page(range(0, 12), 100)), _http_error(500)],
        ):
            with pytest.raises(pcw.CatalogIncomplete):
                collector._collect_winget_pages(WINGET)

    def test_an_unreadable_page_fails_the_catalog(self, collector):
        with patch.object(
            pcw.urllib.request, "urlopen", side_effect=[_response(b"<html>")]
        ):
            with pytest.raises(pcw.CatalogIncomplete):
                collector._collect_winget_pages(WINGET)

    def test_a_runaway_pager_stops(self, collector):
        with patch.object(pcw, "MAX_PAGES", 3), patch.object(
            pcw.urllib.request,
            "urlopen",
            side_effect=lambda *a, **k: _response(_winget_page(range(0, 12), 0)),
        ):
            with pytest.raises(pcw.CatalogIncomplete):
                collector._collect_winget_pages(WINGET)


class TestCollectPublicCatalog:
    def test_partial_fetch_keeps_the_previous_catalog(self, collector):
        def fetch():
            raise pcw.CatalogIncomplete("HTTP 500")

        with patch.object(collector, "_catalog_age", return_value=None), patch.object(
            collector, "_store_packages"
        ) as store:
            assert (
                collector._collect_public_catalog("winget", fetch, "err %s", "empty")
                == 0
            )
        store.assert_not_called()

    def test_fresh_catalog_is_reused(self, collector):
        fetch = MagicMock()
        with patch.object(
            collector, "_catalog_age", return_value=timedelta(hours=2)
        ), patch.object(collector, "get_packages_for_manager", return_value=[1, 2, 3]):
            assert (
                collector._collect_public_catalog("winget", fetch, "err %s", "empty")
                == 3
            )
        fetch.assert_not_called()

    def test_stale_catalog_is_fetched_and_stored(self, collector):
        packages = [{"name": "a", "version": "1"}]
        with patch.object(
            collector, "_catalog_age", return_value=pcw.PUBLIC_CATALOG_MAX_AGE
        ), patch.object(collector, "_store_packages", return_value=1) as store:
            assert (
                collector._collect_public_catalog(
                    "chocolatey", lambda: packages, "err %s", "empty"
                )
                == 1
            )
        store.assert_called_once_with("chocolatey", packages)

    def test_empty_fetch_stores_nothing(self, collector):
        with patch.object(collector, "_catalog_age", return_value=None), patch.object(
            collector, "_store_packages"
        ) as store:
            assert (
                collector._collect_public_catalog("winget", list, "err %s", "empty")
                == 0
            )
        store.assert_not_called()


class TestCatalogAge:
    def _with_newest(self, collector, value):
        session = MagicMock()
        query = session.query.return_value.filter.return_value.order_by.return_value
        query.first.return_value = value
        collector.db_manager.get_session.return_value.__enter__.return_value = session

    def test_naive_timestamp_read_as_utc(self, collector):
        collected = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=3)
        self._with_newest(collector, (collected,))
        age = collector._catalog_age("winget")
        assert timedelta(hours=2, minutes=59) < age < timedelta(hours=3, minutes=1)

    def test_no_catalog(self, collector):
        self._with_newest(collector, None)
        assert collector._catalog_age("winget") is None

    def test_unreadable_database_means_fetch(self, collector):
        collector.db_manager.get_session.side_effect = RuntimeError("locked")
        assert collector._catalog_age("winget") is None
