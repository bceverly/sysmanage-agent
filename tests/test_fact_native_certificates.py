# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The native ``certificates`` table must mean what osquery's does.

Found by the Phase 21.2 S0 spike (2026-09-23), running an osquery-style rule
against this provider on a real host: ``ca`` came from a path/subject
heuristic that called ACCVRAIZ1, a root CA, "not a CA", and the dates were
ISO-8601 where osquery reports epoch seconds -- so ``CAST(not_valid_after AS
INTEGER)`` read "2030-12-31T..." as 2030 and every certificate looked expired.
"""

# pylint: disable=protected-access

from src.sysmanage_agent.collection import fact_native as fn
from src.sysmanage_agent.collection.certificate_collection import (
    CertificateCollector,
)

# ``openssl x509 -purpose`` for a root CA and for a leaf, trimmed to the CA
# lines. Note "Any Purpose CA : Yes" on the LEAF: it says Yes for everything.
CA_PURPOSE = """Certificate purposes:
SSL client : No
SSL client CA : Yes
SSL server CA : Yes
Any Purpose CA : Yes
"""
LEAF_PURPOSE = """Certificate purposes:
SSL client : Yes
SSL client CA : No
SSL server CA : No
Any Purpose CA : Yes
"""


class _Certs:
    def __init__(self, rows):
        self._rows = rows

    def collect_certificates(self):
        return self._rows


def test_epoch_from_iso_matches_the_certificate_not_the_local_clock():
    # ACCVRAIZ1's notAfter is Dec 31 09:37:37 2030 GMT.
    assert fn._osquery_epoch("2030-12-31T09:37:37+00:00") == "1924940257"
    assert fn._osquery_epoch("2030-12-31T09:37:37Z") == "1924940257"
    assert fn._osquery_epoch("2030-12-31T09:37:37") == "1924940257"


def test_epoch_passes_digits_through_and_refuses_to_guess():
    assert fn._osquery_epoch("1924940257") == "1924940257"
    assert fn._osquery_epoch(None) is None
    assert fn._osquery_epoch("next tuesday") is None


def test_dates_are_emitted_as_epoch_text():
    rows = fn.build_certificates(
        _Certs(
            [
                {
                    "subject": "CN=a",
                    "issuer": "CN=a",
                    "not_before": "2011-05-05T09:37:37+00:00",
                    "not_after": "2030-12-31T09:37:37+00:00",
                }
            ]
        )
    )
    assert rows[0]["not_valid_after"] == "1924940257"
    assert rows[0]["not_valid_before"] == "1304588257"


def test_ca_is_x509_not_the_heuristic():
    rows = fn.build_certificates(
        _Certs(
            [
                # The heuristic said no; X.509 says yes -- the ACCVRAIZ1 case.
                {
                    "subject": "CN=r",
                    "issuer": "CN=r",
                    "is_ca": False,
                    "basic_constraints_ca": True,
                },
                # And the other way round: a leaf under a path containing "ca".
                {
                    "subject": "CN=l",
                    "issuer": "CN=r",
                    "is_ca": True,
                    "basic_constraints_ca": False,
                },
            ]
        )
    )
    assert [r["ca"] for r in rows] == [1, 0]


def test_ca_falls_back_to_is_ca_when_the_collector_has_no_x509_answer():
    # Windows records are built from the certificate store, not openssl.
    rows = fn.build_certificates(
        _Certs([{"subject": "CN=w", "issuer": "CN=w", "is_ca": True}])
    )
    assert rows[0]["ca"] == 1


def test_openssl_purpose_ca_lines():
    assert CertificateCollector._openssl_says_ca(CA_PURPOSE) is True
    assert CertificateCollector._openssl_says_ca(LEAF_PURPOSE) is False
    assert CertificateCollector._openssl_says_ca("") is False


def test_parse_records_the_x509_answer_beside_the_heuristic():
    collector = CertificateCollector()
    info = collector._parse_openssl_output(
        "/etc/ssl/certs/leaf.pem",
        "subject=CN=leaf\nissuer=CN=root\n" + LEAF_PURPOSE,
    )
    assert info["basic_constraints_ca"] is False
    assert "is_ca" in info  # the Certificates tab's field is untouched
