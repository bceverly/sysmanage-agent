# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Certificate FILE handling — bundles, and finding each file once.

Split out of ``test_certificate_collection_advanced.py``, which had reached
the repository's 1000-line ceiling. Both classes here guard defects found on
real hardware rather than hypotheticals:

* a PEM file may hold hundreds of certificates and ``openssl x509 -in`` reads
  only the first, so a 118-certificate CA bundle was reported as ONE; and
* ``glob("**/…", recursive=True)`` also matches zero directories, so every
  top-level certificate file was processed twice.

Both were silent. Neither raised, logged, or failed a test.
"""

from unittest.mock import mock_open, patch

from src.sysmanage_agent.collection.certificate_collection import CertificateCollector


class TestGlobDoesNotDoubleCount:
    """``**`` with recursive=True also matches ZERO directories.

    So the "files in this directory" glob and the "files in subdirectories"
    glob both return every top-level file, and each one is processed twice.
    That only surfaced as duplicate ROWS because the dedupe downstream keys on
    ``fingerprint_sha256``, which openssl does not supply on this path, so the
    "no fingerprint, include it anyway" branch appended both copies.

    Measured on FreeBSD 14.4 on 2026-09-21: two identical rows for
    ``/usr/local/share/certs/ca-root-nss.crt``.
    """

    @patch("glob.glob")
    def test_a_file_found_by_both_globs_is_processed_once(self, mock_glob):
        collector = CertificateCollector()
        # What the two globs really return: the recursive one is a superset.
        mock_glob.side_effect = [
            ["/certs/ca.crt"],
            ["/certs/ca.crt", "/certs/sub/other.crt"],
        ]
        processed = []
        with patch.object(
            collector,
            "_process_single_certificate",
            side_effect=lambda f, c, s: processed.append(f),
        ):
            collector._process_certificate_pattern(  # pylint: disable=protected-access
                "/certs", "*.crt", [], set()
            )
        assert processed == ["/certs/ca.crt", "/certs/sub/other.crt"]

    @patch("glob.glob")
    def test_the_order_is_stable(self, mock_glob):
        """Sorted, so a diff of two collections stays meaningful."""
        collector = CertificateCollector()
        mock_glob.side_effect = [["/certs/b.crt"], ["/certs/a.crt", "/certs/b.crt"]]
        processed = []
        with patch.object(
            collector,
            "_process_single_certificate",
            side_effect=lambda f, c, s: processed.append(f),
        ):
            collector._process_certificate_pattern(  # pylint: disable=protected-access
                "/certs", "*.crt", [], set()
            )
        assert processed == ["/certs/a.crt", "/certs/b.crt"]


class TestPemBundlesAreFullyRead:
    """``openssl x509 -in`` reads only the FIRST certificate in a PEM file.

    Measured on FreeBSD 14.4 on 2026-09-21: ``ca-root-nss.crt`` holds 118
    certificates and the collector reported ONE. Every trust anchor after the
    first was invisible to the inventory, and nothing failed — a bundle simply
    looked like a single certificate.
    """

    def _bundle(self, count):
        return "\n".join(
            f"-----BEGIN CERTIFICATE-----\nblock{i}\n-----END CERTIFICATE-----"
            for i in range(count)
        )

    def test_every_block_in_a_bundle_is_split_out(self):
        collector = CertificateCollector()
        blocks = collector._split_pem_bundle(  # pylint: disable=protected-access
            self._bundle(118)
        )
        assert len(blocks) == 118
        assert blocks[0].startswith("-----BEGIN CERTIFICATE-----")
        assert blocks[0].rstrip().endswith("-----END CERTIFICATE-----")

    def test_surrounding_text_does_not_break_the_split(self):
        """Real bundles carry comments and subject lines between blocks."""
        collector = CertificateCollector()
        text = "# Issuer: CN=Example\n" + self._bundle(2) + "\ntrailing noise\n"
        blocks = collector._split_pem_bundle(text)  # pylint: disable=protected-access
        assert len(blocks) == 2

    def test_an_unterminated_block_is_not_emitted(self):
        """A truncated file must not yield a half certificate."""
        collector = CertificateCollector()
        text = self._bundle(1) + "\n-----BEGIN CERTIFICATE-----\ntruncated"
        blocks = collector._split_pem_bundle(text)  # pylint: disable=protected-access
        assert len(blocks) == 1

    def test_the_cap_is_a_bound_not_a_silent_clip(self):
        collector = CertificateCollector()
        collector.MAX_CERTS_PER_FILE = 3
        blocks = collector._split_pem_bundle(  # pylint: disable=protected-access
            self._bundle(10)
        )
        assert len(blocks) == 3

    def test_each_certificate_in_a_bundle_is_parsed_separately(self):
        """openssl is invoked per block, with the PEM on stdin — otherwise it
        re-reads the file and describes the first certificate every time."""
        collector = CertificateCollector()
        seen_inputs = []

        def fake_extract(cert_file, pem=None):
            seen_inputs.append(pem)
            return {
                "file_path": cert_file,
                "fingerprint_sha256": f"fp{len(seen_inputs)}",
            }

        with patch("builtins.open", mock_open(read_data=self._bundle(3))):
            with patch.object(
                collector, "_extract_certificate_info", side_effect=fake_extract
            ):
                out = collector._extract_certificates_from_file(  # pylint: disable=protected-access
                    "/certs/bundle.crt"
                )
        assert len(out) == 3
        assert all(p and "BEGIN CERTIFICATE" in p for p in seen_inputs)

    def test_a_single_certificate_file_takes_the_original_path(self):
        """DER files, keystores and one-cert PEMs must behave exactly as
        before — the bundle handling is additive, not a rewrite."""
        collector = CertificateCollector()
        with patch("builtins.open", mock_open(read_data=self._bundle(1))):
            with patch.object(
                collector, "_extract_certificate_info", return_value={"x": 1}
            ) as single:
                out = collector._extract_certificates_from_file(  # pylint: disable=protected-access
                    "/certs/one.crt"
                )
        assert out == [{"x": 1}]
        # Called WITHOUT a pem block, i.e. the original -in <file> path.
        assert single.call_args.kwargs.get("pem") is None

    def test_an_unreadable_file_falls_back_rather_than_raising(self):
        collector = CertificateCollector()
        with patch("builtins.open", side_effect=OSError("denied")):
            with patch.object(
                collector, "_extract_certificate_info", return_value=None
            ):
                assert (
                    collector._extract_certificates_from_file(  # pylint: disable=protected-access
                        "/certs/nope.crt"
                    )
                    == []
                )


class TestFingerprintParsing:
    """The fingerprint is what makes de-duplication work at all.

    OpenSSL 1.x printed ``SHA256 Fingerprint=``; OpenSSL 3.x prints
    ``sha256 Fingerprint=``. The parser matched the old spelling exactly, so
    on every OpenSSL 3 host the fingerprint stayed None — and since the caller
    treats "no fingerprint" as "include it anyway", the dedupe silently
    stopped deduping. Measured on Ubuntu 26.04: /etc/ssl/certs yielded 243
    rows for 121 certificates, each one appearing once per file it lives in.
    """

    def _parse(self, line):
        collector = CertificateCollector()
        info = {"fingerprint_sha256": None}
        collector._parse_openssl_output_line(
            line, info
        )  # pylint: disable=protected-access
        return info["fingerprint_sha256"]

    def test_openssl_3_lowercase_spelling(self):
        assert self._parse("sha256 Fingerprint=AB:CD:EF") == "abcdef"

    def test_openssl_1_uppercase_spelling(self):
        """Still supported: OpenBSD's LibreSSL and older hosts print this."""
        assert self._parse("SHA256 Fingerprint=AB:CD:EF") == "abcdef"

    def test_a_line_that_is_not_a_fingerprint_is_left_alone(self):
        assert self._parse("issuer=CN=Example") is None
