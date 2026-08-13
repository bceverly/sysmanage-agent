# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent must reach the server over ONE origin, on 443, and nothing else.

The point of these tests is a firewall rule an operator can actually satisfy:
"outbound 443 to your SysManage host". Anything that reintroduces a second port
-- a WebSocket on its own port, a stray default of 8000, an origin that differs
between REST and WebSocket -- is the failure they pin.

They also pin backward compatibility, which is not negotiable: every agent in
the field is configured with hostname/port/use_https, and an upgrade that
ignored those would strand the whole fleet on its next restart.
"""

import ssl

import pytest

from src.sysmanage_agent.core.server_endpoint import ServerEndpoint


class _Config:
    """Minimal stand-in for ConfigManager: the endpoint only needs two methods."""

    def __init__(self, server, verify_ssl=True):
        self._server = server
        self._verify_ssl = verify_ssl

    def get_server_config(self):
        return self._server

    def should_verify_ssl(self):
        return self._verify_ssl


def endpoint(server, verify_ssl=True):
    return ServerEndpoint(_Config(server, verify_ssl))


# ---------------------------------------------------------------------------
# The single-origin goal
# ---------------------------------------------------------------------------


def test_https_url_with_no_port_means_443():
    """The headline case: one origin, no port, nothing to open but 443."""
    ep = endpoint({"url": "https://sysmanage.example.com"})
    assert ep.base_url() == "https://sysmanage.example.com"
    assert ep.rest_url("/api/host/register") == (
        "https://sysmanage.example.com/api/host/register"
    )
    assert ep.websocket_url() == ("wss://sysmanage.example.com/api/agent/connect")


def test_websocket_shares_the_rest_origin_exactly():
    """A WebSocket on its own port is the second firewall hole we are removing.

    Host, port and TLS decision are DERIVED from the one origin rather than
    separately configurable, so they cannot drift apart.
    """
    ep = endpoint({"url": "https://sysmanage.example.com:8443"})
    rest = ep.rest_url("/api/x")
    ws = ep.websocket_url("/api/agent/connect")
    assert rest.startswith("https://sysmanage.example.com:8443/")
    assert ws.startswith("wss://sysmanage.example.com:8443/")


def test_default_port_is_omitted_from_urls():
    """An explicit :443 is noise, and some proxies key on the literal Host."""
    ep = endpoint({"url": "https://example.com:443"})
    assert ep.base_url() == "https://example.com"
    assert ":443" not in ep.websocket_url()


def test_non_default_port_is_kept():
    """Dev runs the backend on 8080 with no proxy in front; that must still work."""
    ep = endpoint({"url": "http://localhost:8080"})
    assert ep.base_url() == "http://localhost:8080"
    assert ep.websocket_url() == "ws://localhost:8080/api/agent/connect"
    assert ep.uses_tls is False


# ---------------------------------------------------------------------------
# Backward compatibility with every agent already deployed
# ---------------------------------------------------------------------------


def test_legacy_hostname_port_still_builds_the_same_urls():
    """Existing configs must keep working byte-for-byte."""
    ep = endpoint({"hostname": "old.example.com", "port": 8080, "use_https": True})
    assert ep.base_url() == "https://old.example.com:8080"
    assert ep.rest_url("/api/agent/auth") == (
        "https://old.example.com:8080/api/agent/auth"
    )
    assert ep.websocket_url() == ("wss://old.example.com:8080/api/agent/connect")


def test_legacy_without_https_is_plain_http():
    ep = endpoint({"hostname": "h", "port": 8080, "use_https": False})
    assert ep.base_url() == "http://h:8080"
    assert ep.websocket_url().startswith("ws://")


def test_legacy_without_a_port_now_means_the_standard_port():
    """The old default was 8000, which matched no shipped template.

    Every config file the project ships sets 8080, so the 8000 default was
    unreachable in practice and simply wrong. Absent a port, the scheme's
    standard port is the only defensible answer -- and it is the one that needs
    no firewall change.
    """
    ep = endpoint({"hostname": "h", "use_https": True})
    assert ep.base_url() == "https://h"
    assert ep.port is None
    assert "8000" not in ep.websocket_url()


def test_url_takes_precedence_over_legacy_fields():
    ep = endpoint(
        {
            "url": "https://new.example.com",
            "hostname": "old.example.com",
            "port": 8080,
            "use_https": False,
        }
    )
    assert ep.base_url() == "https://new.example.com"


def test_wss_url_is_tls_not_silently_downgraded():
    """Six of seven shipped templates say ``url: "wss://host:8443"``.

    Treating ``wss`` as an unrecognised scheme and falling back to ``use_https``
    (absent, so false) produced PLAINTEXT ``ws://`` for every one of those
    installs -- a silent downgrade of exactly the traffic this work is meant to
    secure. Measured against installer/ubuntu/sysmanage-agent.yaml.example.
    """
    ep = endpoint({"url": "wss://sysmanage.example.com:8443"})
    assert ep.uses_tls is True
    assert ep.websocket_url() == ("wss://sysmanage.example.com:8443/api/agent/connect")
    assert ep.rest_url("/api") == "https://sysmanage.example.com:8443/api"


def test_ws_url_is_plain_http():
    ep = endpoint({"url": "ws://localhost:8080"})
    assert ep.uses_tls is False
    assert ep.websocket_url() == "ws://localhost:8080/api/agent/connect"


def test_bare_host_url_falls_back_to_use_https_rather_than_guessing():
    """A schemeless value must not silently change what an install means."""
    assert endpoint({"url": "h.example.com", "use_https": True}).scheme == "https"
    assert endpoint({"url": "h.example.com", "use_https": False}).scheme == "http"


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/api/host/register", "api/host/register"],
)
def test_leading_slash_is_optional(path):
    ep = endpoint({"url": "https://e.com"})
    assert ep.rest_url(path) == "https://e.com/api/host/register"


def test_rest_url_does_not_invent_an_api_prefix():
    """Registration and health deliberately sit outside /api.

    Prepending it here would 404 them, so callers state the full path.
    """
    ep = endpoint({"url": "https://e.com"})
    assert ep.rest_url("/health") == "https://e.com/health"


# ---------------------------------------------------------------------------
# Hostile-but-normal networks
# ---------------------------------------------------------------------------


def test_plain_http_has_no_ssl_context():
    assert endpoint({"url": "http://e.com"}).ssl_context() is None


def test_https_verifies_by_default():
    ctx = endpoint({"url": "https://e.com"}).ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_corporate_ca_is_trusted_without_weakening_verification(tmp_path):
    """The answer for TLS-inspecting proxies is to trust their root.

    Turning verification off would also "work", and is what people reach for;
    this pins that the supported path keeps verification ON.
    """
    ca = tmp_path / "corp-root.pem"
    ca.write_bytes(_make_test_ca())
    ctx = endpoint({"url": "https://e.com", "ca_bundle": str(ca)}).ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    # The bundle really was loaded, not silently ignored.
    subjects = [c["subject"] for c in ctx.get_ca_certs()]
    assert any("sysmanage-test-ca" in str(s) for s in subjects)


def test_verify_ssl_false_disables_verification():
    ctx = endpoint({"url": "https://e.com"}, verify_ssl=False).ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_proxy_is_none_by_default_so_the_environment_is_used():
    """None means "let the transport read HTTPS_PROXY", not "no proxy"."""
    assert endpoint({"url": "https://e.com"}).proxy() is None


def test_explicit_proxy_overrides_the_environment():
    """A Windows service does not inherit a user's shell variables."""
    ep = endpoint({"url": "https://e.com", "proxy": "http://proxy.corp:3128"})
    assert ep.proxy() == "http://proxy.corp:3128"


def test_blank_proxy_is_treated_as_unset():
    assert endpoint({"url": "https://e.com", "proxy": "   "}).proxy() is None


def _make_test_ca() -> bytes:
    """Generate a real throwaway CA certificate in PEM form.

    Generated rather than inlined: a hand-pasted PEM blob is unverifiable by
    eye, and one with a corrupt body would make ``ssl`` raise and the test fail
    for a reason that has nothing to do with what it is checking.
    ``cryptography`` is already a runtime dependency of the agent.
    """
    import datetime  # noqa: PLC0415 - test-only helper

    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sysmanage-test-ca")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# The plumbing is actually connected
#
# ServerEndpoint can expose proxy settings perfectly and still be useless if no
# transport consumes them.  These check the wiring, not the accessor.
# ---------------------------------------------------------------------------


def test_session_kwargs_enables_environment_proxies():
    """aiohttp ignores HTTPS_PROXY unless trust_env is set.

    Without this the "honours your existing proxy configuration" promise is
    simply false, and it fails in the environments hardest to debug.
    """
    kwargs = endpoint({"url": "https://e.com"}).session_kwargs()
    assert kwargs["trust_env"] is True
    assert kwargs["connector"] is not None
    kwargs["connector"].close()


def test_session_kwargs_carries_the_tls_context():
    kwargs = endpoint({"url": "https://e.com"}).session_kwargs()
    try:
        assert kwargs["connector"] is not None
    finally:
        kwargs["connector"].close()


def test_every_server_bound_session_uses_the_shared_kwargs():
    """A new session that hand-rolls its own connector loses proxy + ca_bundle.

    Pinned by inspection because the alternative is mocking aiohttp at six call
    sites, which would test the mock. public_ip_fetcher is excluded on purpose:
    it talks to a third-party IP service, not to the SysManage server.
    """
    import re  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    repo = Path(__file__).resolve().parent.parent
    offenders = []
    for path in list(repo.glob("src/**/*.py")) + [repo / "main.py"]:
        if path.name == "public_ip_fetcher.py":
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"aiohttp\.ClientSession\((.{0,120})", text, re.S):
            if "session_kwargs" not in match.group(1):
                offenders.append(f"{path.relative_to(repo)}: {match.group(1)[:60]!r}")
    assert not offenders, (
        "these sessions bypass ServerEndpoint.session_kwargs(), so they ignore "
        "the configured proxy and ca_bundle:\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# The templates we actually ship
# ---------------------------------------------------------------------------


def test_every_shipped_config_template_resolves_to_a_working_tls_endpoint():
    """Parse each installer's example config with the REAL config manager.

    This is the check that was missing.  Six of the seven templates declare
    ``url: "wss://host:8443"``, a shape ConfigManager never read -- so an
    operator who followed the shipped example got an agent pointed at
    ``ws://localhost:8000`` and wondered why nothing enrolled.  Asserting what
    the templates SAY would have kept passing; this asserts what the agent
    DERIVES from them.
    """
    import yaml  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    repo = Path(__file__).resolve().parent.parent
    templates = sorted(repo.glob("installer/**/*.yaml.example"))
    assert templates, "no shipped config templates found"

    problems = []
    for template in templates:
        raw = yaml.safe_load(template.read_text(encoding="utf-8")) or {}
        server = raw.get("server") or {}
        ep = ServerEndpoint(_Config(server, verify_ssl=True))
        rel = template.relative_to(repo)

        if ep.host in ("localhost", "127.0.0.1"):
            problems.append(
                f"{rel}: resolves to {ep.host} -- the example is not usable"
            )
        if not ep.uses_tls:
            problems.append(
                f"{rel}: resolves to plaintext {ep.websocket_url()} -- "
                "a shipped example must not default to unencrypted transport"
            )
        if ep.port is not None:
            problems.append(
                f"{rel}: pins port {ep.port}. The shipped examples must need "
                "nothing but outbound 443; a port here is a firewall rule we "
                "are asking every customer to write."
            )

    assert not problems, "\n  " + "\n  ".join(problems)


def test_missing_ca_bundle_fails_with_an_attributable_error():
    """A typo in the path must name the setting, not surface from inside ssl.py.

    And it must NOT quietly fall back to the system trust store: the operator
    named a CA for a reason, and ignoring it would either fail confusingly
    elsewhere or trust a chain they never asked to trust.
    """
    ep = endpoint({"url": "https://e.com", "ca_bundle": "/nope/missing-root.pem"})
    with pytest.raises(FileNotFoundError) as excinfo:
        ep.ssl_context()
    message = str(excinfo.value)
    assert "server.ca_bundle" in message, "the error must name the config key"
    assert "/nope/missing-root.pem" in message, "the error must name the path"
