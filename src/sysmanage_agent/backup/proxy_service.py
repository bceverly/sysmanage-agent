# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""restate-proxy as a service on a storage host (server ROADMAP 25.5).

restate's ``restate-proxy`` package installs the service disabled and runs
it as its own ``restate-proxy`` user.  SysManage's repositories are
``root:<account>`` 0770 with the account's files in them (``restate`` by
default), so on a storage host whose target is on the proxy the agent:

* runs it as that account, with group-writable files: on systemd a drop-in
  (``User=``, ``Group=``, ``UMask=0007``); on FreeBSD the rc.conf knobs
  restate's rc script takes (``restate_proxy_user``, ``restate_proxy_umask``);
* gives it its certificate: the key is made HERE and never leaves this host;
  the server signs a request for the target's name with the SysManage CA
  (decided, Bryan, 2026-11-10) and sends the certificate back, when the key
  and certificate are installed together, the key the account's alone;
* enables and starts it once it has a certificate, and restarts it when the
  certificate changes (a proxy reads its certificate only at start).

Back on NFS, the service the agent turned on is stopped and disabled again;
the package stays.  Only these fixed paths and names: the server sends the
proxy's address and the certificate, never a path or a command.
"""

import ipaddress
import os
import posixpath
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.sysmanage_agent.backup import proxy_access as access

UNIT = "restate-proxy.service"
DROP_IN = "/etc/systemd/system/restate-proxy.service.d/sysmanage.conf"
FREEBSD_SERVICE = "restate_proxy"
PENDING_KEY = "proxy-pending.key"
MAX_CERT_BYTES = 64 * 1024
_CERT = "-----BEGIN CERTIFICATE-----"


def check_cert(value: Any) -> Optional[Dict[str, Any]]:
    """The storage side's ``proxy.cert``: ``name`` (a host name or address),
    ``pem`` (the certificate the server holds, or None) and ``renew``."""
    from src.sysmanage_agent.backup.job_validation import (  # noqa: PLC0415
        PolicyError,
    )

    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"name", "pem", "renew"}:
        raise PolicyError("proxy cert must have name, pem and renew")
    name = value["name"]
    try:
        name = str(ipaddress.ip_address(name))
    except (ValueError, TypeError):
        if not isinstance(name, str) or not access.valid_host_name(name):
            raise PolicyError("proxy cert name is not a host name or address") from None
    pem = value["pem"]
    if pem is not None:
        if (
            not isinstance(pem, str)
            or len(pem) > MAX_CERT_BYTES
            or not pem.startswith(_CERT)
        ):
            raise PolicyError("proxy cert pem must be a PEM certificate")
        try:
            x509.load_pem_x509_certificate(pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as error:
            raise PolicyError("proxy cert pem must be a PEM certificate") from error
    if not isinstance(value["renew"], bool):
        raise PolicyError("proxy cert renew must be true or false")
    return {"name": name, "pem": pem, "renew": value["renew"]}


def drop_in(account: str) -> str:
    """The systemd drop-in: the proxy runs as the repositories' account."""
    return (
        "# Written by sysmanage-agent: restate-proxy serves SysManage's\n"
        "# repositories, which are root:"
        + account
        + " 0770 with "
        + account
        + "'s files in them.\n"
        "[Service]\nUser=" + account + "\nGroup=" + account + "\nUMask=0007\n"
    )


def freebsd_settings(account: str) -> List[str]:
    """``sysrc`` arguments for restate's rc script."""
    return [f"restate_proxy_user={account}", "restate_proxy_umask=007"]


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def load_key(text: Optional[str]):
    if not text:
        return None
    try:
        return serialization.load_pem_private_key(text.encode("ascii"), password=None)
    except (ValueError, TypeError):
        return None


def csr_pem(key, name: str) -> str:
    """A request for ``name``; the server sets the name it signs for anyway."""
    try:
        alt: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        alt = x509.DNSName(name)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])]))
        .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def same_key(key, cert_text: str) -> bool:
    """The certificate was issued for this key."""
    try:
        cert = x509.load_pem_x509_certificate(cert_text.encode("ascii"))
    except ValueError:
        return False
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    return cert.public_key().public_bytes(der, spki) == key.public_key().public_bytes(
        der, spki
    )


def pending_path(backup_dir: str) -> str:
    """Where a key waits for its certificate: the agent's own state, 0600."""
    return posixpath.join(backup_dir, PENDING_KEY)


def write_private(path: str, text: str) -> None:
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="ascii") as out:
        out.write(text)
