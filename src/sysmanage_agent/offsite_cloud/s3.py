# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Just enough of Amazon S3 for the off-site copy (server ROADMAP 27.3).

Standard library only (``http.client`` over TLS, AWS Signature Version 4),
so the agent ships no AWS SDK.  What the copy and its restore need:

* ``put_file`` -- one object from a spooled file, with its storage class
  (``DEEP_ARCHIVE`` normally), its Object Lock retention, and both
  ``Content-MD5`` and ``x-amz-checksum-sha256``, which S3 requires for an
  upload with a retention date and which make it check what it stored;
* ``head`` / ``get_to`` -- an object's state and contents;
* ``restore`` -- ask S3 to thaw an archived object for some days;
* ``list_keys`` -- the keys under a prefix (the manifests, for a restore
  planned without the SysManage server);
* ``object_lock`` -- whether the bucket has Object Lock on.

``endpoint`` points it at an S3-compatible store (path-style addressing);
otherwise it talks to AWS, virtual-hosted unless the bucket name has a dot.
The secret key is never logged or put in an error.
"""

import base64
import datetime
import hashlib
import hmac
import http.client
import ssl
import time
import urllib.parse
from typing import BinaryIO, Callable, Dict, Iterable, List, Optional, Tuple
from defusedxml import ElementTree

SERVICE = "s3"
UNSIGNED = "UNSIGNED-PAYLOAD"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
BLOCK = 1 << 16
RETRIES = 5
TIMEOUT = 300
_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


class S3Error(Exception):
    """An S3 request that failed; ``status`` and ``code`` say how."""

    def __init__(self, status: int, code: str, message: str = ""):
        super().__init__(f"S3 {status} {code}: {message}".strip())
        self.status = status
        self.code = code

    @property
    def transient(self) -> bool:
        return self.status in (0, 408, 429, 500, 502, 503, 504) or self.code in (
            "RequestTimeout",
            "SlowDown",
            "InternalError",
            "ServiceUnavailable",
        )


def _quote(text: str, safe: str = "-_.~") -> str:
    return urllib.parse.quote(text, safe=safe)


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


class Client:
    """One bucket, one set of credentials."""

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        bucket: str,
        region: str,
        access_key: str,
        secret_key: str,
        endpoint: Optional[str] = None,
        session_token: Optional[str] = None,
        ca_file: Optional[str] = None,
    ):
        self.bucket = bucket
        self.region = region or "us-east-1"
        self._access = access_key
        self._secret = secret_key
        self._token = session_token
        if endpoint:
            parsed = urllib.parse.urlsplit(endpoint)
            self.scheme = parsed.scheme or "https"
            self.host = parsed.netloc
            self.base = parsed.path.rstrip("/") + "/" + _quote(bucket)
        elif "." in bucket:
            self.scheme, self.host = "https", f"s3.{self.region}.amazonaws.com"
            self.base = "/" + _quote(bucket)
        else:
            self.scheme = "https"
            self.host = f"{bucket}.s3.{self.region}.amazonaws.com"
            self.base = ""
        self._ca_file = ca_file
        self.sleep = time.sleep

    # --- signing ---------------------------------------------------------------

    def _path(self, key: str) -> str:
        return (
            self.base + "/" + _quote(key, safe="-_.~/") if key else (self.base or "/")
        )

    def _headers(
        self,
        method: str,
        path: str,
        query: Dict[str, str],
        headers: Dict[str, str],
        payload_hash: str,
        now: Optional[datetime.datetime] = None,
    ) -> Dict[str, str]:
        now = now or datetime.datetime.now(datetime.timezone.utc)
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        day = stamp[:8]
        signed = {k.lower(): str(v).strip() for k, v in headers.items()}
        signed["host"] = self.host
        signed["x-amz-date"] = stamp
        signed["x-amz-content-sha256"] = payload_hash
        if self._token:
            signed["x-amz-security-token"] = self._token
        names = sorted(signed)
        canonical_query = "&".join(
            f"{_quote(k)}={_quote(v)}" for k, v in sorted(query.items())
        )
        canonical = "\n".join(
            [
                method,
                path,
                canonical_query,
                "".join(f"{n}:{signed[n]}\n" for n in names),
                ";".join(names),
                payload_hash,
            ]
        )
        scope = f"{day}/{self.region}/{SERVICE}/aws4_request"
        to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                stamp,
                scope,
                hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            ]
        )
        key = _sign(("AWS4" + self._secret).encode("utf-8"), day)
        for part in (self.region, SERVICE, "aws4_request"):
            key = _sign(key, part)
        signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        signed["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self._access}/{scope}, "
            f"SignedHeaders={';'.join(names)}, Signature={signature}"
        )
        signed.pop("host")
        return signed

    # --- transport -------------------------------------------------------------

    def _connection(self) -> http.client.HTTPConnection:
        if self.scheme == "http":
            # An S3-compatible lab endpoint only (AWS is always https).  The agent
            # needs Python 3.10+, so blocksize (3.7+) is always there.
            # nosemgrep: python.lang.compatibility.python37.python37-compatibility-httpconn
            return http.client.HTTPConnection(
                self.host, timeout=TIMEOUT, blocksize=BLOCK
            )
        context = ssl.create_default_context(cafile=self._ca_file)
        # The default context verifies the certificate and the host name.
        # nosemgrep: python.lang.compatibility.python37.python37-compatibility-httpsconn, python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
        return http.client.HTTPSConnection(
            self.host, timeout=TIMEOUT, context=context, blocksize=BLOCK
        )

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _once(
        self,
        method: str,
        key: str,
        query: Dict[str, str],
        headers: Dict[str, str],
        body,
        payload_hash: str,
        sink: Optional[Callable[[bytes], object]] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        path = self._path(key)
        signed = self._headers(method, path, query, headers, payload_hash)
        target = path + (
            "?"
            + "&".join(
                f"{_quote(k)}={_quote(v)}" if v != "" else _quote(k)
                for k, v in sorted(query.items())
            )
            if query
            else ""
        )
        conn = self._connection()
        try:
            conn.request(method, target, body=body, headers=signed)
            response = conn.getresponse()
            answer = {k.lower(): v for k, v in response.getheaders()}
            if sink is not None and 200 <= response.status < 300:
                while True:
                    block = response.read(BLOCK)
                    if not block:
                        break
                    sink(block)
                return response.status, answer, b""
            return response.status, answer, response.read()
        except (OSError, http.client.HTTPException) as error:
            raise S3Error(0, "ConnectionError", str(error)) from error
        finally:
            conn.close()

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def request(
        self,
        method: str,
        key: str = "",
        query: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
        ok: Iterable[int] = (200,),
    ) -> Tuple[int, Dict[str, str], bytes]:
        """A small request (no streamed body), retried while S3 says so."""
        payload_hash = hashlib.sha256(body).hexdigest()
        return self._retried(
            lambda: self._once(
                method, key, query or {}, headers or {}, body or None, payload_hash
            ),
            ok,
        )

    def _retried(
        self,
        attempt: Callable[[], Tuple[int, Dict[str, str], bytes]],
        ok: Iterable[int],
    ) -> Tuple[int, Dict[str, str], bytes]:
        delay = 2.0
        for tries in range(RETRIES):
            try:
                status, headers, data = attempt()
            except S3Error:
                if tries + 1 == RETRIES:
                    raise
                self.sleep(delay)
                delay *= 2
                continue
            if status in tuple(ok):
                return status, headers, data
            error = _error_of(status, data)
            if not error.transient or tries + 1 == RETRIES:
                raise error
            self.sleep(delay)
            delay *= 2
        raise S3Error(0, "Retries")  # pragma: no cover - the loop raises first

    # --- operations ------------------------------------------------------------

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def put_file(
        self,
        key: str,
        path: str,
        size: int,
        sha256_hex: str,
        storage_class: str = "DEEP_ARCHIVE",
        retain_until: Optional[datetime.datetime] = None,
        wrap: Optional[Callable[[BinaryIO], BinaryIO]] = None,
    ) -> None:
        """Upload the file at ``path`` (``size`` bytes, SHA-256 known) as
        ``key``; ``wrap`` may throttle the reads."""
        md5 = hashlib.md5(usedforsecurity=False)
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(BLOCK), b""):
                md5.update(block)
        headers = {
            "content-length": str(size),
            "content-type": "application/octet-stream",
            "content-md5": base64.b64encode(md5.digest()).decode("ascii"),
            "x-amz-checksum-sha256": base64.b64encode(bytes.fromhex(sha256_hex)).decode(
                "ascii"
            ),
        }
        if storage_class and storage_class != "STANDARD":
            headers["x-amz-storage-class"] = storage_class
        if retain_until is not None:
            headers["x-amz-object-lock-mode"] = "COMPLIANCE"
            headers["x-amz-object-lock-retain-until-date"] = retain_until.astimezone(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

        def attempt():
            with open(path, "rb") as handle:
                body = wrap(handle) if wrap else handle
                return self._once("PUT", key, {}, headers, body, sha256_hex)

        self._retried(attempt, (200,))

    def put_bytes(self, key: str, data: bytes, retain_until=None) -> None:
        headers = {
            "content-type": "application/octet-stream",
            "content-md5": base64.b64encode(
                hashlib.md5(data, usedforsecurity=False).digest()
            ).decode("ascii"),
        }
        if retain_until is not None:
            headers["x-amz-object-lock-mode"] = "COMPLIANCE"
            headers["x-amz-object-lock-retain-until-date"] = retain_until.astimezone(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.request("PUT", key, headers=headers, body=data)

    def head(self, key: str) -> Optional[Dict[str, str]]:
        """The object's headers, or None when there is no such object."""
        try:
            _status, headers, _data = self.request("HEAD", key, ok=(200,))
        except S3Error as error:
            if error.status == 404:
                return None
            raise
        return headers

    def get_bytes(self, key: str) -> bytes:
        return self.request("GET", key)[2]

    def get_to(self, key: str, sink: Callable[[bytes], object]) -> None:
        """Stream the object into ``sink``.  A retry starts over: ``sink`` must
        be able to restart (a file truncated by the caller)."""
        self._retried(
            lambda: self._once("GET", key, {}, {}, None, EMPTY_SHA256, sink=sink),
            (200,),
        )

    def restore(self, key: str, days: int, tier: str = "Bulk") -> str:
        """Ask S3 to thaw an archived object: ``started``, ``in_progress``
        (asked before) or ``not_archived`` (readable already)."""
        body = (
            '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<Days>{int(days)}</Days><GlacierJobParameters><Tier>{tier}</Tier>"
            "</GlacierJobParameters></RestoreRequest>"
        ).encode("utf-8")
        headers = {
            "content-md5": base64.b64encode(
                hashlib.md5(body, usedforsecurity=False).digest()
            ).decode("ascii"),
        }
        try:
            status, _h, _d = self.request(
                "POST", key, {"restore": ""}, headers, body, ok=(200, 202)
            )
        except S3Error as error:
            if error.code == "RestoreAlreadyInProgress":
                return "in_progress"
            if error.code == "InvalidObjectState" and error.status == 403:
                return "not_archived"
            raise
        return "started" if status == 202 else "in_progress"

    def list_keys(self, prefix: str) -> List[Tuple[str, int]]:
        """``(key, size)`` under ``prefix``, every page."""
        found: List[Tuple[str, int]] = []
        token = None
        while True:
            query = {"list-type": "2", "prefix": prefix}
            if token:
                query["continuation-token"] = token
            data = self.request("GET", "", query)[2]
            root = ElementTree.fromstring(data)
            for item in root.iter(_NS + "Contents"):
                found.append(
                    (
                        item.findtext(_NS + "Key") or "",
                        int(item.findtext(_NS + "Size") or 0),
                    )
                )
            if (root.findtext(_NS + "IsTruncated") or "").lower() != "true":
                return found
            token = root.findtext(_NS + "NextContinuationToken")

    def object_lock(self) -> Optional[bool]:
        """True / False, or None when these credentials may not ask."""
        try:
            data = self.request("GET", "", {"object-lock": ""})[2]
        except S3Error as error:
            if error.code == "ObjectLockConfigurationNotFoundError":
                return False
            if error.status == 403:
                return None
            raise
        root = ElementTree.fromstring(data)
        return (root.findtext(_NS + "ObjectLockEnabled") or "") == "Enabled"


def restore_state(headers: Optional[Dict[str, str]]) -> str:
    """From a HEAD: ``missing``, ``ready`` (readable now), ``archived`` (needs
    a thaw), or ``thawing``."""
    if headers is None:
        return "missing"
    storage = (headers.get("x-amz-storage-class") or "STANDARD").upper()
    restore = headers.get("x-amz-restore") or ""
    if 'ongoing-request="true"' in restore:
        return "thawing"
    if 'ongoing-request="false"' in restore:
        return "ready"
    if storage in ("GLACIER", "DEEP_ARCHIVE"):
        return "archived"
    return "ready"


def _error_of(status: int, data: bytes) -> S3Error:
    code, message = "", ""
    if data:
        try:
            root = ElementTree.fromstring(data)
            code = root.findtext("Code") or ""
            message = root.findtext("Message") or ""
        except ElementTree.ParseError:
            message = data[:200].decode("utf-8", "replace")
    return S3Error(status, code or "HTTP", message)
