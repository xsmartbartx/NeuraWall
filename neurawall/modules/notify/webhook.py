"""Signed JSON webhooks.

A firewall console that POSTs to a URL an administrator typed is a server-side request
forgery primitive unless it is careful. So, on every send (not only when the channel is
saved, because DNS can change in between):

* https only, no credentials in the URL, a named host (no bare IP literals);
* the host is resolved here and *every* address must be globally routable: loopback,
  private, link-local (including cloud metadata), CGNAT, multicast and reserved ranges are
  refused;
* the connection goes to the address that was checked (pinned), with the original hostname
  for SNI and certificate verification, so the name cannot resolve differently a moment later;
* no redirects, a short timeout and a small request body.

The receiver authenticates us with ``X-NeuraWall-Signature: sha256=HMAC(secret, "<ts>.<body>")``,
the same ``ts.body`` scheme NEXORA uses between its own services.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from neurawall.core.errors import RecoverableError, ValidationFailure

TIMEOUT = 5.0
MAX_BODY_BYTES = 64 * 1024

Resolver = Callable[[str, int], list[str]]


class WebhookError(RecoverableError):
    code = "webhook_error"


def _resolve(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationFailure("the webhook host does not resolve") from exc
    return sorted({str(info[4][0]) for info in infos})


def check_url(url: str, *, resolver: Resolver = _resolve) -> tuple[str, str, int, list[str]]:
    """Validate `url` and return (host, path-and-query, port, checked addresses)."""
    if len(url) > 500 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValidationFailure("the webhook URL is not valid")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValidationFailure("the webhook URL must start with https://")
    if parts.username or parts.password:
        raise ValidationFailure("the webhook URL must not contain credentials")
    host = parts.hostname or ""
    if not host:
        raise ValidationFailure("the webhook URL needs a host name")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValidationFailure("use a host name, not an IP address, in the webhook URL")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise ValidationFailure("the webhook URL has an invalid port") from exc
    addresses = resolver(host, port)
    if not addresses:
        raise ValidationFailure("the webhook host does not resolve")
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        # IPv4-mapped IPv6 (::ffff:10.0.0.1) must be judged as the IPv4 address it carries.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            raise ValidationFailure("the webhook host must be a public internet address")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, path, port, addresses


def derive_secret(server_key: str, nonce: str) -> str:
    """The channel's signing secret, derived so it never has to be stored: rotating a channel
    is changing its nonce. (It changes for every channel if the server key is rotated.)"""
    digest = hmac.new(server_key.encode(), f"neurawall/webhook/{nonce}".encode(), hashlib.sha256)
    return "whsec_" + digest.hexdigest()


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def send_webhook(
    url: str,
    secret: str,
    payload: dict[str, Any],
    *,
    now: float,
    resolver: Resolver = _resolve,
    transport: httpx.BaseTransport | None = None,
) -> int:
    """POST `payload`; return the HTTP status. Raises `ValidationFailure` for a URL that fails
    the checks and `WebhookError` for anything transient or a non-2xx answer."""
    host, path, port, addresses = check_url(url, resolver=resolver)
    body = json.dumps(payload, separators=(",", ":")).encode()
    if len(body) > MAX_BODY_BYTES:
        raise ValidationFailure("the webhook payload is too large")
    timestamp = int(now)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "neurawall",
        "X-NeuraWall-Timestamp": str(timestamp),
        "X-NeuraWall-Signature": sign(secret, timestamp, body),
    }
    ip = addresses[0]
    netloc = f"[{ip}]" if ":" in ip else ip
    target = f"https://{netloc}:{port}{path}"
    headers["Host"] = host if port == 443 else f"{host}:{port}"
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=False, transport=transport) as c:
            r = c.post(target, content=body, headers=headers, extensions={"sni_hostname": host})
    except httpx.HTTPError as exc:
        raise WebhookError("the webhook receiver is unreachable") from exc
    if not 200 <= r.status_code < 300:
        raise WebhookError(f"the webhook receiver answered {r.status_code}")
    return r.status_code
