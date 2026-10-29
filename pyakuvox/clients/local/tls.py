"""Exact-certificate TLS trust for explicitly enrolled private endpoints.

A pin is an alternative to CA/hostname trust, never trust-on-first-use. Validation
runs at TLS handshake completion, before HTTP headers (including credentials or
commands) are sent. Pins must be supplied out of band by the consumer.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import ssl
from typing import Any

import httpx


def normalize_certificate_pin(value: str) -> str:
    pin = value.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise ValueError("TLS certificate pin must be a SHA-256 fingerprint")
    return pin


class PinnedTLSError(Exception):
    """Permanent trust failure; callers must not retry or downgrade transport."""


class PinnedLocalTransport(httpx.AsyncHTTPTransport):
    """HTTPS transport restricted to one endpoint and one reviewed certificate."""

    def __init__(self, *, host: str, port: int, fingerprint: str) -> None:
        self._host = host.lower()
        self._port = port
        self._fingerprint = normalize_certificate_pin(fingerprint)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        # Exact leaf pin validation below replaces PKI validation. No HTTP bytes
        # are permitted until that check passes, even for self-signed firmware.
        context.verify_mode = ssl.CERT_NONE
        super().__init__(
            verify=context,
            retries=0,
            http2=False,
            limits=httpx.Limits(max_keepalive_connections=0),
            trust_env=False,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if (
            request.url.scheme != "https"
            or request.url.host.lower() != self._host
            or (request.url.port or 443) != self._port
        ):
            raise PinnedTLSError("Pinned TLS endpoint mismatch")
        verified = False

        async def trace(event: str, info: dict[str, Any]) -> None:
            nonlocal verified
            if event == "connection.start_tls.complete":
                stream = info["return_value"]
                try:
                    peer = stream.get_extra_info("ssl_object")
                    certificate = peer.getpeercert(binary_form=True) if peer else None
                    if not certificate or not hmac.compare_digest(
                        hashlib.sha256(certificate).hexdigest(), self._fingerprint
                    ):
                        raise PinnedTLSError("TLS certificate pin mismatch")
                    verified = True
                except BaseException:
                    await stream.aclose()
                    raise
            elif event == "http11.send_request_headers.started" and not verified:
                raise PinnedTLSError("TLS certificate was not verified before request")

        # Do not allow callers to override this trust check with another trace.
        request.extensions["trace"] = trace
        return await super().handle_async_request(request)


def pinned_client_options(
    *, host: str, port: int, use_ssl: bool, fingerprint: str | None
) -> dict[str, Any]:
    if fingerprint is None:
        return {}
    if not use_ssl:
        raise ValueError("Certificate pinning requires HTTPS")
    return {
        "transport": PinnedLocalTransport(host=host, port=port, fingerprint=fingerprint),
        "trust_env": False,
    }
