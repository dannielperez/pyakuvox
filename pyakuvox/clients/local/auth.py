"""Authentication handling for the Akuvox local HTTP API.

Supports no-auth (IP allowlist), HTTP Basic, and HTTP Digest.
These are the same auth methods documented in pylocal-akuvox and
confirmed by the homeassistant-local-akuvox integration.
"""

from __future__ import annotations

import httpx

from pyakuvox.config import LocalAuthType, LocalSettings


def build_auth(settings: LocalSettings) -> httpx.Auth | None:
    """Construct the appropriate httpx auth handler from config."""
    if settings.auth_type in (LocalAuthType.NONE, LocalAuthType.ALLOWLIST):
        return None

    username = settings.username
    password = settings.password.get_secret_value()

    if settings.auth_type == LocalAuthType.BASIC:
        return httpx.BasicAuth(username=username, password=password)

    if settings.auth_type == LocalAuthType.DIGEST:
        return httpx.DigestAuth(username=username, password=password)

    return None
