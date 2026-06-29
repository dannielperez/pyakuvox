"""Exception hierarchy for pyakuvox.

All exceptions derive from AkuvoxError so callers can catch broadly
or narrowly as needed. The hierarchy mirrors the one in pylocal-akuvox
for consistency but is independent (this package's exceptions are for
the orchestration / service layer, not the raw device client).
"""

from __future__ import annotations


class AkuvoxError(Exception):
    """Base exception for all pyakuvox errors."""


# ── Transport / connectivity ────────────────────────────────────────


class ConnectionError(AkuvoxError):
    """Could not reach the device or cloud endpoint."""


class TimeoutError(AkuvoxError):
    """Request timed out."""


# ── Authentication ──────────────────────────────────────────────────


class AuthenticationError(AkuvoxError):
    """Credentials were rejected or session is invalid."""


class ApiAccessForbiddenError(AuthenticationError):
    """The device returned HTTP 403 — the HTTP API is reachable but is
    refusing the request for a reason that is NOT a bad password.

    On Akuvox firmware a 403 almost always means the API auth mode is
    ``WhiteList`` (mode 2) with an empty/мismatched allow-list, or ``None``
    mode rejecting the path — i.e. the wrong *dialect/mode*, not wrong creds.
    The fix is to flip the API to Digest (mode 4) via the device web UI, not
    to try other passwords. Subclasses AuthenticationError so existing
    ``except AuthenticationError`` handlers (and ``"forbidden" in str(e)``
    checks) keep working.
    """

    def __init__(self, path: str, host: str = "") -> None:
        self.path = path
        self.host = host
        super().__init__(
            f"Access forbidden for {path}"
            f"{f' on {host}' if host else ''} (HTTP 403) — the API is likely in "
            f"WhiteList/None auth mode, not a credential failure; flip it to Digest."
        )


class UnsupportedDialectError(AkuvoxError):
    """The device speaks an API dialect this client cannot drive headlessly.

    SPA firmware (``/api/web/*``) and legacy E18C (``/web/*``) hash the login
    password in browser JavaScript, so writes currently require the
    Playwright-driven scripts. Identification and model/firmware read still
    work without login — see ``pyakuvox.identify``.
    """

    def __init__(self, dialect: str, host: str = "", hint: str = "") -> None:
        self.dialect = dialect
        self.host = host
        detail = f" — {hint}" if hint else ""
        super().__init__(
            f"Device {host or ''} speaks the '{dialect}' dialect which is not "
            f"drivable headlessly by LocalClient{detail}"
        )


class CloudAuthenticationError(AuthenticationError):
    """Cloud-specific auth failure (token expired, SMS validation, etc.)."""


# ── Device responses ────────────────────────────────────────────────


class DeviceError(AkuvoxError):
    """The device returned an error or unexpected response."""


class ParseError(AkuvoxError):
    """Could not parse the device/cloud response into a model."""

    def __init__(self, message: str, raw_data: object = None) -> None:
        super().__init__(message)
        self.raw_data = raw_data


# ── Capability / feature support ────────────────────────────────────


class UnsupportedFeatureError(AkuvoxError):
    """The requested feature is not supported by this provider or device.

    Raised when the capability matrix says a feature is 'unsupported'
    or 'unverified' and the caller has not opted-in to experimental mode.
    """

    def __init__(self, feature: str, provider: str) -> None:
        super().__init__(f"Feature '{feature}' is not supported via '{provider}'")
        self.feature = feature
        self.provider = provider


class ExperimentalFeatureWarning(AkuvoxError):
    """Raised (or logged) when using an unverified/experimental feature.

    Not necessarily fatal — services may catch this and proceed with
    a warning rather than aborting.
    """

    def __init__(self, feature: str, reason: str = "") -> None:
        detail = f": {reason}" if reason else ""
        super().__init__(f"Experimental feature '{feature}'{detail}")
        self.feature = feature


# ── Cloud-specific ──────────────────────────────────────────────────


class CloudError(AkuvoxError):
    """Base for cloud-side errors."""


class CloudUnavailableError(CloudError):
    """Cloud endpoint is unreachable or returned an unexpected status."""


class CloudNotConfiguredError(CloudError):
    """Cloud credentials/settings are missing."""
