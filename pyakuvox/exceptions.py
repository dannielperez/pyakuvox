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


class AmbiguousMutationError(AkuvoxError):
    """A mutating request started but its final device outcome is unknown."""


# ── Authentication ──────────────────────────────────────────────────


class AuthenticationError(AkuvoxError):
    """Credentials were rejected or session is invalid."""


class ApiAccessForbiddenError(AuthenticationError):
    """The API rejected access with HTTP 403; the underlying cause is unknown.

    Keep the AuthenticationError base for compatibility with existing callers.
    The status alone does not identify the API configuration or establish
    whether the supplied credentials are correct.
    """

    def __init__(self, path: str, host: str = "") -> None:
        self.path = path
        self.host = host
        super().__init__(
            f"Access forbidden for {path}"
            f"{f' on {host}' if host else ''} (HTTP 403). "
            "Check API enablement, authentication mode, access restrictions, and "
            "account permissions; this response alone does not identify the cause."
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


class OccupiedSipAccountError(DeviceError):
    """The selected account is populated by an unrecognized SIP registrar."""


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


class ExperimentalFeatureWarning(AkuvoxError):  # noqa: N818 - public compatibility
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
