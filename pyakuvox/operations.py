"""Model-aware high-level operations for Akuvox devices."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pyakuvox.clients.local.webui import (
    ConfigPasswordEncoding,
    SIPAccountStatus,
    WebUIClient,
)
from pyakuvox.exceptions import AkuvoxError, UnsupportedFeatureError
from pyakuvox.identify import SIPStatusSource, identify, profile_for_model

if TYPE_CHECKING:
    from pyakuvox.config import LocalSettings
    from pyakuvox.models.device import DeviceInfo


async def read_sip_account_status(
    host: str,
    account: int,
    *,
    username: str,
    password: str,
    model: str | None = None,
    timeout: int = 15,
    verify_ssl: bool = False,
) -> SIPAccountStatus:
    """Discover the model when needed and execute its SIP-status strategy.

    The X916 profile intentionally uses HTTPS only. Login-page probing inside
    ``WebUIClient`` chooses AES or legacy authentication for the actual
    firmware, keeping that volatile detail out of the model table.
    """
    resolved_model = model or (await identify(host, timeout=float(timeout))).model
    if resolved_model.upper() == "S535":
        from pyakuvox.clients.local.webapi import WebApiClient

        async with WebApiClient(host, timeout=timeout, verify_ssl=verify_ssl) as web:
            await web.login(username, password)
            return await web.get_sip_account_status(account)
    profile = profile_for_model(resolved_model)
    if profile.sip_status_source is not SIPStatusSource.FCGI_WEB:
        raise UnsupportedFeatureError("sip_account_status", resolved_model or "unknown model")

    encoding_name = profile.config_password_encodings[0]
    encoding = ConfigPasswordEncoding(encoding_name)
    last_error: Exception | None = None
    for scheme, port in profile.web_endpoints:
        try:
            async with WebUIClient(
                host=host,
                port=port,
                use_ssl=scheme == "https",
                verify_ssl=verify_ssl,
                timeout=timeout,
                password_encoding=encoding,
            ) as webui:
                await webui.login(username, password)
                return await webui.get_sip_account_status(account)
        except (AkuvoxError, OSError) as exc:
            last_error = exc

    if last_error is not None:
        raise last_error
    raise UnsupportedFeatureError("sip_account_status", resolved_model or "unknown model")


async def ensure_homepage_dial_account(
    settings: LocalSettings, account: int, *, model: str, apply: bool = False
) -> dict[str, Any]:
    """Configure a verified model's homepage account using its existing transport."""
    if model.strip().upper() == "S535":
        from pyakuvox.clients.local.webapi import WebApiClient

        async with WebApiClient(
            settings.host,
            port=settings.port,
            use_ssl=settings.use_ssl,
            verify_ssl=settings.verify_ssl,
            tls_certificate_sha256=getattr(settings, "tls_certificate_sha256", None),
            timeout=settings.timeout,
        ) as web:
            await web.login(settings.username, settings.password.get_secret_value())
            return await web.ensure_homepage_dial_account(account, apply=apply)
    if model.strip().upper() != "X916":
        raise UnsupportedFeatureError("homepage_dial_account", model)
    async with WebUIClient(
        host=settings.host,
        port=settings.port,
        use_ssl=settings.use_ssl,
        verify_ssl=settings.verify_ssl,
        tls_certificate_sha256=getattr(settings, "tls_certificate_sha256", None),
        timeout=settings.timeout,
    ) as webui:
        await webui.login(settings.username, settings.password.get_secret_value())
        return await webui.ensure_x916_homepage_dial_account(account, apply=apply)


async def read_device_info_with_auth_detection(settings: LocalSettings) -> DeviceInfo:
    """Read identity with a bounded Basic-to-Digest compatibility fallback.

    Reuses the supplied credentials and transport; never changes API settings.
    Only rejected Basic authentication attempts Digest. Other failures and
    explicitly selected non-Basic modes propagate without another attempt.
    """
    import asyncio

    from pyakuvox.clients.local.client import LocalClient
    from pyakuvox.config import LocalAuthType
    from pyakuvox.exceptions import AuthenticationError

    async def read() -> DeviceInfo:
        try:
            async with LocalClient(settings, max_retries=0) as client:
                return await client.get_device_info()
        except AuthenticationError:
            if settings.auth_type != LocalAuthType.BASIC:
                raise
        detected = settings.model_copy(update={"auth_type": LocalAuthType.DIGEST})
        async with LocalClient(detected, max_retries=0) as client:
            return await client.get_device_info()

    return await asyncio.wait_for(read(), timeout=min(float(settings.timeout), 30.0))


async def inspect_sip_with_auth_detection(
    settings: LocalSettings, *, timeout_seconds: float = 25
) -> dict[str, Any]:
    """Read SIP evidence with a bounded Basic-to-Digest compatibility fallback.

    Reuse credentials and transport. Only an explicit Basic rejection permits
    Digest; timeouts/device errors propagate. This operation never renews a SIP
    flow or changes configuration, and every client disables transport retries.
    """
    import asyncio

    from pyakuvox.clients.local.client import LocalClient
    from pyakuvox.config import LocalAuthType
    from pyakuvox.exceptions import AuthenticationError
    from pyakuvox.sip_recovery import inspect_sip

    if not 0 < timeout_seconds <= 30:
        raise ValueError("SIP inspection deadline must be within 30 seconds")

    async def read():
        try:
            async with LocalClient(settings, max_retries=0) as client:
                return await inspect_sip(client)
        except AuthenticationError:
            if settings.auth_type != LocalAuthType.BASIC:
                raise
        detected = settings.model_copy(update={"auth_type": LocalAuthType.DIGEST})
        async with LocalClient(detected, max_retries=0) as client:
            return await inspect_sip(client)

    return await asyncio.wait_for(read(), timeout=timeout_seconds)


async def read_status_with_auth_detection(
    settings: LocalSettings,
) -> tuple[DeviceInfo, list[Any]]:
    """Read identity and relays under one deadline using read-only auth detection.

    A rejected Basic read may retry with Digest and the same credentials. Parse,
    transport and device errors never trigger a fallback. Neither settings nor
    device configuration are modified; transport retries are disabled.
    """
    import asyncio

    from pyakuvox.clients.local.client import LocalClient
    from pyakuvox.config import LocalAuthType
    from pyakuvox.exceptions import AuthenticationError

    async def read():
        async def attempt(selected):
            async with LocalClient(selected, max_retries=0) as client:
                info = await client.get_device_info()
                relays = await client.get_relay_status()
                return info, relays

        try:
            return await attempt(settings)
        except AuthenticationError:
            if settings.auth_type != LocalAuthType.BASIC:
                raise
        return await attempt(settings.model_copy(update={"auth_type": LocalAuthType.DIGEST}))

    return await asyncio.wait_for(read(), timeout=min(float(settings.timeout), 30.0))
