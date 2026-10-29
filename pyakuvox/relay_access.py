"""Non-actuating, HTTPS-only preparation of authenticated local relay access."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from pyakuvox.clients.local.client import LocalClient
from pyakuvox.clients.local.webapi import WebApiClient
from pyakuvox.clients.local.webui import ConfigPasswordEncoding, FirmwareAuthMode, WebUIClient
from pyakuvox.config import LocalAuthType
from pyakuvox.exceptions import AmbiguousMutationError, AuthenticationError, DeviceError
from pyakuvox.identify import ApiDialect, profile_for_model

if TYPE_CHECKING:
    from pyakuvox.config import LocalSettings


def _summary(config: Any) -> dict[str, Any]:
    return {
        "enabled": config.enabled,
        "auth_mode": config.auth_mode.name.lower(),
        "password_set": config.password_set,
    }


async def configure_web_relay_access(
    settings: LocalSettings,
    *,
    model: str,
    relay_numbers: tuple[int, ...],
    apply: bool = False,
) -> dict[str, Any]:
    """Preview or configure Digest API access, then read relay status only.

    Credentials come from the caller's secret-bearing settings, never the result.
    The only write changes API enable/authentication/credentials. DTMF, relay
    mode, hold times and output state are untouched. No retry follows a write.
    TLS trust must already be configured; this workflow never downgrades TLS.
    """
    if not settings.use_ssl or not (settings.verify_ssl is True or settings.tls_certificate_sha256):
        raise ValueError("Verified HTTPS is required for web relay preparation")
    if not settings.username or not settings.password.get_secret_value():
        raise ValueError("Saved credentials are required")
    if (
        not relay_numbers
        or len(set(relay_numbers)) != len(relay_numbers)
        or any(type(n) is not int or not 1 <= n <= 8 for n in relay_numbers)
    ):
        raise ValueError("Select unique relay numbers from 1 through 8")
    profile = profile_for_model(model)
    if profile.dialect not in {ApiDialect.WEB_API, ApiDialect.FCGI_WEB}:
        raise ValueError("No verified web configuration strategy for this model")
    options = dict(
        host=settings.host,
        port=settings.port,
        use_ssl=True,
        verify_ssl=True,
        timeout=min(float(settings.timeout), 10.0),
        tls_certificate_sha256=settings.tls_certificate_sha256,
    )
    if profile.dialect == ApiDialect.WEB_API:
        web = WebApiClient(**options)
        required = {
            f"Config.DoorSetting.APIFCGI.{k}"
            for k in ("Enable", "AuthMode", "UserName", "Password")
        }
    else:
        web = WebUIClient(**options, password_encoding=ConfigPasswordEncoding.X916)
        required = {"hcEnable", "hcAuthMode", "hcUserName", "hcPassword"}
    digest = settings.model_copy(update={"auth_type": LocalAuthType.DIGEST})

    async def verify() -> list[int]:
        async with LocalClient(digest, max_retries=0) as client:
            info = await client.get_device_info()
            if info.identity.model.strip().upper() != model.strip().upper():
                raise DeviceError("Device model does not match the reviewed inventory")
            numbers = sorted({r.number for r in await client.get_relay_status()})
        if not set(relay_numbers).issubset(numbers):
            raise DeviceError("Selected relay is absent from device status")
        return numbers

    write_started = False
    try:
        async with asyncio.timeout(60):
            async with web:
                await web.login(settings.username, settings.password.get_secret_value())
                before = await web.get_http_api_config()
                if not required.issubset(before.raw_fields):
                    raise DeviceError("API configuration fields unavailable; no write attempted")
                result = {
                    "before": _summary(before),
                    "desired": {
                        "enabled": True,
                        "auth_mode": "digest",
                        "credential_source": "saved",
                    },
                    "selected_relays": list(relay_numbers),
                    "applied": False,
                    "verified": False,
                    "verdict": "preview",
                }
                ready = before.enabled and before.auth_mode == FirmwareAuthMode.DIGEST
                if ready:
                    try:
                        result["available_relays"] = await verify()
                    except AuthenticationError:
                        ready = False
                    else:
                        result.update(verified=True, verdict="already_configured")
                        return result
                if not apply:
                    return result
                write_started = True
                after = await web.set_http_api_config(
                    enabled=True,
                    auth_mode=FirmwareAuthMode.DIGEST,
                    username=settings.username,
                    password=settings.password.get_secret_value(),
                )
                if not after.enabled or after.auth_mode != FirmwareAuthMode.DIGEST:
                    raise DeviceError("Digest API configuration did not verify")
                result["available_relays"] = await verify()
                result.update(
                    applied=True, verified=True, verdict="configured", after=_summary(after)
                )
                return result
    except Exception as exc:
        if write_started:
            raise AmbiguousMutationError(
                "API configuration was attempted but verification failed; read back before retrying"
            ) from exc
        raise
