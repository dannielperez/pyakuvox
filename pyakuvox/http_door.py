"""Non-actuating preparation of S535's separate Open Relay via HTTP feature.

Field names and Base64 encoding of both credentials were verified in the S535
535.30.10.282 web application. This does not validate a physical opening.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from pyakuvox.clients.local.client import LocalClient
from pyakuvox.clients.local.encoding import encode_config_password_webapi
from pyakuvox.clients.local.webapi import WebApiClient
from pyakuvox.exceptions import AmbiguousMutationError, DeviceError

if TYPE_CHECKING:
    from pyakuvox.config import LocalSettings

BASE = "Config.DoorSetting.RELAY."
FIELDS = tuple(
    BASE + key
    for key in (
        "RelayOnWeb",
        "RelayOnWebSessionCheck",
        "RelayOnWebUser",
        "RelayOnWebPwd",
    )
)


def _matches(raw: dict[str, str], settings: LocalSettings) -> bool:
    # Require exact decoded readback; masked or encoded credentials are not proof.
    return (
        raw.get(FIELDS[0]) == "1"
        and raw.get(FIELDS[1]) == "0"
        and raw.get(FIELDS[2]) == settings.username
        and raw.get(FIELDS[3]) == settings.password.get_secret_value()
    )


async def configure_http_door(
    settings: LocalSettings,
    *,
    model: str,
    relay_numbers: tuple[int, ...],
    apply: bool = False,
) -> dict[str, Any]:
    """Configure machine HTTP-door credentials without sending an open request.

    Only the observed S535 firmware and Relay A are supported. A successful
    readback is configuration evidence, not command or physical-gate acceptance.
    No retries follow any configuration write. No credentials enter the result.
    """
    if model.upper() != "S535" or relay_numbers != (1,):
        raise ValueError("HTTP-door configuration is verified only for S535 Relay A")
    if (
        not settings.use_ssl
        or not (settings.verify_ssl is True or settings.tls_certificate_sha256)
        or settings.legacy_tls
    ):
        raise ValueError("Verified HTTPS is required")
    password = settings.password.get_secret_value()
    if not settings.username or not password:
        raise ValueError("Saved credentials are required")
    if len(settings.username) > 63 or len(password) > 31:
        raise ValueError("Saved credentials exceed HTTP-door field limits")
    if any(char in settings.username for char in "&='%+#"):
        raise ValueError("Saved username is unsupported by HTTP-door configuration")
    options = dict(
        host=settings.host,
        port=settings.port,
        use_ssl=True,
        verify_ssl=True,
        timeout=min(float(settings.timeout), 10.0),
        tls_certificate_sha256=settings.tls_certificate_sha256,
    )
    attempted = False
    try:
        async with asyncio.timeout(60):
            async with LocalClient(settings, max_retries=0) as client:
                info = await client.get_device_info()
                if (
                    info.identity.model.upper() != "S535"
                    or info.firmware_version != "535.30.10.282"
                ):
                    raise DeviceError("HTTP-door device model or firmware is unverified")
                if {relay.number for relay in await client.get_relay_status()} != {1}:
                    raise DeviceError("HTTP-door relay inventory is unverified")
            async with WebApiClient(**options) as web:
                await web.login(settings.username, password)
                before = await web._config_get(list(FIELDS))
                if not set(FIELDS).issubset(before):
                    raise DeviceError("HTTP-door fields unavailable; no write attempted")
                ready = _matches(before, settings)
                result = {
                    "protocol": "http_door",
                    "applied": False,
                    "verified": ready,
                    "opening_verified": False,
                    "selected_relays": [1],
                    "verdict": "already_configured" if ready else "preview",
                }
                if ready or not apply:
                    return result
                desired = {
                    FIELDS[0]: "1",
                    FIELDS[1]: "0",
                    FIELDS[2]: encode_config_password_webapi(settings.username),
                    FIELDS[3]: encode_config_password_webapi(password),
                }
                attempted = True
                await web._config_set(desired)
                if not _matches(await web._config_get(list(FIELDS)), settings):
                    raise DeviceError("HTTP-door configuration readback did not verify")
                result.update(applied=True, verified=True, verdict="configured")
                return result
    except (Exception, asyncio.CancelledError):
        if attempted:
            raise AmbiguousMutationError(
                "HTTP-door configuration attempted; reconcile readback before retrying"
            ) from None
        raise
