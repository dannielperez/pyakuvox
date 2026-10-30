"""Preparation of firmware-verified Open Relay via HTTP features.

Field names and Base64 encoding of both credentials were verified in the S535
535.30.10.282 web application. This does not validate a physical opening.
"""

from __future__ import annotations

import asyncio
import json
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


S539_FIELDS = tuple(BASE + key for key in ("HttpTrig", "SessionCheck", "UserName", "Password"))


def _profile(model: str):
    if model.upper() == "S535":
        return "535.30.10.282", FIELDS, {1}, "base64"
    if model.upper() == "S539":
        return "539.30.10.523", S539_FIELDS, {1, 2, 3}, "cryptojs_aes"
    raise ValueError("HTTP-door model is unverified")


def _matches(raw: dict[str, str], settings: LocalSettings, fields=FIELDS) -> bool:
    # Require exact decoded readback; masked or encoded credentials are not proof.
    return (
        raw.get(fields[0]) == "1"
        and raw.get(fields[1]) == "0"
        and raw.get(fields[2]) == settings.username
        and raw.get(fields[3]) == settings.password.get_secret_value()
    )


async def configure_http_door(
    settings: LocalSettings,
    *,
    model: str,
    relay_numbers: tuple[int, ...],
    apply: bool = False,
) -> dict[str, Any]:
    """Configure machine HTTP-door credentials without sending an open request.

    Only the observed S535 and S539 firmware schemas are supported. A successful
    readback is configuration evidence, not command or physical-gate acceptance.
    No retries follow any configuration write. No credentials enter the result.
    """
    firmware, fields, available, encoding = _profile(model)
    if (
        not relay_numbers
        or len(set(relay_numbers)) != len(relay_numbers)
        or any(type(n) is not int or n not in available for n in relay_numbers)
    ):
        raise ValueError("HTTP-door relay selection is unverified")
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
    if model.upper() == "S539" and not (
        len(password) >= 8
        and any("A" <= c <= "Z" for c in password)
        and any("a" <= c <= "z" for c in password)
        and any("0" <= c <= "9" for c in password)
    ):
        raise ValueError("Saved password does not satisfy verified firmware requirements")
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
                    info.identity.model.upper() != model.upper()
                    or info.firmware_version != firmware
                ):
                    raise DeviceError("HTTP-door device model or firmware is unverified")
                if {relay.number for relay in await client.get_relay_status()} != available:
                    raise DeviceError("HTTP-door relay inventory is unverified")
            async with WebApiClient(**options) as web:
                await web.login(settings.username, password, encoding=encoding)
                before = await web._config_get(list(fields))
                if not set(fields).issubset(before):
                    raise DeviceError("HTTP-door fields unavailable; no write attempted")
                ready = _matches(before, settings, fields)
                result = {
                    "protocol": "http_door",
                    "applied": False,
                    "verified": ready,
                    "opening_verified": False,
                    "selected_relays": list(relay_numbers),
                    "verdict": "already_configured" if ready else "preview",
                }
                if ready or not apply:
                    return result
                desired = {
                    fields[0]: "1",
                    fields[1]: "0",
                    fields[2]: encode_config_password_webapi(settings.username),
                    fields[3]: encode_config_password_webapi(password),
                }
                attempted = True
                await web._config_set(desired)
                if not _matches(await web._config_get(list(fields)), settings, fields):
                    raise DeviceError("HTTP-door configuration readback did not verify")
                result.update(applied=True, verified=True, verdict="configured")
                return result
    except (Exception, asyncio.CancelledError):
        if attempted:
            raise AmbiguousMutationError(
                "HTTP-door configuration attempted; reconcile readback before retrying"
            ) from None
        raise


async def open_http_door(
    settings: LocalSettings, *, model: str, relay_number: int, pulse_seconds: int
):
    """Issue one authenticated HTTP-door command after fresh configuration checks.

    The device controls the pulse duration. Only the observed firmware Relay A
    configuration is admitted. An acknowledgement does not prove gate position.
    Unknown responses and transport failures are ambiguous; never retry/fallback.
    """
    from pyakuvox.models.events import RelayActionResult

    _profile(model)
    if type(relay_number) is not int or relay_number != 1:
        raise ValueError("Only verified Relay A is supported")
    if type(pulse_seconds) is not int or not 1 <= pulse_seconds <= 60:
        raise ValueError("Invalid pulse duration")
    ready = await configure_http_door(
        settings, model=model, relay_numbers=(relay_number,), apply=False
    )
    if not ready["verified"]:
        raise DeviceError("HTTP-door configuration is not verified")
    options = dict(
        host=settings.host,
        port=settings.port,
        use_ssl=True,
        verify_ssl=True,
        timeout=min(float(settings.timeout), 5.0),
        tls_certificate_sha256=settings.tls_certificate_sha256,
    )
    async with WebApiClient(**options) as web:
        encoding = _profile(model)[3]
        await web.login(settings.username, settings.password.get_secret_value(), encoding=encoding)
        timing = (
            ("HoldDelayA", "ModeA", "TriggerDelayA")
            if model.upper() == "S539"
            else ("RelayADelay", "RelayAMode", "TriggerDelayA")
        )
        keys = [BASE + k for k in timing]
        raw = await web._config_get(keys)
        if [raw.get(k) for k in keys] != [str(pulse_seconds), "0", "0"]:
            raise DeviceError("HTTP-door pulse/mode does not match the approved output")
    async with LocalClient(settings, max_retries=0) as client:
        try:
            # This GET mutates hardware: bypass the generic retrying GET helper.
            # Auth stays in headers; credentials never enter the URL.
            response = await client._client.get(
                "/fcgi/OpenDoor",
                params={"action": "OpenDoor", "DoorNum": "1"},
                follow_redirects=False,
            )
            # Do not mistake a login page or arbitrary HTTP 200 for an ack.
            # Captured on both verified firmware versions with physical gate evidence.
            payload = json.loads(response.text) if len(response.text) <= 256 else None
            acknowledged = (
                isinstance(payload, dict)
                and set(payload) == {"retcode", "message"}
                and type(payload["retcode"]) is int
                and payload["retcode"] == 0
                and payload["message"] == "OK"
            )
            if response.status_code != 200 or not acknowledged:
                raise AmbiguousMutationError(
                    "HTTP-door response is unverified; do not retry the physical command"
                )
        except (Exception, asyncio.CancelledError):
            raise AmbiguousMutationError(
                "HTTP-door command attempted; reconcile physical outcome before retrying"
            ) from None
    return RelayActionResult(
        relay_number=relay_number,
        success=True,
        delay_seconds=pulse_seconds,
        source="local",
        message="HTTP-door acknowledgement; physical position unverified",
    )
