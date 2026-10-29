"""Narrow, verified R29C call-speaker adjustment over native FCGI management."""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any

from pyakuvox.clients.local.webui import ConfigPasswordEncoding, WebUIClient
from pyakuvox.exceptions import AmbiguousMutationError, DeviceError

if TYPE_CHECKING:
    from pyakuvox.config import LocalSettings

_PAGE = "id=4&id=3"
_FIRMWARE = "29.30.10.203"
_PRESERVED = (
    "hcHandsetSendVolume",
    "hcHeadsetSendVolume",
    "hcHandoffSendVolume",
    "hcKeypadVolume",
    "hcPromptVolume",
    "hcTamperAlarmVolume",
)


def _level(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 15:
        raise ValueError("Speaker volume must be an integer from 1 through 15")
    return value


def _mac(value: str) -> str:
    return re.sub(r"[:-]", "", value).lower()


def _read_level(fields: dict[str, str]) -> int:
    try:
        return _level(int(fields["hcSpeakerVolume"]))
    except (KeyError, ValueError) as exc:
        raise DeviceError("Speaker volume unavailable or unsupported") from exc


async def configure_speaker_volume(
    settings: LocalSettings,
    *,
    expected_mac: str,
    level: int,
    expected_level: int | None = None,
    apply: bool = False,
) -> dict[str, Any]:
    """Preview or set only call-speaker output, with no reboot or write retry.

    The supported contract is R29C firmware 29.30.10.203, whose native
    phoneVoice.js submits only changed fields and validates speaker levels 1..15.
    Apply requires the operator's previously observed level. A changed level
    refuses the write; this read-before-write check is not device-side atomic CAS.
    Saved transport settings are honored without auth-mode changes or fallback.
    """
    _level(level)
    if expected_level is not None:
        _level(expected_level)
    if apply and expected_level is None:
        raise ValueError("The observed current speaker volume is required")
    if not re.fullmatch(r"[0-9a-f]{12}", _mac(expected_mac or "")):
        raise ValueError("A recorded device MAC address is required")
    if not settings.username or not settings.password.get_secret_value():
        raise ValueError("Saved management credentials are required")
    write_started = False
    try:
        async with asyncio.timeout(30):
            async with WebUIClient(
                settings.host,
                port=settings.port,
                use_ssl=settings.use_ssl,
                verify_ssl=settings.verify_ssl,
                tls_certificate_sha256=getattr(settings, "tls_certificate_sha256", None),
                timeout=min(float(settings.timeout), 5),
                password_encoding=ConfigPasswordEncoding.R29C,
            ) as web:
                await web.login(settings.username, settings.password.get_secret_value())
                identity = await web._read_page("id=1")
                if (
                    identity.get("hcProductModelEx") != "R29C"
                    or identity.get("hcFirmwareVersion") != _FIRMWARE
                    or _mac(identity.get("hcMACAddress", "")) != _mac(expected_mac)
                ):
                    raise DeviceError("Device identity or firmware is not supported")
                fields = await web._read_page(_PAGE)
                if fields.get("hcVolumeReqReboot") != "0" or not all(
                    key in fields for key in _PRESERVED
                ):
                    raise DeviceError("Audio configuration contract is unavailable")
                before = _read_level(fields)
                result = {
                    "before": {"speaker_volume": before},
                    "desired": {"speaker_volume": level},
                    "after": {},
                    "applied": False,
                    "verified": False,
                    "verdict": "preview",
                }
                if not apply:
                    return result
                if before != expected_level:
                    raise DeviceError("Speaker volume changed; review a fresh preview")
                if before == level:
                    result.update(after=result["before"], verified=True, verdict="already-set")
                    return result
                write_started = True
                status = await web._write_page(
                    _PAGE, f"begin&Operation=Submit&cSpeakerVolume={level}&SubmitData=end"
                )
                if status != 200:
                    raise AmbiguousMutationError("Speaker write was not acknowledged")
                after = await web._read_page(_PAGE)
                observed = _read_level(after)
                verified = observed == level and all(
                    after.get(key) == fields[key] for key in _PRESERVED
                )
                result.update(
                    after={"speaker_volume": observed},
                    applied=True,
                    verified=verified,
                    verdict="set-verified" if verified else "verification-failed",
                )
                return result
    except AmbiguousMutationError:
        raise
    except Exception as exc:
        if write_started:
            raise AmbiguousMutationError(
                "Speaker change outcome unknown; read current configuration before retrying"
            ) from exc
        raise
