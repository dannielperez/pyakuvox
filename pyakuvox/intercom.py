"""Model-aware translation for caller-owned intercom configuration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, NotRequired, TypedDict

from pyakuvox.exceptions import DeviceError

if TYPE_CHECKING:
    from collections.abc import Callable


class IntercomKeyType(StrEnum):
    """Vendor-neutral homepage key actions."""

    SPEED_DIAL = "speed-dial"
    PIN = "pin"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class IntercomHomepageKey:
    """One caller-defined key on an intercom homepage."""

    key_type: IntercomKeyType
    label: str
    value: str
    show_name: bool

    def __post_init__(self) -> None:
        if self.key_type is IntercomKeyType.SPEED_DIAL and not self.value.strip():
            raise ValueError("speed-dial keys require a value")


@dataclass(frozen=True, slots=True)
class IntercomConfiguration:
    """Explicit, organization-agnostic intercom intent supplied by a caller."""

    homepage_keys: tuple[IntercomHomepageKey, ...]
    relay_dtmf_codes: tuple[str, ...]
    relay_hold_seconds: int
    allow_dtmf_from_all_numbers: bool

    def __post_init__(self) -> None:
        if not self.homepage_keys:
            raise ValueError("at least one homepage key is required")
        if len(set(self.relay_dtmf_codes)) != len(self.relay_dtmf_codes) or any(
            len(code) != 1 or code not in "0123456789" for code in self.relay_dtmf_codes
        ):
            raise ValueError("relay DTMF codes must be unique single digits")
        if not 1 <= self.relay_hold_seconds <= 60:
            raise ValueError("relay hold must be between 1 and 60 seconds")


class IntercomConfigurationVerdict(StrEnum):
    """Typed outcomes for model-specific configuration application."""

    WOULD_CHANGE = "would-change"
    ALREADY_SET = "already-set"
    SET_VERIFIED = "set-verified"
    SET_DID_NOT_STICK = "set-did-not-stick"
    UNSUPPORTED_MODEL = "unsupported-model"
    UNSUPPORTED_FIRMWARE = "unsupported-firmware"
    UNSUPPORTED_CONFIGURATION = "unsupported-configuration"


class IntercomConfigurationResult(TypedDict):
    """Result that separates unsupported capability from mutation failure."""

    before: dict[str, str]
    plan: dict[str, str]
    changed: bool
    applied: bool
    verdict: IntercomConfigurationVerdict
    after: NotRequired[dict[str, str]]
    reason: NotRequired[str]


@dataclass(frozen=True, slots=True)
class IntercomAdapter:
    """One model's audited transport and configuration mapping."""

    model: str
    transport: str
    build_config: Callable[[IntercomConfiguration], dict[str, str]]
    validate_surface: Callable[[dict[str, Any], dict[str, str]], None]


def x916_intercom_config(configuration: IntercomConfiguration) -> dict[str, str]:
    """Translate explicit intercom intent into the audited X916 AutoP map."""
    if len(configuration.homepage_keys) != 6:
        raise ValueError("X916 homepage configuration requires exactly six keys")
    if len(configuration.relay_dtmf_codes) != 4:
        raise ValueError("X916 relay configuration requires exactly four DTMF codes")

    display = "Config.DoorSetting.DISPLAY"
    general = "Config.DoorSetting.GENERAL"
    dtmf = "Config.DoorSetting.DTMF"
    relay = "Config.DoorSetting.RELAY"
    key_type_codes = {
        IntercomKeyType.SPEED_DIAL: "5",
        IntercomKeyType.PIN: "2",
        IntercomKeyType.DISABLED: "6",
    }
    wants = {
        f"{general}.Theme": "2",
        f"{general}.BuildingDisplayType": "0",
        f"{dtmf}.Enable": "1",
        f"{dtmf}.Option": "0",
        f"{dtmf}.DtmfWhitelist": (
            "2" if configuration.allow_dtmf_from_all_numbers else "0"
        ),
    }
    for slot, key in enumerate(configuration.homepage_keys, start=1):
        wants.update(
            {
                f"{display}.Key{slot}Label": key.label,
                f"{display}.Key{slot}Type": key_type_codes[key.key_type],
                f"{display}.Key{slot}Number": key.value,
                f"{display}.Key{slot}NameDisplay": "1" if key.show_name else "0",
            }
        )
    for relay_number, (suffix, code) in enumerate(
        zip("ABCD", configuration.relay_dtmf_codes, strict=True),
        start=1,
    ):
        wants.update(
            {
                f"{dtmf}.Code{relay_number}": code,
                f"{relay}.Mode{suffix}": "0",
                f"{relay}.Type{suffix}": "0",
                f"{relay}.TriggerDelay{suffix}": "0",
                f"{relay}.HoldDelay{suffix}": str(configuration.relay_hold_seconds),
            }
        )
    return wants


def require_x916_intercom_surface(config: dict[str, Any], wants: dict[str, str]) -> None:
    """Fail closed when firmware does not expose the audited fields."""
    missing = sorted(key for key in wants if key not in config)
    if missing:
        preview = ", ".join(missing[:3])
        suffix = "..." if len(missing) > 3 else ""
        raise DeviceError(
            f"X916 intercom configuration is unsupported by this firmware; "
            f"missing {preview}{suffix}"
        )


_INTERCOM_ADAPTERS = {
    "X916": IntercomAdapter(
        model="X916",
        transport="digest-config-api",
        build_config=x916_intercom_config,
        validate_surface=require_x916_intercom_surface,
    ),
}


def intercom_adapter(model: str) -> IntercomAdapter | None:
    """Return the audited adapter for a model without guessing a fallback."""
    return _INTERCOM_ADAPTERS.get(model.strip().upper())


__all__ = [
    "IntercomAdapter",
    "IntercomConfiguration",
    "IntercomConfigurationResult",
    "IntercomConfigurationVerdict",
    "IntercomHomepageKey",
    "IntercomKeyType",
    "intercom_adapter",
    "require_x916_intercom_surface",
    "x916_intercom_config",
]
