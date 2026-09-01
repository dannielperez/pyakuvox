"""Model-aware visitor-intercom presets.

The values in this module are operator intent, not a generic bag of Akuvox
AutoP fields.  A preset is expanded only after the connected device proves it
has the audited X916 configuration surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pyakuvox.exceptions import DeviceError

RESIDENTIAL_VISITOR_INTERCOM_PRESET = "residential_visitor_intercom_v1"


@dataclass(frozen=True, slots=True)
class VisitorIntercomPreset:
    """Unique Security baseline for a residential visitor intercom."""

    name: str = RESIDENTIAL_VISITOR_INTERCOM_PRESET
    guard_label: str = "Centro/Guard"
    guard_number: str = "99"
    relay_codes: tuple[str, str, str, str] = ("6", "7", "8", "9")
    relay_hold_seconds: int = 5

    def __post_init__(self) -> None:
        if self.name != RESIDENTIAL_VISITOR_INTERCOM_PRESET:
            raise ValueError(f"unsupported visitor-intercom preset: {self.name}")
        if not self.guard_label.strip() or not self.guard_number.strip():
            raise ValueError("guard label and number are required")
        if len(set(self.relay_codes)) != 4 or any(
            len(code) != 1 or code not in "0123456789" for code in self.relay_codes
        ):
            raise ValueError("relay codes must be four unique single digits")
        if not 1 <= self.relay_hold_seconds <= 60:
            raise ValueError("relay hold must be between 1 and 60 seconds")


def x916_visitor_config(preset: VisitorIntercomPreset) -> dict[str, str]:
    """Expand the residential intent into the audited X916 AutoP map."""
    display = "Config.DoorSetting.DISPLAY"
    general = "Config.DoorSetting.GENERAL"
    dtmf = "Config.DoorSetting.DTMF"
    relay = "Config.DoorSetting.RELAY"
    wants = {
        f"{general}.Theme": "2",  # Intercom theme
        f"{general}.BuildingDisplayType": "0",  # Homepage
        f"{display}.Key1Label": preset.guard_label,
        f"{display}.Key1Type": "5",  # Speed Dial
        f"{display}.Key1Number": preset.guard_number,
        f"{display}.Key1NameDisplay": "1",
        f"{display}.Key2Label": "",
        f"{display}.Key2Type": "2",  # PIN
        f"{display}.Key2Number": "",
        f"{display}.Key2NameDisplay": "1",
        f"{dtmf}.Enable": "1",
        f"{dtmf}.Option": "0",  # one-digit DTMF
        f"{dtmf}.DtmfWhitelist": "2",  # All Numbers
    }
    for slot in range(3, 7):
        wants.update(
            {
                f"{display}.Key{slot}Label": "",
                f"{display}.Key{slot}Type": "6",  # Null
                f"{display}.Key{slot}Number": "",
                f"{display}.Key{slot}NameDisplay": "1",
            }
        )
    for suffix, code in zip("ABCD", preset.relay_codes, strict=True):
        relay_number = "ABCD".index(suffix) + 1
        wants.update(
            {
                f"{dtmf}.Code{relay_number}": code,
                f"{relay}.Mode{suffix}": "0",  # Monostable
                f"{relay}.Type{suffix}": "0",  # Default state
                f"{relay}.TriggerDelay{suffix}": "0",
                f"{relay}.HoldDelay{suffix}": str(preset.relay_hold_seconds),
            }
        )
    return wants


def require_x916_visitor_surface(config: dict[str, Any], wants: dict[str, str]) -> None:
    """Fail closed when firmware does not expose the audited preset fields."""
    missing = sorted(key for key in wants if key not in config)
    if missing:
        preview = ", ".join(missing[:3])
        suffix = "..." if len(missing) > 3 else ""
        raise DeviceError(
            f"X916 visitor preset is unsupported by this firmware; missing {preview}{suffix}"
        )


__all__ = [
    "RESIDENTIAL_VISITOR_INTERCOM_PRESET",
    "VisitorIntercomPreset",
    "require_x916_visitor_surface",
    "x916_visitor_config",
]
