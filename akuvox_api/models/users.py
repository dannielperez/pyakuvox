"""User / access code models."""

from __future__ import annotations

from pydantic import BaseModel


class UserCode(BaseModel):
    """Normalized user/PIN/card entry from a device.

    Local source: pylocal-akuvox User model
    Cloud source: not available (cloud manages temp keys, not local users)
    """

    id: str | None = None  # device-internal record ID
    name: str
    user_id: str  # external user identifier
    private_pin: str | None = None  # SECURITY: redact in logs
    card_code: str | None = None
    schedule_relay: str = ""
    web_relay: str | None = None
    lift_floor_num: str | None = None
    user_type: str | None = None
    # Provenance tracking
    source: str | None = None  # "local", "cloud", etc.
    source_type: str | None = None  # device-reported source type
    is_cloud_provisioned: bool = False  # if True, cannot modify/delete locally

    @property
    def has_pin(self) -> bool:
        return bool(self.private_pin)

    @property
    def has_card(self) -> bool:
        return bool(self.card_code)
