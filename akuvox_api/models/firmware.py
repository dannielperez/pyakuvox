"""Firmware-related models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FirmwareInfo(BaseModel):
    """Firmware version details for a device.

    Local source: parsed from /api/system/info (DeviceInfo.firmware_version).
    Cloud source: potentially from userconf or firmware update endpoints (unverified).
    """

    mac_address: str
    current_version: str
    hardware_version: str = ""
    model: str = ""
    # Fields below would come from a firmware update service (future)
    latest_available: str | None = None
    update_available: bool = False
    checked_at: datetime = Field(default_factory=datetime.now)
