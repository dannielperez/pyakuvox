"""Normalized device models.

These are our internal domain objects. Both the local adapter
(pylocal-akuvox) and cloud adapter map their responses INTO these
models so the rest of the codebase never deals with raw dicts or
vendor-specific shapes.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class DeviceSource(StrEnum):
    """Where the device record originated."""

    LOCAL = "local"
    CLOUD = "cloud"
    MANUAL = "manual"


class OnlineStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class DeviceIdentity(BaseModel):
    """Immutable hardware identifiers for an Akuvox device."""

    mac_address: str = Field(..., description="MAC address (primary key for device matching)")
    model: str = Field(default="", description="Device model, e.g. 'E21V', 'R29C'")
    serial_number: str = Field(default="", description="Serial number if available")
    hardware_version: str = Field(default="")

    def normalized_mac(self) -> str:
        """Uppercase, colon-separated MAC for consistent comparison."""
        clean = self.mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


class DeviceInfo(BaseModel):
    """Combined identity + network + firmware snapshot of a device.

    This is the "full picture" you get when you query a device.
    Fields are optional where a provider might not supply them.
    """

    identity: DeviceIdentity
    firmware_version: str = ""
    ip_address: str = ""
    hostname: str = ""
    uptime: str | None = None
    web_language: int | None = None
    source: DeviceSource = DeviceSource.LOCAL
    online_status: OnlineStatus = OnlineStatus.UNKNOWN
    last_seen: datetime | None = None

    # Cloud-only fields (populated when source=CLOUD)
    cloud_device_id: str | None = None
    cloud_project_name: str | None = None


class DeviceStatus(BaseModel):
    """Point-in-time operational status from a device."""

    mac_address: str
    unix_time: int = 0
    uptime_seconds: int = 0
    online: OnlineStatus = OnlineStatus.UNKNOWN
    queried_at: datetime = Field(default_factory=datetime.now)
    source: DeviceSource = DeviceSource.LOCAL


class RelayState(BaseModel):
    """Current state of a single relay on a device."""

    number: int
    state: str | None = None  # raw state string from device
    name: str = ""  # e.g. "Relay A", "Front Door"
