"""Normalized domain models for akuvox-api.

All models are Pydantic v2 BaseModel subclasses. They represent
the internal domain language — both local and cloud adapters
map their raw responses into these types.
"""

from akuvox_api.models.device import (
    DeviceIdentity,
    DeviceInfo,
    DeviceSource,
    DeviceStatus,
    OnlineStatus,
    RelayState,
)
from akuvox_api.models.events import (
    CallEvent,
    DoorEvent,
    EventSource,
    EventType,
    RelayActionResult,
)
from akuvox_api.models.firmware import FirmwareInfo
from akuvox_api.models.schedules import Schedule, ScheduleType
from akuvox_api.models.session import CloudDevice, CloudRelay, CloudSession
from akuvox_api.models.users import UserCode

__all__ = [
    "CallEvent",
    "CloudDevice",
    "CloudRelay",
    "CloudSession",
    "DeviceIdentity",
    "DeviceInfo",
    "DeviceSource",
    "DeviceStatus",
    "DoorEvent",
    "EventSource",
    "EventType",
    "FirmwareInfo",
    "OnlineStatus",
    "RelayActionResult",
    "RelayState",
    "Schedule",
    "ScheduleType",
    "UserCode",
]