"""Normalized domain models for pyakuvox.

All models are Pydantic v2 BaseModel subclasses. They represent
the internal domain language — both local and cloud adapters
map their raw responses into these types.
"""

from pyakuvox.models.device import (
    DeviceIdentity,
    DeviceInfo,
    DeviceSource,
    DeviceStatus,
    OnlineStatus,
    RelayState,
)
from pyakuvox.models.events import (
    CallEvent,
    DoorEvent,
    EventSource,
    EventType,
    RelayActionResult,
)
from pyakuvox.models.firmware import FirmwareInfo
from pyakuvox.models.schedules import Schedule, ScheduleType
from pyakuvox.models.session import CloudDevice, CloudRelay, CloudSession
from pyakuvox.models.users import UserCode

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