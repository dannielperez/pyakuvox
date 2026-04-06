"""Event models for door access, relay actions, and call logs."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class EventSource(StrEnum):
    LOCAL_LOG = "local_log"
    LOCAL_WEBHOOK = "local_webhook"
    CLOUD_POLL = "cloud_poll"


class EventType(StrEnum):
    DOOR_ACCESS = "door_access"
    RELAY_TRIGGERED = "relay_triggered"
    RELAY_CLOSED = "relay_closed"
    INPUT_TRIGGERED = "input_triggered"
    INPUT_CLOSED = "input_closed"
    VALID_CODE = "valid_code"
    INVALID_CODE = "invalid_code"
    CALL = "call"
    FACE_UNLOCK = "face_unlock"
    UNKNOWN = "unknown"


class DoorEvent(BaseModel):
    """Normalized door/access event from any source.

    Local source: pylocal-akuvox DoorLogEntry (paginated log API)
    Local webhook: homeassistant-local-akuvox webhook events
    Cloud source: nimroddolev/akuvox getDoorLog polling
    """

    event_id: str = ""
    mac_address: str = ""
    event_type: EventType = EventType.UNKNOWN
    timestamp: datetime | None = None
    date_str: str = ""  # raw date string from device
    time_str: str = ""  # raw time string from device
    user_name: str = ""
    user_code: str = ""  # PIN or card code (redact in logs!)
    door_type: str = ""
    status: str = ""
    relay: str | None = None
    access_mode: str | None = None
    source: EventSource = EventSource.LOCAL_LOG
    # Cloud-specific
    pic_url: str | None = None
    initiator: str | None = None
    location: str | None = None


class CallEvent(BaseModel):
    """Normalized call log entry."""

    event_id: str = ""
    mac_address: str = ""
    timestamp: datetime | None = None
    date_str: str = ""
    time_str: str = ""
    caller_name: str = ""
    call_type: str = ""
    local_identity: str = ""
    count: str = ""
    pic_url: str | None = None
    source: EventSource = EventSource.LOCAL_LOG


class RelayActionResult(BaseModel):
    """Result of a relay trigger/unlock command."""

    mac_address: str = ""
    relay_number: int
    success: bool
    message: str = ""
    triggered_at: datetime = Field(default_factory=datetime.now)
    delay_seconds: int = 0
    source: str = "local"
