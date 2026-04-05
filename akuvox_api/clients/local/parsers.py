"""Parsers to normalize raw Akuvox local API responses into domain models.

These map the PascalCase JSON responses from the device's HTTP API
into our Pydantic models. Field mappings are based on pylocal-akuvox
source code (verified against real device responses).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from akuvox_api.exceptions import ParseError
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
from akuvox_api.models.users import UserCode


def parse_device_info(data: dict[str, Any], ip_address: str = "") -> DeviceInfo:
    """Parse /api/system/info response → DeviceInfo.

    Expected shape: {"Status": {"Model": "...", "MAC": "...", ...}}
    """
    status = data.get("Status", data)  # some devices omit the Status wrapper
    if not isinstance(status, dict):
        raise ParseError("Expected dict in device info response", raw_data=data)

    try:
        identity = DeviceIdentity(
            mac_address=status["MAC"],
            model=status.get("Model", ""),
            hardware_version=status.get("HardwareVersion", ""),
        )
    except KeyError as exc:
        raise ParseError(f"Missing required field {exc} in device info", raw_data=data) from exc

    return DeviceInfo(
        identity=identity,
        firmware_version=status.get("FirmwareVersion", ""),
        ip_address=ip_address,
        uptime=status.get("Uptime"),
        web_language=_safe_int(status.get("WebLang")),
        source=DeviceSource.LOCAL,
        online_status=OnlineStatus.ONLINE,
        last_seen=datetime.now(),
    )


def parse_device_status(data: dict[str, Any], mac_address: str = "") -> DeviceStatus:
    """Parse /api/system/status response → DeviceStatus.

    Expected shape: {"SystemTime": "...", "UpTime": "..."}
    """
    try:
        return DeviceStatus(
            mac_address=mac_address,
            unix_time=int(data["SystemTime"]),
            uptime_seconds=int(data["UpTime"]),
            online=OnlineStatus.ONLINE,
            queried_at=datetime.now(),
            source=DeviceSource.LOCAL,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ParseError(f"Failed to parse device status: {exc}", raw_data=data) from exc


def parse_firmware_info(data: dict[str, Any]) -> FirmwareInfo:
    """Extract firmware info from /api/system/info response."""
    status = data.get("Status", data)
    return FirmwareInfo(
        mac_address=status.get("MAC", ""),
        current_version=status.get("FirmwareVersion", ""),
        hardware_version=status.get("HardwareVersion", ""),
        model=status.get("Model", ""),
    )


def parse_relay_status(data: dict[str, Any]) -> list[RelayState]:
    """Parse relay status response → list of RelayState."""
    relays: list[RelayState] = []
    # Response shape varies; handle both list and dict formats
    if isinstance(data, list):
        for item in data:
            relays.append(RelayState(
                number=int(item.get("number", 0)),
                state=item.get("state"),
            ))
    elif isinstance(data, dict):
        for key, value in data.items():
            if key.startswith("Relay") or key.startswith("relay"):
                relays.append(RelayState(number=len(relays) + 1, state=str(value)))
    return relays


def parse_users(data: list[dict[str, Any]]) -> list[UserCode]:
    """Parse user list response → list of UserCode."""
    users: list[UserCode] = []
    for item in data:
        try:
            users.append(UserCode(
                id=item.get("ID"),
                name=item["Name"],
                user_id=item["UserID"],
                private_pin=item.get("PrivatePIN") or None,
                card_code=item.get("CardCode") or None,
                schedule_relay=item.get("ScheduleRelay", ""),
                web_relay=item.get("WebRelay"),
                lift_floor_num=item.get("LiftFloorNum"),
                user_type=item.get("Type"),
                source=item.get("Source"),
                source_type=item.get("SourceType"),
                is_cloud_provisioned=item.get("SourceType") == "cloud",
            ))
        except KeyError as exc:
            raise ParseError(f"Missing field {exc} in user data", raw_data=item) from exc
    return users


def parse_schedules(data: list[dict[str, Any]]) -> list[Schedule]:
    """Parse schedule list response → list of Schedule."""
    schedules: list[Schedule] = []
    for item in data:
        try:
            schedules.append(Schedule(
                id=item.get("ID"),
                name=item.get("Name"),
                schedule_type=ScheduleType(item["Type"]),
                date_start=item.get("DateStart"),
                date_end=item.get("DateEnd"),
                time_start=item.get("TimeStart"),
                time_end=item.get("TimeEnd"),
                week=item.get("Week"),
                daily=item.get("Daily"),
                display_id=item.get("DisplayID"),
                mode=item.get("Mode"),
                sun=item.get("Sun"),
                mon=item.get("Mon"),
                tue=item.get("Tue"),
                wed=item.get("Wed"),
                thur=item.get("Thur"),
                fri=item.get("Fri"),
                sat=item.get("Sat"),
                source_type=item.get("SourceType"),
                is_cloud_provisioned=item.get("SourceType") == "cloud",
            ))
        except (KeyError, ValueError) as exc:
            raise ParseError(f"Failed to parse schedule: {exc}", raw_data=item) from exc
    return schedules


def parse_door_logs(data: list[dict[str, Any]], mac_address: str = "") -> list[DoorEvent]:
    """Parse door log response → list of DoorEvent."""
    events: list[DoorEvent] = []
    for item in data:
        try:
            events.append(DoorEvent(
                event_id=item.get("ID", ""),
                mac_address=mac_address,
                event_type=EventType.DOOR_ACCESS,
                date_str=item.get("Date", ""),
                time_str=item.get("Time", ""),
                user_name=item.get("Name", ""),
                user_code=item.get("Code", ""),
                door_type=item.get("Type", ""),
                status=item.get("Status", ""),
                relay=item.get("Relay"),
                access_mode=item.get("AccessMode"),
                source=EventSource.LOCAL_LOG,
            ))
        except Exception as exc:
            raise ParseError(f"Failed to parse door log: {exc}", raw_data=item) from exc
    return events


def parse_call_logs(data: list[dict[str, Any]], mac_address: str = "") -> list[CallEvent]:
    """Parse call log response → list of CallEvent."""
    events: list[CallEvent] = []
    for item in data:
        try:
            events.append(CallEvent(
                event_id=item.get("ID", ""),
                mac_address=mac_address,
                date_str=item.get("Date", ""),
                time_str=item.get("Time", ""),
                caller_name=item.get("Name", ""),
                call_type=item.get("Type", ""),
                local_identity=item.get("LocalIdentity", ""),
                count=item.get("Num", ""),
                pic_url=item.get("PicUrl"),
                source=EventSource.LOCAL_LOG,
            ))
        except Exception as exc:
            raise ParseError(f"Failed to parse call log: {exc}", raw_data=item) from exc
    return events


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
