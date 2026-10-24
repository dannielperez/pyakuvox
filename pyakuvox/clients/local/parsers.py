"""Parsers to normalize raw Akuvox local API responses into domain models.

These map the PascalCase JSON responses from the device's HTTP API
into our Pydantic models. Field mappings are based on pylocal-akuvox
source code (verified against real device responses).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pyakuvox.exceptions import ParseError
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
)
from pyakuvox.models.firmware import FirmwareInfo
from pyakuvox.models.schedules import Schedule, ScheduleType
from pyakuvox.models.users import UserCode


def parse_device_info(data: dict[str, Any], ip_address: str = "") -> DeviceInfo:
    """Parse /api/system/info response → DeviceInfo.

    Expected shape: {"Status": {...}} or {"data": {"Status": {...}}}.
    """
    payload = data.get("data", data)
    if not isinstance(payload, dict):
        raise ParseError("Expected dict in device info response", raw_data=data)
    status = payload.get("Status", payload)  # some devices omit the Status wrapper
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


def parse_relay_status(data: dict[str, Any] | list[Any]) -> list[RelayState]:
    """Read explicit relay identities, never assign outputs by response order."""
    if isinstance(data, dict) and "data" in data:
        data = data["data"]
    if not isinstance(data, (dict, list)):
        raise ParseError("Expected relay status object or list")
    relays: dict[int, RelayState] = {}
    if isinstance(data, list):
        entries = [
            (item.get("number"), item.get("state")) for item in data if isinstance(item, dict)
        ]
        if len(entries) != len(data):
            raise ParseError("Invalid relay status entry")
    else:
        entries = []
        for key, value in data.items():
            if not key.lower().startswith("relay"):
                continue
            match = re.fullmatch(r"relay([a-p]|[1-9]|1[0-6])", key, re.IGNORECASE)
            if not match:
                raise ParseError("Unrecognized relay identity")
            suffix = match.group(1)
            number = ord(suffix.upper()) - ord("A") + 1 if suffix.isalpha() else int(suffix)
            entries.append((number, value))
    for number, value in entries:
        if isinstance(number, bool) or not str(number).isdigit():
            raise ParseError("Invalid relay number")
        number = int(number)
        if not 1 <= number <= 16 or number in relays:
            raise ParseError("Invalid or duplicate relay identity")
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise ParseError("Invalid relay state")
        relays[number] = RelayState(number=number, state=None if value is None else str(value))
    return [relays[number] for number in sorted(relays)]


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
