"""Access schedule models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class ScheduleType(StrEnum):
    """Schedule types as defined by the Akuvox local API.

    Source: pylocal-akuvox + homeassistant-local-akuvox docs
    """

    DATE_RANGE = "0"  # specific start/end dates
    WEEKLY = "1"  # selected days of the week
    DAILY = "2"  # every day


class Schedule(BaseModel):
    """Normalized access schedule from a device.

    Local source: pylocal-akuvox AccessSchedule model
    """

    id: str | None = None
    name: str | None = None
    schedule_type: ScheduleType
    date_start: str | None = None
    date_end: str | None = None
    time_start: str | None = None
    time_end: str | None = None
    week: str | None = None
    daily: str | None = None
    display_id: str | None = None
    mode: str | None = None
    # Day-of-week flags
    sun: str | None = None
    mon: str | None = None
    tue: str | None = None
    wed: str | None = None
    thur: str | None = None
    fri: str | None = None
    sat: str | None = None
    # Provenance
    source_type: str | None = None
    is_cloud_provisioned: bool = False
