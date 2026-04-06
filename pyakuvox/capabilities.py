"""Capability tracking for Akuvox features across providers.

This module lets us honestly declare what each provider (local HTTP,
cloud official, cloud reverse-engineered) can actually do. Every
feature has a support level per provider so the service layer can
decide whether to attempt an operation, warn, or refuse.

Support levels:
  - SUPPORTED:    Verified working, tested against real devices/API
  - PARTIAL:      Works in some scenarios, known limitations
  - UNVERIFIED:   Code exists but has not been tested against real hardware
  - UNSUPPORTED:  Known to not work or not available via this provider
  - UNKNOWN:      No information — hasn't been researched yet
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class SupportLevel(StrEnum):
    """How well a feature is supported by a given provider."""

    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNVERIFIED = "unverified"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class Provider(StrEnum):
    """Known integration providers."""

    LOCAL_HTTP = "local_http"
    CLOUD_OFFICIAL = "cloud_official"
    CLOUD_REVERSE_ENGINEERED = "cloud_reverse_engineered"


class ApiCapability(BaseModel):
    """Support status for a single feature on a single provider."""

    feature: str
    provider: Provider
    level: SupportLevel
    notes: str = ""
    verified_on: str = ""  # e.g. "E21V firmware 23.0.3.67.2"
    source: str = ""  # e.g. "pylocal-akuvox", "nimroddolev/akuvox", "manual test"

    @property
    def is_usable(self) -> bool:
        """True if the feature is at least partially working."""
        return self.level in (SupportLevel.SUPPORTED, SupportLevel.PARTIAL)

    @property
    def is_experimental(self) -> bool:
        return self.level == SupportLevel.UNVERIFIED


class ApiCapabilityMatrix(BaseModel):
    """Full matrix of feature × provider support levels.

    Usage:
        matrix = build_default_matrix()
        cap = matrix.get("device_info", Provider.LOCAL_HTTP)
        if cap and cap.is_usable:
            ...
    """

    capabilities: list[ApiCapability] = []

    def get(self, feature: str, provider: Provider) -> ApiCapability | None:
        """Look up a specific feature+provider pair."""
        for cap in self.capabilities:
            if cap.feature == feature and cap.provider == provider:
                return cap
        return None

    def for_feature(self, feature: str) -> list[ApiCapability]:
        """All provider entries for a given feature."""
        return [c for c in self.capabilities if c.feature == feature]

    def for_provider(self, provider: Provider) -> list[ApiCapability]:
        """All feature entries for a given provider."""
        return [c for c in self.capabilities if c.provider == provider]

    def features(self) -> list[str]:
        """Unique feature names in the matrix."""
        return sorted({c.feature for c in self.capabilities})

    def summary(self) -> list[dict[str, Any]]:
        """Table-friendly summary: one row per feature with provider columns."""
        rows: list[dict[str, Any]] = []
        for feature in self.features():
            row: dict[str, Any] = {"feature": feature}
            for cap in self.for_feature(feature):
                row[cap.provider.value] = cap.level.value
                if cap.notes:
                    row[f"{cap.provider.value}_notes"] = cap.notes
            rows.append(row)
        return rows


# ── Default matrix based on research ────────────────────────────────
#
# Sources:
#   LOCAL_HTTP:                 pylocal-akuvox v0.2.3 source code
#   CLOUD_REVERSE_ENGINEERED:  nimroddolev/akuvox + ezhevita/AkuvoxAPI
#   CLOUD_OFFICIAL:            No public API documentation found
#


def _cap(
    feature: str,
    provider: Provider,
    level: SupportLevel,
    notes: str = "",
    source: str = "",
) -> ApiCapability:
    return ApiCapability(
        feature=feature, provider=provider, level=level, notes=notes, source=source
    )


L = Provider.LOCAL_HTTP
CO = Provider.CLOUD_OFFICIAL
CR = Provider.CLOUD_REVERSE_ENGINEERED


def build_default_matrix() -> ApiCapabilityMatrix:
    """Construct the capability matrix based on current research.

    This is the single source of truth for what we believe each
    provider can do. Update this as testing confirms/denies features.
    """
    return ApiCapabilityMatrix(
        capabilities=[
            # ── Device identification ──
            _cap("device_info", L, SupportLevel.SUPPORTED,
                 "GET /api/system/info — model, MAC, firmware, hardware",
                 "pylocal-akuvox"),
            _cap("device_info", CO, SupportLevel.UNKNOWN,
                 "No official API docs found"),
            _cap("device_info", CR, SupportLevel.PARTIAL,
                 "userconf endpoint returns device list with basic info",
                 "nimroddolev/akuvox"),

            # ── Device status ──
            _cap("device_status", L, SupportLevel.SUPPORTED,
                 "GET /api/system/status — uptime, system time",
                 "pylocal-akuvox"),
            _cap("device_status", CO, SupportLevel.UNKNOWN),
            _cap("device_status", CR, SupportLevel.UNSUPPORTED,
                 "Cloud API does not expose device health/status"),

            # ── Firmware info ──
            _cap("firmware_info", L, SupportLevel.SUPPORTED,
                 "Included in /api/system/info response",
                 "pylocal-akuvox"),
            _cap("firmware_info", CO, SupportLevel.UNKNOWN),
            _cap("firmware_info", CR, SupportLevel.UNVERIFIED,
                 "May be available in userconf or servers_list response"),

            # ── Relay / door unlock ──
            _cap("relay_unlock", L, SupportLevel.SUPPORTED,
                 "POST relay trigger with num, mode, level, delay",
                 "pylocal-akuvox"),
            _cap("relay_unlock", CO, SupportLevel.UNKNOWN),
            _cap("relay_unlock", CR, SupportLevel.PARTIAL,
                 "opendoor endpoint works via SmartPlus tokens",
                 "nimroddolev/akuvox"),

            # ── Relay status ──
            _cap("relay_status", L, SupportLevel.SUPPORTED,
                 "GET relay status", "pylocal-akuvox"),
            _cap("relay_status", CO, SupportLevel.UNKNOWN),
            _cap("relay_status", CR, SupportLevel.UNSUPPORTED),

            # ── User / PIN management ──
            _cap("user_list", L, SupportLevel.SUPPORTED,
                 "Paginated user list with PIN, card, schedule info",
                 "pylocal-akuvox"),
            _cap("user_add", L, SupportLevel.SUPPORTED,
                 source="pylocal-akuvox"),
            _cap("user_modify", L, SupportLevel.SUPPORTED,
                 source="pylocal-akuvox"),
            _cap("user_delete", L, SupportLevel.SUPPORTED,
                 notes="Cloud-provisioned users cannot be deleted locally",
                 source="pylocal-akuvox + homeassistant-local-akuvox docs"),
            _cap("user_list", CO, SupportLevel.UNKNOWN),
            _cap("user_list", CR, SupportLevel.UNSUPPORTED,
                 "Cloud API focuses on temp keys, not local user CRUD"),

            # ── Schedule management ──
            _cap("schedule_list", L, SupportLevel.SUPPORTED,
                 "Paginated schedule list", "pylocal-akuvox"),
            _cap("schedule_add", L, SupportLevel.SUPPORTED,
                 source="pylocal-akuvox"),
            _cap("schedule_modify", L, SupportLevel.SUPPORTED,
                 source="pylocal-akuvox"),
            _cap("schedule_delete", L, SupportLevel.SUPPORTED,
                 notes="Cloud-provisioned schedules cannot be deleted locally",
                 source="pylocal-akuvox"),
            _cap("schedule_list", CO, SupportLevel.UNKNOWN),
            _cap("schedule_list", CR, SupportLevel.UNSUPPORTED),

            # ── Door / access logs ──
            _cap("door_logs", L, SupportLevel.SUPPORTED,
                 "Paginated door access log", "pylocal-akuvox"),
            _cap("call_logs", L, SupportLevel.SUPPORTED,
                 "Paginated call log", "pylocal-akuvox"),
            _cap("door_logs", CR, SupportLevel.PARTIAL,
                 "getDoorLog endpoint returns last event, polling-based",
                 "nimroddolev/akuvox"),

            # ── Device config get/set ──
            _cap("config_get", L, SupportLevel.SUPPORTED,
                 "Full autop-format config dump", "pylocal-akuvox"),
            _cap("config_set", L, SupportLevel.SUPPORTED,
                 "Set autop-format key-value pairs", "pylocal-akuvox"),
            _cap("config_get", CO, SupportLevel.UNKNOWN),
            _cap("config_set", CO, SupportLevel.UNKNOWN),
            _cap("config_get", CR, SupportLevel.UNSUPPORTED),
            _cap("config_set", CR, SupportLevel.UNSUPPORTED),

            # ── Temp keys ──
            _cap("temp_key_list", L, SupportLevel.UNSUPPORTED,
                 "Temp keys are a cloud-only feature"),
            _cap("temp_key_list", CR, SupportLevel.PARTIAL,
                 "getPersonalTempKeyList works via SmartPlus tokens",
                 "nimroddolev/akuvox"),

            # ── Camera / RTSP ──
            _cap("camera_stream", L, SupportLevel.UNVERIFIED,
                 "RTSP likely available on LAN but endpoints unconfirmed"),
            _cap("camera_stream", CR, SupportLevel.PARTIAL,
                 "Camera URLs returned in userconf response",
                 "nimroddolev/akuvox"),

            # ── Cloud auth ──
            _cap("cloud_sms_login", CR, SupportLevel.PARTIAL,
                 "SMS login + token refresh via reverse-engineered flow",
                 "nimroddolev/akuvox"),
            _cap("cloud_token_login", CR, SupportLevel.PARTIAL,
                 "Reuse auth_token + token from SmartPlus app",
                 "nimroddolev/akuvox"),

            # ── Reboot ──
            _cap("reboot", L, SupportLevel.UNVERIFIED,
                 "Likely available via config API or dedicated endpoint, untested"),
            _cap("reboot", CO, SupportLevel.UNKNOWN),
            _cap("reboot", CR, SupportLevel.UNSUPPORTED),

            # ── Webhook / event push ──
            _cap("webhook_events", L, SupportLevel.SUPPORTED,
                 "Device pushes relay/input/code events to configured URL",
                 "homeassistant-local-akuvox"),
            _cap("webhook_events", CR, SupportLevel.UNSUPPORTED,
                 "Cloud uses polling, not push"),
        ]
    )
