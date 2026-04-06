"""Cloud session / authentication models.

WARNING: All cloud integration is EXPERIMENTAL. These models represent
the session data structures observed in the reverse-engineered SmartPlus
API (nimroddolev/akuvox). Akuvox has no public API documentation.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, SecretStr


class CloudSession(BaseModel):
    """Represents an authenticated SmartPlus cloud session.

    Based on reverse-engineering of the SmartPlus mobile app API.
    Tokens may expire without warning; no documented refresh flow.
    """

    auth_token: SecretStr = SecretStr("")
    token: SecretStr = SecretStr("")
    phone_number: str = ""
    country_code: str = ""
    subdomain: str = "ecloud"
    host: str = ""  # resolved API host, e.g. "ecloud.akuvox.com"
    rtsp_ip: str | None = None
    app_type: str = "community"  # "community" or "single"
    project_name: str = ""
    authenticated_at: datetime | None = None
    expires_at: datetime | None = None  # unknown if tokens expire

    @property
    def is_active(self) -> bool:
        """Best-guess at whether the session is still valid."""
        if not self.token.get_secret_value():
            return False
        if self.expires_at and datetime.now() > self.expires_at:
            return False
        return True


class CloudDevice(BaseModel):
    """Device record as returned by the SmartPlus cloud userconf endpoint.

    EXPERIMENTAL: field names based on nimroddolev/akuvox data parsing.
    The actual response shape may vary by region, firmware, or API version.
    """

    device_id: str = ""
    name: str = ""
    mac: str = ""
    ip: str = ""
    model: str = ""
    location: str = ""
    # Relay info from cloud
    relays: list[CloudRelay] = Field(default_factory=list)
    # Camera
    camera_url: str = ""
    rtsp_url: str = ""


class CloudRelay(BaseModel):
    """Relay descriptor from the cloud device list."""

    relay_id: str = ""
    name: str = ""  # e.g. "Front Door"
    token: str = ""  # opendoor token for this relay
    host: str = ""  # API host for this relay's open command


# Fix forward reference
CloudDevice.model_rebuild()
