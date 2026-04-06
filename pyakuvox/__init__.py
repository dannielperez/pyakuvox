"""pyakuvox: Proof-of-concept Python library for Akuvox intercom integration."""

__version__ = "0.1.0"

from pyakuvox.clients.local.client import LocalClient
from pyakuvox.config import LocalAuthType, LocalSettings
from pyakuvox.exceptions import (
    AkuvoxError,
    AuthenticationError,
    ConnectionError,
    DeviceError,
    ParseError,
    TimeoutError,
    UnsupportedFeatureError,
)
from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState

__all__ = [
    "AkuvoxError",
    "AuthenticationError",
    "ConnectionError",
    "DeviceError",
    "DeviceInfo",
    "DeviceStatus",
    "LocalAuthType",
    "LocalClient",
    "LocalSettings",
    "ParseError",
    "RelayState",
    "TimeoutError",
    "UnsupportedFeatureError",
]
