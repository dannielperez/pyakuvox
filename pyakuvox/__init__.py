"""pyakuvox: Proof-of-concept Python library for Akuvox intercom integration."""

__version__ = "0.1.0"

from pyakuvox.exceptions import (
    AkuvoxError,
    AuthenticationError,
    ConnectionError,
    DeviceError,
    ParseError,
    TimeoutError,
    UnsupportedFeatureError,
)
from pyakuvox.network import (
    ConfigKeyMap,
    CustomPostProfile,
    NetworkConfig,
    build_config_set_payload,
    map_ip,
    plan_static_network,
    render_body,
    render_url,
)

try:
    from pyakuvox.clients.local.client import LocalClient
    from pyakuvox.config import LocalAuthType, LocalSettings
    from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState
except ModuleNotFoundError:  # pragma: no cover - supports lightweight helper imports
    LocalClient = None  # type: ignore[assignment]
    LocalAuthType = None  # type: ignore[assignment]
    LocalSettings = None  # type: ignore[assignment]
    DeviceInfo = None  # type: ignore[assignment]
    DeviceStatus = None  # type: ignore[assignment]
    RelayState = None  # type: ignore[assignment]

__all__ = [
    "AkuvoxError",
    "AuthenticationError",
    "ConnectionError",
    "ConfigKeyMap",
    "CustomPostProfile",
    "DeviceError",
    "DeviceInfo",
    "DeviceStatus",
    "LocalAuthType",
    "LocalClient",
    "LocalSettings",
    "NetworkConfig",
    "ParseError",
    "RelayState",
    "TimeoutError",
    "UnsupportedFeatureError",
    "build_config_set_payload",
    "map_ip",
    "plan_static_network",
    "render_body",
    "render_url",
]
