"""pyakuvox: Proof-of-concept Python library for Akuvox intercom integration."""

__version__ = "0.2.0"

from pyakuvox.exceptions import (
    AkuvoxError,
    ApiAccessForbiddenError,
    AuthenticationError,
    ConnectionError,
    DeviceError,
    ParseError,
    TimeoutError,
    UnsupportedDialectError,
    UnsupportedFeatureError,
)
from pyakuvox.identify import (
    ApiDialect,
    DeviceIdentity,
    dialect_for_model,
    identify,
    identify_many,
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
    from pyakuvox.clients.local.flip import FlipResult, enable_api_digest, verify_digest
    from pyakuvox.config import LocalAuthType, LocalSettings
    from pyakuvox.device import AkuvoxDevice
    from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState
except ModuleNotFoundError:  # pragma: no cover - supports lightweight helper imports
    LocalClient = None  # type: ignore[assignment]
    FlipResult = None  # type: ignore[assignment]
    enable_api_digest = None  # type: ignore[assignment]
    verify_digest = None  # type: ignore[assignment]
    LocalAuthType = None  # type: ignore[assignment]
    LocalSettings = None  # type: ignore[assignment]
    AkuvoxDevice = None  # type: ignore[assignment]
    DeviceInfo = None  # type: ignore[assignment]
    DeviceStatus = None  # type: ignore[assignment]
    RelayState = None  # type: ignore[assignment]

__all__ = [
    "AkuvoxDevice",
    "AkuvoxError",
    "ApiAccessForbiddenError",
    "ApiDialect",
    "AuthenticationError",
    "ConfigKeyMap",
    "ConnectionError",
    "CustomPostProfile",
    "DeviceError",
    "DeviceIdentity",
    "DeviceInfo",
    "DeviceStatus",
    "FlipResult",
    "LocalAuthType",
    "LocalClient",
    "LocalSettings",
    "NetworkConfig",
    "ParseError",
    "RelayState",
    "TimeoutError",
    "UnsupportedDialectError",
    "UnsupportedFeatureError",
    "build_config_set_payload",
    "dialect_for_model",
    "enable_api_digest",
    "identify",
    "identify_many",
    "map_ip",
    "plan_static_network",
    "render_body",
    "render_url",
    "verify_digest",
]
