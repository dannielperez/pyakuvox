"""pyakuvox: Proof-of-concept Python library for Akuvox intercom integration."""

from typing import TYPE_CHECKING

__version__ = "0.3.0"

from pyakuvox.capture import JPEGSnapshot, RTSPFrame, capture_mjpeg_snapshot, capture_rtsp_frame
from pyakuvox.exceptions import (
    AkuvoxError,
    AmbiguousMutationError,
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
from pyakuvox.rtsp import RTSPStreamConfig, build_rtsp_url
from pyakuvox.security import CredentialRisk, SecuritySnapshot, UserAccountSummary

if TYPE_CHECKING:
    from pyakuvox.clients.local.client import LocalClient
    from pyakuvox.clients.local.flip import (
        FlipResult,
        enable_api,
        enable_api_digest,
        verify_digest,
    )
    from pyakuvox.config import LocalAuthType, LocalSettings
    from pyakuvox.device import (
        AkuvoxDevice,
        CredentialRotationResult,
        CredentialRotationVerdict,
        SetResult,
        SetVerdict,
    )
    from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState
else:
    try:
        from pyakuvox.clients.local.client import LocalClient
        from pyakuvox.clients.local.flip import (
            FlipResult,
            enable_api,
            enable_api_digest,
            verify_digest,
        )
        from pyakuvox.config import LocalAuthType, LocalSettings
        from pyakuvox.device import (
            AkuvoxDevice,
            CredentialRotationResult,
            CredentialRotationVerdict,
            SetResult,
            SetVerdict,
        )
        from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState
    except ModuleNotFoundError:  # pragma: no cover - supports lightweight helper imports
        LocalClient = None
        FlipResult = None
        enable_api = None
        enable_api_digest = None
        verify_digest = None
        LocalAuthType = None
        LocalSettings = None
        AkuvoxDevice = None
        CredentialRotationResult = None
        CredentialRotationVerdict = None
        SetResult = None
        SetVerdict = None
        DeviceInfo = None
        DeviceStatus = None
        RelayState = None

__all__ = [
    "AkuvoxDevice",
    "AkuvoxError",
    "AmbiguousMutationError",
    "ApiAccessForbiddenError",
    "ApiDialect",
    "AuthenticationError",
    "ConfigKeyMap",
    "ConnectionError",
    "CredentialRisk",
    "CredentialRotationResult",
    "CredentialRotationVerdict",
    "CustomPostProfile",
    "DeviceError",
    "DeviceIdentity",
    "DeviceInfo",
    "DeviceStatus",
    "FlipResult",
    "JPEGSnapshot",
    "LocalAuthType",
    "LocalClient",
    "LocalSettings",
    "NetworkConfig",
    "ParseError",
    "RTSPFrame",
    "RTSPStreamConfig",
    "RelayState",
    "SecuritySnapshot",
    "SetResult",
    "SetVerdict",
    "TimeoutError",
    "UnsupportedDialectError",
    "UnsupportedFeatureError",
    "UserAccountSummary",
    "build_config_set_payload",
    "build_rtsp_url",
    "capture_mjpeg_snapshot",
    "capture_rtsp_frame",
    "dialect_for_model",
    "enable_api",
    "enable_api_digest",
    "identify",
    "identify_many",
    "map_ip",
    "plan_static_network",
    "render_body",
    "render_url",
    "verify_digest",
]
