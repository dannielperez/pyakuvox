"""pyakuvox: Proof-of-concept Python library for Akuvox intercom integration."""

from typing import TYPE_CHECKING

__version__ = "0.3.0"

from pyakuvox.capture import (
    DOCUMENTED_MJPEG_SNAPSHOT_PATHS,
    JPEGSnapshot,
    RTSPFrame,
    capture_mjpeg_snapshot,
    capture_rtsp_frame,
)
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
    DeviceProfile,
    SIPStatusSource,
    dialect_for_model,
    identify,
    identify_many,
    profile_for_model,
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
from pyakuvox.visitor import (
    RESIDENTIAL_VISITOR_INTERCOM_PRESET,
    VisitorIntercomPreset,
)

if TYPE_CHECKING:
    from pyakuvox.clients.local.client import LocalClient
    from pyakuvox.clients.local.flip import (
        FlipResult,
        enable_api,
        enable_api_digest,
        verify_digest,
    )
    from pyakuvox.clients.local.webui import (
        SIPAccountStatus,
        SIPRegistrationStatus,
        WebUIClient,
    )
    from pyakuvox.config import LocalAuthType, LocalSettings
    from pyakuvox.device import (
        SIP_PASSWORD_FORBIDDEN_CHARACTERS,
        SIP_PASSWORD_MAX_LENGTH,
        AkuvoxDevice,
        CredentialRotationResult,
        CredentialRotationVerdict,
        SetResult,
        SetVerdict,
        validate_sip_password,
    )
    from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState
    from pyakuvox.operations import read_sip_account_status
else:
    try:
        from pyakuvox.clients.local.client import LocalClient
        from pyakuvox.clients.local.flip import (
            FlipResult,
            enable_api,
            enable_api_digest,
            verify_digest,
        )
        from pyakuvox.clients.local.webui import (
            SIPAccountStatus,
            SIPRegistrationStatus,
            WebUIClient,
        )
        from pyakuvox.config import LocalAuthType, LocalSettings
        from pyakuvox.device import (
            SIP_PASSWORD_FORBIDDEN_CHARACTERS,
            SIP_PASSWORD_MAX_LENGTH,
            AkuvoxDevice,
            CredentialRotationResult,
            CredentialRotationVerdict,
            SetResult,
            SetVerdict,
            validate_sip_password,
        )
        from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState
        from pyakuvox.operations import read_sip_account_status
    except ModuleNotFoundError:  # pragma: no cover - supports lightweight helper imports
        LocalClient = None
        SIPAccountStatus = None
        SIPRegistrationStatus = None
        WebUIClient = None
        FlipResult = None
        enable_api = None
        enable_api_digest = None
        verify_digest = None
        LocalAuthType = None
        LocalSettings = None
        AkuvoxDevice = None
        CredentialRotationResult = None
        CredentialRotationVerdict = None
        SIP_PASSWORD_FORBIDDEN_CHARACTERS = None
        SIP_PASSWORD_MAX_LENGTH = None
        SetResult = None
        SetVerdict = None
        validate_sip_password = None
        DeviceInfo = None
        DeviceStatus = None
        RelayState = None
        read_sip_account_status = None

__all__ = [
    "DOCUMENTED_MJPEG_SNAPSHOT_PATHS",
    "RESIDENTIAL_VISITOR_INTERCOM_PRESET",
    "SIP_PASSWORD_FORBIDDEN_CHARACTERS",
    "SIP_PASSWORD_MAX_LENGTH",
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
    "DeviceProfile",
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
    "SIPAccountStatus",
    "SIPRegistrationStatus",
    "SIPStatusSource",
    "SecuritySnapshot",
    "SetResult",
    "SetVerdict",
    "TimeoutError",
    "UnsupportedDialectError",
    "UnsupportedFeatureError",
    "UserAccountSummary",
    "VisitorIntercomPreset",
    "WebUIClient",
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
    "profile_for_model",
    "read_sip_account_status",
    "render_body",
    "render_url",
    "validate_sip_password",
    "verify_digest",
]
