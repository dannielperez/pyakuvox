"""Model-aware high-level operations for Akuvox devices."""

from __future__ import annotations

from pyakuvox.clients.local.webui import (
    ConfigPasswordEncoding,
    SIPAccountStatus,
    WebUIClient,
)
from pyakuvox.exceptions import AkuvoxError, UnsupportedFeatureError
from pyakuvox.identify import SIPStatusSource, identify, profile_for_model


async def read_sip_account_status(
    host: str,
    account: int,
    *,
    username: str,
    password: str,
    model: str | None = None,
    timeout: int = 15,
    verify_ssl: bool = False,
) -> SIPAccountStatus:
    """Discover the model when needed and execute its SIP-status strategy.

    The X916 profile intentionally uses HTTPS only. Login-page probing inside
    ``WebUIClient`` chooses AES or legacy authentication for the actual
    firmware, keeping that volatile detail out of the model table.
    """
    resolved_model = model or (await identify(host, timeout=float(timeout))).model
    profile = profile_for_model(resolved_model)
    if profile.sip_status_source is not SIPStatusSource.FCGI_WEB:
        raise UnsupportedFeatureError("sip_account_status", resolved_model or "unknown model")

    encoding_name = profile.config_password_encodings[0]
    encoding = ConfigPasswordEncoding(encoding_name)
    last_error: Exception | None = None
    for scheme, port in profile.web_endpoints:
        try:
            async with WebUIClient(
                host=host,
                port=port,
                use_ssl=scheme == "https",
                verify_ssl=verify_ssl,
                timeout=timeout,
                password_encoding=encoding,
            ) as webui:
                await webui.login(username, password)
                return await webui.get_sip_account_status(account)
        except (AkuvoxError, OSError) as exc:
            last_error = exc

    if last_error is not None:
        raise last_error
    raise UnsupportedFeatureError("sip_account_status", resolved_model or "unknown model")
