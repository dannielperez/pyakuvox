"""Akuvox local device clients.

- ``LocalClient``: Communicates with the device HTTP API (requires API access).
- ``WebUIClient``: Configures an FCGI (``/fcgi/do``) panel — X916/R29C.
- ``WebApiClient``: Configures an SPA (``/api/web/*``) panel — S5xx.
- ``enable_api_digest``: Universal "flip the HTTP API to Digest" across dialects.
"""

from pyakuvox.clients.local.client import LocalClient
from pyakuvox.clients.local.flip import (
    FlipResult,
    enable_api_digest,
    verify_digest,
)
from pyakuvox.clients.local.webapi import WebApiClient
from pyakuvox.clients.local.webui import (
    ConfigPasswordEncoding,
    FirmwareAuthMode,
    HttpApiConfig,
    WebUIClient,
)

__all__ = [
    "ConfigPasswordEncoding",
    "FirmwareAuthMode",
    "FlipResult",
    "HttpApiConfig",
    "LocalClient",
    "WebApiClient",
    "WebUIClient",
    "enable_api_digest",
    "verify_digest",
]
