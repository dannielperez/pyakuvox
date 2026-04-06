"""Akuvox local device clients.

- ``LocalClient``: Communicates with the device HTTP API (requires API access).
- ``WebUIClient``: Configures the device via its web management interface.
"""

from pyakuvox.clients.local.client import LocalClient
from pyakuvox.clients.local.webui import (
    FirmwareAuthMode,
    HttpApiConfig,
    WebUIClient,
)

__all__ = [
    "FirmwareAuthMode",
    "HttpApiConfig",
    "LocalClient",
    "WebUIClient",
]