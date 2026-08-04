"""Vendor-neutral helpers for Akuvox device RTSP stream addresses."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote


@dataclass(frozen=True, slots=True)
class RTSPStreamConfig:
    """Connection details for one device-owned RTSP stream.

    The password is accepted only to render a connection URL for an immediate
    capture. Callers should not persist the rendered URL because it contains a
    credential.
    """

    host: str
    username: str = ""
    password: str = ""
    port: int = 554
    path: str = "/live/ch00_0"


def build_rtsp_url(config: RTSPStreamConfig) -> str:
    """Build an authenticated RTSP URL without changing the configured path."""
    host = config.host.strip()
    if not host:
        raise ValueError("RTSP host is required")
    if not 1 <= config.port <= 65535:
        raise ValueError("RTSP port must be between 1 and 65535")
    path = config.path.strip()
    if not path.startswith("/"):
        path = f"/{path}"
    credentials = ""
    if config.username:
        credentials = quote(config.username, safe="")
        if config.password:
            credentials += f":{quote(config.password, safe='')}"
        credentials += "@"
    return f"rtsp://{credentials}{host}:{config.port}{path}"
