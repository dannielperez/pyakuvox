"""Bounded RTSP frame capture for Akuvox device-owned camera streams."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

import httpx

DEFAULT_MJPEG_PORT = 8080
DEFAULT_MJPEG_SNAPSHOT_PATH = "/picture.jpg"
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class RTSPFrame:
    """Typed result for one single-frame RTSP capture attempt."""

    ok: bool
    image_bytes: bytes = b""
    error: str = ""


@dataclass(frozen=True, slots=True)
class JPEGSnapshot:
    """Typed result for one bounded direct JPEG request."""

    ok: bool
    image_bytes: bytes = b""
    error: str = ""
    error_kind: str = ""


def capture_mjpeg_snapshot(
    host: str,
    username: str,
    password: str,
    *,
    port: int = DEFAULT_MJPEG_PORT,
    path: str = DEFAULT_MJPEG_SNAPSHOT_PATH,
    timeout: float = 3.0,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> JPEGSnapshot:
    """Fetch Akuvox's documented MJPEG still with bounded Digest auth.

    The credential never enters the URL, exception text, or returned result.
    """
    normalized_host = host.strip()
    if (
        not normalized_host
        or "://" in normalized_host
        or any(character in normalized_host for character in "/@?#")
    ):
        raise ValueError("MJPEG host is invalid")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ValueError("MJPEG port is invalid")
    if not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError("MJPEG snapshot path is invalid")
    if not username.strip() or not password:
        raise ValueError("MJPEG credentials are incomplete")
    if timeout <= 0 or timeout > 30:
        raise ValueError("MJPEG timeout is invalid")
    if max_bytes < 1024:
        raise ValueError("MJPEG byte limit is invalid")

    url = httpx.URL(scheme="http", host=normalized_host, port=port, path=path)
    try:
        with (
            httpx.Client(
                auth=httpx.DigestAuth(username, password),
                timeout=timeout,
                follow_redirects=False,
            ) as client,
            client.stream("GET", url) as response,
        ):
            if response.status_code in {401, 403}:
                return JPEGSnapshot(
                    ok=False,
                    error="MJPEG authentication failed",
                    error_kind="authentication",
                )
            if response.status_code != 200:
                return JPEGSnapshot(
                    ok=False,
                    error="MJPEG snapshot request failed",
                    error_kind="http_error",
                )
            image = bytearray()
            for chunk in response.iter_bytes():
                image.extend(chunk)
                if len(image) > max_bytes:
                    return JPEGSnapshot(
                        ok=False,
                        error="MJPEG snapshot exceeds the size limit",
                        error_kind="image_too_large",
                    )
    except httpx.TimeoutException:
        return JPEGSnapshot(
            ok=False,
            error="MJPEG snapshot request timed out",
            error_kind="timeout",
        )
    except httpx.HTTPError:
        return JPEGSnapshot(
            ok=False,
            error="MJPEG snapshot request failed",
            error_kind="unavailable",
        )

    payload = bytes(image)
    if not payload.startswith(b"\xff\xd8") or not payload.endswith(b"\xff\xd9"):
        return JPEGSnapshot(
            ok=False,
            error="MJPEG snapshot response is not a JPEG",
            error_kind="invalid_image",
        )
    return JPEGSnapshot(ok=True, image_bytes=payload)


def capture_rtsp_frame(
    rtsp_url: str,
    *,
    timeout: int = 5,
) -> RTSPFrame:
    """Capture one JPEG frame with ffmpeg, never logging the URL or credentials."""
    timeout = max(1, min(timeout, 30))
    if not shutil.which("ffmpeg"):
        return RTSPFrame(ok=False, error="ffmpeg is not installed")
    # Feed the credential-bearing URL through an anonymous stdin pipe using
    # ffconcat.  Putting it directly after ``-i`` exposes it in the child
    # process argument vector and process-command telemetry.
    escaped_url = rtsp_url.replace("\\", "\\\\").replace("'", "\\'")
    playlist = f"ffconcat version 1.0\nfile '{escaped_url}'\n".encode()
    args = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-timeout",
        str(timeout * 1_000_000),
        "-f",
        "concat",
        "-safe",
        "0",
        "-protocol_whitelist",
        "file,pipe,rtsp,tcp,udp,http,https,tls,crypto",
        "-i",
        "pipe:0",
        "-frames:v",
        "1",
        "-f",
        "image2",
        "pipe:1",
    ]
    try:
        result = subprocess.run(
            args,
            input=playlist,
            capture_output=True,
            timeout=timeout + 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return RTSPFrame(ok=False, error="RTSP frame capture timed out")
    if result.returncode != 0 or not result.stdout:
        return RTSPFrame(ok=False, error="RTSP frame capture failed")
    return RTSPFrame(ok=True, image_bytes=result.stdout)
