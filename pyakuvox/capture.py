"""Bounded RTSP frame capture for Akuvox device-owned camera streams."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RTSPFrame:
    """Typed result for one single-frame RTSP capture attempt."""

    ok: bool
    image_bytes: bytes = b""
    error: str = ""


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
