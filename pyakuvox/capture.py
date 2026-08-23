"""Bounded RTSP frame capture for Akuvox device-owned camera streams."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass

import httpx

DEFAULT_MJPEG_PORT = 8080
DEFAULT_MJPEG_SNAPSHOT_PATH = "/picture.jpg"
# The three still-image paths Akuvox documents for the MJPEG service. Firmware
# families disagree about which one they serve, so a caller that does not pin a
# path gets them tried in documented order. This tuple is a CLOSED allowlist:
# nothing outside it is ever requested during negotiation.
DOCUMENTED_MJPEG_SNAPSHOT_PATHS = ("/picture.jpg", "/picture.cgi", "/jpeg.cgi")
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
_DIGEST_HTTP_PHASES = 8
# Statuses that mean "this device does not serve THIS path" — the only signal
# that advances negotiation. Every other outcome (auth rejected, timeout,
# non-JPEG body, oversize, transport error) is a property of the device or the
# network, not of the path, and terminates immediately. That distinction is
# what keeps negotiation from becoming retry amplification.
_PATH_NOT_SERVED_STATUSES = frozenset({404, 405, 501})


@dataclass(frozen=True, slots=True)
class RTSPFrame:
    """Typed result for one single-frame RTSP capture attempt."""

    ok: bool
    image_bytes: bytes = b""
    error: str = ""


@dataclass(frozen=True, slots=True)
class JPEGSnapshot:
    """Typed result for one bounded direct JPEG request.

    ``path_used`` names the documented path that produced this result. It is
    one of :data:`DOCUMENTED_MJPEG_SNAPSHOT_PATHS` (or the caller's pinned
    path) and never carries a credential, a host, or a rendered URL.
    """

    ok: bool
    image_bytes: bytes = b""
    error: str = ""
    error_kind: str = ""
    path_used: str = ""


def capture_mjpeg_snapshot(
    host: str,
    username: str,
    password: str,
    *,
    port: int = DEFAULT_MJPEG_PORT,
    path: str | None = None,
    timeout: float = 3.0,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> JPEGSnapshot:
    """Fetch Akuvox's documented MJPEG still with bounded Digest auth.

    ``path=None`` (the default) negotiates across
    :data:`DOCUMENTED_MJPEG_SNAPSHOT_PATHS` in documented order, because
    firmware families disagree about which one they serve. Passing an explicit
    ``path`` pins that single path and disables negotiation.

    Negotiation is bounded, not a retry loop:

    * ``timeout`` is ONE total monotonic deadline for the whole call, however
      many paths get tried — it is not a per-attempt budget;
    * only a "path not served" status (404/405/501) advances to the next path;
      an authentication rejection, a timeout, a non-JPEG body, an oversize
      body, or a transport error returns immediately;
    * only paths in the closed documented allowlist are ever requested;
    * every attempt shares ONE client, so a second path costs a request, not a
      fresh connection and Digest handshake.

    A successful path is deliberately NOT cached: the process holds no device
    identity to key it on and no signal that would invalidate it after a
    firmware change, so a stale cache would pin a device to a path it stopped
    serving. The cost of not caching is one extra request on devices that do
    not serve the first documented path.

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
    if path is None:
        paths = DOCUMENTED_MJPEG_SNAPSHOT_PATHS
    else:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("MJPEG snapshot path is invalid")
        paths = (path,)
    if not username.strip() or not password:
        raise ValueError("MJPEG credentials are incomplete")
    if timeout <= 0 or timeout > 30:
        raise ValueError("MJPEG timeout is invalid")
    if max_bytes < 1024:
        raise ValueError("MJPEG byte limit is invalid")

    # ONE deadline for the whole call. HTTPX deadlines are per network
    # operation, not whole-call deadlines, and a Digest exchange can perform
    # two requests (pool/connect/write/read, then pool/write/read) before the
    # streamed body read — so each attempt derives its per-operation slice from
    # what is LEFT of this deadline, and the monotonic checks stop a peer that
    # drip-feeds chunks from extending the call indefinitely.
    deadline = time.monotonic() + timeout
    attempted = ""
    with httpx.Client(
        auth=httpx.DigestAuth(username, password),
        timeout=max(0.001, timeout / _DIGEST_HTTP_PHASES),
        follow_redirects=False,
    ) as client:
        for candidate in paths:
            attempted = candidate
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _mjpeg_timeout(candidate)
            result = _attempt_mjpeg_snapshot(
                client,
                host=normalized_host,
                port=port,
                path=candidate,
                deadline=deadline,
                remaining=remaining,
                max_bytes=max_bytes,
            )
            if result is not None:
                return result
    # Every documented path answered "not served".
    return JPEGSnapshot(
        ok=False,
        error="MJPEG snapshot path is not served by this device",
        error_kind="http_error",
        path_used=attempted,
    )


def _attempt_mjpeg_snapshot(
    client: httpx.Client,
    *,
    host: str,
    port: int,
    path: str,
    deadline: float,
    remaining: float,
    max_bytes: int,
) -> JPEGSnapshot | None:
    """Try one documented path. ``None`` means "not served — try the next"."""
    operation_timeout = max(0.001, remaining / _DIGEST_HTTP_PHASES)
    content_deadline = min(deadline, time.monotonic() + remaining - operation_timeout)
    url = httpx.URL(scheme="http", host=host, port=port, path=path)
    try:
        with client.stream("GET", url, timeout=operation_timeout) as response:
            if time.monotonic() >= content_deadline:
                return _mjpeg_timeout(path)
            if response.status_code in {401, 403}:
                return JPEGSnapshot(
                    ok=False,
                    error="MJPEG authentication failed",
                    error_kind="authentication",
                    path_used=path,
                )
            if response.status_code in _PATH_NOT_SERVED_STATUSES:
                return None
            if response.status_code != 200:
                return JPEGSnapshot(
                    ok=False,
                    error="MJPEG snapshot request failed",
                    error_kind="http_error",
                    path_used=path,
                )
            image = bytearray()
            for chunk in response.iter_bytes():
                if time.monotonic() >= content_deadline:
                    return _mjpeg_timeout(path)
                image.extend(chunk)
                if len(image) > max_bytes:
                    return JPEGSnapshot(
                        ok=False,
                        error="MJPEG snapshot exceeds the size limit",
                        error_kind="image_too_large",
                        path_used=path,
                    )
    except httpx.TimeoutException:
        return _mjpeg_timeout(path)
    except httpx.HTTPError:
        return JPEGSnapshot(
            ok=False,
            error="MJPEG snapshot request failed",
            error_kind="unavailable",
            path_used=path,
        )

    payload = bytes(image)
    if not payload.startswith(b"\xff\xd8") or not payload.endswith(b"\xff\xd9"):
        return JPEGSnapshot(
            ok=False,
            error="MJPEG snapshot response is not a JPEG",
            error_kind="invalid_image",
            path_used=path,
        )
    return JPEGSnapshot(ok=True, image_bytes=payload, path_used=path)


def _mjpeg_timeout(path: str = "") -> JPEGSnapshot:
    return JPEGSnapshot(
        ok=False,
        error="MJPEG snapshot request timed out",
        error_kind="timeout",
        path_used=path,
    )


def capture_rtsp_frame(
    rtsp_url: str,
    *,
    timeout: float = 5,
    total_timeout: float | None = None,
) -> RTSPFrame:
    """Capture one JPEG frame with ffmpeg, never logging the URL or credentials.

    ``timeout`` bounds ffmpeg's RTSP network wait. ``total_timeout`` optionally
    caps the entire child-process call, including ffmpeg startup and cleanup, so
    an orchestration layer can fit the capture inside its own monotonic budget.
    Omitting it preserves the historical ``timeout + 5`` process allowance.
    """
    timeout = max(0.001, min(float(timeout), 30.0))
    if total_timeout is None:
        process_timeout = timeout + 5.0
    else:
        total_timeout = float(total_timeout)
        if total_timeout <= 0 or total_timeout > 60:
            raise ValueError("RTSP total timeout is invalid")
        process_timeout = total_timeout
        timeout = min(timeout, total_timeout)
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
        str(int(timeout * 1_000_000)),
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
            timeout=process_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return RTSPFrame(ok=False, error="RTSP frame capture timed out")
    if result.returncode != 0 or not result.stdout:
        return RTSPFrame(ok=False, error="RTSP frame capture failed")
    return RTSPFrame(ok=True, image_bytes=result.stdout)
