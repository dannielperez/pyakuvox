from unittest.mock import patch

import httpx
import pytest

from pyakuvox.capture import capture_mjpeg_snapshot, capture_rtsp_frame

_HTTPX_CLIENT = httpx.Client


def test_capture_rtsp_frame_returns_jpeg_bytes():
    completed = type("Completed", (), {"returncode": 0, "stdout": b"jpeg"})()
    with (
        patch("pyakuvox.capture.shutil.which", return_value="/usr/bin/ffmpeg"),
        patch("pyakuvox.capture.subprocess.run", return_value=completed) as run,
    ):
        result = capture_rtsp_frame("rtsp://user:pass@example.invalid/live/ch00_0")

    assert result.ok is True
    assert result.image_bytes == b"jpeg"
    assert run.call_args.kwargs["timeout"] == 10
    assert "user" not in repr(run.call_args.args[0])
    assert "pass" not in repr(run.call_args.args[0])
    assert "example.invalid" not in repr(run.call_args.args[0])
    assert run.call_args.kwargs["input"].startswith(b"ffconcat version 1.0")


def test_capture_rtsp_frame_degrades_when_ffmpeg_is_missing():
    with patch("pyakuvox.capture.shutil.which", return_value=None):
        result = capture_rtsp_frame("rtsp://example.invalid/live/ch00_0")

    assert result.ok is False
    assert result.error == "ffmpeg is not installed"


def _transport(handler):
    return httpx.MockTransport(handler)


def test_capture_mjpeg_snapshot_uses_digest_auth_without_url_credentials():
    requests = []

    def handler(request):
        requests.append(request)
        if "authorization" not in request.headers:
            return httpx.Response(
                401,
                headers={"www-authenticate": 'Digest realm="camera", nonce="abc", qop="auth"'},
            )
        return httpx.Response(200, content=b"\xff\xd8jpeg\xff\xd9")

    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(handler),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot(
            "192.0.2.10",
            "media-user",
            "media-secret",
        )

    assert result.ok is True
    assert result.image_bytes == b"\xff\xd8jpeg\xff\xd9"
    assert len(requests) == 2
    assert requests[-1].url == httpx.URL("http://192.0.2.10:8080/picture.jpg")
    assert "media-user" not in str(requests[-1].url)
    assert "media-secret" not in repr(result)


@pytest.mark.parametrize("status", [401, 403])
def test_capture_mjpeg_snapshot_classifies_authentication(status):
    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(lambda _request: httpx.Response(status)),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot("camera.local", "user", "secret")

    assert result.ok is False
    assert result.error_kind == "authentication"
    assert "secret" not in repr(result)


def test_capture_mjpeg_snapshot_bounds_response_bytes():
    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(
                lambda _request: httpx.Response(200, content=b"\xff\xd8" + b"x" * 2048),
            ),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot(
            "camera.local",
            "user",
            "secret",
            max_bytes=1024,
        )

    assert result.error_kind == "image_too_large"


def test_capture_mjpeg_snapshot_rejects_non_jpeg_response():
    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(lambda _request: httpx.Response(200, content=b"not jpeg")),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot("camera.local", "user", "secret")

    assert result.error_kind == "invalid_image"


def test_capture_mjpeg_snapshot_maps_timeout_without_credentials():
    def timeout(_request):
        raise httpx.ReadTimeout("timed out")

    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(timeout),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot("camera.local", "user", "secret")

    assert result.error_kind == "timeout"
    assert "secret" not in repr(result)
