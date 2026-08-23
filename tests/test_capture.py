from unittest.mock import patch

import httpx
import pytest

from pyakuvox.capture import (
    DOCUMENTED_MJPEG_SNAPSHOT_PATHS,
    capture_mjpeg_snapshot,
    capture_rtsp_frame,
)

_HTTPX_CLIENT = httpx.Client


def _clock(*readings):
    """A monotonic stub that yields ``readings`` then holds the last value."""
    remaining = list(readings)

    def monotonic():
        return remaining.pop(0) if len(remaining) > 1 else remaining[0]

    return monotonic


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


def test_capture_mjpeg_snapshot_bounds_digest_and_drip_feed_to_one_deadline():
    class DripFeed(httpx.SyncByteStream):
        def __iter__(self):
            yield b"\xff\xd8"
            yield b"jpeg"
            yield b"\xff\xd9"

    observed_options = {}

    def client(**options):
        observed_options.update(options)
        return _HTTPX_CLIENT(
            transport=_transport(
                lambda _request: httpx.Response(200, stream=DripFeed()),
            ),
            **options,
        )

    with (
        patch("pyakuvox.capture.httpx.Client", side_effect=client),
        patch(
            "pyakuvox.capture.time.monotonic",
            new=_clock(100.0, 100.1, 100.2, 100.3, 102.0),
        ),
    ):
        result = capture_mjpeg_snapshot(
            "camera.local",
            "user",
            "secret",
            timeout=1,
        )

    assert result.error_kind == "timeout"
    assert observed_options["timeout"] == 0.125


# ---------------------------------------------------------------------------
# Bounded documented-path negotiation
# ---------------------------------------------------------------------------


def test_negotiation_advances_only_past_a_path_the_device_does_not_serve():
    requested = []

    def handler(request):
        requested.append(request.url.path)
        if request.url.path == "/jpeg.cgi":
            return httpx.Response(200, content=b"\xff\xd8jpeg\xff\xd9")
        return httpx.Response(404)

    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(handler),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot("192.0.2.10", "user", "secret")

    assert result.ok is True
    assert result.path_used == "/jpeg.cgi"
    assert requested == list(DOCUMENTED_MJPEG_SNAPSHOT_PATHS)
    assert "secret" not in repr(result)


def test_negotiation_only_ever_requests_documented_paths():
    requested = []

    def handler(request):
        requested.append(request.url.path)
        return httpx.Response(404)

    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(handler),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot("192.0.2.10", "user", "secret")

    assert set(requested) <= set(DOCUMENTED_MJPEG_SNAPSHOT_PATHS)
    assert result.ok is False
    assert result.error_kind == "http_error"


@pytest.mark.parametrize(
    ("status", "error_kind"),
    [(401, "authentication"), (403, "authentication"), (500, "http_error")],
)
def test_a_device_level_failure_stops_negotiation_immediately(status, error_kind):
    """Only "path not served" advances; anything else must not amplify."""
    requested = []

    def handler(request):
        requested.append(request.url.path)
        return httpx.Response(status)

    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(handler),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot("192.0.2.10", "user", "secret")

    assert result.error_kind == error_kind
    assert requested == ["/picture.jpg"]


def test_a_timeout_stops_negotiation_immediately():
    requested = []

    def handler(request):
        requested.append(request.url.path)
        raise httpx.ReadTimeout("timed out")

    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(handler),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot("192.0.2.10", "user", "secret")

    assert result.error_kind == "timeout"
    assert requested == ["/picture.jpg"]


def test_a_non_jpeg_body_stops_negotiation_immediately():
    requested = []

    def handler(request):
        requested.append(request.url.path)
        return httpx.Response(200, content=b"<html>login</html>")

    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(handler),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot("192.0.2.10", "user", "secret")

    assert result.error_kind == "invalid_image"
    assert requested == ["/picture.jpg"]


def test_negotiation_shares_one_deadline_across_every_attempt():
    """The budget is the whole call, not per path."""
    requested = []

    def handler(request):
        requested.append(request.url.path)
        return httpx.Response(404)

    with (
        patch(
            "pyakuvox.capture.httpx.Client",
            side_effect=lambda **options: _HTTPX_CLIENT(
                transport=_transport(handler),
                **options,
            ),
        ),
        # Budget is spent after the first attempt; the rest must not run.
        patch("pyakuvox.capture.time.monotonic", new=_clock(100.0, 100.1, 100.2, 200.0)),
    ):
        result = capture_mjpeg_snapshot("192.0.2.10", "user", "secret", timeout=1)

    assert result.error_kind == "timeout"
    assert requested == ["/picture.jpg"]


def test_negotiation_reuses_one_client_for_every_attempt():
    clients = []

    def handler(request):
        return httpx.Response(
            404 if request.url.path != "/jpeg.cgi" else 200, content=b"\xff\xd8jpeg\xff\xd9"
        )

    def client(**options):
        made = _HTTPX_CLIENT(transport=_transport(handler), **options)
        clients.append(made)
        return made

    with patch("pyakuvox.capture.httpx.Client", side_effect=client):
        result = capture_mjpeg_snapshot("192.0.2.10", "user", "secret")

    assert result.ok is True
    assert len(clients) == 1


def test_an_explicit_path_pins_it_and_disables_negotiation():
    requested = []

    def handler(request):
        requested.append(request.url.path)
        return httpx.Response(404)

    with patch(
        "pyakuvox.capture.httpx.Client",
        side_effect=lambda **options: _HTTPX_CLIENT(
            transport=_transport(handler),
            **options,
        ),
    ):
        result = capture_mjpeg_snapshot(
            "192.0.2.10",
            "user",
            "secret",
            path="/picture.cgi",
        )

    assert requested == ["/picture.cgi"]
    assert result.ok is False


def test_an_undocumented_explicit_path_is_still_rejected():
    with pytest.raises(ValueError, match="path is invalid"):
        capture_mjpeg_snapshot("192.0.2.10", "user", "secret", path="picture.jpg")
