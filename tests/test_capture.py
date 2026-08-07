from unittest.mock import patch

from pyakuvox.capture import capture_rtsp_frame


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
