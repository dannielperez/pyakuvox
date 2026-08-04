from pyakuvox.rtsp import RTSPStreamConfig, build_rtsp_url


def test_builds_default_akuvox_stream_url_without_credentials():
    assert build_rtsp_url(RTSPStreamConfig(host="192.0.2.10")) == (
        "rtsp://192.0.2.10:554/live/ch00_0"
    )


def test_quotes_rtsp_credentials_and_preserves_custom_path():
    url = build_rtsp_url(
        RTSPStreamConfig(
            host="192.0.2.10",
            username="rtsp user",
            password="p@ss/word",
            port=8554,
            path="live/ch00_1",
        ),
    )
    assert url == "rtsp://rtsp%20user:p%40ss%2Fword@192.0.2.10:8554/live/ch00_1"
