from io import BytesIO
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from PIL import Image

from pyakuvox.branding_upload import ensure_legacy_x916_icons
from pyakuvox.config import LocalSettings


def artwork():
    buffer = BytesIO()
    Image.new("RGB", (218, 176), "purple").save(buffer, "PNG")
    return buffer.getvalue()


def info(firmware="916.30.10.114", mac="00:11:22:33:44:55"):
    return SimpleNamespace(
        identity=SimpleNamespace(model="X916", normalized_mac=lambda: mac),
        firmware_version=firmware,
    )


@pytest.mark.asyncio
async def test_wrong_hardware_refuses_before_web_login():
    with (
        patch(
            "pyakuvox.branding_upload.read_device_info_with_auth_detection",
            AsyncMock(return_value=info()),
        ),
        pytest.raises(ValueError, match="identity"),
    ):
        await ensure_legacy_x916_icons(
            LocalSettings(host="192.0.2.1"), {"2": artwork()}, expected_mac="different"
        )


@pytest.mark.asyncio
async def test_unknown_firmware_is_explicitly_unsupported():
    with patch(
        "pyakuvox.branding_upload.read_device_info_with_auth_detection",
        AsyncMock(return_value=info("new")),
    ):
        result = await ensure_legacy_x916_icons(
            LocalSettings(host="192.0.2.1"), {"2": artwork()}, expected_mac="00:11:22:33:44:55"
        )
    assert result["verdict"] == "unsupported-firmware"


@pytest.mark.asyncio
@pytest.mark.parametrize("existing", [True, False])
async def test_readback_and_idempotence_preserve_actions(existing):
    data = artwork()
    fields = {f"hcKey{i}Type": "2" if i == 2 else "0" for i in range(1, 7)}
    fields["hcKey1Number"] = "99"
    web = MagicMock()
    web.base_url = "https://192.0.2.1"
    web.login = AsyncMock()
    web._read_page = AsyncMock(return_value=fields)
    good = httpx.Response(200, content=data, request=httpx.Request("GET", "https://192.0.2.1"))
    missing = httpx.Response(404, request=httpx.Request("GET", "https://192.0.2.1"))
    web._get = AsyncMock(side_effect=[good] if existing else [missing, good, good])
    web._ensure_client.return_value.post = AsyncMock(return_value=good)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=web)
    context.__aexit__ = AsyncMock(return_value=None)
    with (
        patch(
            "pyakuvox.branding_upload.read_device_info_with_auth_detection",
            AsyncMock(return_value=info()),
        ),
        patch("pyakuvox.branding_upload.WebUIClient", return_value=context),
    ):
        result = await ensure_legacy_x916_icons(
            LocalSettings(host="192.0.2.1"), {"2": data}, expected_mac="00:11:22:33:44:55"
        )
    assert result["verdict"] == ("already-set" if existing else "set-verified")
    assert web._ensure_client.return_value.post.await_count == (0 if existing else 1)
    assert result["verified"][0]["type"] == "2"


@pytest.mark.asyncio
async def test_invalid_image_never_connects():
    with patch(
        "pyakuvox.branding_upload.read_device_info_with_auth_detection", AsyncMock()
    ) as read:
        with pytest.raises(OSError):
            await ensure_legacy_x916_icons(
                LocalSettings(host="192.0.2.1"), {"2": b"bad"}, expected_mac="00:11:22:33:44:55"
            )
        read.assert_not_called()
