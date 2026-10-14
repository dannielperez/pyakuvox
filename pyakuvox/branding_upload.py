"""Verified icon uploads for the audited legacy X916 FCGI firmware.

Artwork uploads never write key labels, actions, SIP accounts or dial numbers.
Other firmware must acquire its own tested adapter before writes are enabled.
"""

from __future__ import annotations

import asyncio
import hashlib
from io import BytesIO
from typing import TYPE_CHECKING, Any

from PIL import Image

from pyakuvox.clients.local.webui import WebUIClient
from pyakuvox.operations import read_device_info_with_auth_detection

if TYPE_CHECKING:
    from pyakuvox.config import LocalSettings

_ICON_DESTINATIONS = {
    "1": ("TempKey", "home_cloud_temp_key_bg.png"),
    "2": ("PIN", "home_cloud_passwd_bg.png"),
    "4": ("Contact", "home_cloud_contact_book_bg.png"),
    "5": ("SpeedDial", "home_cloud_leasing_bg.png"),
}
_PAGE = "id=130&id=19"


def _pixels(data: bytes) -> tuple[tuple[int, int], bytes]:
    if len(data) > 1024 * 1024:
        raise ValueError("Icon exceeds 1 MiB")
    with Image.open(BytesIO(data)) as image:
        if image.format != "PNG" or image.size != (218, 176):
            raise ValueError("Legacy X916 icons require 218x176 PNG artwork")
        return image.size, image.convert("RGBA").tobytes()


async def ensure_legacy_x916_icons(
    settings: LocalSettings,
    assets: dict[str, bytes],
    *,
    expected_mac: str,
    timeout_seconds: float = 45,
) -> dict[str, Any]:
    """Apply only icons for active actions; compare decoded pixels on readback.

    The caller supplies reviewed artwork indexed by button type. A matching
    live hardware identity and exact firmware are mandatory. Every operation is
    bounded by a total timeout; ambiguous writes must be reconciled by readback
    on the next invocation rather than retried blindly.
    """
    if not assets or not set(assets).issubset(_ICON_DESTINATIONS):
        raise ValueError("Unsupported or empty icon set")
    for asset in assets.values():
        _pixels(asset)
    async with asyncio.timeout(timeout_seconds):
        info = await read_device_info_with_auth_detection(settings)
        if info.identity.normalized_mac() != expected_mac.upper():
            raise ValueError("Hardware identity does not match inventory")
        if info.identity.model.upper() != "X916" or info.firmware_version != "916.30.10.114":
            return {"verdict": "unsupported-firmware", "verified": []}
        async with WebUIClient(
            host=settings.host,
            port=settings.port,
            use_ssl=settings.use_ssl,
            verify_ssl=settings.verify_ssl,
            timeout=5,
        ) as web:
            await web.login(settings.username, settings.password.get_secret_value())
            before = await web._read_page(_PAGE)
            protected = {
                key: value
                for key, value in before.items()
                if key.startswith("hcKey") or key in {"hcBuildingKeyNumber", "hcResidentTheme"}
            }
            if not all(f"hcKey{slot}Type" in before for slot in range(1, 7)):
                return {"verdict": "unsupported-layout", "verified": []}
            active = {before[f"hcKey{slot}Type"] for slot in range(1, 7)}
            selected = sorted(active.intersection(assets))
            if not selected:
                return {"verdict": "not-applicable", "verified": []}
            verified = []
            changed = False
            client = web._ensure_client()
            for key_type in selected:
                destination, filename = _ICON_DESTINATIONS[key_type]
                url = f"{web.base_url}/download/{destination}/{filename}"
                current = await web._get(url)
                expected = _pixels(assets[key_type])
                try:
                    matches = current.status_code == 200 and _pixels(current.content) == expected
                except (ValueError, OSError):
                    matches = False
                if not matches:
                    prepare = await web._get(
                        f"{web.base_url}/fcgi/do?{_PAGE}&Operation=GetDivContent&DivName=div{destination}"
                    )
                    prepare.raise_for_status()
                    response = await client.post(
                        f"{web.base_url}/fcgi/do?{_PAGE}",
                        data={
                            "uploadType": f"&Operation=Upload&DestUpFile={destination}&",
                            "cButtonType": key_type,
                        },
                        files={"importButtonIcon": ("icon.PNG", assets[key_type], "image/png")},
                    )
                    response.raise_for_status()
                    current = await web._get(url)
                    current.raise_for_status()
                    if _pixels(current.content) != expected:
                        raise ValueError("Uploaded icon readback did not match")
                    changed = True
                verified.append(
                    {"type": key_type, "sha256": hashlib.sha256(assets[key_type]).hexdigest()}
                )
            after = await web._read_page(_PAGE)
            if any(after.get(key) != value for key, value in protected.items()):
                raise ValueError("Functional key settings changed during artwork upload")
            return {"verdict": "set-verified" if changed else "already-set", "verified": verified}
