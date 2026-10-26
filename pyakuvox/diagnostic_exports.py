"""Bounded authenticated diagnostic exports from observed FCGI and SPA controls.

Binary artifacts may contain private data. Callers own encrypted storage,
access control and retention. Neither artifact content nor credentials are logged.
"""

from __future__ import annotations

import asyncio
import hashlib
import tarfile
import zlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from io import BytesIO
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from pyakuvox.clients.local.webapi import WebApiClient
from pyakuvox.clients.local.webui import WebUIClient
from pyakuvox.exceptions import DeviceError, UnsupportedFeatureError
from pyakuvox.operations import read_device_info_with_auth_detection

if TYPE_CHECKING:
    from pyakuvox.config import LocalSettings

PAGE = "id=6&id=2"
MAX_BYTES = 8 * 1024 * 1024


class DiagnosticExportBusyError(DeviceError):
    """Firmware refused diagnostic export while reporting a call in progress.

    This is an export refusal, not independent proof of an active SIP call.
    """


@dataclass(frozen=True)
class DiagnosticArtifact:
    kind: str
    mac: str
    model: str
    firmware: str
    sha256: str
    data: bytes = field(repr=False)


class _Inputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        row = dict(attrs)
        if tag == "input" and row.get("id"):
            self.values[row["id"]] = row.get("value") or ""


def export_path(html: str, operation: str) -> str:
    """Accept only the exact operation's hidden same-device download path."""
    parser = _Inputs()
    parser.feed(html)
    path = parser.values.get(f"hc{operation}_Div", "")
    return _safe_download_path(path)


def _safe_download_path(path: str) -> str:
    parsed = urlsplit(path)
    decoded = unquote(path)
    if (
        not path.startswith("/download/")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or ".." in decoded
        or "\\" in decoded
        or "%" in decoded
        or any(ord(c) < 33 or ord(c) > 126 for c in path)
    ):
        raise ValueError("No safe diagnostic download path was returned")
    return path


async def export_system_log(
    settings: LocalSettings,
    *,
    expected_mac: str,
    max_bytes: int = 1024 * 1024,
    timeout_seconds: float = 25,
) -> DiagnosticArtifact:
    """Export current logs without changing log level or enabling remote logging.

    Observed R29 FCGI and S539 SPA layouts are supported. No fallback URL guessing,
    configuration export, trace start or retry is performed.
    """
    if not 1 <= max_bytes <= MAX_BYTES or not 1 <= timeout_seconds <= 60:
        raise ValueError("Invalid diagnostic bounds")
    if not expected_mac:
        raise ValueError("Expected hardware identity is required")
    async with asyncio.timeout(timeout_seconds):
        info = await read_device_info_with_auth_detection(settings)
        mac = info.identity.normalized_mac()
        if mac != expected_mac.upper():
            raise ValueError("Hardware identity does not match")
        if info.identity.model.upper() == "S539":
            if info.firmware_version != "539.30.10.523":
                raise UnsupportedFeatureError("system_log_export", "unverified S539 firmware")
            return await _export_spa_system_log(settings, info, mac, max_bytes)
        if info.identity.model.upper() not in {"R29", "R29C", "R29S", "R29F"}:
            raise UnsupportedFeatureError("system_log_export", info.identity.model)
        async with WebUIClient(
            settings.host,
            port=settings.port,
            use_ssl=settings.use_ssl,
            verify_ssl=settings.verify_ssl,
            timeout=5,
        ) as web:
            await web.login(settings.username, settings.password.get_secret_value())
            page = await web._get(f"{web.base_url}/fcgi/do?{PAGE}")
            if page.status_code != 200 or 'id="BtnExportLog"' not in page.text:
                # FCGI also emits single-quoted and unquoted HTML attributes.
                controls = _Inputs()
                controls.feed(page.text)
                if page.status_code != 200 or "BtnExportLog" not in controls.values:
                    raise UnsupportedFeatureError("system_log_export", info.identity.model)
            response = await web._get(
                f"{web.base_url}/fcgi/do?{PAGE}&Operation=GetDivContent&DivName=divExportLog"
            )
            if response.status_code != 200:
                raise ValueError("Diagnostic export failed")
            path = export_path(response.text, "ExportLog")
            data = bytearray()
            async with web._ensure_client().stream(
                "GET", web.base_url + path, follow_redirects=False
            ) as download:
                if download.status_code != 200:
                    raise ValueError("Diagnostic download failed")
                async for chunk in download.aiter_bytes():
                    if len(data) + len(chunk) > max_bytes:
                        raise ValueError("Diagnostic artifact exceeds size limit")
                    data.extend(chunk)
            _validate_log_archive(data)
            after = await read_device_info_with_auth_detection(settings)
            if after.identity.normalized_mac() != mac:
                raise ValueError("Hardware identity changed during diagnostic export")
            payload = bytes(data)
            return DiagnosticArtifact(
                kind="system_log",
                mac=mac,
                model=info.identity.model,
                firmware=info.firmware_version or "",
                data=payload,
                sha256=hashlib.sha256(payload).hexdigest(),
            )


def _validate_log_archive(data):
    if data.startswith(b"\x1f\x8b"):
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            inflater.decompress(bytes(data), 16 * 1024 * 1024)
        except zlib.error as exc:
            raise ValueError("Invalid gzip log archive") from exc
        if not inflater.eof or inflater.unused_data:
            raise ValueError("Truncated or oversized expanded log archive")
    elif data[257:262] == b"ustar":
        # Some R29 firmware returns plain TAR with a .tgz filename.
        # Validate headers and bounds, never extract archive members.
        try:
            with tarfile.open(fileobj=BytesIO(data), mode="r:") as archive:
                count = 0
                for member in archive:
                    count += 1
                    if (
                        count > 1024
                        or member.size < 0
                        or member.offset_data + member.size > len(data)
                    ):
                        raise ValueError("Invalid or oversized TAR log archive")
                if not count:
                    raise ValueError("Empty TAR log archive")
        except tarfile.TarError as exc:
            raise ValueError("Invalid TAR log archive") from exc
    else:
        raise ValueError("Expected a log archive, not an HTML/login response")


async def _export_spa_system_log(settings, info, mac, max_bytes):
    """S539 maintenance export; never export configuration or user data."""
    async with WebApiClient(
        settings.host,
        port=settings.port,
        use_ssl=settings.use_ssl,
        verify_ssl=settings.verify_ssl,
        timeout=5,
    ) as web:
        await web.login(
            settings.username, settings.password.get_secret_value(), encoding="cryptojs_aes"
        )
        response = await web._post(
            "/api/web/upgrade_advance/export",
            {"target": "upgrade_advance", "action": "export", "data": {"type": "systemlog"}},
        )
        if response.status_code != 200:
            raise ValueError("Diagnostic export failed")
        body = response.json()
        if isinstance(body, dict) and body.get("retcode") == -101:
            raise DiagnosticExportBusyError("Device reports a call in progress; export refused")
        if (
            not isinstance(body, dict)
            or type(body.get("retcode")) is not int
            or body["retcode"] != 0
        ):
            raise ValueError("Diagnostic export was not successful")
        result = body.get("data")
        path = result.get("url") if isinstance(result, dict) else None
        if not isinstance(path, str):
            raise ValueError("Diagnostic export has no download path")
        path = _safe_download_path(path)
        data = bytearray()
        async with web._ensure_client().stream(
            "GET",
            web.base_url + path,
            follow_redirects=False,
        ) as download:
            if download.status_code != 200:
                raise ValueError("Diagnostic download failed")
            async for chunk in download.aiter_bytes():
                if len(data) + len(chunk) > max_bytes:
                    raise ValueError("Diagnostic artifact exceeds size limit")
                data.extend(chunk)
        _validate_log_archive(data)
        after = await read_device_info_with_auth_detection(settings)
        if after.identity.normalized_mac() != mac:
            raise ValueError("Hardware identity changed during diagnostic export")
        payload = bytes(data)
        return DiagnosticArtifact(
            kind="system_log",
            mac=mac,
            model=info.identity.model,
            firmware=info.firmware_version or "",
            data=payload,
            sha256=hashlib.sha256(payload).hexdigest(),
        )
