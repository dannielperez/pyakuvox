"""Unauthenticated Akuvox device identification.

The single most useful primitive when managing many devices: given an IP, work out *which
API dialect the firmware speaks* and (where the firmware leaks it) its model
and firmware version — **without logging in**. Every higher-level operation
(connect, configure, audit) should start here so it talks to the device the
right way instead of guessing.

Why this matters: Akuvox firmware ships at least three mutually-incompatible
local HTTP API dialects, and the *same* request (``GET /api/system/info``)
returns a different status code on each. This was validated against real hardware:

    GET /api/system/info  (no auth)        ->  dialect
    ─────────────────────────────────────────────────────────────────
    401 + WWW-Authenticate realm="HTTP API"  ->  DIGEST_API   (old /api/* digest)
    200 + JSON {retcode:0,...}               ->  DIGEST_API   (auth mode = None)
    308 / 30x redirect                       ->  WEB_API      (SPA S5xx/R29C, /api/web/*)
    403                                       ->  LEGACY_WEB   (E18C /web/*)  *or*
                                                  DIGEST_API blocked by an empty
                                                  WhiteList auth mode (flip to Digest)

For WEB_API the model+firmware are then readable, still unauthenticated, from
``GET /api/web/system/info``; for LEGACY_WEB the product name from
``GET /web/status/get?session=&web=1``.

Server header alone does NOT classify — ``EasyHttpServer`` appears on both the
digest-401 and SPA-308 families. The status code on ``/api/system/info`` is the
reliable discriminator.
"""

from __future__ import annotations

import asyncio
import json
import ssl
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx
import structlog
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

_JSON = json.JSONDecoder()


class ApiDialect(StrEnum):
    """How a device's local HTTP API must be spoken to."""

    DIGEST_API = "digest_api"  # /api/* HTTP Digest (LocalClient drives this headlessly)
    WEB_API = "web_api"  # /api/web/* token login (SPA S5xx/R29C — JS-hashed login)
    LEGACY_WEB = "legacy_web"  # /web/* token login (E18C — JS-hashed login)
    FCGI_WEB = "fcgi_web"  # /fcgi/do session (X916/older R29C — see WebUIClient)
    UNKNOWN = "unknown"


class SIPStatusSource(StrEnum):
    """Firmware surface used to read SIP registration state."""

    FCGI_WEB = "fcgi_web"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class DeviceProfile:
    """Model-selected local management behavior.

    Runtime probes still detect firmware details such as AES login. The model
    profile only selects stable routing decisions so applications do not need
    to know which scheme, port, UI, or status page a model uses.
    """

    family: str
    dialect: ApiDialect
    web_endpoints: tuple[tuple[str, int], ...] = ()
    config_password_encodings: tuple[str, ...] = ()
    sip_status_source: SIPStatusSource = SIPStatusSource.UNSUPPORTED


_UNKNOWN_PROFILE = DeviceProfile(family="unknown", dialect=ApiDialect.UNKNOWN)

# Prefix match (case-insensitive); first hit wins, so longer prefixes come first.
_MODEL_PROFILES: list[tuple[str, DeviceProfile]] = [
    ("S5", DeviceProfile("S5", ApiDialect.WEB_API, (("https", 443),))),
    ("R29C", DeviceProfile("R29C", ApiDialect.WEB_API, (("http", 80), ("https", 443)))),
    ("E18", DeviceProfile("E18", ApiDialect.LEGACY_WEB, (("http", 80),))),
    (
        "X916",
        DeviceProfile(
            "X916",
            ApiDialect.FCGI_WEB,
            (("https", 443),),
            ("x916", "r29c"),
            SIPStatusSource.FCGI_WEB,
        ),
    ),
    ("R29", DeviceProfile("R29", ApiDialect.DIGEST_API, (("http", 80),))),
    ("R27", DeviceProfile("R27", ApiDialect.DIGEST_API, (("http", 80),))),
    ("A05", DeviceProfile("A05", ApiDialect.DIGEST_API, (("http", 80),))),
]


def profile_for_model(model: str | None) -> DeviceProfile:
    """Return the immutable execution profile for a model string."""
    if not model:
        return _UNKNOWN_PROFILE
    normalized = model.strip().upper()
    for prefix, profile in _MODEL_PROFILES:
        if normalized.startswith(prefix):
            return profile
    return _UNKNOWN_PROFILE


def dialect_for_model(model: str | None) -> ApiDialect:
    """Best-effort dialect from a model string (e.g. 'S539', 'E18C')."""
    return profile_for_model(model).dialect


class DeviceIdentity(BaseModel):
    """Result of an unauthenticated identification probe."""

    host: str
    port: int = 80
    reachable: bool = False
    dialect: ApiDialect = ApiDialect.UNKNOWN
    model: str = ""
    firmware: str = ""
    hardware: str = ""
    server: str = ""
    http_status: int | None = None  # status of the primary /api/system/info probe
    model_source: str = ""  # which endpoint yielded model/fw ("" = none, needs login)
    note: str = ""

    @property
    def profile(self) -> DeviceProfile:
        """Model-driven management profile for this identity."""
        return profile_for_model(self.model)

    @property
    def headless_manageable(self) -> bool:
        """True if pyakuvox can drive config get/set without a browser.

        Only DIGEST_API qualifies today (WEB_API/LEGACY_WEB hash their login
        in browser JS). Note: an E18C whose HTTP API has been flipped to Digest
        reports as DIGEST_API here and IS manageable.
        """
        return self.dialect == ApiDialect.DIGEST_API

    @property
    def needs_login_for_model(self) -> bool:
        return self.reachable and not self.model and self.dialect == ApiDialect.DIGEST_API


def _legacy_ctx() -> ssl.SSLContext:
    """Permissive TLS context — old Akuvox firmware negotiates weak DH/ciphers."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with suppress(ValueError, AttributeError):
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with suppress(ssl.SSLError):
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    return ctx


def _parse_status_block(text: str) -> dict[str, Any]:
    """Pull the ``data.Status`` block from an Akuvox JSON body.

    Tolerates trailing bytes after the JSON and non-UTF8 content (E18C serves
    a body the stdlib can't always decode as UTF-8).
    """
    text = (text or "").lstrip()
    if not text.startswith("{"):
        return {}
    try:
        obj, _ = _JSON.raw_decode(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(obj, dict):
        return {}
    data = obj.get("data") if isinstance(obj.get("data"), dict) else obj
    status = data.get("Status") if isinstance(data, dict) else None
    return status if isinstance(status, dict) else (data if isinstance(data, dict) else {})


async def _get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        return await client.get(url)
    except (httpx.HTTPError, ssl.SSLError, OSError):
        return None


async def _probe_web_api(client: httpx.AsyncClient, host: str) -> tuple[str, str, str] | None:
    """SPA /api/web/system/info → (model, firmware, hardware), no auth."""
    for scheme in ("https", "http"):
        r = await _get(client, f"{scheme}://{host}/api/web/system/info")
        if r is not None and r.status_code == 200:
            s = _parse_status_block(r.text)
            if s.get("Model"):
                return (
                    s.get("Model", ""),
                    s.get("FirmwareVersion", ""),
                    s.get("HardwareVersion", ""),
                )
    return None


async def _probe_fcgi_web(client: httpx.AsyncClient, host: str) -> bool:
    """Return whether the panel exposes the legacy FCGI login nonce.

    Some R29/X916 firmware redirects every HTTP request to HTTPS with 308.  A
    redirect alone therefore cannot distinguish the Vue SPA from the older
    ``/fcgi/do`` UI.
    """
    for scheme in ("https", "http"):
        r = await _get(client, f"{scheme}://{host}/fcgi/do?action=Encrypt")
        if r is not None and r.status_code == 200 and "value='" in r.text:
            return True
    return False


async def _probe_legacy_web(client: httpx.AsyncClient, host: str) -> str | None:
    """E18C /web/status/get → ProductName, no auth."""
    for scheme in ("http", "https"):
        r = await _get(client, f"{scheme}://{host}/web/status/get?session=&web=1")
        if r is not None and r.status_code == 200:
            d = _parse_status_block(r.text)
            pn = d.get("ProductName") or d.get("productName") or d.get("Model")
            if pn:
                return str(pn)
    return None


async def identify(
    host: str,
    *,
    port: int = 80,
    timeout: float = 6.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> DeviceIdentity:
    """Identify a device's API dialect (and model/fw where free) without login.

    Never raises for an offline/odd device — returns a ``DeviceIdentity`` with
    ``reachable=False`` / ``dialect=UNKNOWN`` instead, so it is safe to fan out
    across a whole subnet. ``transport`` is an injection seam for tests.
    """
    ident = DeviceIdentity(host=host, port=port)
    client_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": False,
    }
    if transport is not None:
        client_kwargs["transport"] = transport
    else:
        client_kwargs["verify"] = _legacy_ctx()
    async with httpx.AsyncClient(**client_kwargs) as client:
        primary = await _get(client, f"http://{host}:{port}/api/system/info")
        if primary is None:
            # Port 80 dead — try an HTTPS SPA probe before giving up.
            web = await _probe_web_api(client, host)
            if web:
                ident.reachable = True
                ident.dialect = ApiDialect.WEB_API
                ident.model, ident.firmware, ident.hardware = web
                ident.model_source = "/api/web/system/info"
                ident.note = "port 80 unreachable; identified via HTTPS SPA endpoint"
            else:
                ident.note = "unreachable on :80 and SPA endpoint"
            return ident

        ident.reachable = True
        ident.http_status = primary.status_code
        ident.server = primary.headers.get("server", "")
        www = primary.headers.get("www-authenticate", "")

        if primary.status_code == 401 and "HTTP API" in www:
            ident.dialect = ApiDialect.DIGEST_API
            ident.note = "digest API (login required for model/fw)"
            return ident

        if primary.status_code == 200:
            ident.dialect = ApiDialect.DIGEST_API
            s = _parse_status_block(primary.text)
            ident.model = s.get("Model", "")
            ident.firmware = s.get("FirmwareVersion", "")
            ident.hardware = s.get("HardwareVersion", "")
            ident.model_source = "/api/system/info" if ident.model else ""
            ident.note = "digest API, auth mode = None (open)"
            return ident

        if primary.status_code in (301, 302, 307, 308):
            web = await _probe_web_api(client, host)
            if web:
                ident.dialect = ApiDialect.WEB_API
                ident.model, ident.firmware, ident.hardware = web
                ident.model_source = "/api/web/system/info"
                ident.note = "SPA web API (login is browser-JS hashed)"
            elif await _probe_fcgi_web(client, host):
                ident.dialect = ApiDialect.FCGI_WEB
                ident.note = "HTTPS FCGI web UI (login uses /fcgi/do session)"
            else:
                ident.dialect = ApiDialect.WEB_API
                ident.note = "SPA web API (login is browser-JS hashed)"
            return ident

        if primary.status_code == 403:
            # Ambiguous: legacy E18C, or a digest panel blocked by empty WhiteList.
            product = await _probe_legacy_web(client, host)
            if product:
                ident.dialect = ApiDialect.LEGACY_WEB
                ident.model = product
                ident.model_source = "/web/status/get"
                ident.note = "legacy E18C web API (login is browser-JS hashed)"
                return ident
            web = await _probe_web_api(client, host)
            if web:
                ident.dialect = ApiDialect.WEB_API
                ident.model, ident.firmware, ident.hardware = web
                ident.model_source = "/api/web/system/info"
                ident.note = "SPA web API (403 on digest path)"
                return ident
            ident.dialect = ApiDialect.DIGEST_API
            ident.note = (
                "403 on /api/system/info but not SPA/E18C — digest API blocked by "
                "WhiteList/None auth mode; flip HTTPAPI.AuthMode to 4 (Digest)"
            )
            return ident

        ident.note = f"unrecognised status {primary.status_code} on /api/system/info"
        return ident


async def identify_many(
    hosts: list[str],
    *,
    port: int = 80,
    timeout: float = 6.0,
    concurrency: int = 16,
) -> list[DeviceIdentity]:
    """Identify many hosts concurrently (rate-limited). Order matches input."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(h: str) -> DeviceIdentity:
        async with sem:
            return await identify(h, port=port, timeout=timeout)

    return list(await asyncio.gather(*(_one(h) for h in hosts)))
