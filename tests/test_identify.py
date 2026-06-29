"""Tests for unauthenticated dialect identification."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from pyakuvox.identify import (
    ApiDialect,
    DeviceIdentity,
    dialect_for_model,
    identify,
)


def _status_body(model: str, fw: str = "1.0", hw: str = "1") -> str:
    return json.dumps(
        {"retcode": 0, "data": {"Status": {"Model": model, "FirmwareVersion": fw, "HardwareVersion": hw}}}
    )


def _run(coro):
    return asyncio.run(coro)


def _transport(handler):
    return httpx.MockTransport(handler)


# ── model → dialect mapping ─────────────────────────────────────────


@pytest.mark.parametrize(
    "model,expected",
    [
        ("S539", ApiDialect.WEB_API),
        ("S535", ApiDialect.WEB_API),
        ("R29C", ApiDialect.WEB_API),
        ("E18C", ApiDialect.LEGACY_WEB),
        ("X916", ApiDialect.FCGI_WEB),
        ("R29", ApiDialect.DIGEST_API),
        ("R27", ApiDialect.DIGEST_API),
        ("", ApiDialect.UNKNOWN),
        (None, ApiDialect.UNKNOWN),
        ("WhoKnows", ApiDialect.UNKNOWN),
    ],
)
def test_dialect_for_model(model, expected):
    assert dialect_for_model(model) == expected


# ── identification decision tree ────────────────────────────────────


def test_digest_api_401_realm():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/system/info"
        return httpx.Response(
            401, headers={"www-authenticate": 'Digest realm="HTTP API"', "server": "lighttpd/1.4.30"}
        )

    ident = _run(identify("192.0.2.1", transport=_transport(handler)))
    assert ident.reachable
    assert ident.dialect == ApiDialect.DIGEST_API
    assert ident.http_status == 401
    assert ident.needs_login_for_model
    assert ident.headless_manageable


def test_digest_api_open_mode_returns_model():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=_status_body("R29"), headers={"server": "EasyHttpServer"})

    ident = _run(identify("192.0.2.2", transport=_transport(handler)))
    assert ident.dialect == ApiDialect.DIGEST_API
    assert ident.model == "R29"
    assert ident.firmware == "1.0"
    assert ident.model_source == "/api/system/info"


def test_web_api_308_then_model():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/system/info":
            return httpx.Response(308, headers={"location": "/", "server": "EasyHttpServer"})
        if request.url.path == "/api/web/system/info":
            return httpx.Response(200, text=_status_body("S539", "539.30.10.428"))
        return httpx.Response(404)

    ident = _run(identify("192.0.2.3", transport=_transport(handler)))
    assert ident.dialect == ApiDialect.WEB_API
    assert ident.model == "S539"
    assert ident.firmware == "539.30.10.428"
    assert not ident.headless_manageable


def test_legacy_e18c_403_then_productname():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/system/info":
            return httpx.Response(403, headers={"server": "lighttpd web server"})
        if request.url.path == "/web/status/get":
            return httpx.Response(200, text=json.dumps({"retcode": 0, "data": {"ProductName": "E18C"}}))
        return httpx.Response(404)

    ident = _run(identify("192.0.2.4", transport=_transport(handler)))
    assert ident.dialect == ApiDialect.LEGACY_WEB
    assert ident.model == "E18C"
    assert ident.model_source == "/web/status/get"


def test_403_whitelist_blocked_digest():
    """403 with no SPA/E18C signature => a digest panel blocked by WhiteList mode."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/system/info":
            return httpx.Response(403, headers={"server": "EasyHttpServer"})
        return httpx.Response(404)  # neither /web/status/get nor /api/web/system/info answer

    ident = _run(identify("192.0.2.5", transport=_transport(handler)))
    assert ident.dialect == ApiDialect.DIGEST_API
    assert "WhiteList" in ident.note or "Digest" in ident.note


def test_unreachable_returns_safe_identity():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    ident = _run(identify("192.0.2.6", transport=_transport(handler)))
    assert isinstance(ident, DeviceIdentity)
    assert not ident.reachable
    assert ident.dialect == ApiDialect.UNKNOWN
