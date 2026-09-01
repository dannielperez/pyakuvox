"""Unit tests for the multi-dialect HTTP-API flip: encodings, WebApiClient SPA
flow, and the enable_api_digest orchestrator. All httpx is mocked — no network.
"""

from __future__ import annotations

import asyncio
import base64
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from pyakuvox.clients.local import flip as flip_mod
from pyakuvox.clients.local.encoding import (
    encode_config_password,
    encode_config_password_legacy,
    encode_config_password_webapi,
    post_encode,
)
from pyakuvox.clients.local.flip import (
    FlipResult,
    enable_api,
    enable_api_digest,
    verify_digest,
)
from pyakuvox.clients.local.webapi import WebApiClient
from pyakuvox.clients.local.webui import FirmwareAuthMode
from pyakuvox.exceptions import AuthenticationError
from pyakuvox.identify import ApiDialect, DeviceIdentity


def _resp(status: int = 200, body: dict | None = None, text: str = "") -> httpx.Response:
    if body is not None:
        content, ctype = json.dumps(body).encode(), "application/json"
    else:
        content, ctype = text.encode(), "text/plain"
    return httpx.Response(
        status_code=status,
        content=content,
        headers={"content-type": ctype},
        request=httpx.Request("POST", "http://test/"),
    )


# ── Encodings (pure functions — the load-bearing per-dialect difference) ──


def test_x916_encoding_is_postencode_of_base64():
    pw = "S3cr3t/&pass"
    assert encode_config_password(pw) == post_encode(base64.b64encode(pw.encode()).decode())


def test_r29c_encoding_is_postencode_of_raw():
    pw = "S3cr3t/&pass"
    assert encode_config_password_legacy(pw) == post_encode(pw)
    # specials get backtick-escaped, but the value is NOT base64'd
    assert "`H" in encode_config_password_legacy(pw)  # '/'
    assert "`B" in encode_config_password_legacy(pw)  # '&'


def test_s535_encoding_is_plain_base64():
    pw = "S3cr3t/&pass"
    out = encode_config_password_webapi(pw)
    assert out == base64.b64encode(pw.encode()).decode()
    assert "`" not in out  # no post_encode wrapper — JSON transport is clean


def test_the_three_encodings_are_distinct():
    # base64 here contains padding ('=') so the X916 post_encode wrapper differs
    # from the plain-base64 S535 form (they coincide only when base64 has no
    # post-encodable chars — a real property, not a bug).
    pw = "secret/key"
    assert (
        len(
            {
                encode_config_password(pw),
                encode_config_password_legacy(pw),
                encode_config_password_webapi(pw),
            }
        )
        == 3
    )


# ── WebApiClient SPA flow ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webapi_login_success_sets_token():
    mock = AsyncMock()
    mock.cookies = httpx.Cookies()  # real jar so cookies.set() works (not a coro)
    mock.post = AsyncMock(
        side_effect=[
            _resp(body={"retcode": 0, "data": {"encrypt": "NONCE"}}),
            _resp(body={"retcode": 0, "data": {"token": "TKN"}}),
        ]
    )
    async with WebApiClient("1.2.3.4") as web:
        web._client = mock
        tok = await web.login("admin", "webpass")
        assert web.is_authenticated
    assert tok == "TKN"
    # password sent = base64(nonce + webpass)
    sent = mock.post.call_args_list[1].kwargs["json"]["data"]["password"]
    assert sent == base64.b64encode(b"NONCEwebpass").decode()


@pytest.mark.asyncio
async def test_webapi_login_backs_off_on_throttle_then_raises():
    from pyakuvox.exceptions import AuthenticationError

    async with WebApiClient("1.2.3.4") as web:
        web._client = AsyncMock()
        web._client.post = AsyncMock(return_value=_resp(status=401, text="<?xml ?>"))
        with (
            patch("asyncio.sleep", AsyncMock()) as slept,
            pytest.raises(AuthenticationError, match="throttled"),
        ):  # no real waiting
            await web.login("admin", "webpass")
    # 4 attempts → 3 backoff sleeps
    assert slept.await_count == 3


@pytest.mark.asyncio
async def test_webapi_enable_api_access_sends_base64_password():
    mock = AsyncMock()
    mock.post = AsyncMock(
        side_effect=[
            _resp(body={"retcode": 0}),  # config/set
            _resp(
                body={
                    "retcode": 0,
                    "data": {  # get_http_api_config re-read
                        "Config.DoorSetting.APIFCGI.Enable": "1",
                        "Config.DoorSetting.APIFCGI.AuthMode": "4",
                        "Config.DoorSetting.APIFCGI.UserName": "admin",
                        "Config.DoorSetting.APIFCGI.Password": "x",
                    },
                }
            ),
        ]
    )
    async with WebApiClient("1.2.3.4") as web:
        web._token = "TKN"
        web._client = mock
        cfg = await web.enable_api_access("admin", "apipass")
    set_data = mock.post.call_args_list[0].kwargs["json"]["data"]
    assert set_data["Config.DoorSetting.APIFCGI.AuthMode"] == "4"
    assert set_data["Config.DoorSetting.APIFCGI.Password"] == base64.b64encode(b"apipass").decode()
    assert cfg.auth_mode is FirmwareAuthMode.DIGEST


# ── Orchestrator dispatch (generic enable_api + Digest wrapper) ──────────


@pytest.mark.asyncio
async def test_fcgi_flip_falls_back_to_https_endpoint():
    attempts = []

    class FakeWebUIClient:
        def __init__(self, _host, **kwargs):
            self.port = kwargs["port"]
            self.use_ssl = kwargs["use_ssl"]
            attempts.append((self.port, self.use_ssl))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def login(self, _user, _password):
            if not self.use_ssl:
                raise AuthenticationError("HTTP redirected to HTTPS")

        async def enable_api_access(self, _user, _password, _mode):
            return object()

    endpoint = flip_mod._DigestEndpoint(scheme="https", port=443)
    with (
        patch.object(flip_mod, "WebUIClient", FakeWebUIClient),
        patch.object(
            flip_mod,
            "_verify",
            AsyncMock(return_value=(True, endpoint)),
        ),
    ):
        encoding, verified_endpoint = await flip_mod._flip_fcgi(
            "1.2.3.4",
            "admin",
            "web-pass",
            "admin",
            "api-pass",
            FirmwareAuthMode.DIGEST,
            "R29C",
            15,
        )

    assert attempts == [(80, False), (443, True)]
    assert encoding == "r29c"
    assert verified_endpoint == endpoint


@pytest.mark.parametrize("text", ["", "not-json"])
def test_verify_digest_rejects_200_without_json_object(text):
    response = _resp(status=200, text=text)
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get = AsyncMock(return_value=response)

    with patch.object(flip_mod.httpx, "AsyncClient", return_value=client):
        assert not asyncio.run(verify_digest("1.2.3.4", "admin", "pw"))


def test_verify_digest_accepts_200_json_object():
    response = _resp(status=200, body={"data": {"Status": {"Model": "S535"}}})
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get = AsyncMock(return_value=response)

    with patch.object(flip_mod.httpx, "AsyncClient", return_value=client):
        assert asyncio.run(verify_digest("1.2.3.4", "admin", "pw"))


@pytest.mark.asyncio
async def test_enable_api_reports_verified_https_endpoint():
    endpoint = flip_mod._DigestEndpoint(scheme="https", port=443)
    with patch.object(
        flip_mod,
        "_probe_digest_endpoint",
        AsyncMock(return_value=endpoint),
    ):
        result = await enable_api_digest(
            "1.2.3.4",
            web_user="admin",
            web_pass="pw",
            api_user="admin",
            api_pass="pw",
        )

    assert result.ok is True
    assert result.verdict == "already-set"
    assert result.verified_scheme == "https"
    assert result.verified_port == 443


class TaskAbortError(Exception):
    """Stand-in for caller control flow such as a Celery soft time limit."""


def test_enable_api_does_not_swallow_caller_control_flow():
    ident = DeviceIdentity(
        host="1.2.3.4",
        reachable=True,
        dialect=ApiDialect.FCGI_WEB,
        model="X916",
    )
    abort = TaskAbortError("stop now")
    with (
        patch.object(flip_mod, "_probe_digest_endpoint", AsyncMock(return_value=None)),
        patch.object(flip_mod, "identify", AsyncMock(return_value=ident)),
        patch.object(flip_mod, "_flip_fcgi", AsyncMock(side_effect=abort)),
        pytest.raises(TaskAbortError, match="stop now"),
    ):
        asyncio.run(
            enable_api_digest(
                "1.2.3.4",
                web_user="a",
                web_pass="b",
                api_user="admin",
                api_pass="pw",
            )
        )


@pytest.mark.asyncio
async def test_enable_api_digest_short_circuits_when_already_set():
    endpoint = flip_mod._DigestEndpoint(scheme="http", port=80)
    with patch.object(
        flip_mod,
        "_probe_digest_endpoint",
        AsyncMock(return_value=endpoint),
    ):
        res = await enable_api_digest(
            "1.2.3.4", web_user="a", web_pass="b", api_user="admin", api_pass="pw"
        )
    assert res.ok and res.verdict == "already-set"
    assert res.auth_mode is FirmwareAuthMode.DIGEST  # wrapper pins Digest
    assert res.verified_scheme == "http" and res.verified_port == 80


@pytest.mark.asyncio
async def test_enable_api_dispatches_webapi_for_spa():
    ident = DeviceIdentity(host="1.2.3.4", reachable=True, dialect=ApiDialect.WEB_API, model="S535")
    endpoint = flip_mod._DigestEndpoint(scheme="https", port=443)
    probe = AsyncMock(side_effect=[None, endpoint])
    with (
        patch.object(flip_mod, "_probe_digest_endpoint", probe),
        patch.object(flip_mod, "identify", AsyncMock(return_value=ident)),
        patch.object(
            flip_mod,
            "_flip_webapi",
            AsyncMock(return_value=("web_api", endpoint)),
        ) as spa,
        patch.object(flip_mod, "_flip_fcgi", AsyncMock(return_value=("", None))) as fcgi,
    ):
        res = await enable_api(
            "1.2.3.4", web_user="a", web_pass="b", api_user="admin", api_pass="pw"
        )
    assert res.ok and res.verdict == "applied" and res.encoding_used == "web_api"
    assert res.verified_scheme == "https" and res.verified_port == 443
    spa.assert_awaited_once()
    fcgi.assert_not_awaited()


@pytest.mark.asyncio
async def test_enable_api_non_digest_mode_skips_digest_shortcircuit():
    """A non-Digest target must NOT short-circuit on verify_digest — it should
    identify + apply and confirm via the mode read back (mocked _flip)."""
    ident = DeviceIdentity(
        host="1.2.3.4", reachable=True, dialect=ApiDialect.FCGI_WEB, model="X916"
    )
    probe = AsyncMock(return_value=flip_mod._DigestEndpoint(scheme="https", port=443))
    with (
        patch.object(flip_mod, "_probe_digest_endpoint", probe),
        patch.object(flip_mod, "identify", AsyncMock(return_value=ident)) as ident_mock,
        patch.object(flip_mod, "_flip_fcgi", AsyncMock(return_value=("x916", None))) as fcgi,
    ):
        res = await enable_api(
            "1.2.3.4",
            web_user="a",
            web_pass="b",
            api_user="admin",
            api_pass="pw",
            auth_mode=FirmwareAuthMode.WHITELIST,
        )
    assert res.ok and res.verdict == "applied"
    assert res.auth_mode is FirmwareAuthMode.WHITELIST
    ident_mock.assert_awaited_once()  # did NOT short-circuit
    probe.assert_not_awaited()  # digest check irrelevant for WhiteList
    fcgi.assert_awaited_once()


@pytest.mark.asyncio
async def test_enable_api_unsupported_dialect():
    ident = DeviceIdentity(
        host="1.2.3.4", reachable=True, dialect=ApiDialect.LEGACY_WEB, model="E18C"
    )
    with (
        patch.object(flip_mod, "_probe_digest_endpoint", AsyncMock(return_value=None)),
        patch.object(flip_mod, "identify", AsyncMock(return_value=ident)),
    ):
        res = await enable_api(
            "1.2.3.4", web_user="a", web_pass="b", api_user="admin", api_pass="pw"
        )
    assert not res.ok and res.verdict == "unsupported-dialect"


@pytest.mark.asyncio
async def test_enable_api_unreachable():
    ident = DeviceIdentity(host="1.2.3.4", reachable=False, dialect=ApiDialect.UNKNOWN)
    with (
        patch.object(flip_mod, "_probe_digest_endpoint", AsyncMock(return_value=None)),
        patch.object(flip_mod, "identify", AsyncMock(return_value=ident)),
    ):
        res = await enable_api(
            "1.2.3.4", web_user="a", web_pass="b", api_user="admin", api_pass="pw"
        )
    assert not res.ok and res.verdict == "unreachable"


@pytest.mark.asyncio
async def test_enable_api_fcgi_not_verified_reports_failure():
    ident = DeviceIdentity(
        host="1.2.3.4", reachable=True, dialect=ApiDialect.FCGI_WEB, model="X916"
    )
    with (
        patch.object(flip_mod, "_probe_digest_endpoint", AsyncMock(return_value=None)),
        patch.object(flip_mod, "identify", AsyncMock(return_value=ident)),
        patch.object(flip_mod, "_flip_fcgi", AsyncMock(return_value=("", None))),
    ):
        res = await enable_api(
            "1.2.3.4", web_user="a", web_pass="b", api_user="admin", api_pass="pw"
        )
    assert not res.ok and res.verdict == "not-verified"


def test_flipresult_defaults():
    r = FlipResult(host="x")
    assert r.ok is False and r.dialect is ApiDialect.UNKNOWN
