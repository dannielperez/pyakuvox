"""Only exact-device HTTPS read upgrades may carry the existing credentials."""

import httpx
import pytest
import respx

from pyakuvox.clients.local.client import LocalClient
from pyakuvox.config import LocalSettings
from pyakuvox.exceptions import AuthenticationError, DeviceError, TimeoutError

HTTP = "http://192.0.2.1/api/system/info"
HTTPS = "https://192.0.2.1/api/system/info"
INFO = {"retcode": 0, "data": {"Status": {"MAC": "00:11:22:33:44:55", "Model": "S539"}}}


@respx.mock
async def test_empty_308_upgrades_exact_get_and_keeps_settings_unchanged():
    respx.get(HTTP).mock(return_value=httpx.Response(308, headers={"Location": HTTPS}))
    route = respx.get(HTTPS).mock(return_value=httpx.Response(200, json=INFO))
    settings = LocalSettings(host="192.0.2.1", password="synthetic")
    async with LocalClient(settings, max_retries=0) as client:
        info = await client.get_device_info()
    assert info.identity.model == "S539"
    assert route.call_count == 1
    assert not settings.use_ssl


@pytest.mark.parametrize(
    "location",
    [
        "https://192.0.2.2/api/system/info",
        "http://192.0.2.1/api/system/info",
        "https://192.0.2.1:8443/api/system/info",
        "https://user@192.0.2.1/api/system/info",
        "https://192.0.2.1/other",
        HTTPS + "?different=1",
        HTTPS + "#fragment",
        "",
    ],
)
@respx.mock
async def test_unverified_redirect_never_receives_a_request(location):
    respx.get(HTTP).mock(return_value=httpx.Response(308, headers={"Location": location}))
    async with LocalClient(LocalSettings(host="192.0.2.1"), max_retries=0) as client:
        with pytest.raises(DeviceError):
            await client.get_device_info()
    assert len(respx.calls) == 1


@respx.mock
async def test_mutation_redirect_is_not_replayed():
    respx.post("http://192.0.2.1/api/system/reboot").mock(
        return_value=httpx.Response(
            308, headers={"Location": "https://192.0.2.1/api/system/reboot"}
        )
    )
    async with LocalClient(LocalSettings(host="192.0.2.1"), max_retries=0) as client:
        with pytest.raises(DeviceError):
            await client.raw_post("/api/system/reboot", {})
    assert len(respx.calls) == 1


@pytest.mark.parametrize("status,error", [(308, DeviceError), (401, AuthenticationError)])
@respx.mock
async def test_final_response_errors_are_not_parsed_as_identity(status, error):
    respx.get(HTTP).mock(return_value=httpx.Response(308, headers={"Location": HTTPS}))
    respx.get(HTTPS).mock(return_value=httpx.Response(status, headers={"Location": HTTPS}))
    async with LocalClient(LocalSettings(host="192.0.2.1"), max_retries=0) as client:
        with pytest.raises(error):
            await client.get_device_info()


@respx.mock
async def test_https_timeout_remains_typed():
    respx.get(HTTP).mock(return_value=httpx.Response(308, headers={"Location": HTTPS}))
    respx.get(HTTPS).mock(side_effect=httpx.ReadTimeout("timeout"))
    async with LocalClient(LocalSettings(host="192.0.2.1"), max_retries=0) as client:
        with pytest.raises(TimeoutError):
            await client.get_device_info()
