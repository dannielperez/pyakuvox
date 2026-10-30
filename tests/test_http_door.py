"""HTTP-door configuration must never actuate and must fail closed."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from pyakuvox.clients.local.encoding import encode_config_password_webapi
from pyakuvox.config import LocalSettings
from pyakuvox.exceptions import AmbiguousMutationError, DeviceError
from pyakuvox.http_door import FIELDS, configure_http_door


@pytest.fixture
def clients():
    settings = LocalSettings(
        host="192.0.2.5",
        port=443,
        use_ssl=True,
        verify_ssl=True,
        username="operator",
        password="Test-Saved-Secret1",
    )
    local, web = AsyncMock(), AsyncMock()
    local.__aenter__.return_value = local
    web.__aenter__.return_value = web
    local.get_device_info.return_value = SimpleNamespace(
        identity=SimpleNamespace(model="S535"), firmware_version="535.30.10.282"
    )
    local.get_relay_status.return_value = [SimpleNamespace(number=1)]
    before = dict.fromkeys(FIELDS, "")
    after = dict(
        zip(
            FIELDS, ("1", "0", settings.username, settings.password.get_secret_value()), strict=True
        )
    )
    web._config_get.side_effect = [before, after]
    with (
        patch("pyakuvox.http_door.LocalClient", return_value=local),
        patch("pyakuvox.http_door.WebApiClient", return_value=web),
    ):
        yield settings, local, web, after


async def test_preview_never_writes(clients):
    settings, local, web, _ = clients
    result = await configure_http_door(settings, model="S535", relay_numbers=(1,))
    assert result["verdict"] == "preview"
    web._config_set.assert_not_called()
    local.trigger_relay.assert_not_called()


async def test_apply_encodes_both_credentials_and_never_opens(clients):
    settings, local, web, _ = clients
    result = await configure_http_door(settings, model="S535", relay_numbers=(1,), apply=True)
    assert result["verified"] and not result["opening_verified"]
    web._config_set.assert_awaited_once_with(
        {
            FIELDS[0]: "1",
            FIELDS[1]: "0",
            FIELDS[2]: encode_config_password_webapi(settings.username),
            FIELDS[3]: encode_config_password_webapi(settings.password.get_secret_value()),
        }
    )
    local.trigger_relay.assert_not_called()
    assert settings.password.get_secret_value() not in json.dumps(result)


async def test_existing_configuration_is_noop(clients):
    settings, _, web, after = clients
    web._config_get.side_effect = [after]
    assert (await configure_http_door(settings, model="S535", relay_numbers=(1,), apply=True))[
        "verified"
    ]
    web._config_set.assert_not_called()


async def test_missing_fields_do_not_write(clients):
    settings, _, web, _ = clients
    web._config_get.side_effect = [{}]
    with pytest.raises(DeviceError, match="fields unavailable"):
        await configure_http_door(settings, model="S535", relay_numbers=(1,), apply=True)
    web._config_set.assert_not_called()


@pytest.mark.parametrize("failure", ["timeout", "masked"])
async def test_uncertain_write_never_retries(clients, failure):
    settings, local, web, after = clients
    if failure == "timeout":
        web._config_set.side_effect = TimeoutError("secret")
    else:
        after[FIELDS[3]] = "********"
    with pytest.raises(AmbiguousMutationError):
        await configure_http_door(settings, model="S535", relay_numbers=(1,), apply=True)
    assert web._config_set.await_count == 1
    local.trigger_relay.assert_not_called()


async def test_unknown_firmware_does_not_write(clients):
    settings, local, web, _ = clients
    local.get_device_info.return_value.firmware_version = "unknown"
    with pytest.raises(DeviceError, match="firmware"):
        await configure_http_door(settings, model="S535", relay_numbers=(1,), apply=True)
    web.login.assert_not_called()


@pytest.mark.parametrize(
    "change", [{"use_ssl": False}, {"verify_ssl": False}, {"legacy_tls": True}]
)
async def test_insecure_transport_does_not_connect(clients, change):
    settings, local, web, _ = clients
    with pytest.raises(ValueError, match="HTTPS"):
        await configure_http_door(
            settings.model_copy(update=change), model="S535", relay_numbers=(1,)
        )
    local.get_device_info.assert_not_called()
    web.login.assert_not_called()


@pytest.mark.parametrize(
    "reply",
    [
        '{"retcode":0, "message":"OK"}',
        "Success",
        "<html>Login</html>",
        "",
        "OK",
        '{"retcode":false,"message":"OK"}',
        '{"retcode":1,"message":"OK"}',
    ],
)
async def test_http_command_is_single_and_requires_explicit_ack(clients, reply):
    from pyakuvox.http_door import BASE, open_http_door

    settings, local, web, after = clients
    web._config_get.side_effect = [
        after,
        {BASE + "RelayADelay": "5", BASE + "RelayAMode": "0", BASE + "TriggerDelayA": "0"},
    ]
    local._client.get.return_value = SimpleNamespace(status_code=200, text=reply)
    if reply == '{"retcode":0, "message":"OK"}':
        result = await open_http_door(settings, model="S535", relay_number=1, pulse_seconds=5)
        assert result.success
        assert "physical position unverified" in result.message
    else:
        with pytest.raises(AmbiguousMutationError):
            await open_http_door(settings, model="S535", relay_number=1, pulse_seconds=5)
    local._client.get.assert_awaited_once_with(
        "/fcgi/OpenDoor", params={"action": "OpenDoor", "DoorNum": "1"}, follow_redirects=False
    )
    local.trigger_relay.assert_not_called()
    web._config_set.assert_not_called()


@pytest.mark.parametrize("mode,delay,trigger", [("1", "5", "0"), ("0", "6", "0"), ("0", "5", "1")])
async def test_http_command_blocks_unapproved_timing(clients, mode, delay, trigger):
    from pyakuvox.http_door import BASE, open_http_door

    settings, local, web, after = clients
    web._config_get.side_effect = [
        after,
        {BASE + "RelayADelay": delay, BASE + "RelayAMode": mode, BASE + "TriggerDelayA": trigger},
    ]
    with pytest.raises(DeviceError, match="pulse/mode"):
        await open_http_door(settings, model="S535", relay_number=1, pulse_seconds=5)
    local._client.get.assert_not_called()


async def test_http_command_timeout_never_retries(clients):
    from pyakuvox.http_door import BASE, open_http_door

    settings, local, web, after = clients
    web._config_get.side_effect = [
        after,
        {BASE + "RelayADelay": "5", BASE + "RelayAMode": "0", BASE + "TriggerDelayA": "0"},
    ]
    local._client.get.side_effect = TimeoutError("secret response")
    with pytest.raises(AmbiguousMutationError, match="reconcile") as error:
        await open_http_door(settings, model="S535", relay_number=1, pulse_seconds=5)
    assert "secret" not in str(error.value)
    assert local._client.get.await_count == 1
    local.trigger_relay.assert_not_called()


@pytest.mark.parametrize("status", [200, 302, 503, "timeout"])
async def test_http_transport_uses_digest_and_never_retries(status):
    import httpx

    from pyakuvox.http_door import BASE, open_http_door

    settings = LocalSettings(
        host="panel.example.test",
        port=443,
        use_ssl=True,
        verify_ssl=True,
        username="test-user",
        password="test-password",
        auth_type="digest",
    )
    web = AsyncMock()
    web.__aenter__.return_value = web
    web._config_get.return_value = {
        BASE + "RelayADelay": "5",
        BASE + "RelayAMode": "0",
        BASE + "TriggerDelayA": "0",
    }
    requests = []
    real_client = httpx.AsyncClient

    def respond(request):
        requests.append(request)
        if not request.headers.get("authorization"):
            return httpx.Response(
                401, headers={"WWW-Authenticate": 'Digest realm="panel", nonce="fixed", qop="auth"'}
            )
        if status == "timeout":
            raise httpx.ReadTimeout("unknown outcome")
        return httpx.Response(
            status, text='{"retcode":0, "message":"OK"}', headers={"Location": "/login"}
        )

    def client(**kwargs):
        return real_client(**kwargs, transport=httpx.MockTransport(respond))

    with (
        patch("pyakuvox.http_door.configure_http_door", AsyncMock(return_value={"verified": True})),
        patch("pyakuvox.http_door.WebApiClient", return_value=web),
        patch("httpx.AsyncClient", side_effect=client),
    ):
        if status == 200:
            assert (
                await open_http_door(settings, model="S535", relay_number=1, pulse_seconds=5)
            ).success
        else:
            with pytest.raises(AmbiguousMutationError):
                await open_http_door(settings, model="S535", relay_number=1, pulse_seconds=5)
    assert len(requests) == 2  # one authentication challenge, one authenticated submission
    assert requests[-1].headers["authorization"].startswith("Digest ")
    assert all(r.method == "GET" and r.url.path == "/fcgi/OpenDoor" for r in requests)
    assert all(
        "test-password" not in str(r.url) and "test-user" not in str(r.url) for r in requests
    )


@pytest.mark.parametrize("apply", [False, True])
async def test_s539_verified_schema_uses_aes_login_and_preserves_outputs(clients, apply):
    from pyakuvox.http_door import S539_FIELDS

    settings, local, web, _ = clients
    local.get_device_info.return_value = SimpleNamespace(
        identity=SimpleNamespace(model="S539"), firmware_version="539.30.10.523"
    )
    local.get_relay_status.return_value = [SimpleNamespace(number=n) for n in (1, 2, 3)]
    before = dict.fromkeys(S539_FIELDS, "")
    after = dict(
        zip(
            S539_FIELDS,
            ("1", "0", settings.username, settings.password.get_secret_value()),
            strict=True,
        )
    )
    web._config_get.side_effect = [before, after]
    result = await configure_http_door(settings, model="S539", relay_numbers=(2,), apply=apply)
    web.login.assert_awaited_once_with(
        settings.username, settings.password.get_secret_value(), encoding="cryptojs_aes"
    )
    assert result["selected_relays"] == [2]
    assert result["opening_verified"] is False
    if apply:
        sent = web._config_set.call_args.args[0]
        assert set(sent) == set(S539_FIELDS)
        assert sent[S539_FIELDS[2]] == encode_config_password_webapi(settings.username)
        assert sent[S539_FIELDS[3]] == encode_config_password_webapi(
            settings.password.get_secret_value()
        )
        assert result["verified"]
    else:
        web._config_set.assert_not_called()
    local.trigger_relay.assert_not_called()


@pytest.mark.parametrize("fault", ["firmware", "inventory", "password", "selection"])
async def test_s539_rejects_unverified_setup(clients, fault):
    settings, local, web, _ = clients
    local.get_device_info.return_value = SimpleNamespace(
        identity=SimpleNamespace(model="S539"), firmware_version="539.30.10.523"
    )
    local.get_relay_status.return_value = [SimpleNamespace(number=n) for n in (1, 2, 3)]
    selection = (1,)
    if fault == "firmware":
        local.get_device_info.return_value.firmware_version = "539.30.10.999"
    elif fault == "inventory":
        local.get_relay_status.return_value = [SimpleNamespace(number=1)]
    elif fault == "password":
        settings = settings.model_copy(
            update={"password": __import__("pydantic").SecretStr("weak")}
        )
    else:
        selection = (4,)
    with pytest.raises((ValueError, DeviceError)):
        await configure_http_door(settings, model="S539", relay_numbers=selection, apply=True)
    web._config_set.assert_not_called()
    local.trigger_relay.assert_not_called()


@pytest.mark.parametrize(
    "body,valid",
    [
        ('{"retcode":0, "message":"OK"}', True),
        ('{"retcode":false,"message":"OK"}', False),
        ('{"retcode":1,"message":"OK"}', False),
        ('{"retcode":0,"message":"Failed"}', False),
        ('{"retcode":0,"message":"OK","other":1}', False),
        ("Success", False),
        ("<html>login</html>", False),
    ],
)
async def test_s539_live_ack_contract(clients, body, valid):
    from pyakuvox.http_door import BASE, S539_FIELDS, open_http_door

    settings, local, web, _ = clients
    local.get_device_info.return_value = SimpleNamespace(
        identity=SimpleNamespace(model="S539"), firmware_version="539.30.10.523"
    )
    local.get_relay_status.return_value = [SimpleNamespace(number=n) for n in (1, 2, 3)]
    web._config_get.side_effect = [
        dict(
            zip(
                S539_FIELDS,
                ("1", "0", settings.username, settings.password.get_secret_value()),
                strict=True,
            )
        ),
        {BASE + "HoldDelayA": "5", BASE + "ModeA": "0", BASE + "TriggerDelayA": "0"},
    ]
    local._client.get.return_value = SimpleNamespace(status_code=200, text=body)
    if valid:
        assert (
            await open_http_door(settings, model="S539", relay_number=1, pulse_seconds=5)
        ).success
    else:
        with pytest.raises(AmbiguousMutationError):
            await open_http_door(settings, model="S539", relay_number=1, pulse_seconds=5)
    assert local._client.get.await_count == 1
    local.trigger_relay.assert_not_called()
    web._config_set.assert_not_called()


async def test_s539_unverified_output_never_actuates(clients):
    from pyakuvox.http_door import open_http_door

    settings, local, _, _ = clients
    with pytest.raises(ValueError):
        await open_http_door(settings, model="S539", relay_number=2, pulse_seconds=5)
    local._client.get.assert_not_called()
