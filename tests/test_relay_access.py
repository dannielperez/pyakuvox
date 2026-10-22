"""Configuration never invokes a relay command; every transport is mocked."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr

from pyakuvox.clients.local.webui import FirmwareAuthMode, HttpApiConfig
from pyakuvox.config import LocalSettings
from pyakuvox.exceptions import AmbiguousMutationError, DeviceError
from pyakuvox.relay_access import configure_web_relay_access


@pytest.fixture
def setup_clients():
    settings = LocalSettings(
        host="192.0.2.5",
        port=443,
        use_ssl=True,
        verify_ssl=True,
        username="operator",
        password=SecretStr("private-test-value"),
    )
    web = AsyncMock()
    web.__aenter__.return_value = web
    cfg = HttpApiConfig(
        enabled=False,
        auth_mode=FirmwareAuthMode.NONE,
        raw_fields={k: "" for k in ("hcEnable", "hcAuthMode", "hcUserName", "hcPassword")},
    )
    web.get_http_api_config.return_value = cfg
    web.set_http_api_config.return_value = HttpApiConfig(
        enabled=True, auth_mode=FirmwareAuthMode.DIGEST
    )
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.get_device_info.return_value = SimpleNamespace(identity=SimpleNamespace(model="X916"))
    client.get_relay_status.return_value = [SimpleNamespace(number=1), SimpleNamespace(number=2)]
    with (
        patch("pyakuvox.relay_access.WebUIClient", return_value=web),
        patch("pyakuvox.relay_access.LocalClient", return_value=client) as factory,
    ):
        yield settings, web, client, factory


async def test_preview_does_not_write_or_actuate(setup_clients):
    settings, web, client, _ = setup_clients
    result = await configure_web_relay_access(settings, model="X916", relay_numbers=(1,))
    assert result["verdict"] == "preview"
    web.set_http_api_config.assert_not_called()
    client.trigger_relay.assert_not_called()
    assert "private-test-value" not in json.dumps(result)


async def test_apply_config_only_and_verify_relay_inventory(setup_clients):
    settings, web, client, factory = setup_clients
    result = await configure_web_relay_access(
        settings, model="X916", relay_numbers=(1, 2), apply=True
    )
    assert result["verified"] and result["applied"]
    web.set_http_api_config.assert_awaited_once_with(
        enabled=True,
        auth_mode=FirmwareAuthMode.DIGEST,
        username="operator",
        password="private-test-value",
    )
    assert factory.call_args.kwargs["max_retries"] == 0
    client.trigger_relay.assert_not_called()
    assert "private-test-value" not in json.dumps(result)


async def test_repeat_is_noop(setup_clients):
    settings, web, client, _ = setup_clients
    web.get_http_api_config.return_value.enabled = True
    web.get_http_api_config.return_value.auth_mode = FirmwareAuthMode.DIGEST
    result = await configure_web_relay_access(
        settings, model="X916", relay_numbers=(1,), apply=True
    )
    assert result["verdict"] == "already_configured"
    web.set_http_api_config.assert_not_called()
    client.trigger_relay.assert_not_called()


@pytest.mark.parametrize("failure", ["write", "readback", "missing_relay"])
async def test_ambiguous_write_is_never_retried(setup_clients, failure):
    settings, web, client, _ = setup_clients
    if failure == "write":
        web.set_http_api_config.side_effect = TimeoutError()
    elif failure == "readback":
        client.get_device_info.side_effect = DeviceError("private-test-value")
    else:
        client.get_relay_status.return_value = []
    with pytest.raises(AmbiguousMutationError, match="read back before retrying") as exc:
        await configure_web_relay_access(settings, model="X916", relay_numbers=(1,), apply=True)
    assert "private-test-value" not in str(exc.value)
    assert web.set_http_api_config.await_count == 1
    client.trigger_relay.assert_not_called()


@pytest.mark.parametrize("change", [{"use_ssl": False}, {"verify_ssl": False}])
async def test_no_tls_downgrade(setup_clients, change):
    settings, web, _, _ = setup_clients
    with pytest.raises(ValueError, match="Verified HTTPS"):
        await configure_web_relay_access(
            settings.model_copy(update=change), model="X916", relay_numbers=(1,), apply=True
        )
    web.login.assert_not_called()


async def test_missing_fields_block_write(setup_clients):
    settings, web, _, _ = setup_clients
    web.get_http_api_config.return_value.raw_fields = {}
    with pytest.raises(DeviceError, match="no write attempted"):
        await configure_web_relay_access(settings, model="X916", relay_numbers=(1,), apply=True)
    web.set_http_api_config.assert_not_called()


@pytest.mark.parametrize("numbers", [(), (True,), (0,), (9,), (1, 1)])
async def test_invalid_relay_selection(setup_clients, numbers):
    settings, web, _, _ = setup_clients
    with pytest.raises(ValueError):
        await configure_web_relay_access(settings, model="X916", relay_numbers=numbers, apply=True)
    web.login.assert_not_called()


async def test_spa_uses_existing_api_configuration_dialect(setup_clients):
    settings, web, client, _ = setup_clients
    web.get_http_api_config.return_value.raw_fields = {
        f"Config.DoorSetting.APIFCGI.{key}": ""
        for key in ("Enable", "AuthMode", "UserName", "Password")
    }
    client.get_device_info.return_value.identity.model = "S535"
    with patch("pyakuvox.relay_access.WebApiClient", return_value=web):
        result = await configure_web_relay_access(
            settings, model="S535", relay_numbers=(1,), apply=True
        )
    assert result["verified"]
    web.set_http_api_config.assert_awaited_once()
    client.trigger_relay.assert_not_called()


async def test_unknown_model_never_logs_in(setup_clients):
    settings, web, _, _ = setup_clients
    with pytest.raises(ValueError, match="strategy"):
        await configure_web_relay_access(settings, model="UNKNOWN", relay_numbers=(1,), apply=True)
    web.login.assert_not_called()


async def test_model_mismatch_does_not_reconfigure_ready_api(setup_clients):
    settings, web, client, _ = setup_clients
    web.get_http_api_config.return_value.enabled = True
    web.get_http_api_config.return_value.auth_mode = FirmwareAuthMode.DIGEST
    client.get_device_info.return_value.identity.model = "DIFFERENT"
    with pytest.raises(DeviceError, match="model"):
        await configure_web_relay_access(settings, model="X916", relay_numbers=(1,), apply=True)
    web.set_http_api_config.assert_not_called()
