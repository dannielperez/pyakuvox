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
