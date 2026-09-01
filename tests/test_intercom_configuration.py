"""Tests for model-aware, caller-owned intercom configuration."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from pyakuvox.device import AkuvoxDevice
from pyakuvox.identify import ApiDialect, DeviceIdentity
from pyakuvox.intercom import (
    IntercomConfiguration,
    IntercomConfigurationVerdict,
    IntercomHomepageKey,
    IntercomKeyType,
    intercom_adapter,
    x916_intercom_config,
)


class FakeClient:
    def __init__(self, config: dict[str, str], *, model: str = "X916", sticky: bool = True):
        self.config = dict(config)
        self.model = model
        self.sticky = sticky
        self.sets: list[dict[str, str]] = []

    async def get_device_info(self):
        return SimpleNamespace(identity=SimpleNamespace(model=self.model))

    async def get_config(self):
        return {"data": dict(self.config)}

    async def set_config(self, settings):
        self.sets.append(dict(settings))
        if self.sticky:
            self.config.update(settings)


def device(client: FakeClient) -> AkuvoxDevice:
    identity = DeviceIdentity(
        host="192.0.2.10",
        reachable=True,
        dialect=ApiDialect.DIGEST_API,
    )
    return AkuvoxDevice(identity, client)


def requested_configuration() -> IntercomConfiguration:
    return IntercomConfiguration(
        homepage_keys=(
            IntercomHomepageKey(IntercomKeyType.SPEED_DIAL, "Reception", "700", True),
            IntercomHomepageKey(IntercomKeyType.PIN, "", "", True),
            IntercomHomepageKey(IntercomKeyType.DISABLED, "", "", True),
            IntercomHomepageKey(IntercomKeyType.DISABLED, "", "", True),
            IntercomHomepageKey(IntercomKeyType.DISABLED, "", "", True),
            IntercomHomepageKey(IntercomKeyType.DISABLED, "", "", True),
        ),
        relay_dtmf_codes=("1", "2", "3", "4"),
        relay_hold_seconds=3,
        allow_dtmf_from_all_numbers=True,
    )


def desired_config() -> dict[str, str]:
    return x916_intercom_config(requested_configuration())


def run(coro):
    return asyncio.run(coro)


def test_configuration_dry_run_translates_explicit_homepage_and_relays():
    current = {key: "legacy" for key in desired_config()}
    client = FakeClient(current)

    result = run(device(client).ensure_intercom_configuration(requested_configuration()))

    assert result["verdict"] is IntercomConfigurationVerdict.WOULD_CHANGE
    assert result["changed"] is True
    assert client.sets == []
    wants = desired_config()
    assert wants["Config.DoorSetting.DISPLAY.Key1Number"] == "700"
    assert wants["Config.DoorSetting.DTMF.DtmfWhitelist"] == "2"
    assert [wants[f"Config.DoorSetting.DTMF.Code{slot}"] for slot in range(1, 5)] == [
        "1",
        "2",
        "3",
        "4",
    ]


def test_configuration_applies_once_and_verifies_complete_readback():
    client = FakeClient({key: "legacy" for key in desired_config()})

    result = run(
        device(client).ensure_intercom_configuration(requested_configuration(), apply=True)
    )

    assert result["verdict"] is IntercomConfigurationVerdict.SET_VERIFIED
    assert client.sets == [desired_config()]


def test_configuration_already_set_does_not_write():
    client = FakeClient(desired_config())

    result = run(
        device(client).ensure_intercom_configuration(requested_configuration(), apply=True)
    )

    assert result["verdict"] is IntercomConfigurationVerdict.ALREADY_SET
    assert client.sets == []


def test_configuration_detects_silent_device_noop():
    client = FakeClient({key: "legacy" for key in desired_config()}, sticky=False)

    result = run(
        device(client).ensure_intercom_configuration(requested_configuration(), apply=True)
    )

    assert result["verdict"] is IntercomConfigurationVerdict.SET_DID_NOT_STICK


def test_configuration_refuses_unknown_model_before_writing():
    client = FakeClient(desired_config(), model="R29")

    result = run(
        device(client).ensure_intercom_configuration(requested_configuration(), apply=True)
    )

    assert result["verdict"] is IntercomConfigurationVerdict.UNSUPPORTED_MODEL
    assert "R29" in result["reason"]
    assert client.sets == []


def test_configuration_refuses_unknown_firmware_surface_before_writing():
    config = desired_config()
    config.pop("Config.DoorSetting.DTMF.DtmfWhitelist")
    client = FakeClient(config)

    result = run(
        device(client).ensure_intercom_configuration(requested_configuration(), apply=True)
    )

    assert result["verdict"] is IntercomConfigurationVerdict.UNSUPPORTED_FIRMWARE
    assert "missing" in result["reason"]
    assert client.sets == []


def test_configuration_validates_relay_codes():
    with pytest.raises(ValueError, match="unique single digits"):
        IntercomConfiguration(
            homepage_keys=requested_configuration().homepage_keys,
            relay_dtmf_codes=("1", "2", "2", "4"),
            relay_hold_seconds=3,
            allow_dtmf_from_all_numbers=True,
        )


def test_x916_adapter_rejects_unsupported_shape_nonblockingly():
    configuration = IntercomConfiguration(
        homepage_keys=requested_configuration().homepage_keys[:2],
        relay_dtmf_codes=("1",),
        relay_hold_seconds=3,
        allow_dtmf_from_all_numbers=True,
    )
    client = FakeClient(desired_config())

    result = run(device(client).ensure_intercom_configuration(configuration, apply=True))

    assert result["verdict"] is IntercomConfigurationVerdict.UNSUPPORTED_CONFIGURATION
    assert client.sets == []


def test_model_adapter_registry_never_guesses_fallback():
    adapter = intercom_adapter("x916")

    assert adapter is not None
    assert adapter.model == "X916"
    assert adapter.transport == "digest-config-api"
    assert intercom_adapter("R29") is None
