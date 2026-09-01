"""Tests for the X916 residential visitor-intercom preset."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from pyakuvox.device import AkuvoxDevice, SetVerdict
from pyakuvox.exceptions import DeviceError
from pyakuvox.identify import ApiDialect, DeviceIdentity
from pyakuvox.visitor import VisitorIntercomPreset, x916_visitor_config


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


def desired_config() -> dict[str, str]:
    return x916_visitor_config(VisitorIntercomPreset())


def run(coro):
    return asyncio.run(coro)


def test_preset_dry_run_plans_homepage_and_sequential_relays():
    current = {key: "legacy" for key in desired_config()}
    client = FakeClient(current)

    result = run(device(client).ensure_visitor_intercom_preset())

    assert result["verdict"] is SetVerdict.WOULD_CHANGE
    assert result["changed"] is True
    assert client.sets == []
    wants = desired_config()
    assert wants["Config.DoorSetting.DISPLAY.Key1Number"] == "99"
    assert wants["Config.DoorSetting.DTMF.DtmfWhitelist"] == "2"
    assert [wants[f"Config.DoorSetting.DTMF.Code{slot}"] for slot in range(1, 5)] == [
        "6",
        "7",
        "8",
        "9",
    ]


def test_preset_applies_once_and_verifies_complete_readback():
    current = {key: "legacy" for key in desired_config()}
    client = FakeClient(current)

    result = run(device(client).ensure_visitor_intercom_preset(apply=True))

    assert result["verdict"] is SetVerdict.SET_VERIFIED
    assert client.sets == [desired_config()]


def test_preset_already_set_does_not_write():
    client = FakeClient(desired_config())

    result = run(device(client).ensure_visitor_intercom_preset(apply=True))

    assert result["verdict"] is SetVerdict.ALREADY_SET
    assert client.sets == []


def test_preset_detects_silent_device_noop():
    current = {key: "legacy" for key in desired_config()}
    client = FakeClient(current, sticky=False)

    result = run(device(client).ensure_visitor_intercom_preset(apply=True))

    assert result["verdict"] is SetVerdict.SET_DID_NOT_STICK


def test_preset_refuses_non_x916_before_writing():
    client = FakeClient(desired_config(), model="R29")

    with pytest.raises(DeviceError, match="only on X916"):
        run(device(client).ensure_visitor_intercom_preset(apply=True))

    assert client.sets == []


def test_preset_refuses_unknown_firmware_surface_before_writing():
    config = desired_config()
    config.pop("Config.DoorSetting.DTMF.DtmfWhitelist")
    client = FakeClient(config)

    with pytest.raises(DeviceError, match="unsupported by this firmware"):
        run(device(client).ensure_visitor_intercom_preset(apply=True))

    assert client.sets == []


def test_preset_validates_relay_codes():
    with pytest.raises(ValueError, match="four unique single digits"):
        VisitorIntercomPreset(relay_codes=("6", "7", "7", "9"))
