from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr

from pyakuvox import speaker_volume as volume
from pyakuvox.config import LocalSettings
from pyakuvox.exceptions import AmbiguousMutationError, DeviceError


@pytest.fixture
def setup(monkeypatch):
    settings = LocalSettings(host="192.0.2.1", username="admin", password=SecretStr("test"))
    web = AsyncMock()
    web.__aenter__.return_value = web
    identity = {
        "hcProductModelEx": "R29C",
        "hcFirmwareVersion": "29.30.10.203",
        "hcMACAddress": "00:11:22:33:44:55",
    }
    fields = {
        "hcSpeakerVolume": "12",
        "hcVolumeReqReboot": "0",
        **{key: "8" for key in volume._PRESERVED},
    }
    web._read_page.side_effect = [identity, fields, {**fields, "hcSpeakerVolume": "13"}]
    web._write_page.return_value = 200
    monkeypatch.setattr(volume, "WebUIClient", lambda *a, **kw: web)
    return settings, web, identity, fields


async def run(setup, **kwargs):
    return await volume.configure_speaker_volume(
        setup[0], expected_mac="00:11:22:33:44:55", level=13, **kwargs
    )


async def test_preview_does_not_write(setup):
    result = await run(setup)
    assert result["before"] == {"speaker_volume": 12}
    assert result["verdict"] == "preview"
    setup[1]._write_page.assert_not_called()


async def test_write_only_speaker_and_verify(setup):
    result = await run(setup, apply=True, expected_level=12)
    assert result["verified"] is True
    setup[1]._write_page.assert_awaited_once_with(
        "id=4&id=3", "begin&Operation=Submit&cSpeakerVolume=13&SubmitData=end"
    )


@pytest.mark.parametrize("level", [0, 16, True, "13", 1.5, None])
async def test_invalid_level_never_connects(setup, level):
    with pytest.raises(ValueError):
        await volume.configure_speaker_volume(setup[0], expected_mac="001122334455", level=level)
    setup[1].login.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("hcProductModelEx", "X916"),
        ("hcFirmwareVersion", "unknown"),
        ("hcMACAddress", "00:11:22:33:44:66"),
    ],
)
async def test_wrong_identity_refuses_write(setup, field, value):
    setup[2][field] = value
    with pytest.raises(DeviceError):
        await run(setup, apply=True, expected_level=12)
    setup[1]._write_page.assert_not_called()


async def test_stale_expected_level_refuses_write(setup):
    with pytest.raises(DeviceError):
        await run(setup, apply=True, expected_level=5)
    setup[1]._write_page.assert_not_called()


async def test_apply_requires_observed_level(setup):
    with pytest.raises(ValueError):
        await run(setup, apply=True)
    setup[1].login.assert_not_called()


async def test_noop(setup):
    result = await volume.configure_speaker_volume(
        setup[0], expected_mac="001122334455", level=12, expected_level=12, apply=True
    )
    assert result["verdict"] == "already-set"
    setup[1]._write_page.assert_not_called()


@pytest.mark.parametrize("change", [{"hcSpeakerVolume": "12"}, {"hcPromptVolume": "9"}])
async def test_failed_verification_is_not_success(setup, change):
    setup[1]._read_page.side_effect = [
        setup[2],
        setup[3],
        {**setup[3], "hcSpeakerVolume": "13", **change},
    ]
    result = await run(setup, apply=True, expected_level=12)
    assert result["verified"] is False


async def test_timeout_after_write_is_ambiguous_and_not_retried(setup):
    setup[1]._write_page.side_effect = TimeoutError()
    with pytest.raises(AmbiguousMutationError):
        await run(setup, apply=True, expected_level=12)
    assert setup[1]._write_page.await_count == 1


@pytest.mark.parametrize("missing", ["hcSpeakerVolume", "hcVolumeReqReboot", "hcPromptVolume"])
async def test_missing_fields_refuse_write(setup, missing):
    setup[3].pop(missing)
    with pytest.raises(DeviceError):
        await run(setup, apply=True, expected_level=12)
    setup[1]._write_page.assert_not_called()
