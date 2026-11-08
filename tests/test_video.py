from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from pyakuvox.exceptions import ApiAccessForbiddenError, AuthenticationError
from pyakuvox.video import (
    Outcome,
    Truth,
    VideoIntent,
    compare_video_configuration,
    inspect_video_configuration,
    plan_video_configuration,
    plan_video_rollback,
    read_video_configuration,
)


def configuration(model="S539"):
    p = "Config.Account2."
    result = {
        p + "GENERAL.UserName": "2001",
        p + "SIP.Server": "192.0.2.10",
        p + "Video00.Name": "H264",
        p + "Video00.Enable": "0",
        p + "Video00.Priority": "2",
        "Config.Features.TWOWAYVIDEO.Enable": "1",
        p + "GENERAL.Password": "must-never-escape",
        "Config.DoorSetting.RELAY.A": "5",
    }
    if model == "S539":
        result.update(
            {p + "Video01.Name": "H263", p + "Video01.Enable": "0", p + "Video01.Priority": "1"}
        )
    return result


def observe(cfg=None, model="S539", firmware="539.30.10.523"):
    return inspect_video_configuration(
        cfg or configuration(model), model=model, firmware=firmware, mac="00:11:22:33:44:55"
    )


def test_minimal_plan_backup_and_idempotence():
    cfg = configuration()
    baseline = observe(cfg)
    plan = plan_video_configuration(baseline, VideoIntent(h264=True))
    assert len(plan.changes) == 1
    assert plan.changes[0].key == "Config.Account2.Video00.Enable"
    assert plan.recovery_ready and not plan.application_supported
    assert "must-never-escape" not in plan.model_dump_json()
    assert "Password" not in plan.model_dump_json()
    cfg.update({c.key: c.after for c in plan.changes})
    current = observe(cfg)
    assert not plan_video_configuration(current, VideoIntent(h264=True)).changes
    assert compare_video_configuration(current, VideoIntent(h264=True)).state == "compliant"
    rollback = plan_video_rollback(plan, current)
    assert rollback.changes[0].after == "0"
    assert not plan_video_rollback(plan, baseline).changes


def test_unknown_is_not_disabled_or_recoverable():
    cfg = configuration("S535")
    cfg["Config.Features.TWOWAYVIDEO.Enable"] = ""
    baseline = observe(cfg, "S535", "535.30.10.282")
    assert baseline.two_way == Truth.UNKNOWN
    plan = plan_video_configuration(baseline, VideoIntent(two_way=True))
    assert plan.blockers and not plan.recovery_ready
    assert compare_video_configuration(baseline, VideoIntent(two_way=True)).state == "unknown"
    assert plan_video_configuration(baseline, VideoIntent(h263=True)).blockers


@pytest.mark.parametrize(
    "field,value",
    [
        ("Config.DoorSetting.RELAY.A", "6"),
        ("Config.Account2.GENERAL.UserName", "2002"),
        ("Config.Account2.SIP.Server", "192.0.2.11"),
    ],
)
def test_rollback_refuses_unrelated_drift(field, value):
    cfg = configuration()
    plan = plan_video_configuration(observe(cfg), VideoIntent(h264=True))
    cfg[field] = value
    assert plan_video_rollback(plan, observe(cfg)).blockers


def test_unsupported_firmware_and_wrong_codec_surface():
    assert observe(firmware="539.30.10.999").outcome == Outcome.UNSUPPORTED
    cfg = configuration()
    cfg["Config.Account2.Video00.Name"] = "H265"
    assert observe(cfg).outcome == Outcome.UNSUPPORTED


@pytest.mark.parametrize("raw", ["", "x", "999", None])
def test_unknown_priority_cannot_produce_recovery_plan(raw):
    cfg = configuration()
    cfg["Config.Account2.Video00.Priority"] = raw
    assert plan_video_configuration(observe(cfg), VideoIntent(h264_priority=1)).blockers


@pytest.mark.parametrize(
    "error,outcome",
    [
        (ApiAccessForbiddenError("/config"), Outcome.FORBIDDEN),
        (AuthenticationError("must-never-escape"), Outcome.AUTHENTICATION_FAILED),
        (TimeoutError("must-never-escape"), Outcome.UNREACHABLE),
    ],
)
async def test_safe_read_failure(error, outcome):
    client = SimpleNamespace(get_device_info=AsyncMock(side_effect=error), get_config=AsyncMock())
    result = await read_video_configuration(client)
    assert result.outcome == outcome
    assert "must-never-escape" not in result.model_dump_json()
    client.get_config.assert_not_called()


async def test_readback_uses_existing_reader_without_mutation():
    info = SimpleNamespace(
        identity=SimpleNamespace(model="S539", normalized_mac=lambda: "aabb"),
        firmware_version="539.30.10.523",
    )
    client = SimpleNamespace(
        get_device_info=AsyncMock(return_value=info),
        get_config=AsyncMock(return_value={"data": configuration()}),
    )
    assert (await read_video_configuration(client)).outcome == Outcome.OBSERVED


def test_intent_rejects_unrelated_changes():
    with pytest.raises(ValueError):
        VideoIntent(relay=1)
