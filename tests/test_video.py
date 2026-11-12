from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from pyakuvox import video
from pyakuvox.exceptions import (
    AmbiguousMutationError,
    ApiAccessForbiddenError,
    AuthenticationError,
)
from pyakuvox.video import (
    Outcome,
    Truth,
    VideoIntent,
    apply_video_plan,
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


# ── Guarded application ─────────────────────────────────────────────────

S535 = ("S535", "535.30.10.282")
MAC = "00:11:22:33:44:55"


class FakePanel:
    """An HTTP-API panel: config get/set and call status, no reboot method."""

    def __init__(self, cfg, *, status="Ready", applies=True, retries=0, fail_set=False):
        self.cfg = cfg
        self.status = status
        self.applies = applies
        self.fail_set = fail_set
        self._max_retries = retries
        self.writes = []

    async def get_device_info(self):
        return SimpleNamespace(
            identity=SimpleNamespace(model=S535[0], normalized_mac=lambda: MAC),
            firmware_version=S535[1],
        )

    async def get_config(self):
        return {"data": dict(self.cfg)}

    async def set_config(self, settings):
        self.writes.append(dict(settings))
        if self.fail_set:
            raise ConnectionError("must-never-escape")
        if self.applies:
            self.cfg.update(settings)

    async def _get(self, path):
        assert path == "/api/call/status"
        return {"data": {"Status": self.status}}


def s535():
    cfg = configuration("S535")
    cfg["Config.Features.TWOWAYVIDEO.Enable"] = ""  # the unknown flag seen on 30102
    return cfg


async def h264_plan(panel):
    baseline = await read_video_configuration(panel)
    return plan_video_configuration(baseline, VideoIntent(h264=True))


@pytest.fixture
def validated(monkeypatch):
    monkeypatch.setattr(video, "_WRITE_VALIDATED", frozenset({S535}))


async def test_unvalidated_hardware_is_refused_without_a_write():
    panel = FakePanel(s535())
    plan = await h264_plan(panel)
    assert not plan.application_supported
    with pytest.raises(ValueError, match="not validated on hardware"):
        await apply_video_plan(panel, plan, expected_mac=MAC)
    assert panel.writes == []


async def test_h264_only_change_is_written_once_and_verified(validated):
    panel = FakePanel(s535())
    plan = await h264_plan(panel)
    assert plan.application_supported
    result = await apply_video_plan(panel, plan, expected_mac=MAC)
    assert result.verdict == "set-verified" and result.applied and result.verified
    assert panel.writes == [{"Config.Account2.Video00.Enable": "1"}]
    # The unknown two-way flag, identity, registrar and relay are untouched.
    assert panel.cfg["Config.Features.TWOWAYVIDEO.Enable"] == ""
    assert panel.cfg["Config.DoorSetting.RELAY.A"] == "5"
    assert result.restart_required == "unknown"
    assert "must-never-escape" not in result.model_dump_json()


async def test_rollback_restores_the_exact_previous_value(validated):
    panel = FakePanel(s535())
    plan = await h264_plan(panel)
    await apply_video_plan(panel, plan, expected_mac=MAC)
    rollback = plan_video_rollback(plan, await read_video_configuration(panel))
    result = await apply_video_plan(panel, rollback, expected_mac=MAC)
    assert result.verdict == "set-verified"
    assert panel.cfg["Config.Account2.Video00.Enable"] == "0"
    again = await apply_video_plan(
        panel,
        plan_video_rollback(plan, await read_video_configuration(panel)),
        expected_mac=MAC,
    )
    assert again.verdict == "no-change" and len(panel.writes) == 2


@pytest.mark.parametrize(
    "panel_kwargs,mutate,mac,reason",
    [
        ({"retries": 3}, None, MAC, "non-retrying"),
        ({"status": "Talking"}, None, MAC, "call state"),
        ({"status": "garbled"}, None, MAC, "call state"),
        ({}, ("Config.DoorSetting.RELAY.A", "6"), MAC, "protected configuration"),
        ({}, ("Config.Account2.SIP.Server", "192.0.2.11"), MAC, "protected configuration"),
        ({}, ("Config.Account2.Video00.Enable", "1"), MAC, "changed since the plan"),
        ({}, None, "00:11:22:33:44:56", "approved device"),
    ],
)
async def test_refusals_send_nothing(validated, panel_kwargs, mutate, mac, reason):
    panel = FakePanel(s535(), **panel_kwargs)
    plan = await h264_plan(panel)
    if mutate:
        panel.cfg[mutate[0]] = mutate[1]
    with pytest.raises(ValueError, match=reason):
        await apply_video_plan(panel, plan, expected_mac=mac)
    assert panel.writes == []


async def test_plan_with_unknown_baseline_is_refused(validated):
    panel = FakePanel(s535())
    baseline = await read_video_configuration(panel)
    plan = plan_video_configuration(baseline, VideoIntent(two_way=True))
    with pytest.raises(ValueError, match="blockers"):
        await apply_video_plan(panel, plan, expected_mac=MAC)
    assert panel.writes == []


async def test_ignored_write_is_reported_not_retried(validated):
    panel = FakePanel(s535(), applies=False)
    result = await apply_video_plan(panel, await h264_plan(panel), expected_mac=MAC)
    assert result.verdict == "verification-failed" and not result.verified
    assert len(panel.writes) == 1


async def test_failed_write_is_ambiguous_and_leaks_nothing(validated):
    panel = FakePanel(s535(), fail_set=True)
    with pytest.raises(AmbiguousMutationError) as caught:
        await apply_video_plan(panel, await h264_plan(panel), expected_mac=MAC)
    assert "must-never-escape" not in str(caught.value)
    assert len(panel.writes) == 1
