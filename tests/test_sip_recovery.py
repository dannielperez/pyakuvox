import asyncio
import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from pyakuvox import sip_recovery as recovery


@pytest.fixture
def panel(monkeypatch):
    clock = [0]
    monkeypatch.setattr(recovery.time, "monotonic", lambda: clock[0])

    async def sleep(seconds):
        clock[0] += seconds

    monkeypatch.setattr(recovery.asyncio, "sleep", sleep)
    prefix = "Config.Account2."
    config = {
        prefix + "GENERAL.Enable": "1",
        prefix + "GENERAL.UserName": "1201",
        prefix + "SIP.Server": "192.0.2.11",
        prefix + "SIP.TransType": "0",
        prefix + "SIP.Port": "5060",
        prefix + "SIP.ListenPortMin": "5064",
        prefix + "SIP.ListenPortMax": "5064",
        prefix + "GENERAL.Password": "do-not-export",
    }
    writes = []
    client = SimpleNamespace(_max_retries=0, state="READY", register=True)

    async def get_config():
        return copy.deepcopy(config)

    async def get(path):
        return (
            {"Status": client.state}
            if path.endswith("call/status")
            else {"Account2": {"Status": "2" if writes and client.register else "3"}}
        )

    async def write(values):
        writes.append(values)
        config.update(values)

    client.get_config = get_config
    client.get_device_info = AsyncMock(
        return_value=SimpleNamespace(
            identity=SimpleNamespace(normalized_mac=lambda: "00:11:22:33:44:55")
        )
    )
    client._get = get
    client.set_config = write
    return client, config, writes


async def renew(client):
    return await recovery.renew_udp_flow(
        client, slot=2, username="1201", server="192.0.2.11", mac="00:11:22:33:44:55"
    )


def test_rotates_only_account_port_after_idle_and_verifies(panel):
    client, config, writes = panel
    result = asyncio.run(renew(client))
    assert result["verified"]
    assert len(writes) == 1
    assert set(writes[0]) == {
        "Config.Account2.SIP.ListenPortMin",
        "Config.Account2.SIP.ListenPortMax",
    }
    assert config["Config.Account2.GENERAL.Password"] == "do-not-export"
    assert "do-not-export" not in str(asyncio.run(recovery.inspect_sip(client)))


@pytest.mark.parametrize("state", ["TALKING", "RINGING", "UNKNOWN", ""])
def test_active_or_unknown_call_never_writes(panel, state):
    client, _, writes = panel
    client.state = state
    with pytest.raises(ValueError, match="active or unknown"):
        asyncio.run(renew(client))
    assert not writes


def test_failed_registration_restores_only_owned_ports(panel):
    client, config, writes = panel
    client.register = False
    result = asyncio.run(renew(client))
    assert not result["verified"] and result["rollback"] == "verified"
    assert len(writes) == 2
    assert config["Config.Account2.SIP.ListenPortMin"] == "5064"


def test_identity_or_tcp_refuses_without_write(panel):
    client, config, writes = panel
    config["Config.Account2.SIP.TransType"] = "1"
    with pytest.raises(ValueError, match="UDP only"):
        asyncio.run(renew(client))
    assert not writes


def test_retries_must_be_disabled(panel):
    client, _, writes = panel
    client._max_retries = 3
    with pytest.raises(ValueError, match="non-retrying"):
        asyncio.run(renew(client))
    assert not writes


def test_ambiguous_write_is_not_retried_and_restore_is_audited(panel):
    client, config, writes = panel
    original = client.set_config

    async def uncertain(values):
        await original(values)
        if len(writes) == 1:
            raise TimeoutError("secret response must not escape")

    client.set_config = uncertain
    result = asyncio.run(renew(client))
    assert result["rollback"] == "verified"
    assert len(writes) == 2  # initial send and one restoration, never a retry
    assert "secret" not in str(result)
    assert config["Config.Account2.SIP.ListenPortMin"] == "5064"


def test_concurrent_change_is_not_overwritten_on_rollback(panel):
    client, config, writes = panel
    original = client.set_config

    async def concurrent(values):
        await original(values)
        config["Config.Account2.SIP.ListenPortMin"] = "5088"
        config["Config.Account2.SIP.ListenPortMax"] = "5088"

    client.set_config = concurrent
    result = asyncio.run(renew(client))
    assert result["rollback"] == "not_owned_or_busy_or_unknown"
    assert len(writes) == 1
    assert config["Config.Account2.SIP.ListenPortMin"] == "5088"


def test_wrong_identity_and_all_ports_reserved_refuse(panel):
    client, config, writes = panel
    with pytest.raises(ValueError, match="identity"):
        asyncio.run(
            recovery.renew_udp_flow(
                client, slot=2, username="1201", server="192.0.2.11", mac="00:00:00:00:00:00"
            )
        )
    config.update(
        {
            "Config.Account1.GENERAL.Enable": "1",
            "Config.Account1.SIP.ListenPortMin": "5060",
            "Config.Account1.SIP.ListenPortMax": "5099",
        }
    )
    with pytest.raises(ValueError, match="No free SIP port"):
        asyncio.run(renew(client))
    assert not writes


@pytest.mark.parametrize(
    "changes, reason",
    [
        ({"SIP.ListenPortMax": "5070"}, "fixed local UDP port"),
        ({"SIP.ListenPortMin": "", "SIP.ListenPortMax": ""}, "fixed local UDP port"),
        ({"SIP.ListenPortMin": "0", "SIP.ListenPortMax": "0"}, "invalid local port"),
        ({"SIP.TransType": "1"}, "UDP only"),
        ({"GENERAL.Enable": "0"}, "disabled"),
    ],
)
def test_diagnosis_explains_unsupported_configuration_without_writing(panel, changes, reason):
    client, config, writes = panel
    config.update({"Config.Account2." + key: value for key, value in changes.items()})
    account = asyncio.run(recovery.inspect_sip(client))["accounts"][0]
    assert account["udp_recovery_supported"] is False
    assert reason in account["udp_recovery_reason"]
    assert not writes
    with pytest.raises(ValueError):
        asyncio.run(renew(client))
    assert not writes


@pytest.mark.parametrize(
    "low, high, reason",
    [
        ("5060", "5099", "No free SIP port"),
        ("", "", "unknown local ports"),
        ("5090", "5060", "invalid local port range"),
    ],
)
def test_other_enabled_account_blocks_diagnosis_and_execution(panel, low, high, reason):
    client, config, writes = panel
    config.update(
        {
            "Config.Account1.GENERAL.Enable": "1",
            "Config.Account1.SIP.ListenPortMin": low,
            "Config.Account1.SIP.ListenPortMax": high,
        }
    )
    account = next(
        a for a in asyncio.run(recovery.inspect_sip(client))["accounts"] if a["slot"] == 2
    )
    assert not account["udp_recovery_supported"]
    assert reason in account["udp_recovery_reason"]
    with pytest.raises(ValueError, match=reason):
        asyncio.run(renew(client))
    assert not writes


def test_supported_readiness_is_not_idle_or_registration_verification(panel):
    client, _, writes = panel
    client.state = "TALKING"
    account = asyncio.run(recovery.inspect_sip(client))["accounts"][0]
    assert account["udp_recovery_supported"] is True
    with pytest.raises(ValueError, match="active or unknown"):
        asyncio.run(renew(client))
    assert not writes


@pytest.mark.parametrize(
    "status",
    [
        {},
        {"Account2": None},
        {"Account2": []},
        {"Account2": {}},
        {"Account2": {"Status": "unknown"}},
        {"Account2": {"Status": True}},
        {"Account2": {"Status": 2.0}},
        [],
    ],
)
def test_missing_or_malformed_registration_is_unknown(panel, status):
    client, _, writes = panel
    original = client._get

    async def get(path):
        return status if path.endswith("system/info") else await original(path)

    client._get = get
    account = asyncio.run(recovery.inspect_sip(client))["accounts"][0]
    assert account["registered"] is None
    assert not writes


@pytest.mark.parametrize(
    "status, expected",
    [("2", True), (2, True), ("0", False), ("1", False), ("3", False), ("-1", False), (3, False)],
)
def test_known_registration_statuses_keep_their_meaning(panel, status, expected):
    client, _, _ = panel
    original = client._get

    async def get(path):
        return (
            {"Account2": {"Status": status}}
            if path.endswith("system/info")
            else await original(path)
        )

    client._get = get
    assert asyncio.run(recovery.inspect_sip(client))["accounts"][0]["registered"] is expected


def test_unknown_registration_cannot_verify_a_port_renewal(panel):
    client, _, writes = panel
    original = client._get

    async def get(path):
        return {} if path.endswith("system/info") else await original(path)

    client._get = get
    result = asyncio.run(renew(client))
    assert result["verified"] is False
    assert result["rollback"] == "verified"
    assert len(writes) == 2


@pytest.mark.parametrize("state", ["Talking", "Ringing", "Calling", "unknown", None, 0, {}])
def test_native_mixed_case_and_unknown_states_never_admit_renewal(panel, state):
    client, _, writes = panel
    client.state = state
    report = asyncio.run(recovery.inspect_sip(client))
    assert report["call_state"] == (
        state.upper() if state in ["Talking", "Ringing", "Calling"] else "UNKNOWN"
    )
    with pytest.raises(ValueError, match="active or unknown"):
        asyncio.run(renew(client))
    assert not writes


def test_native_ready_case_uses_same_continuous_idle_gate(panel):
    client, _, writes = panel
    client.state = "Ready"
    assert asyncio.run(renew(client))["verified"]
    assert len(writes) == 1
