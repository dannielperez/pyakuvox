"""Tests for the AkuvoxDevice facade — firmware-agnostic SIP-account helpers.

All addresses are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — the SDK is domain-agnostic and holds no real infrastructure.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from pyakuvox.device import AkuvoxDevice, SetVerdict
from pyakuvox.exceptions import UnsupportedDialectError
from pyakuvox.identify import ApiDialect, DeviceIdentity

# Generic stand-in addresses supplied by the caller, never by the SDK.
PRIMARY = "203.0.113.10"      # e.g. a primary/internal SIP server
FALLBACK = "198.51.100.20"    # e.g. a secondary/public SIP server
DEVICE_HOST = "192.0.2.9"


class FakeClient:
    """Stand-in for LocalClient: serves a canned config, records set_config."""

    def __init__(self, config: dict):
        self._config = dict(config)
        self.sets: list[dict] = []
        self.reboots = 0

    async def get_config(self):
        return {"data": dict(self._config)}

    async def set_config(self, settings):
        self.sets.append(settings)
        self._config.update(settings)

    async def reboot(self):
        self.reboots += 1
        return True


def _device(config: dict, dialect=ApiDialect.DIGEST_API) -> AkuvoxDevice:
    ident = DeviceIdentity(host=DEVICE_HOST, reachable=True, dialect=dialect)
    return AkuvoxDevice(ident, FakeClient(config))


def _run(coro):
    return asyncio.run(coro)


# ── account-key resolution across firmware namespaces ───────────────


def test_multi_account_keys_resolved():
    dev = _device({
        "Config.Account2.SIP.Server": FALLBACK,
        "Config.Account2.SIP.Server2": "",
        "Config.Account2.GENERAL.Enable": "1",
    })
    acct = _run(dev.account_sip(2))
    assert acct["keys"]["server"] == "Config.Account2.SIP.Server"
    assert acct["server"] == FALLBACK
    assert acct["enabled"] is True
    assert acct["has_fallback"] is False


def test_e18c_single_account_namespace():
    dev = _device({
        "Config.Account.SIP.Server": PRIMARY,
        "Config.Account.OUTPROXY.Server": "",
        "Config.Account.GENERAL.Enable": "1",
    })
    acct = _run(dev.account_sip(2))  # logical "Account2" maps to the single E18C account
    assert acct["keys"]["server"] == "Config.Account.SIP.Server"
    assert acct["keys"]["server2"] == "Config.Account.OUTPROXY.Server"
    assert acct["has_fallback"] is False


# ── set_sip_server planning + apply ─────────────────────────────────


def test_set_sip_server_dry_run_plans_change():
    dev = _device({
        "Config.Account2.SIP.Server": FALLBACK,
        "Config.Account2.SIP.Server2": FALLBACK,
        "Config.Account2.GENERAL.Enable": "1",
    })
    res = _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=False))
    assert res["verdict"] == "would-change"
    assert res["applied"] is False
    assert dev._client.sets == []  # nothing written


def test_set_sip_server_apply_writes_and_verifies():
    dev = _device({
        "Config.Account2.SIP.Server": PRIMARY,
        "Config.Account2.SIP.Server2": FALLBACK,
        "Config.Account2.GENERAL.Enable": "1",
    })
    res = _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=True))
    assert res["verdict"] == "set-verified"
    assert res["applied"] is True
    # only the secondary changed (primary already matched); fallback cleared
    assert dev._client.sets[0] == {"Config.Account2.SIP.Server2": ""}


def test_set_sip_server_leaves_secondary_untouched_when_none():
    dev = _device({
        "Config.Account2.SIP.Server": FALLBACK,
        "Config.Account2.SIP.Server2": FALLBACK,
        "Config.Account2.GENERAL.Enable": "1",
    })
    res = _run(dev.set_sip_server(2, PRIMARY, apply=True))  # secondary=None
    assert res["verdict"] == "set-verified"
    assert dev._client.sets[0] == {"Config.Account2.SIP.Server": PRIMARY}  # server2 not touched


def test_set_sip_server_already_set_is_noop():
    dev = _device({
        "Config.Account2.SIP.Server": PRIMARY,
        "Config.Account2.SIP.Server2": "",
        "Config.Account2.GENERAL.Enable": "1",
    })
    res = _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=True))
    assert res["verdict"] == "already-set"
    assert dev._client.sets == []


def test_set_sip_server_account_disabled():
    dev = _device({
        "Config.Account2.SIP.Server": FALLBACK,
        "Config.Account2.SIP.Server2": FALLBACK,
        "Config.Account2.GENERAL.Enable": "0",
    })
    res = _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=True))
    assert res["verdict"] == "account-disabled"
    assert dev._client.sets == []


def test_set_sip_server_refuses_e18c_apply():
    dev = _device({
        "Config.Account.SIP.Server": FALLBACK,
        "Config.Account.OUTPROXY.Server": FALLBACK,
        "Config.Account.GENERAL.Enable": "1",
    })
    with pytest.raises(UnsupportedDialectError):
        _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=True))


# ── registration period (REG.Timeout / REG.Timeout2) ────────────────


def _multi_account_config(**overrides) -> dict:
    cfg = {
        "Config.Account2.SIP.Server": FALLBACK,
        "Config.Account2.SIP.Server2": "",
        "Config.Account2.GENERAL.Enable": "1",
        "Config.Account2.REG.Timeout": "1800",
        "Config.Account2.REG.Timeout2": "1800",
    }
    cfg.update(overrides)
    return cfg


def test_account_sip_exposes_reg_timeouts():
    dev = _device(_multi_account_config())
    acct = _run(dev.account_sip(2))
    assert acct["reg_timeout"] == "1800"
    assert acct["reg_timeout2"] == "1800"
    assert acct["keys"]["reg_timeout"] == "Config.Account2.REG.Timeout"


def test_set_reg_period_dry_run_plans_change():
    dev = _device(_multi_account_config())
    res = _run(dev.set_reg_period(2, 30, apply=False))
    assert res["verdict"] == "would-change"
    assert res["applied"] is False
    assert set(res["plan"]) == {"reg_timeout", "reg_timeout2"}
    assert dev._client.sets == []


def test_set_reg_period_apply_writes_both_and_verifies():
    dev = _device(_multi_account_config())
    res = _run(dev.set_reg_period(2, 30, apply=True))
    assert res["verdict"] == "set-verified"
    assert res["applied"] is True
    assert dev._client.sets[0] == {
        "Config.Account2.REG.Timeout": "30",
        "Config.Account2.REG.Timeout2": "30",
    }


def test_set_reg_period_already_set_is_noop():
    dev = _device(_multi_account_config(**{
        "Config.Account2.REG.Timeout": "30",
        "Config.Account2.REG.Timeout2": "30",
    }))
    res = _run(dev.set_reg_period(2, 30, apply=True))
    assert res["verdict"] == "already-set"
    assert dev._client.sets == []


def test_set_reg_period_refuses_e18c_apply():
    dev = _device({
        "Config.Account.SIP.Server": FALLBACK,
        "Config.Account.OUTPROXY.Server": "",
        "Config.Account.GENERAL.Enable": "1",
        "Config.Account.REG.Timeout": "1800",
    })
    with pytest.raises(UnsupportedDialectError):
        _run(dev.set_reg_period(2, 30, apply=True))


# ── set_sip_failover composite (servers + reg period + reboot) ──────


def test_set_sip_failover_dry_run_plans_all_writes_nothing():
    dev = _device(_multi_account_config())
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=False))
    assert res["verdict"] == "would-change"
    assert res["applied"] is False
    assert res["rebooted"] is False
    assert set(res["plan"]) == {"server", "server2", "reg_timeout", "reg_timeout2"}
    assert dev._client.sets == []
    assert dev._client.reboots == 0


def test_set_sip_failover_apply_single_write_verify_reboot():
    dev = _device(_multi_account_config())
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=True))
    assert res["verdict"] == "set-verified"
    assert res["applied"] is True
    assert res["rebooted"] is True
    # ONE combined config write: both servers + both reg-timeout keys
    assert dev._client.sets == [{
        "Config.Account2.SIP.Server": PRIMARY,
        "Config.Account2.SIP.Server2": FALLBACK,
        "Config.Account2.REG.Timeout": "30",
        "Config.Account2.REG.Timeout2": "30",
    }]
    assert dev._client.reboots == 1


def test_set_sip_failover_reboot_false_skips_reboot():
    dev = _device(_multi_account_config())
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=True, reboot=False))
    assert res["verdict"] == "set-verified"
    assert res["rebooted"] is False
    assert dev._client.reboots == 0


def test_set_sip_failover_already_set_skips_write_and_reboot():
    dev = _device(_multi_account_config(**{
        "Config.Account2.SIP.Server": PRIMARY,
        "Config.Account2.SIP.Server2": FALLBACK,
        "Config.Account2.REG.Timeout": "30",
        "Config.Account2.REG.Timeout2": "30",
    }))
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=True))
    assert res["verdict"] == "already-set"
    assert dev._client.sets == []
    assert dev._client.reboots == 0


def test_set_sip_failover_account_disabled():
    dev = _device(_multi_account_config(**{"Config.Account2.GENERAL.Enable": "0"}))
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=True))
    assert res["verdict"] == "account-disabled"
    assert res["rebooted"] is False
    assert dev._client.sets == []


def test_set_sip_failover_refuses_e18c_apply():
    dev = _device({
        "Config.Account.SIP.Server": FALLBACK,
        "Config.Account.OUTPROXY.Server": "",
        "Config.Account.GENERAL.Enable": "1",
    })
    with pytest.raises(UnsupportedDialectError):
        _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=True))


# ── SetVerdict vocabulary (consumer contract) ────────────────────────


def test_set_verdict_vocabulary_pinned():
    """The verdict strings are a published contract — consumers key on them."""
    assert SetVerdict.ACCOUNT_DISABLED == "account-disabled"
    assert SetVerdict.ALREADY_SET == "already-set"
    assert SetVerdict.WOULD_CHANGE == "would-change"
    assert SetVerdict.SET_VERIFIED == "set-verified"
    assert SetVerdict.SET_DID_NOT_STICK == "set-did-not-stick"
    assert len(SetVerdict) == 5


def test_set_verdict_exported_from_package_root():
    import pyakuvox

    assert pyakuvox.SetVerdict is SetVerdict
    assert "SetVerdict" in pyakuvox.__all__


def test_helpers_return_setverdict_members():
    """Returned verdicts are SetVerdict members (and therefore plain str)."""
    dev = _device(_multi_account_config())
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=False))
    assert res["verdict"] is SetVerdict.WOULD_CHANGE
    assert isinstance(res["verdict"], str)
    res = _run(dev.set_reg_period(2, 30, apply=True))
    assert res["verdict"] is SetVerdict.SET_VERIFIED


# ── from_client factory (adopt a caller-owned client) ────────────────


class FakeSettingsClient(FakeClient):
    """FakeClient that also carries connection settings, like LocalClient."""

    def __init__(self, config: dict, host: str = DEVICE_HOST, port: int = 8443):
        super().__init__(config)
        self.settings = SimpleNamespace(host=host, port=port)
        self.exits = 0

    async def __aexit__(self, *args):
        self.exits += 1


def test_from_client_builds_identity_from_settings():
    client = FakeSettingsClient(_multi_account_config())
    dev = AkuvoxDevice.from_client(client)
    assert dev.identity.host == DEVICE_HOST
    assert dev.identity.port == 8443
    assert dev.identity.reachable is True
    assert dev.identity.dialect is ApiDialect.UNKNOWN
    acct = _run(dev.account_sip(2))  # helpers work through the adopted client
    assert acct["server"] == FALLBACK


def test_from_client_dialect_passthrough():
    client = FakeSettingsClient(_multi_account_config())
    dev = AkuvoxDevice.from_client(client, dialect=ApiDialect.DIGEST_API)
    assert dev.identity.dialect is ApiDialect.DIGEST_API


def test_from_client_close_leaves_caller_owned_client_open():
    client = FakeSettingsClient(_multi_account_config())
    dev = AkuvoxDevice.from_client(client)
    _run(dev.close())
    assert client.exits == 0
    assert dev._client is None  # device still detaches its reference


def test_direct_construction_close_still_exits_client():
    """Pins the pre-existing ownership default: __init__-built devices own."""
    client = FakeSettingsClient(_multi_account_config())
    ident = DeviceIdentity(host=DEVICE_HOST, reachable=True)
    dev = AkuvoxDevice(ident, client)
    _run(dev.close())
    assert client.exits == 1
