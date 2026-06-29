"""Tests for the AkuvoxDevice facade — firmware-agnostic SIP-account helpers.

All addresses are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — the SDK is domain-agnostic and holds no real infrastructure.
"""

from __future__ import annotations

import asyncio

import pytest

from pyakuvox.device import AkuvoxDevice
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

    async def get_config(self):
        return {"data": dict(self._config)}

    async def set_config(self, settings):
        self.sets.append(settings)
        self._config.update(settings)


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
