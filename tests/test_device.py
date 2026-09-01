"""Tests for the AkuvoxDevice facade — firmware-agnostic SIP-account helpers.

All addresses are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — the SDK is domain-agnostic and holds no real infrastructure.
"""

from __future__ import annotations

import asyncio
from typing import NotRequired, get_args, get_origin, get_type_hints, is_typeddict

import pytest

from pyakuvox.device import (
    AkuvoxDevice,
    CredentialRotationVerdict,
    SetResult,
    SetVerdict,
)
from pyakuvox.exceptions import AmbiguousMutationError, UnsupportedDialectError
from pyakuvox.exceptions import TimeoutError as AkuvoxTimeoutError
from pyakuvox.identify import ApiDialect, DeviceIdentity

# Generic stand-in addresses supplied by the caller, never by the SDK.
PRIMARY = "203.0.113.10"  # e.g. a primary/internal SIP server
FALLBACK = "198.51.100.20"  # e.g. a secondary/public SIP server
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


class NonStickingClient(FakeClient):
    """Records writes while simulating firmware that silently ignores them."""

    async def set_config(self, settings):
        self.sets.append(settings)


class PasswordMaskingClient(FakeClient):
    """Simulates firmware that never returns a configured SIP password."""

    async def get_config(self):
        config = await super().get_config()
        config["data"]["Config.Account2.GENERAL.Pwd"] = ""
        return config


class TimingOutWriteClient(FakeClient):
    async def set_config(self, settings):
        self.sets.append(settings)
        raise AkuvoxTimeoutError("write timed out")


class FailedWriteClient(FakeClient):
    def __init__(self, config: dict, error: Exception):
        super().__init__(config)
        self._error = error

    async def set_config(self, settings):
        self.sets.append(settings)
        raise self._error


class SlowPreflightClient(FakeClient):
    async def get_config(self):
        await asyncio.sleep(0.2)
        return await super().get_config()


class SlowWriteClient(FakeClient):
    async def set_config(self, settings):
        self.sets.append(settings)
        await asyncio.sleep(0.2)


def _device(config: dict, dialect=ApiDialect.DIGEST_API) -> AkuvoxDevice:
    ident = DeviceIdentity(host=DEVICE_HOST, reachable=True, dialect=dialect)
    return AkuvoxDevice(ident, FakeClient(config))


def _run(coro):
    return asyncio.run(coro)


def _access_media_config() -> dict[str, str]:
    return {
        "Config.DoorSetting.APIFCGI.Enable": "1",
        "Config.DoorSetting.APIFCGI.AuthMode": "1",
        "Config.DoorSetting.APIFCGI.UserName": "admin",
        "Config.DoorSetting.APIFCGI.Password": "old-password",
        "Config.DoorSetting.RTSP.Enable": "0",
        "Config.DoorSetting.RTSP.Authorization": "0",
        "Config.DoorSetting.RTSP.MJPEGAuthorization": "0",
        "Config.DoorSetting.RTSP.AuthenticationType": "0",
        "Config.DoorSetting.RTSP.Username": "viewer",
        "Config.DoorSetting.RTSP.Password": "old-rtsp-password",
        "Config.OnvifServer.DEVICE.Mode": "0",
        "Config.OnvifServer.DEVICE.User": "onvif",
        "Config.OnvifServer.DEVICE.Pwd": "old-onvif-password",
    }


def test_rotate_access_media_credentials_is_one_secret_free_write():
    dev = _device(_access_media_config())

    result = _run(
        dev.rotate_access_media_credentials(
            "operator",
            "new-secret",
            apply=True,
        ),
    )

    assert result["verdict"] is CredentialRotationVerdict.APPLIED_PENDING_RECONNECT
    assert result["applied"] is True
    assert dev._client.sets == [
        {
            "Config.DoorSetting.APIFCGI.AuthMode": "4",
            "Config.DoorSetting.APIFCGI.UserName": "operator",
            "Config.DoorSetting.APIFCGI.Password": "new-secret",
            "Config.DoorSetting.RTSP.Enable": "1",
            "Config.DoorSetting.RTSP.Authorization": "1",
            "Config.DoorSetting.RTSP.MJPEGAuthorization": "1",
            "Config.DoorSetting.RTSP.AuthenticationType": "1",
            "Config.DoorSetting.RTSP.Username": "operator",
            "Config.DoorSetting.RTSP.Password": "new-secret",
            "Config.OnvifServer.DEVICE.Mode": "1",
            "Config.OnvifServer.DEVICE.User": "operator",
            "Config.OnvifServer.DEVICE.Pwd": "new-secret",
        },
    ]
    assert "new-secret" not in repr(result)
    assert "old-password" not in repr(result)
    assert "old-rtsp-password" not in repr(result)
    assert "old-onvif-password" not in repr(result)


def test_rotate_access_media_credentials_dry_run_does_not_write():
    dev = _device(_access_media_config())

    result = _run(
        dev.rotate_access_media_credentials("operator", "new-secret"),
    )

    assert result["verdict"] is CredentialRotationVerdict.WOULD_CHANGE
    assert result["applied"] is False
    assert dev._client.sets == []
    assert "new-secret" not in repr(result)


def test_rotate_access_media_credentials_resolves_r29_rtsp_keys():
    config = _access_media_config()
    for key in (
        "Config.DoorSetting.RTSP.Authorization",
        "Config.DoorSetting.RTSP.MJPEGAuthorization",
        "Config.DoorSetting.RTSP.Username",
        "Config.DoorSetting.RTSP.Password",
    ):
        config.pop(key)
    config.update(
        {
            "Config.DoorSetting.RTSP.AuthEnable": "0",
            "Config.DoorSetting.MJPEGSERVICE.Authorization": "0",
            "Config.DoorSetting.RTSP.UserName": "admin",
            "Config.DoorSetting.RTSP.UserPasswd": "old-password",
        },
    )
    dev = _device(config)

    _run(dev.rotate_access_media_credentials("operator", "new-secret", apply=True))

    written = dev._client.sets[0]
    assert written["Config.DoorSetting.RTSP.AuthEnable"] == "1"
    assert written["Config.DoorSetting.MJPEGSERVICE.Authorization"] == "1"
    assert written["Config.DoorSetting.RTSP.UserName"] == "operator"
    assert written["Config.DoorSetting.RTSP.UserPasswd"] == "new-secret"
    assert written["Config.DoorSetting.RTSP.AuthenticationType"] == "1"


def test_rotate_access_media_credentials_wraps_ambiguous_write_timeout():
    ident = DeviceIdentity(host=DEVICE_HOST, reachable=True, dialect=ApiDialect.DIGEST_API)
    dev = AkuvoxDevice(ident, TimingOutWriteClient(_access_media_config()))

    with pytest.raises(AmbiguousMutationError):
        _run(
            dev.rotate_access_media_credentials(
                "operator",
                "new-secret",
                apply=True,
            ),
        )


def test_rotate_access_media_credentials_whole_budget_times_out_before_write():
    ident = DeviceIdentity(host=DEVICE_HOST, reachable=True, dialect=ApiDialect.DIGEST_API)
    client = SlowPreflightClient(_access_media_config())
    dev = AkuvoxDevice(ident, client)

    with pytest.raises(AkuvoxTimeoutError, match="before any write"):
        _run(
            dev.rotate_access_media_credentials(
                "operator",
                "new-secret",
                apply=True,
                total_timeout=0.01,
            ),
        )

    assert client.sets == []


def test_rotate_access_media_credentials_whole_budget_is_ambiguous_after_dispatch():
    ident = DeviceIdentity(host=DEVICE_HOST, reachable=True, dialect=ApiDialect.DIGEST_API)
    client = SlowWriteClient(_access_media_config())
    dev = AkuvoxDevice(ident, client)

    with pytest.raises(AmbiguousMutationError):
        _run(
            dev.rotate_access_media_credentials(
                "operator",
                "new-secret",
                apply=True,
                total_timeout=0.05,
            ),
        )

    assert len(client.sets) == 1


def test_ensure_rtsp_credentials_changes_only_rtsp_and_verifies_readback():
    dev = _device(_access_media_config())

    result = _run(
        dev.ensure_rtsp_credentials("operator", "new-secret", apply=True),
    )

    assert result["verdict"] is SetVerdict.SET_VERIFIED
    assert result["applied"] is True
    assert dev._client.sets == [
        {
            "Config.DoorSetting.RTSP.Enable": "1",
            "Config.DoorSetting.RTSP.Authorization": "1",
            "Config.DoorSetting.RTSP.MJPEGAuthorization": "1",
            "Config.DoorSetting.RTSP.AuthenticationType": "1",
            "Config.DoorSetting.RTSP.Username": "operator",
            "Config.DoorSetting.RTSP.Password": "new-secret",
        },
    ]
    assert not any("APIFCGI" in key or "Onvif" in key for key in dev._client.sets[0])
    assert "new-secret" not in repr(result)
    assert "old-rtsp-password" not in repr(result)


def test_ensure_rtsp_credentials_detects_silent_noop():
    ident = DeviceIdentity(host=DEVICE_HOST, reachable=True, dialect=ApiDialect.DIGEST_API)
    dev = AkuvoxDevice(ident, NonStickingClient(_access_media_config()))

    result = _run(
        dev.ensure_rtsp_credentials("operator", "new-secret", apply=True),
    )

    assert result["verdict"] is SetVerdict.SET_DID_NOT_STICK
    assert result["applied"] is True
    assert "new-secret" not in repr(result)


def test_ensure_rtsp_credentials_already_set_does_not_write():
    config = _access_media_config()
    config.update(
        {
            "Config.DoorSetting.RTSP.Enable": "1",
            "Config.DoorSetting.RTSP.Authorization": "1",
            "Config.DoorSetting.RTSP.MJPEGAuthorization": "1",
            "Config.DoorSetting.RTSP.AuthenticationType": "1",
            "Config.DoorSetting.RTSP.Username": "operator",
            "Config.DoorSetting.RTSP.Password": "new-secret",
        },
    )
    dev = _device(config)

    result = _run(
        dev.ensure_rtsp_credentials("operator", "new-secret", apply=True),
    )

    assert result["verdict"] is SetVerdict.ALREADY_SET
    assert dev._client.sets == []
    assert "new-secret" not in repr(result)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(Exception("401 after apply"), id="post-write-auth"),
        pytest.param(Exception("500 after apply"), id="post-write-device-error"),
        pytest.param(Exception("empty response"), id="post-write-parse-error"),
    ],
)
def test_rotate_access_media_credentials_wraps_every_post_dispatch_error(error):
    ident = DeviceIdentity(host=DEVICE_HOST, reachable=True, dialect=ApiDialect.DIGEST_API)
    dev = AkuvoxDevice(ident, FailedWriteClient(_access_media_config(), error))

    with pytest.raises(AmbiguousMutationError):
        _run(
            dev.rotate_access_media_credentials(
                "operator",
                "new-secret",
                apply=True,
            ),
        )


@pytest.mark.parametrize(
    ("username", "password", "message"),
    [("", "secret", "username"), ("admin", "", "password")],
)
def test_rotate_access_media_credentials_rejects_empty_credentials(
    username,
    password,
    message,
):
    dev = _device(_access_media_config())

    with pytest.raises(ValueError, match=message):
        _run(dev.rotate_access_media_credentials(username, password, apply=True))

    assert dev._client.sets == []


# ── account-key resolution across firmware namespaces ───────────────


def test_multi_account_keys_resolved():
    dev = _device(
        {
            "Config.Account2.SIP.Server": FALLBACK,
            "Config.Account2.SIP.Server2": "",
            "Config.Account2.GENERAL.Enable": "1",
        }
    )
    acct = _run(dev.account_sip(2))
    assert acct["keys"]["server"] == "Config.Account2.SIP.Server"
    assert acct["server"] == FALLBACK
    assert acct["enabled"] is True
    assert acct["has_fallback"] is False


def test_e18c_single_account_namespace():
    dev = _device(
        {
            "Config.Account.SIP.Server": PRIMARY,
            "Config.Account.OUTPROXY.Server": "",
            "Config.Account.GENERAL.Enable": "1",
        }
    )
    acct = _run(dev.account_sip(2))  # logical "Account2" maps to the single E18C account
    assert acct["keys"]["server"] == "Config.Account.SIP.Server"
    assert acct["keys"]["server2"] == "Config.Account.OUTPROXY.Server"
    assert acct["has_fallback"] is False


# ── set_sip_server planning + apply ─────────────────────────────────


def test_set_sip_server_dry_run_plans_change():
    dev = _device(
        {
            "Config.Account2.SIP.Server": FALLBACK,
            "Config.Account2.SIP.Server2": FALLBACK,
            "Config.Account2.GENERAL.Enable": "1",
        }
    )
    res = _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=False))
    assert res["verdict"] == "would-change"
    assert res["applied"] is False
    assert dev._client.sets == []  # nothing written


def test_set_sip_server_apply_writes_and_verifies():
    dev = _device(
        {
            "Config.Account2.SIP.Server": PRIMARY,
            "Config.Account2.SIP.Server2": FALLBACK,
            "Config.Account2.GENERAL.Enable": "1",
        }
    )
    res = _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=True))
    assert res["verdict"] == "set-verified"
    assert res["applied"] is True
    # only the secondary changed (primary already matched); fallback cleared
    assert dev._client.sets[0] == {"Config.Account2.SIP.Server2": ""}


def test_set_sip_server_leaves_secondary_untouched_when_none():
    dev = _device(
        {
            "Config.Account2.SIP.Server": FALLBACK,
            "Config.Account2.SIP.Server2": FALLBACK,
            "Config.Account2.GENERAL.Enable": "1",
        }
    )
    res = _run(dev.set_sip_server(2, PRIMARY, apply=True))  # secondary=None
    assert res["verdict"] == "set-verified"
    assert dev._client.sets[0] == {"Config.Account2.SIP.Server": PRIMARY}  # server2 not touched


def test_set_sip_server_already_set_is_noop():
    dev = _device(
        {
            "Config.Account2.SIP.Server": PRIMARY,
            "Config.Account2.SIP.Server2": "",
            "Config.Account2.GENERAL.Enable": "1",
        }
    )
    res = _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=True))
    assert res["verdict"] == "already-set"
    assert dev._client.sets == []


def test_set_sip_server_account_disabled():
    dev = _device(
        {
            "Config.Account2.SIP.Server": FALLBACK,
            "Config.Account2.SIP.Server2": FALLBACK,
            "Config.Account2.GENERAL.Enable": "0",
        }
    )
    res = _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=True))
    assert res["verdict"] == "account-disabled"
    assert dev._client.sets == []


def test_set_sip_server_refuses_e18c_apply():
    dev = _device(
        {
            "Config.Account.SIP.Server": FALLBACK,
            "Config.Account.OUTPROXY.Server": FALLBACK,
            "Config.Account.GENERAL.Enable": "1",
        }
    )
    with pytest.raises(UnsupportedDialectError):
        _run(dev.set_sip_server(2, PRIMARY, secondary="", apply=True))


# ── registration period (REG.Timeout / REG.Timeout2) ────────────────


def _multi_account_config(**overrides) -> dict:
    cfg = {
        "Config.Account2.SIP.Server": FALLBACK,
        "Config.Account2.SIP.Server2": "",
        "Config.Account2.SIP.Port": "5060",
        "Config.Account2.SIP.TransType": "0",
        "Config.Account2.GENERAL.Enable": "1",
        "Config.Account2.GENERAL.UserName": "old-user",
        "Config.Account2.GENERAL.AuthName": "old-user",
        "Config.Account2.GENERAL.Pwd": "old-password",
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
    dev = _device(
        _multi_account_config(
            **{
                "Config.Account2.REG.Timeout": "30",
                "Config.Account2.REG.Timeout2": "30",
            }
        )
    )
    res = _run(dev.set_reg_period(2, 30, apply=True))
    assert res["verdict"] == "already-set"
    assert dev._client.sets == []


def test_set_reg_period_refuses_e18c_apply():
    dev = _device(
        {
            "Config.Account.SIP.Server": FALLBACK,
            "Config.Account.OUTPROXY.Server": "",
            "Config.Account.GENERAL.Enable": "1",
            "Config.Account.REG.Timeout": "1800",
        }
    )
    with pytest.raises(UnsupportedDialectError):
        _run(dev.set_reg_period(2, 30, apply=True))


# ── complete SIP-account provisioning ──────────────────────────────


def test_set_sip_account_apply_writes_canonical_keys_and_verifies():
    dev = _device(_multi_account_config())

    res = _run(
        dev.set_sip_account(
            2,
            server=PRIMARY,
            username="1001",
            password="new-secret",
            port=5070,
            transport="tcp",
            apply=True,
        )
    )

    assert res["verdict"] == "set-verified"
    assert res["applied"] is True
    assert dev._client.sets == [
        {
            "Config.Account2.SIP.Server": PRIMARY,
            "Config.Account2.SIP.Port": "5070",
            "Config.Account2.SIP.TransType": "1",
            "Config.Account2.GENERAL.UserName": "1001",
            "Config.Account2.GENERAL.AuthName": "1001",
            "Config.Account2.GENERAL.Pwd": "new-secret",
        }
    ]


def test_set_sip_account_result_never_discloses_password():
    dev = _device(_multi_account_config())

    res = _run(
        dev.set_sip_account(
            2,
            server=PRIMARY,
            username="1001",
            password="new-secret",
            apply=True,
        )
    )

    assert "new-secret" not in repr(res)
    assert "old-password" not in repr(res)


def test_set_sip_account_detects_silent_noop():
    config = _multi_account_config()
    ident = DeviceIdentity(
        host=DEVICE_HOST,
        reachable=True,
        dialect=ApiDialect.DIGEST_API,
    )
    dev = AkuvoxDevice(ident, NonStickingClient(config))

    res = _run(
        dev.set_sip_account(
            2,
            server=PRIMARY,
            username="1001",
            password="new-secret",
            apply=True,
        )
    )

    assert res["verdict"] == "set-did-not-stick"
    assert res["applied"] is True
    assert "new-secret" not in repr(res)


def test_set_sip_account_accepts_write_only_password_readback():
    config = _multi_account_config(
        **{
            "Config.Account2.SIP.Server": PRIMARY,
            "Config.Account2.GENERAL.UserName": "1001",
            "Config.Account2.GENERAL.AuthName": "1001",
        }
    )
    ident = DeviceIdentity(
        host=DEVICE_HOST,
        reachable=True,
        dialect=ApiDialect.DIGEST_API,
    )
    dev = AkuvoxDevice(ident, PasswordMaskingClient(config))

    res = _run(
        dev.set_sip_account(
            2,
            server=PRIMARY,
            username="1001",
            password="new-secret",
            apply=True,
        )
    )

    assert res["verdict"] == "set-verified"
    assert res["after"]["password_set"] is False


def test_set_sip_account_enables_disabled_account():
    dev = _device(_multi_account_config(**{"Config.Account2.GENERAL.Enable": "0"}))

    res = _run(
        dev.set_sip_account(
            2,
            server=PRIMARY,
            username="1001",
            password="new-secret",
            apply=True,
        )
    )

    assert res["verdict"] == "set-verified"
    assert dev._client.sets[0]["Config.Account2.GENERAL.Enable"] == "1"


def test_set_sip_account_rejects_unknown_transport_without_writing():
    dev = _device(_multi_account_config())

    with pytest.raises(ValueError, match="transport"):
        _run(
            dev.set_sip_account(
                2,
                server=PRIMARY,
                username="1001",
                password="new-secret",
                transport="sctp",
                apply=True,
            )
        )

    assert dev._client.sets == []


@pytest.mark.parametrize(
    "password",
    ["x" * 64, "bad&secret", "bad%secret", "bad'secret", "bad=secret"],
)
def test_set_sip_account_rejects_device_incompatible_password_without_reading(
    password: str,
):
    dev = _device(_multi_account_config())

    with pytest.raises(ValueError) as exc_info:
        _run(
            dev.set_sip_account(
                2,
                server=PRIMARY,
                username="1001",
                password=password,
                apply=True,
            )
        )

    assert password not in str(exc_info.value)
    assert dev._client.sets == []


def test_set_sip_account_accepts_63_character_safe_password():
    dev = _device(_multi_account_config())

    res = _run(
        dev.set_sip_account(
            2,
            server=PRIMARY,
            username="1001",
            password="A" * 63,
        )
    )

    assert res["verdict"] == "would-change"


def test_set_sip_account_refuses_e18c_apply():
    dev = _device(
        {
            "Config.Account.SIP.Server": FALLBACK,
            "Config.Account.SIP.Port": "5060",
            "Config.Account.SIP.TransType": "0",
            "Config.Account.GENERAL.Enable": "1",
            "Config.Account.GENERAL.UserName": "old-user",
            "Config.Account.GENERAL.AuthName": "old-user",
            "Config.Account.GENERAL.Pwd": "old-password",
        }
    )

    with pytest.raises(UnsupportedDialectError):
        _run(
            dev.set_sip_account(
                2,
                server=PRIMARY,
                username="1001",
                password="new-secret",
                apply=True,
            )
        )

    assert dev._client.sets == []


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
    assert dev._client.sets == [
        {
            "Config.Account2.SIP.Server": PRIMARY,
            "Config.Account2.SIP.Server2": FALLBACK,
            "Config.Account2.REG.Timeout": "30",
            "Config.Account2.REG.Timeout2": "30",
        }
    ]
    assert dev._client.reboots == 1


def test_set_sip_failover_reboot_false_skips_reboot():
    dev = _device(_multi_account_config())
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=True, reboot=False))
    assert res["verdict"] == "set-verified"
    assert res["rebooted"] is False
    assert dev._client.reboots == 0


def test_set_sip_failover_already_set_skips_write_and_reboot():
    dev = _device(
        _multi_account_config(
            **{
                "Config.Account2.SIP.Server": PRIMARY,
                "Config.Account2.SIP.Server2": FALLBACK,
                "Config.Account2.REG.Timeout": "30",
                "Config.Account2.REG.Timeout2": "30",
            }
        )
    )
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
    dev = _device(
        {
            "Config.Account.SIP.Server": FALLBACK,
            "Config.Account.OUTPROXY.Server": "",
            "Config.Account.GENERAL.Enable": "1",
        }
    )
    with pytest.raises(UnsupportedDialectError):
        _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=True))


# ── SetVerdict vocabulary + from_client factory ──────────────────────


def test_set_verdict_members_are_the_documented_literals():
    from pyakuvox.device import SetVerdict

    assert SetVerdict.WOULD_CHANGE == "would-change"
    assert SetVerdict.ALREADY_SET == "already-set"
    assert SetVerdict.SET_VERIFIED == "set-verified"
    assert SetVerdict.SET_DID_NOT_STICK == "set-did-not-stick"
    assert SetVerdict.ACCOUNT_DISABLED == "account-disabled"


def test_set_verdict_exported_from_package_root():
    import pyakuvox

    assert pyakuvox.SetVerdict is not None
    assert "SetVerdict" in pyakuvox.__all__


def test_set_result_typed_dict_contract():
    import pyakuvox

    value_map = dict[str, str | bool | None]
    assert is_typeddict(SetResult)
    assert get_type_hints(SetResult) == {
        "before": value_map,
        "plan": dict[str, str],
        "changed": bool,
        "applied": bool,
        "verdict": SetVerdict,
        "after": value_map,
    }
    after_hint = get_type_hints(SetResult, include_extras=True)["after"]
    assert get_origin(after_hint) is NotRequired
    assert get_args(after_hint) == (value_map,)
    for method in (
        AkuvoxDevice.set_sip_account,
        AkuvoxDevice.set_sip_server,
        AkuvoxDevice.set_reg_period,
    ):
        assert get_type_hints(method)["return"] is SetResult
    assert pyakuvox.SetResult is SetResult
    assert "SetResult" in pyakuvox.__all__


@pytest.mark.parametrize(
    ("path", "expected_verdict", "expected_keys"),
    [
        (
            "already-set",
            SetVerdict.ALREADY_SET,
            {"before", "plan", "changed", "applied", "verdict"},
        ),
        (
            "would-change",
            SetVerdict.WOULD_CHANGE,
            {"before", "plan", "changed", "applied", "verdict"},
        ),
        (
            "applied",
            SetVerdict.SET_VERIFIED,
            {"before", "plan", "changed", "applied", "verdict", "after"},
        ),
    ],
)
def test_set_result_key_sets_for_every_typed_setter(
    path: str,
    expected_verdict: SetVerdict,
    expected_keys: set[str],
):
    already_set = path == "already-set"
    apply = path != "would-change"

    account_result = _run(
        _device(_multi_account_config()).set_sip_account(
            2,
            server=FALLBACK if already_set else PRIMARY,
            username="old-user" if already_set else "1001",
            password="old-password" if already_set else "new-secret",
            apply=apply,
        )
    )
    server_result = _run(
        _device(_multi_account_config()).set_sip_server(
            2,
            FALLBACK if already_set else PRIMARY,
            secondary="",
            apply=apply,
        )
    )
    period_config = (
        _multi_account_config(
            **{
                "Config.Account2.REG.Timeout": "30",
                "Config.Account2.REG.Timeout2": "30",
            }
        )
        if already_set
        else _multi_account_config()
    )
    period_result = _run(_device(period_config).set_reg_period(2, 30, apply=apply))

    for result in (account_result, server_result, period_result):
        assert result["verdict"] is expected_verdict
        assert set(result) == expected_keys


def test_verdicts_json_serialize_as_plain_strings():
    """StrEnum members in the result dict must round-trip like the literals."""
    import json

    dev = _device(_multi_account_config())
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=False))
    assert json.loads(json.dumps(res))["verdict"] == "would-change"


def test_from_client_derives_identity_from_client_settings():
    from types import SimpleNamespace

    from pyakuvox.identify import ApiDialect

    client = FakeClient(_multi_account_config())
    client._settings = SimpleNamespace(host=DEVICE_HOST, port=8443)
    dev = AkuvoxDevice.from_client(client)
    assert dev.identity.host == DEVICE_HOST
    assert dev.identity.port == 8443
    assert dev.identity.reachable is True
    assert dev.identity.dialect is ApiDialect.DIGEST_API
    assert dev._client is client  # wraps, never reconnects or probes


def test_from_client_wrapper_is_fully_usable():
    """The factory-built wrapper drives the same recipes as a connected one."""
    client = FakeClient(_multi_account_config())
    client._settings = None  # settings-less client still wraps (blank identity)
    dev = AkuvoxDevice.from_client(client)
    assert dev.identity.host == ""
    assert dev.identity.port == 80
    res = _run(dev.set_sip_failover(2, PRIMARY, FALLBACK, apply=False))
    assert res["verdict"] == "would-change"
    assert client.sets == []  # dry-run wrote nothing
