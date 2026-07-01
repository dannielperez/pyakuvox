"""High-level Akuvox device facade — the "bridge engine" entry point.

Scripts and apps should reach for ``AkuvoxDevice.connect(...)`` instead of
wiring ``LocalSettings`` + ``LocalClient`` + dialect detection + per-firmware
key naming by hand. It:

  1. Identifies the API dialect without logging in (``pyakuvox.identify``).
  2. Connects over the right transport (digest /api on :80 today).
  3. Exposes *uniform* helpers that work regardless of firmware quirks —
     most importantly SIP-account reads/writes that resolve the
     ``Config.Account2.*`` (multi-account) vs ``Config.Account.*`` (E18C
     single-account) namespace difference for you.

Example (values like the SIP server are supplied by the caller — the SDK holds
no site-specific addresses)::

    async with await AkuvoxDevice.connect(host, "admin", pw) as dev:
        print(dev.identity.model, dev.identity.dialect)
        acct = await dev.account_sip(2)              # {'server','server2','has_fallback',...}
        if acct["has_fallback"]:
            await dev.set_sip_server(2, primary_server, secondary="", apply=True)

Devices that speak the browser-JS-hashed dialects (SPA ``/api/web``, legacy
E18C ``/web``) cannot be *written* headlessly yet: ``connect`` raises
``UnsupportedDialectError`` for them. You can still ``identify()`` them, and
once an E18C's HTTP API is flipped to Digest it connects normally.
"""

from __future__ import annotations

from typing import Any

import structlog

from pyakuvox.config import LocalAuthType, LocalSettings
from pyakuvox.exceptions import DeviceError, UnsupportedDialectError
from pyakuvox.identify import ApiDialect, DeviceIdentity, identify
from pyakuvox.models.device import DeviceInfo

logger = structlog.get_logger(__name__)

# Browser-JS-hashed login dialects we can't drive headlessly (yet).
_BROWSER_ONLY = {ApiDialect.WEB_API, ApiDialect.LEGACY_WEB, ApiDialect.FCGI_WEB}


class AkuvoxDevice:
    """A connected Akuvox device with a firmware-agnostic high-level API."""

    def __init__(self, identity: DeviceIdentity, client: Any) -> None:
        self.identity = identity
        self._client = client  # LocalClient (digest)
        self._config_cache: dict[str, Any] | None = None

    # ── Construction ────────────────────────────────────────────────

    @classmethod
    async def connect(
        cls,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 80,
        timeout: int = 10,
        dialect: ApiDialect | None = None,
    ) -> AkuvoxDevice:
        """Identify then connect. ``dialect`` skips identification if you
        already know it.

        Raises:
            UnsupportedDialectError: device speaks a browser-only dialect.
            ConnectionError: device unreachable.
        """
        ident = (
            DeviceIdentity(host=host, port=port, reachable=True, dialect=dialect)
            if dialect is not None
            else await identify(host, port=port, timeout=float(timeout))
        )
        if not ident.reachable:
            from pyakuvox.exceptions import ConnectionError as AkConnErr

            raise AkConnErr(f"{host} is unreachable (no Akuvox HTTP API on :{port})")
        if ident.dialect in _BROWSER_ONLY:
            raise UnsupportedDialectError(
                ident.dialect.value,
                host=host,
                hint="login password is hashed in browser JS — use the Playwright "
                "scripts (akuvox_web_validate.py / akuvox_e18c_*.py) for writes, or "
                "flip an E18C's HTTPAPI.AuthMode to Digest to manage it here",
            )

        # DIGEST_API (and UNKNOWN, optimistically) → LocalClient over digest.
        from pyakuvox.clients.local.client import LocalClient

        settings = LocalSettings(
            host=host,
            port=port,
            use_ssl=(port == 443),
            verify_ssl=False,
            legacy_tls=True,
            username=username,
            password=password,  # type: ignore[arg-type]
            auth_type=LocalAuthType.DIGEST,
            timeout=timeout,
        )
        client = LocalClient(settings)
        await client.__aenter__()
        return cls(ident, client)

    async def __aenter__(self) -> AkuvoxDevice:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.__aexit__(None, None, None)
            self._client = None

    # ── Raw config passthrough ──────────────────────────────────────

    async def get_config(self, *, refresh: bool = False) -> dict[str, Any]:
        """Full autop config (the inner ``data`` map), cached per device."""
        if self._config_cache is None or refresh:
            raw = await self._client.get_config()
            self._config_cache = raw.get("data", raw) if isinstance(raw, dict) else {}
        return self._config_cache

    async def set_config(self, settings: dict[str, str]) -> None:
        await self._client.set_config(settings)
        self._config_cache = None  # invalidate

    async def info(self) -> DeviceInfo:
        return await self._client.get_device_info()

    async def reboot(self) -> bool:
        return await self._client.reboot()

    # ── Account / SIP helpers (firmware-agnostic) ───────────────────

    @staticmethod
    def _resolve_account_keys(cfg: dict[str, Any], account: int) -> dict[str, str]:
        """Map a logical account number to this firmware's config keys.

        Multi-account firmware uses ``Config.Account{n}.SIP.*``; E18C uses a
        single ``Config.Account.SIP.*`` namespace (the monitoring-center PBX
        line is the only account). Returns the key NAMES that actually exist.
        """
        multi = f"Config.Account{account}.SIP.Server"
        if multi in cfg:
            base = f"Config.Account{account}"
            return {
                "server": f"{base}.SIP.Server",
                "server2": f"{base}.SIP.Server2",
                "port": f"{base}.SIP.Port",
                "enable": f"{base}.GENERAL.Enable",
                "reg_timeout": f"{base}.REG.Timeout",
                "reg_timeout2": f"{base}.REG.Timeout2",
            }
        if "Config.Account.SIP.Server" in cfg:  # E18C single-account
            return {
                "server": "Config.Account.SIP.Server",
                "server2": "Config.Account.OUTPROXY.Server",  # E18C fallback = outbound proxy
                "port": "Config.Account.SIP.Port",
                "enable": "Config.Account.GENERAL.Enable",
                "reg_timeout": "Config.Account.REG.Timeout",
                "reg_timeout2": "Config.Account.REG.Timeout2",
            }
        raise DeviceError(
            f"No SIP keys for account {account} in config "
            f"(neither '{multi}' nor 'Config.Account.SIP.Server' present)"
        )

    async def account_sip(self, account: int = 2) -> dict[str, Any]:
        """Read a SIP account's routing in a uniform, address-agnostic shape.

        Returns ``{'server','server2','port','enable','enabled','has_fallback',
        'reg_timeout','reg_timeout2','keys'}``. ``has_fallback`` is True when a
        secondary server is set. The SDK makes no judgement about which address
        is "good" — the caller owns that policy.
        """
        cfg = await self.get_config()
        keys = self._resolve_account_keys(cfg, account)
        server = cfg.get(keys["server"]) or ""
        server2 = cfg.get(keys["server2"]) or ""
        return {
            "server": server,
            "server2": server2,
            "port": cfg.get(keys["port"]),
            "enable": cfg.get(keys["enable"]),
            "enabled": str(cfg.get(keys["enable"])) in ("1", "true", "True"),
            "has_fallback": bool(server2),
            "reg_timeout": cfg.get(keys["reg_timeout"]),
            "reg_timeout2": cfg.get(keys["reg_timeout2"]),
            "keys": keys,
        }

    async def set_sip_server(
        self,
        account: int,
        primary: str,
        *,
        secondary: str | None = None,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Set an account's primary SIP server (and optionally its secondary).

        Generic, address-agnostic primitive — the caller supplies the server
        value(s). Pass ``secondary=""`` to clear the fallback, ``secondary=None``
        (default) to leave it untouched, or a string to set it.

        Default is a dry-run plan. ``apply=True`` writes (multi-account firmware
        only — E18C single-account SIP writes need the keyed ``/web`` edit
        envelope, so apply refuses there with ``UnsupportedDialectError``).

        Returns ``{'before','plan','changed','applied','verdict'}``.
        """
        acct = await self.account_sip(account)
        keys = acct["keys"]
        before = {"server": acct["server"], "server2": acct["server2"]}
        if not acct["enabled"]:
            return {"before": before, "plan": {}, "changed": False, "applied": False,
                    "verdict": "account-disabled"}

        diff: dict[str, str] = {}
        plan: dict[str, str] = {}
        if acct["server"] != primary:
            diff[keys["server"]] = primary
            plan["server"] = f"{acct['server']!r} -> {primary!r}"
        if secondary is not None and (acct["server2"] or "") != secondary:
            diff[keys["server2"]] = secondary
            plan["server2"] = f"{acct['server2']!r} -> {secondary!r}"

        if not diff:
            return {"before": before, "plan": {}, "changed": False, "applied": False,
                    "verdict": "already-set"}
        if not apply:
            return {"before": before, "plan": plan, "changed": False, "applied": False,
                    "verdict": "would-change"}
        if keys["server"] == "Config.Account.SIP.Server":
            raise UnsupportedDialectError(
                "legacy_web", host=self.identity.host,
                hint="E18C single-account SIP server needs the keyed /web edit "
                "envelope (action=edit, '<value>&<cfgId>&<keyNum>'), not flat set",
            )
        await self.set_config(diff)
        after = await self.account_sip(account)
        ok = after["server"] == primary and (secondary is None or (after["server2"] or "") == secondary)
        return {"before": before, "plan": plan, "changed": True, "applied": True,
                "verdict": "set-verified" if ok else "set-did-not-stick",
                "after": {"server": after["server"], "server2": after["server2"]}}

    async def set_reg_period(
        self,
        account: int,
        seconds: int = 30,
        *,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Set an account's SIP registration period (``REG.Timeout``/``.Timeout2``).

        The device only re-registers — and therefore fails over to the
        secondary server — when the registration period expires. The 1800s
        default was the root cause of slow SIP failover; 30s is the
        field-validated value. Writes BOTH the primary and secondary timeout
        keys to the same value.

        Default is a dry-run plan. ``apply=True`` writes (multi-account
        firmware only — same E18C refusal as ``set_sip_server``).

        Returns ``{'before','plan','changed','applied','verdict'}``.
        """
        acct = await self.account_sip(account)
        keys = acct["keys"]
        before = {"reg_timeout": acct["reg_timeout"], "reg_timeout2": acct["reg_timeout2"]}
        if not acct["enabled"]:
            return {"before": before, "plan": {}, "changed": False, "applied": False,
                    "verdict": "account-disabled"}

        want = str(seconds)
        diff: dict[str, str] = {}
        plan: dict[str, str] = {}
        for field in ("reg_timeout", "reg_timeout2"):
            have = "" if acct[field] is None else str(acct[field])
            if have != want:
                diff[keys[field]] = want
                plan[field] = f"{have!r} -> {want!r}"

        if not diff:
            return {"before": before, "plan": {}, "changed": False, "applied": False,
                    "verdict": "already-set"}
        if not apply:
            return {"before": before, "plan": plan, "changed": False, "applied": False,
                    "verdict": "would-change"}
        if keys["server"] == "Config.Account.SIP.Server":
            raise UnsupportedDialectError(
                "legacy_web", host=self.identity.host,
                hint="E18C single-account writes need the keyed /web edit "
                "envelope (action=edit, '<value>&<cfgId>&<keyNum>'), not flat set",
            )
        await self.set_config(diff)
        after = await self.account_sip(account)
        ok = str(after["reg_timeout"]) == want and str(after["reg_timeout2"]) == want
        return {"before": before, "plan": plan, "changed": True, "applied": True,
                "verdict": "set-verified" if ok else "set-did-not-stick",
                "after": {"reg_timeout": after["reg_timeout"],
                          "reg_timeout2": after["reg_timeout2"]}}

    async def set_sip_failover(
        self,
        account: int,
        primary: str,
        failover: str,
        *,
        reg_period_sec: int = 30,
        apply: bool = False,
        reboot: bool = True,
    ) -> dict[str, Any]:
        """Apply the field-validated resilient-calling recipe in one shot.

        Sets ``SIP.Server`` = ``primary`` (e.g. the internal/VPN PBX address),
        ``SIP.Server2`` = ``failover`` (e.g. the public PBX address) and the
        registration period (``REG.Timeout``/``.Timeout2``) to
        ``reg_period_sec`` — ONE config write, one verify read. After an
        applied change it reboots by default: these devices can lose unsaved
        config on power loss, so persisting immediately is part of the recipe.
        Pass ``failover=""`` to clear the secondary. The SDK holds no
        site-specific addresses — both servers are supplied by the caller.

        Default is a dry-run plan. ``apply=True`` writes (multi-account
        firmware only — same E18C refusal as ``set_sip_server``).

        Returns ``{'before','plan','changed','applied','rebooted','verdict'}``.
        """
        acct = await self.account_sip(account)
        keys = acct["keys"]
        before = {"server": acct["server"], "server2": acct["server2"],
                  "reg_timeout": acct["reg_timeout"], "reg_timeout2": acct["reg_timeout2"]}
        if not acct["enabled"]:
            return {"before": before, "plan": {}, "changed": False, "applied": False,
                    "rebooted": False, "verdict": "account-disabled"}

        want_period = str(reg_period_sec)
        targets = {
            "server": (keys["server"], acct["server"] or "", primary),
            "server2": (keys["server2"], acct["server2"] or "", failover),
            "reg_timeout": (
                keys["reg_timeout"],
                "" if acct["reg_timeout"] is None else str(acct["reg_timeout"]),
                want_period,
            ),
            "reg_timeout2": (
                keys["reg_timeout2"],
                "" if acct["reg_timeout2"] is None else str(acct["reg_timeout2"]),
                want_period,
            ),
        }
        diff: dict[str, str] = {}
        plan: dict[str, str] = {}
        for name, (key, have, want) in targets.items():
            if have != want:
                diff[key] = want
                plan[name] = f"{have!r} -> {want!r}"

        if not diff:
            return {"before": before, "plan": {}, "changed": False, "applied": False,
                    "rebooted": False, "verdict": "already-set"}
        if not apply:
            return {"before": before, "plan": plan, "changed": False, "applied": False,
                    "rebooted": False, "verdict": "would-change"}
        if keys["server"] == "Config.Account.SIP.Server":
            raise UnsupportedDialectError(
                "legacy_web", host=self.identity.host,
                hint="E18C single-account writes need the keyed /web edit "
                "envelope (action=edit, '<value>&<cfgId>&<keyNum>'), not flat set",
            )
        await self.set_config(diff)
        after = await self.account_sip(account)
        ok = (
            after["server"] == primary
            and (after["server2"] or "") == failover
            and str(after["reg_timeout"]) == want_period
            and str(after["reg_timeout2"]) == want_period
        )
        rebooted = False
        if reboot:
            rebooted = bool(await self.reboot())
        return {"before": before, "plan": plan, "changed": True, "applied": True,
                "rebooted": rebooted,
                "verdict": "set-verified" if ok else "set-did-not-stick",
                "after": {"server": after["server"], "server2": after["server2"],
                          "reg_timeout": after["reg_timeout"],
                          "reg_timeout2": after["reg_timeout2"]}}
