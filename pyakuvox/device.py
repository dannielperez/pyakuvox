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

import asyncio
from enum import StrEnum
from typing import TYPE_CHECKING, Any, NotRequired, Protocol, TypedDict

import structlog

from pyakuvox.config import LocalAuthType, LocalSettings
from pyakuvox.exceptions import AmbiguousMutationError, DeviceError, UnsupportedDialectError
from pyakuvox.exceptions import TimeoutError as AkuvoxTimeoutError
from pyakuvox.identify import ApiDialect, DeviceIdentity, identify

if TYPE_CHECKING:
    from collections.abc import Collection

    from pyakuvox.models.device import DeviceInfo
    from pyakuvox.models.users import UserCode
    from pyakuvox.security import SecuritySnapshot

logger = structlog.get_logger(__name__)

# Browser-JS-hashed login dialects we can't drive headlessly (yet).
_BROWSER_ONLY = {ApiDialect.WEB_API, ApiDialect.LEGACY_WEB, ApiDialect.FCGI_WEB}
_SIP_TRANSPORT_CODES = {
    "udp": "0",
    "tcp": "1",
    "tls": "2",
    "dns-naptr": "3",
}
SIP_PASSWORD_MAX_LENGTH = 63
SIP_PASSWORD_FORBIDDEN_CHARACTERS = frozenset({"&", "%", "'", "="})


def validate_sip_password(password: str) -> None:
    """Validate a SIP password against Akuvox account input constraints."""
    if len(password) > SIP_PASSWORD_MAX_LENGTH:
        raise ValueError(f"Akuvox SIP passwords cannot exceed {SIP_PASSWORD_MAX_LENGTH} characters")
    if SIP_PASSWORD_FORBIDDEN_CHARACTERS.intersection(password):
        raise ValueError("Akuvox SIP passwords contain unsupported characters")


class _DeviceClient(Protocol):
    async def __aexit__(self, *args: Any) -> None: ...

    async def get_config(self) -> dict[str, Any]: ...

    async def set_config(self, settings: dict[str, str]) -> None: ...

    async def get_device_info(self) -> DeviceInfo: ...

    async def list_all_users(self) -> list[UserCode]: ...

    async def reboot(self) -> bool: ...


class SetVerdict(StrEnum):
    """Verdict vocabulary of the ``set_*`` helpers (``result["verdict"]``).

    ``StrEnum`` members ARE the historical literal strings — existing
    consumers comparing ``result["verdict"] == "set-verified"`` keep working
    unchanged, and new consumers can import the members instead of
    hand-copying literals. The returned dicts carry these members directly
    (JSON-serializes as the plain string).
    """

    WOULD_CHANGE = "would-change"  # dry-run: a write is planned
    ALREADY_SET = "already-set"  # nothing to write (and nothing rebooted)
    SET_VERIFIED = "set-verified"  # written and re-read matched
    SET_DID_NOT_STICK = "set-did-not-stick"  # written but re-read mismatched
    ACCOUNT_DISABLED = "account-disabled"  # refused: target account disabled


class CredentialRotationVerdict(StrEnum):
    """Outcome vocabulary for a coordinated access/media credential write."""

    WOULD_CHANGE = "would-change"
    APPLIED_PENDING_RECONNECT = "applied-pending-reconnect"


class SetResult(TypedDict):
    """Result shared by setters that plan, apply, and verify config changes."""

    before: dict[str, str | bool | None]
    plan: dict[str, str]
    changed: bool
    applied: bool
    verdict: SetVerdict
    after: NotRequired[dict[str, str | bool | None]]


class CredentialRotationResult(TypedDict):
    """Secret-free result from :meth:`rotate_access_media_credentials`."""

    before: dict[str, str | bool]
    plan: dict[str, str]
    applied: bool
    verdict: CredentialRotationVerdict


_ACCESS_MEDIA_KEYS = {
    "api_enabled": "Config.DoorSetting.APIFCGI.Enable",
    "api_auth_mode": "Config.DoorSetting.APIFCGI.AuthMode",
    "api_username": "Config.DoorSetting.APIFCGI.UserName",
    "api_password": "Config.DoorSetting.APIFCGI.Password",
    "rtsp_enabled": "Config.DoorSetting.RTSP.Enable",
    "rtsp_authorization": "Config.DoorSetting.RTSP.Authorization",
    "rtsp_mjpeg_authorization": "Config.DoorSetting.RTSP.MJPEGAuthorization",
    "rtsp_auth_mode": "Config.DoorSetting.RTSP.AuthenticationType",
    "rtsp_username": "Config.DoorSetting.RTSP.Username",
    "rtsp_password": "Config.DoorSetting.RTSP.Password",
    "onvif_enabled": "Config.OnvifServer.DEVICE.Mode",
    "onvif_username": "Config.OnvifServer.DEVICE.User",
    "onvif_password": "Config.OnvifServer.DEVICE.Pwd",
}
_ACCESS_MEDIA_SECRET_NAMES = frozenset(
    {"api_password", "rtsp_password", "onvif_password"},
)


def _resolve_access_media_keys(cfg: dict[str, Any]) -> dict[str, str]:
    """Resolve documented R29 vs newer door-phone AutoP key variants."""
    keys = dict(_ACCESS_MEDIA_KEYS)
    candidates = {
        "rtsp_authorization": (
            "Config.DoorSetting.RTSP.AuthEnable",
            "Config.DoorSetting.RTSP.Authorization",
        ),
        "rtsp_mjpeg_authorization": (
            "Config.DoorSetting.MJPEGSERVICE.Authorization",
            "Config.DoorSetting.RTSP.MJPEGAuthorization",
        ),
        "rtsp_username": (
            "Config.DoorSetting.RTSP.UserName",
            "Config.DoorSetting.RTSP.Username",
        ),
        "rtsp_password": (
            "Config.DoorSetting.RTSP.UserPasswd",
            "Config.DoorSetting.RTSP.Password",
        ),
    }
    for name, variants in candidates.items():
        keys[name] = next((key for key in variants if key in cfg), keys[name])
    return keys


class AkuvoxDevice:
    """A connected Akuvox device with a firmware-agnostic high-level API."""

    def __init__(self, identity: DeviceIdentity, client: _DeviceClient) -> None:
        self.identity = identity
        self._client: _DeviceClient | None = client
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

    @classmethod
    def from_client(
        cls,
        client: _DeviceClient,
        *,
        dialect: ApiDialect = ApiDialect.DIGEST_API,
    ) -> AkuvoxDevice:
        """Wrap an already-configured ``LocalClient`` — no identify probe.

        For callers that build their own ``LocalClient`` (custom auth_type /
        SSL / timeout settings) and manage its lifecycle themselves (e.g.
        ``async with LocalClient(settings) as client:``): derives the
        :class:`DeviceIdentity` from the client's settings instead of
        re-probing the device or forcing ``connect()``'s digest-only auth.

        The caller keeps ownership of the client: when the client is
        context-managed, do NOT also call :meth:`close` on the wrapper
        (it would close the underlying client a second time).
        """
        settings = getattr(client, "_settings", None)
        return cls(
            DeviceIdentity(
                host=str(getattr(settings, "host", "") or ""),
                port=int(getattr(settings, "port", 80) or 80),
                reachable=True,
                dialect=dialect,
            ),
            client,
        )

    async def __aenter__(self) -> AkuvoxDevice:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.__aexit__(None, None, None)
            self._client = None

    def _ensure_client(self) -> _DeviceClient:
        if self._client is None:
            raise DeviceError("AkuvoxDevice is closed")
        return self._client

    # ── Raw config passthrough ──────────────────────────────────────

    async def get_config(self, *, refresh: bool = False) -> dict[str, Any]:
        """Full autop config (the inner ``data`` map), cached per device."""
        if self._config_cache is None or refresh:
            raw = await self._ensure_client().get_config()
            self._config_cache = raw.get("data", raw) if isinstance(raw, dict) else {}
        return self._config_cache

    async def set_config(self, settings: dict[str, str]) -> None:
        await self._ensure_client().set_config(settings)
        self._config_cache = None  # invalidate

    async def info(self) -> DeviceInfo:
        return await self._ensure_client().get_device_info()

    async def security_snapshot(
        self,
        username: str,
        password: str,
        *,
        weak_passwords: Collection[str] = (),
        treat_username_as_weak: bool = False,
    ) -> SecuritySnapshot:
        """Return secret-free evidence with optional caller-owned weak policy."""
        from pyakuvox.security import SecuritySnapshot, assess_credential, summarize_user

        users = await self._ensure_client().list_all_users()
        return SecuritySnapshot(
            credential_risk=assess_credential(
                username,
                password,
                weak_passwords=weak_passwords,
                treat_username_as_weak=treat_username_as_weak,
            ),
            users=tuple(summarize_user(user) for user in users),
        )

    async def reboot(self) -> bool:
        return await self._ensure_client().reboot()

    async def ensure_visitor_intercom_preset(
        self,
        preset: str = "residential_visitor_intercom_v1",
        *,
        apply: bool = False,
    ) -> SetResult:
        """Apply and verify the audited X916 visitor homepage and relays.

        The caller selects a vendor-neutral preset name.  This method verifies
        both device model and field availability before dispatching one write,
        then re-reads every required value.  It never guesses field names for
        another model or firmware generation.
        """
        from pyakuvox.visitor import (
            VisitorIntercomPreset,
            require_x916_visitor_surface,
            x916_visitor_config,
        )

        requested = VisitorIntercomPreset(name=preset)
        info = await self.info()
        model = str(getattr(getattr(info, "identity", None), "model", "")).upper()
        if model != "X916":
            raise DeviceError(
                f"visitor-intercom preset {preset!r} is supported only on X916, "
                f"got {model or 'unknown'}"
            )

        cfg = await self.get_config(refresh=True)
        wants = x916_visitor_config(requested)
        require_x916_visitor_surface(cfg, wants)
        diff = {key: want for key, want in wants.items() if str(cfg.get(key)) != want}
        before = {key: str(cfg.get(key, "")) for key in wants}
        plan = {key: f"{before[key]!r} -> {want!r}" for key, want in diff.items()}

        if not diff:
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.ALREADY_SET,
                "after": before,
            }
        if not apply:
            return {
                "before": before,
                "plan": plan,
                "changed": True,
                "applied": False,
                "verdict": SetVerdict.WOULD_CHANGE,
            }

        await self.set_config(diff)
        after_cfg = await self.get_config(refresh=True)
        after = {key: str(after_cfg.get(key, "")) for key in wants}
        verified = all(after[key] == want for key, want in wants.items())
        return {
            "before": before,
            "plan": plan,
            "changed": True,
            "applied": True,
            "verdict": (
                SetVerdict.SET_VERIFIED if verified else SetVerdict.SET_DID_NOT_STICK
            ),
            "after": after,
        }

    async def rotate_access_media_credentials(
        self,
        username: str,
        password: str,
        *,
        apply: bool = False,
        total_timeout: float | None = None,
    ) -> CredentialRotationResult:
        """Keep management API, RTSP, and ONVIF on one credential pair.

        The write enables the HTTP API in Akuvox Digest mode (``AuthMode=4``),
        enables RTSP authorization for both H.264 and MJPEG, and enables ONVIF.
        RTSP ``AuthenticationType=1`` pins Digest (``0`` is Basic). The operation
        uses one config write so the three device-owned credential surfaces
        cannot drift between separate successful calls.

        Changing the API password invalidates the current authenticated client,
        so this method deliberately does not claim read-back verification. The
        caller must reconnect with the requested credential before persisting it.
        Returned data never includes either the old or requested password.
        """
        username = str(username).strip()
        if not username:
            raise ValueError("username is required")
        if not password:
            raise ValueError("password is required")

        deadline: float | None = None
        if total_timeout is not None:
            total_timeout = float(total_timeout)
            if total_timeout <= 0 or total_timeout > 60:
                raise ValueError("credential rotation total timeout is invalid")
            deadline = asyncio.get_running_loop().time() + total_timeout
            try:
                async with asyncio.timeout(total_timeout):
                    cfg = await self.get_config(refresh=True)
            except TimeoutError as exc:
                raise AkuvoxTimeoutError(
                    "Credential configuration preflight timed out before any write.",
                ) from exc
        else:
            cfg = await self.get_config(refresh=True)
        keys = _resolve_access_media_keys(cfg)
        wants = {
            "api_enabled": "1",
            "api_auth_mode": "4",
            "api_username": username,
            "api_password": password,
            "rtsp_enabled": "1",
            "rtsp_authorization": "1",
            "rtsp_mjpeg_authorization": "1",
            "rtsp_auth_mode": "1",
            "rtsp_username": username,
            "rtsp_password": password,
            "onvif_enabled": "1",
            "onvif_username": username,
            "onvif_password": password,
        }
        before: dict[str, str | bool] = {}
        plan: dict[str, str] = {}
        raw_plan: dict[str, str] = {}
        for name, want in wants.items():
            key = keys[name]
            have = cfg.get(key)
            if name in _ACCESS_MEDIA_SECRET_NAMES:
                before[f"{name}_set"] = bool(have)
                plan[name] = "<redacted> -> <redacted>"
                raw_plan[key] = want
            else:
                before[name] = "" if have is None else str(have)
                if str(have) != want:
                    plan[name] = f"{have!r} -> {want!r}"
                    raw_plan[key] = want

        if not apply:
            return {
                "before": before,
                "plan": plan,
                "applied": False,
                "verdict": CredentialRotationVerdict.WOULD_CHANGE,
            }

        remaining: float | None = None
        if deadline is not None:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise AkuvoxTimeoutError(
                    "Credential configuration budget expired before any write.",
                )
        try:
            if remaining is None:
                await self.set_config(raw_plan)
            else:
                async with asyncio.timeout(remaining):
                    await self.set_config(raw_plan)
        except Exception as exc:
            raise AmbiguousMutationError(
                "Credential config write started but was not confirmed.",
            ) from exc
        return {
            "before": before,
            "plan": plan,
            "applied": True,
            "verdict": CredentialRotationVerdict.APPLIED_PENDING_RECONNECT,
        }

    async def ensure_rtsp_credentials(
        self,
        username: str,
        password: str,
        *,
        apply: bool = False,
    ) -> SetResult:
        """Enable RTSP with one credential pair and verify the device read-back.

        This operation changes only the RTSP surface.  It deliberately leaves
        the management API and ONVIF credentials untouched, so callers may use
        their already-authenticated management credential as the requested RTSP
        credential without rotating another service.  Returned data never
        contains the current or requested password.
        """
        username = str(username).strip()
        if not username:
            raise ValueError("username is required")
        if not password:
            raise ValueError("password is required")

        cfg = await self.get_config(refresh=True)
        keys = _resolve_access_media_keys(cfg)
        wants = {
            "rtsp_enabled": "1",
            "rtsp_authorization": "1",
            "rtsp_mjpeg_authorization": "1",
            "rtsp_auth_mode": "1",
            "rtsp_username": username,
            "rtsp_password": password,
        }
        before: dict[str, str | bool | None] = {}
        plan: dict[str, str] = {}
        raw_plan: dict[str, str] = {}
        for name, want in wants.items():
            key = keys[name]
            have = cfg.get(key)
            if name == "rtsp_password":
                before["rtsp_password_set"] = bool(have)
                if have != want:
                    plan[name] = "<redacted> -> <redacted>"
                    raw_plan[key] = want
            else:
                before[name] = None if have is None else str(have)
                if str(have) != want:
                    plan[name] = f"{have!r} -> {want!r}"
                    raw_plan[key] = want

        if not raw_plan:
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.ALREADY_SET,
                "after": before,
            }
        if not apply:
            return {
                "before": before,
                "plan": plan,
                "changed": True,
                "applied": False,
                "verdict": SetVerdict.WOULD_CHANGE,
            }

        await self.set_config(raw_plan)
        after_cfg = await self.get_config(refresh=True)
        matches = all(str(after_cfg.get(keys[name])) == want for name, want in wants.items())
        after = {
            name if name != "rtsp_password" else "rtsp_password_set": (
                bool(after_cfg.get(keys[name]))
                if name == "rtsp_password"
                else str(after_cfg.get(keys[name], ""))
            )
            for name in wants
        }
        return {
            "before": before,
            "plan": plan,
            "changed": True,
            "applied": True,
            "verdict": (SetVerdict.SET_VERIFIED if matches else SetVerdict.SET_DID_NOT_STICK),
            "after": after,
        }

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
                "transport": f"{base}.SIP.TransType",
                "enable": f"{base}.GENERAL.Enable",
                "username": f"{base}.GENERAL.UserName",
                "auth_name": f"{base}.GENERAL.AuthName",
                "password": f"{base}.GENERAL.Pwd",
                "reg_timeout": f"{base}.REG.Timeout",
                "reg_timeout2": f"{base}.REG.Timeout2",
            }
        if "Config.Account.SIP.Server" in cfg:  # E18C single-account
            return {
                "server": "Config.Account.SIP.Server",
                "server2": "Config.Account.OUTPROXY.Server",  # E18C fallback = outbound proxy
                "port": "Config.Account.SIP.Port",
                "transport": "Config.Account.SIP.TransType",
                "enable": "Config.Account.GENERAL.Enable",
                "username": "Config.Account.GENERAL.UserName",
                "auth_name": "Config.Account.GENERAL.AuthName",
                "password": "Config.Account.GENERAL.Pwd",
                "reg_timeout": "Config.Account.REG.Timeout",
                "reg_timeout2": "Config.Account.REG.Timeout2",
            }
        raise DeviceError(
            f"No SIP keys for account {account} in config "
            f"(neither '{multi}' nor 'Config.Account.SIP.Server' present)"
        )

    async def account_sip(self, account: int = 2) -> dict[str, Any]:
        """Read a SIP account's routing in a uniform, address-agnostic shape.

        Returns ``{'server','server2','port','transport','enable','enabled',
        'username','auth_name','has_fallback','reg_timeout','reg_timeout2',
        'keys'}``. ``has_fallback`` is True when a secondary server is set. The
        SDK makes no judgement about which address is "good" — the caller owns
        that policy. Passwords are never returned.
        """
        cfg = await self.get_config()
        keys = self._resolve_account_keys(cfg, account)
        server = cfg.get(keys["server"]) or ""
        server2 = cfg.get(keys["server2"]) or ""
        return {
            "server": server,
            "server2": server2,
            "port": cfg.get(keys["port"]),
            "transport": cfg.get(keys["transport"]),
            "enable": cfg.get(keys["enable"]),
            "enabled": str(cfg.get(keys["enable"])) in ("1", "true", "True"),
            "username": cfg.get(keys["username"]),
            "auth_name": cfg.get(keys["auth_name"]),
            "has_fallback": bool(server2),
            "reg_timeout": cfg.get(keys["reg_timeout"]),
            "reg_timeout2": cfg.get(keys["reg_timeout2"]),
            "keys": keys,
        }

    async def set_sip_account(
        self,
        account: int,
        *,
        server: str,
        username: str,
        password: str,
        port: int | str = 5060,
        transport: str = "udp",
        registration_period: int | None = None,
        apply: bool = False,
    ) -> SetResult:
        """Configure and verify one complete SIP registration account.

        Resolves the firmware's account namespace before writing the canonical
        AutoP fields. ``transport`` accepts ``udp``, ``tcp``, ``tls``, or
        ``dns-naptr`` and is encoded to Akuvox's numeric ``SIP.TransType``.

        Result dictionaries never contain the current or requested password.
        Default is a dry-run plan. ``apply=True`` writes and re-reads the full
        account, returning ``set-verified`` when every readable requested value
        persisted. Password fields are write-only on some firmware and are
        verified end-to-end by SIP registration. E18C single-account writes
        remain unsupported because that dialect requires the keyed ``/web``
        edit envelope.
        """
        validate_sip_password(password)
        transport_name = transport.strip().lower()
        try:
            transport_code = _SIP_TRANSPORT_CODES[transport_name]
        except KeyError as exc:
            supported = ", ".join(_SIP_TRANSPORT_CODES)
            raise ValueError(
                f"unsupported SIP transport {transport!r}; expected {supported}"
            ) from exc
        if registration_period is not None and not 30 <= registration_period <= 65535:
            raise ValueError("registration_period must be between 30 and 65535 seconds")

        cfg = await self.get_config()
        keys = self._resolve_account_keys(cfg, account)
        wants = {
            "enable": "1",
            "server": str(server),
            "port": str(port),
            "transport": transport_code,
            "username": str(username),
            "auth_name": str(username),
            "password": str(password),
        }
        if registration_period is not None:
            wants["reg_timeout"] = str(registration_period)
            wants["reg_timeout2"] = str(registration_period)
        before = {name: cfg.get(keys[name]) for name in wants if name != "password"}
        before["password_set"] = bool(cfg.get(keys["password"]))

        diff: dict[str, str] = {}
        plan: dict[str, str] = {}
        for name, want in wants.items():
            have = "" if cfg.get(keys[name]) is None else str(cfg[keys[name]])
            if have == want:
                continue
            diff[keys[name]] = want
            plan[name] = (
                "<redacted> -> <redacted>" if name == "password" else f"{have!r} -> {want!r}"
            )

        if not diff:
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.ALREADY_SET,
            }
        if not apply:
            return {
                "before": before,
                "plan": plan,
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.WOULD_CHANGE,
            }
        if keys["server"] == "Config.Account.SIP.Server":
            raise UnsupportedDialectError(
                "legacy_web",
                host=self.identity.host,
                hint="E18C single-account writes need the keyed /web edit "
                "envelope (action=edit, '<value>&<cfgId>&<keyNum>'), not flat set",
            )

        await self.set_config(diff)
        after_cfg = await self.get_config()
        verified = all(
            str(after_cfg.get(keys[name], "")) == want
            for name, want in wants.items()
            if name != "password"
        )
        after = {name: after_cfg.get(keys[name]) for name in wants if name != "password"}
        after["password_set"] = bool(after_cfg.get(keys["password"]))
        return {
            "before": before,
            "plan": plan,
            "changed": True,
            "applied": True,
            "verdict": (SetVerdict.SET_VERIFIED if verified else SetVerdict.SET_DID_NOT_STICK),
            "after": after,
        }

    async def set_sip_server(
        self,
        account: int,
        primary: str,
        *,
        secondary: str | None = None,
        apply: bool = False,
    ) -> SetResult:
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
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.ACCOUNT_DISABLED,
            }

        diff: dict[str, str] = {}
        plan: dict[str, str] = {}
        if acct["server"] != primary:
            diff[keys["server"]] = primary
            plan["server"] = f"{acct['server']!r} -> {primary!r}"
        if secondary is not None and (acct["server2"] or "") != secondary:
            diff[keys["server2"]] = secondary
            plan["server2"] = f"{acct['server2']!r} -> {secondary!r}"

        if not diff:
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.ALREADY_SET,
            }
        if not apply:
            return {
                "before": before,
                "plan": plan,
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.WOULD_CHANGE,
            }
        if keys["server"] == "Config.Account.SIP.Server":
            raise UnsupportedDialectError(
                "legacy_web",
                host=self.identity.host,
                hint="E18C single-account SIP server needs the keyed /web edit "
                "envelope (action=edit, '<value>&<cfgId>&<keyNum>'), not flat set",
            )
        await self.set_config(diff)
        after = await self.account_sip(account)
        ok = after["server"] == primary and (
            secondary is None or (after["server2"] or "") == secondary
        )
        return {
            "before": before,
            "plan": plan,
            "changed": True,
            "applied": True,
            "verdict": SetVerdict.SET_VERIFIED if ok else SetVerdict.SET_DID_NOT_STICK,
            "after": {"server": after["server"], "server2": after["server2"]},
        }

    async def set_reg_period(
        self,
        account: int,
        seconds: int = 30,
        *,
        apply: bool = False,
    ) -> SetResult:
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
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.ACCOUNT_DISABLED,
            }

        want = str(seconds)
        diff: dict[str, str] = {}
        plan: dict[str, str] = {}
        for field in ("reg_timeout", "reg_timeout2"):
            have = "" if acct[field] is None else str(acct[field])
            if have != want:
                diff[keys[field]] = want
                plan[field] = f"{have!r} -> {want!r}"

        if not diff:
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.ALREADY_SET,
            }
        if not apply:
            return {
                "before": before,
                "plan": plan,
                "changed": False,
                "applied": False,
                "verdict": SetVerdict.WOULD_CHANGE,
            }
        if keys["server"] == "Config.Account.SIP.Server":
            raise UnsupportedDialectError(
                "legacy_web",
                host=self.identity.host,
                hint="E18C single-account writes need the keyed /web edit "
                "envelope (action=edit, '<value>&<cfgId>&<keyNum>'), not flat set",
            )
        await self.set_config(diff)
        after = await self.account_sip(account)
        ok = str(after["reg_timeout"]) == want and str(after["reg_timeout2"]) == want
        return {
            "before": before,
            "plan": plan,
            "changed": True,
            "applied": True,
            "verdict": SetVerdict.SET_VERIFIED if ok else SetVerdict.SET_DID_NOT_STICK,
            "after": {"reg_timeout": after["reg_timeout"], "reg_timeout2": after["reg_timeout2"]},
        }

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
        before = {
            "server": acct["server"],
            "server2": acct["server2"],
            "reg_timeout": acct["reg_timeout"],
            "reg_timeout2": acct["reg_timeout2"],
        }
        if not acct["enabled"]:
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "rebooted": False,
                "verdict": SetVerdict.ACCOUNT_DISABLED,
            }

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
            return {
                "before": before,
                "plan": {},
                "changed": False,
                "applied": False,
                "rebooted": False,
                "verdict": SetVerdict.ALREADY_SET,
            }
        if not apply:
            return {
                "before": before,
                "plan": plan,
                "changed": False,
                "applied": False,
                "rebooted": False,
                "verdict": SetVerdict.WOULD_CHANGE,
            }
        if keys["server"] == "Config.Account.SIP.Server":
            raise UnsupportedDialectError(
                "legacy_web",
                host=self.identity.host,
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
        return {
            "before": before,
            "plan": plan,
            "changed": True,
            "applied": True,
            "rebooted": rebooted,
            "verdict": SetVerdict.SET_VERIFIED if ok else SetVerdict.SET_DID_NOT_STICK,
            "after": {
                "server": after["server"],
                "server2": after["server2"],
                "reg_timeout": after["reg_timeout"],
                "reg_timeout2": after["reg_timeout2"],
            },
        }
