"""Akuvox S5xx-family SPA web-API client (the ``/api/web/*`` dialect).

Newer Akuvox door stations (S535/S539 and some R29C firmware) drop the legacy
``/fcgi/do`` web UI for a Vue single-page app that talks JSON to ``/api/web/*``.
Like :class:`~pyakuvox.clients.local.webui.WebUIClient`, the one thing we need it
for is configuring the HTTP API itself (auth mode + credentials) so the headless
:class:`~pyakuvox.clients.local.client.LocalClient` digest ``/api`` can take over.

Protocol (reverse-engineered from the S535 SPA bundle, 2026-06):

  1. POST /api/web/login/set    {target:login,action:set}              -> data.encrypt (nonce)
  2. POST /api/web/login/login  {..,data:{userName,password}}          -> data.token
       password = Base64(nonce + web_password)
  3. send the token as a ``token`` cookie on every subsequent call
  4. POST /api/web/config/get   {..,data:{item:[<keys>]}}              -> data{key:val}
  5. POST /api/web/config/set   {..,data:{<key>:<val>,...}}            -> retcode 0

HTTP-API config lives under ``Config.DoorSetting.APIFCGI.*`` (NOT ``HTTPAPI``).
The API **password** field is plain ``Base64(pw)`` (``encode_config_password_webapi``).

These panels THROTTLE a fast request burst — the login endpoint then returns
``401`` with a stale Digest challenge. That is rate-limiting, **not** a lockout
(the browser still logs in fine). :meth:`login` backs off and retries.
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any

import httpx
import structlog

from pyakuvox.clients.local.encoding import encode_config_password_webapi
from pyakuvox.clients.local.webui import FirmwareAuthMode, HttpApiConfig
from pyakuvox.exceptions import AuthenticationError, ConnectionError, DeviceError

logger = structlog.get_logger(__name__)

_APIFCGI = "Config.DoorSetting.APIFCGI"
_LOGIN_RETRIES = 4
_LOGIN_BACKOFF = 3.0  # seconds, multiplied by attempt number (gentle on throttle)


class WebApiClient:
    """Client for the Akuvox S5xx SPA web API (``/api/web/*``).

    Usage::

        async with WebApiClient(host="192.0.2.10") as web:
            await web.login("admin", "web-password")
            await web.enable_api_access("admin", "api-password")
    """

    def __init__(
        self,
        host: str,
        port: int = 443,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        timeout: int = 15,
    ) -> None:
        self._host = host
        self._port = port
        self._scheme = "https" if use_ssl else "http"
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None

    @property
    def base_url(self) -> str:
        return f"{self._scheme}://{self._host}:{self._port}"

    @property
    def is_authenticated(self) -> bool:
        return self._token is not None

    async def __aenter__(self) -> WebApiClient:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            verify=self._verify_ssl,
            follow_redirects=True,
            headers={"User-Agent": "pyakuvox"},
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        self._token = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if not self._client:
            raise ConnectionError(
                "WebApiClient not initialized — use 'async with' context manager"
            )
        return self._client

    def _ensure_session(self) -> None:
        if not self._token:
            raise AuthenticationError("Not logged in — call login() first")

    async def _post(self, path: str, payload: dict) -> httpx.Response:
        client = self._ensure_client()
        try:
            return await client.post(f"{self.base_url}{path}", json=payload)
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot reach {self._host}: {exc}") from exc

    # ── Login ───────────────────────────────────────────────────────

    async def login(self, username: str, password: str) -> str:
        """Token-login to the SPA web API; returns the session token.

        Retries with backoff when the login endpoint throttles (``401`` on
        ``/api/web/login/set``). Raises after ``_LOGIN_RETRIES`` attempts.

        Raises:
            AuthenticationError: bad credentials, or throttled past the retries.
            ConnectionError: device unreachable.
        """
        log = logger.bind(host=self._host)
        last = ""
        for attempt in range(1, _LOGIN_RETRIES + 1):
            r = await self._post("/api/web/login/set",
                                  {"target": "login", "action": "set"})
            if r.status_code == 200 and r.text.lstrip().startswith("{"):
                nonce = (r.json().get("data") or {}).get("encrypt", "")
                if not nonce:
                    raise AuthenticationError(f"No login nonce from {self._host}")
                enc = base64.b64encode((nonce + password).encode("utf-8")).decode("ascii")
                lr = await self._post("/api/web/login/login", {
                    "target": "login", "action": "login",
                    "data": {"userName": username, "password": enc},
                })
                body = lr.json() if lr.text.lstrip().startswith("{") else {}
                token = (body.get("data") or {}).get("token")
                if token:
                    self._token = token
                    self._ensure_client().cookies.set("token", token, domain=self._host)
                    log.info("webapi_login_success", host=self._host)
                    return token
                raise AuthenticationError(
                    f"Login failed for {username}@{self._host} (retcode={body.get('retcode')})"
                )
            last = f"login/set http{r.status_code}"
            log.debug("webapi_login_throttled", host=self._host,
                      attempt=attempt, status=r.status_code)
            if attempt < _LOGIN_RETRIES:
                await asyncio.sleep(_LOGIN_BACKOFF * attempt)
        raise AuthenticationError(f"Login to {self._host} failed: {last} (throttled?)")

    # ── Config get/set ──────────────────────────────────────────────

    async def _config_get(self, keys: list[str]) -> dict[str, str]:
        self._ensure_session()
        r = await self._post("/api/web/config/get",
                             {"target": "config", "action": "get", "data": {"item": keys}})
        if r.status_code != 200:
            raise DeviceError(f"config/get HTTP {r.status_code} on {self._host}")
        return (r.json().get("data") or {}) if r.text.lstrip().startswith("{") else {}

    async def _config_set(self, data: dict[str, str]) -> None:
        self._ensure_session()
        r = await self._post("/api/web/config/set",
                             {"target": "config", "action": "set", "data": data})
        if r.status_code != 200:
            raise DeviceError(f"config/set HTTP {r.status_code} on {self._host}")
        body = r.json() if r.text.lstrip().startswith("{") else {}
        if body.get("retcode") not in (0, None):
            raise DeviceError(f"config/set retcode={body.get('retcode')} on {self._host}")

    # ── HTTP API config ─────────────────────────────────────────────

    async def get_http_api_config(self) -> HttpApiConfig:
        """Read the current HTTP API configuration (``APIFCGI.*``)."""
        keys = [
            f"{_APIFCGI}.Enable", f"{_APIFCGI}.AuthMode", f"{_APIFCGI}.UserName",
            f"{_APIFCGI}.Password",
            *[f"{_APIFCGI}.WhiteListIP{i:02d}" for i in range(1, 6)],
        ]
        f = await self._config_get(keys)
        ips = [f.get(f"{_APIFCGI}.WhiteListIP{i:02d}", "").strip() for i in range(1, 6)]
        try:
            auth_mode = FirmwareAuthMode(int(f.get(f"{_APIFCGI}.AuthMode", "2") or "2"))
        except ValueError:
            auth_mode = FirmwareAuthMode.WHITELIST
        return HttpApiConfig(
            enabled=f.get(f"{_APIFCGI}.Enable", "0") == "1",
            auth_mode=auth_mode,
            username=f.get(f"{_APIFCGI}.UserName", ""),
            password_set=bool(f.get(f"{_APIFCGI}.Password", "")),
            whitelist_ips=[ip for ip in ips if ip],
            raw_fields=f,
        )

    async def set_http_api_config(
        self,
        *,
        auth_mode: FirmwareAuthMode | None = None,
        username: str | None = None,
        password: str | None = None,
        whitelist_ips: list[str] | None = None,
        enabled: bool | None = None,
    ) -> HttpApiConfig:
        """Update the HTTP API configuration. Only provided fields change.

        The ``password`` is sent as plain Base64 (the SPA's encoding); writing
        the raw password would make digest auth 401.
        """
        data: dict[str, str] = {}
        if enabled is not None:
            data[f"{_APIFCGI}.Enable"] = "1" if enabled else "0"
        if auth_mode is not None:
            data[f"{_APIFCGI}.AuthMode"] = str(auth_mode.value)
        if username is not None:
            data[f"{_APIFCGI}.UserName"] = username
        if password is not None:
            data[f"{_APIFCGI}.Password"] = encode_config_password_webapi(password)
        if whitelist_ips is not None:
            for i in range(1, 6):
                data[f"{_APIFCGI}.WhiteListIP{i:02d}"] = (
                    whitelist_ips[i - 1] if i - 1 < len(whitelist_ips) else ""
                )
        await self._config_set(data)
        logger.info("webapi_config_updated", host=self._host, keys=list(data))
        return await self.get_http_api_config()

    async def enable_api_access(
        self,
        username: str,
        password: str,
        auth_mode: FirmwareAuthMode = FirmwareAuthMode.DIGEST,
    ) -> HttpApiConfig:
        """One-shot: enable the HTTP API with Digest auth + the given creds."""
        return await self.set_http_api_config(
            enabled=True, auth_mode=auth_mode, username=username, password=password,
        )
