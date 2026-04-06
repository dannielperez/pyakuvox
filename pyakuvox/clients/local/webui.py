"""Akuvox web UI client for device configuration.

Communicates with the Akuvox device's web management interface to
read and write settings that are NOT exposed via the HTTP API — most
importantly, the HTTP API configuration itself (auth mode, credentials,
IP whitelist).

Protocol reverse-engineered from the Akuvox X916 web UI
(firmware 916.30.10.114, lighttpd/1.4.30). Flow:

  1. GET  /fcgi/do?action=Encrypt       → random 32-char hex nonce
  2. POST /fcgi/do?id=1 (CreateSession) → session token
  3. GET  /fcgi/do?id=<page>            → read config page (hidden fields)
  4. POST /fcgi/do?id=<page>            → submit config changes

Auth modes (firmware field hcAuthMode):
  0 = None (no auth — anyone on the network can call the API)
  1 = Basic Auth (BROKEN on some firmware — always returns "unknow")
  2 = IP WhiteList (requires IPs to be pre-registered)
  3 = Digest (server-side only? — returns 401 even with correct creds)
  4 = Digest Auth (works correctly — recommended)
  5 = Basic + Digest hybrid (works with Basic creds)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import httpx
import structlog

from pyakuvox.clients.local.encoding import (
    encode_config_password,
    encode_login_password,
    post_encode,
)
from pyakuvox.exceptions import AuthenticationError, ConnectionError, DeviceError

logger = structlog.get_logger(__name__)

# Config page for HTTP API settings.
_HTTP_API_CONFIG_PAGE = "id=130&id=16"


class FirmwareAuthMode(IntEnum):
    """HTTP API auth modes as stored in the device firmware.

    These are the raw values for the hcAuthMode config field.
    Discovered by brute-force testing modes 0–5 on real hardware.
    """

    NONE = 0
    BASIC = 1  # Broken on firmware 916.30.10.114
    WHITELIST = 2
    DIGEST_SERVER = 3  # Server-side only — clients get 401
    DIGEST = 4  # Recommended for programmatic access
    BASIC_DIGEST = 5  # Hybrid — accepts Basic credentials


@dataclass
class HttpApiConfig:
    """Current HTTP API configuration read from the device web UI."""

    enabled: bool = False
    auth_mode: FirmwareAuthMode = FirmwareAuthMode.WHITELIST
    username: str = ""
    password_set: bool = False  # We can detect if set but can't read the value
    whitelist_ips: list[str] = field(default_factory=list)
    raw_fields: dict[str, str] = field(default_factory=dict)


class WebUIClient:
    """Client for the Akuvox device web management interface.

    Used to configure the HTTP API (auth mode, credentials, IP whitelist)
    before the main ``LocalClient`` can communicate with the device.

    Usage::

        async with WebUIClient(host="192.0.2.10") as webui:
            await webui.login("admin", "password")
            config = await webui.get_http_api_config()
            await webui.set_http_api_config(
                auth_mode=FirmwareAuthMode.DIGEST,
                username="admin",
                password="password",
            )
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        use_ssl: bool = False,
        verify_ssl: bool = False,
        timeout: int = 15,
    ) -> None:
        self._host = host
        self._port = port
        self._scheme = "https" if use_ssl else "http"
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None

    @property
    def base_url(self) -> str:
        return f"{self._scheme}://{self._host}:{self._port}"

    @property
    def is_authenticated(self) -> bool:
        return self._session_id is not None

    async def __aenter__(self) -> WebUIClient:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            verify=self._verify_ssl,
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        self._session_id = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if not self._client:
            raise ConnectionError(
                "WebUIClient not initialized — use 'async with' context manager"
            )
        return self._client

    def _ensure_session(self) -> None:
        if not self._session_id:
            raise AuthenticationError("Not logged in — call login() first")

    # ── Login ───────────────────────────────────────────────────────

    async def login(self, username: str, password: str) -> str:
        """Authenticate with the Akuvox web management interface.

        Returns the session ID on success.

        Raises:
            AuthenticationError: If login fails (bad credentials or no nonce).
            ConnectionError: If the device is unreachable.
        """
        client = self._ensure_client()
        log = logger.bind(host=self._host)

        # Step 1: Get encryption nonce
        try:
            resp = await client.get(f"{self.base_url}/fcgi/do?action=Encrypt")
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot reach {self._host}: {exc}") from exc

        match = re.search(r"value='([^']*)'", resp.text)
        if not match or not match.group(1):
            raise AuthenticationError(
                f"Failed to get encryption nonce from {self._host}"
            )
        nonce = match.group(1)
        log.debug("webui_nonce_received", nonce_len=len(nonce))

        # Step 2: Encode credentials
        encoded_password = encode_login_password(nonce, password)
        encoded_username = post_encode(username)

        # Set cookies expected by the web UI
        client.cookies.set("UserName", username, domain=self._host)
        client.cookies.set("Password", encoded_password, domain=self._host)

        # Step 3: Create session
        submit_data = (
            f"begin&Operation=CreateSession&DestURL=id`C1"
            f"&UserName={encoded_username}"
            f"&Password={encoded_password}"
            f"&SubmitData=end"
        )
        resp = await client.post(
            f"{self.base_url}/fcgi/do?id=1",
            data={"SubmitData": submit_data},
        )

        session_match = re.search(r"hcSessionIdNow.*?value='([^']*)'", resp.text)
        if not session_match or not session_match.group(1):
            raise AuthenticationError(
                f"Login failed for {username}@{self._host} — no session token returned"
            )

        self._session_id = session_match.group(1)
        client.cookies.set("SessionId", self._session_id, domain=self._host)
        log.info("webui_login_success", host=self._host)
        return self._session_id

    # ── Config page helpers ─────────────────────────────────────────

    async def _read_page(self, page_id: str) -> dict[str, str]:
        """Read a web UI config page and extract all hidden field values.

        Returns a dict of field_name → value from the HTML hidden inputs.
        """
        client = self._ensure_client()
        self._ensure_session()

        resp = await client.get(f"{self.base_url}/fcgi/do?{page_id}")
        fields: dict[str, str] = {}
        for match in re.finditer(
            r"id=(hc\w+)\s+type=hidden\s+value='([^']*)'", resp.text
        ):
            fields[match.group(1)] = match.group(2)
        return fields

    async def _write_page(self, page_id: str, submit_data: str) -> int:
        """Submit a config change to a web UI page.

        Returns the HTTP status code of the response.
        """
        client = self._ensure_client()
        self._ensure_session()

        resp = await client.post(
            f"{self.base_url}/fcgi/do?{page_id}",
            data={"SubmitData": submit_data},
        )
        return resp.status_code

    # ── HTTP API config ─────────────────────────────────────────────

    async def get_http_api_config(self) -> HttpApiConfig:
        """Read the current HTTP API configuration from the device.

        Returns an HttpApiConfig with the current auth mode, username,
        whitelist IPs, and whether a password is set.
        """
        self._ensure_session()
        fields = await self._read_page(_HTTP_API_CONFIG_PAGE)
        logger.debug("webui_config_read", host=self._host, fields=fields)

        # Parse whitelist IPs (hcIP_01 through hcIP_05)
        ips: list[str] = []
        for i in range(1, 6):
            ip = fields.get(f"hcIP_{i:02d}", "").strip()
            if ip:
                ips.append(ip)

        auth_mode_raw = int(fields.get("hcAuthMode", "2"))
        try:
            auth_mode = FirmwareAuthMode(auth_mode_raw)
        except ValueError:
            logger.warning("webui_unknown_auth_mode", mode=auth_mode_raw)
            auth_mode = FirmwareAuthMode(auth_mode_raw)

        return HttpApiConfig(
            enabled=fields.get("hcEnable", "0") == "1",
            auth_mode=auth_mode,
            username=fields.get("hcUserName", ""),
            password_set=bool(fields.get("hcPassword", "")),
            whitelist_ips=ips,
            raw_fields=fields,
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
        """Update the HTTP API configuration on the device.

        Only provided fields are changed; others are left as-is.
        Returns the updated config (re-read from the device).

        Args:
            auth_mode: Which auth method the HTTP API should require.
            username: API username (used with Basic/Digest auth).
            password: API password (will be Base64+PostEncoded before submission).
            whitelist_ips: Up to 5 IP addresses for whitelist mode.
            enabled: Whether the HTTP API is enabled at all.
        """
        self._ensure_session()
        log = logger.bind(host=self._host)

        parts: list[str] = ["begin", "Operation=Submit"]

        if enabled is not None:
            parts.append(f"cEnable={'1' if enabled else '0'}")

        if auth_mode is not None:
            parts.append(f"cAuthMode={auth_mode.value}")
            log.info("webui_set_auth_mode", mode=auth_mode.name, value=auth_mode.value)

        if username is not None:
            parts.append(f"cUserName={post_encode(username)}")

        if password is not None:
            parts.append(f"cPassword={encode_config_password(password)}")

        if whitelist_ips is not None:
            for i in range(5):
                ip = whitelist_ips[i] if i < len(whitelist_ips) else ""
                parts.append(f"cIP_{i + 1:02d}={post_encode(ip)}")

        parts.append("SubmitData=end")
        submit_data = "&".join(parts)

        status = await self._write_page(_HTTP_API_CONFIG_PAGE, submit_data)
        if status >= 400:
            raise DeviceError(
                f"Config submission failed with HTTP {status} on {self._host}"
            )

        log.info("webui_config_updated", host=self._host)
        return await self.get_http_api_config()

    async def enable_api_access(
        self,
        username: str,
        password: str,
        auth_mode: FirmwareAuthMode = FirmwareAuthMode.DIGEST,
    ) -> HttpApiConfig:
        """One-shot convenience: configure Digest auth for API access.

        Sets auth mode to Digest (mode 4) by default — the most secure
        option that works reliably across tested firmware versions.

        Note: Does NOT send the ``enabled`` flag because some firmware
        versions (e.g. R29C) reject the entire submission when cEnable
        is included. The HTTP API is enabled by default on all tested
        models.

        Args:
            username: API username.
            password: API password.
            auth_mode: Auth mode to set (default: Digest).
        """
        return await self.set_http_api_config(
            auth_mode=auth_mode,
            username=username,
            password=password,
        )
