"""Akuvox local HTTP API client.

Communicates directly with Akuvox devices on the LAN via their
built-in HTTP API. Endpoint paths based on pylocal-akuvox source code.

Verified endpoints (from pylocal-akuvox):
  GET  /api/system/info     → device identity + firmware
  GET  /api/system/status   → uptime, system time
  POST /api/relay/trigger   → unlock door/gate
  GET  /api/relay/status    → relay states
  GET  /api/user/list       → user/PIN list (paginated)
  POST /api/user/add        → add user
  POST /api/user/set        → modify user
  POST /api/user/del        → delete user
  GET  /api/schedule/list   → schedule list (paginated)
  POST /api/schedule/add    → add schedule
  POST /api/schedule/set    → modify schedule
  POST /api/schedule/del    → delete schedule
  GET  /api/log/door        → door access log (paginated)
  GET  /api/log/call        → call log (paginated)
  GET  /api/config/get      → full device config
  POST /api/config/set      → update device config

Unverified / experimental:
  - Reboot endpoint (likely exists, path unknown)
  - Firmware update endpoint
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from pyakuvox.clients.base import AkuvoxClientBase
from pyakuvox.clients.local.auth import build_auth
from pyakuvox.clients.local.parsers import (
    parse_call_logs,
    parse_device_info,
    parse_device_status,
    parse_door_logs,
    parse_firmware_info,
    parse_relay_status,
    parse_schedules,
    parse_users,
)
from pyakuvox.config import LocalSettings
from pyakuvox.exceptions import (
    AuthenticationError,
    ConnectionError,
    DeviceError,
    ParseError,
    TimeoutError,
)
from pyakuvox.logging_config import redact_headers
from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState
from pyakuvox.models.events import CallEvent, DoorEvent, RelayActionResult
from pyakuvox.models.firmware import FirmwareInfo
from pyakuvox.models.schedules import Schedule
from pyakuvox.models.users import UserCode

logger = structlog.get_logger(__name__)


class LocalClient(AkuvoxClientBase):
    """HTTP client for direct LAN communication with Akuvox devices."""

    def __init__(self, settings: LocalSettings) -> None:
        self._settings = settings
        self._base_url = settings.base_url
        self._auth = build_auth(settings)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> LocalClient:
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            auth=self._auth,
            timeout=httpx.Timeout(self._settings.timeout),
            verify=self._settings.verify_ssl,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Raw HTTP ────────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request and return parsed JSON.

        Handles error mapping: HTTP errors → our exception hierarchy.
        Logs request/response at debug level with redacted headers.
        """
        if not self._client:
            raise ConnectionError("Client not initialized — use 'async with' context manager")

        log = logger.bind(method=method, path=path, host=self._settings.host)
        log.debug("request_start", params=params)

        try:
            response = await self._client.request(
                method,
                path,
                params=params,
                data=data,
                json=json_body,
            )
        except httpx.ConnectError as exc:
            log.error("connection_failed", error=str(exc))
            raise ConnectionError(f"Cannot reach {self._base_url}: {exc}") from exc
        except httpx.TimeoutException as exc:
            log.error("request_timeout", error=str(exc))
            raise TimeoutError(f"Request to {path} timed out") from exc

        log.debug(
            "response_received",
            status=response.status_code,
            headers=redact_headers(dict(response.headers)),
        )

        if response.status_code == 401:
            raise AuthenticationError(
                f"Authentication failed for {self._base_url} "
                f"(auth_type={self._settings.auth_type})"
            )
        if response.status_code == 403:
            raise AuthenticationError(f"Access forbidden for {path}")

        if response.status_code >= 400:
            raise DeviceError(
                f"Device returned HTTP {response.status_code} for {method} {path}: "
                f"{response.text[:200]}"
            )

        try:
            return response.json()
        except Exception as exc:
            log.error("json_parse_failed", body=response.text[:500])
            raise ParseError(
                f"Invalid JSON from {path}", raw_data=response.text[:500]
            ) from exc

    async def _get(self, path: str, **params: Any) -> dict[str, Any]:
        return await self._request("GET", path, params=params or None)

    async def _post(self, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("POST", path, data=data)

    async def _post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", path, json_body=body)

    # ── Device info ─────────────────────────────────────────────────

    async def get_device_info(self) -> DeviceInfo:
        data = await self._get("/api/system/info")
        return parse_device_info(data, ip_address=self._settings.host)

    async def get_device_status(self) -> DeviceStatus:
        data = await self._get("/api/system/status")
        info = await self.get_device_info()
        return parse_device_status(data, mac_address=info.identity.mac_address)

    async def get_firmware_info(self) -> FirmwareInfo:
        data = await self._get("/api/system/info")
        return parse_firmware_info(data)

    # ── Relay / door control ────────────────────────────────────────

    async def get_relay_status(self) -> list[RelayState]:
        data = await self._get("/api/relay/status")
        return parse_relay_status(data)

    async def trigger_relay(self, relay_num: int = 1, delay: int = 5) -> RelayActionResult:
        """Trigger a relay to unlock a door.

        Args:
            relay_num: Relay number (1-based). Most devices have 1-2 relays.
            delay: Hold time in seconds before the relay closes.
        """
        logger.info("relay_trigger", relay=relay_num, delay=delay, host=self._settings.host)
        try:
            await self._post_json("/api/relay/trigger", {
                "num": relay_num,
                "mode": 0,
                "level": 0,
                "delay": delay,
            })
            return RelayActionResult(
                relay_number=relay_num,
                success=True,
                message=f"Relay {relay_num} triggered for {delay}s",
                delay_seconds=delay,
                source="local",
            )
        except Exception as exc:
            return RelayActionResult(
                relay_number=relay_num,
                success=False,
                message=str(exc),
                delay_seconds=delay,
                source="local",
            )

    # ── Users ───────────────────────────────────────────────────────

    async def list_users(self, page: int | None = None) -> list[UserCode]:
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        data = await self._get("/api/user/list", **params)
        # Response may be {"UserList": [...]} or a bare list
        user_list = data.get("UserList", data) if isinstance(data, dict) else data
        if not isinstance(user_list, list):
            raise ParseError("Expected list in user response", raw_data=data)
        return parse_users(user_list)

    # ── Schedules ───────────────────────────────────────────────────

    async def list_schedules(self, page: int | None = None) -> list[Schedule]:
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        data = await self._get("/api/schedule/list", **params)
        schedule_list = data.get("ScheduleList", data) if isinstance(data, dict) else data
        if not isinstance(schedule_list, list):
            raise ParseError("Expected list in schedule response", raw_data=data)
        return parse_schedules(schedule_list)

    # ── Logs ────────────────────────────────────────────────────────

    async def get_door_logs(self, page: int | None = None) -> list[DoorEvent]:
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        data = await self._get("/api/log/door", **params)
        log_list = data.get("DoorLog", data) if isinstance(data, dict) else data
        if not isinstance(log_list, list):
            raise ParseError("Expected list in door log response", raw_data=data)
        return parse_door_logs(log_list)

    async def get_call_logs(self, page: int | None = None) -> list[CallEvent]:
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        data = await self._get("/api/log/call", **params)
        log_list = data.get("CallLog", data) if isinstance(data, dict) else data
        if not isinstance(log_list, list):
            raise ParseError("Expected list in call log response", raw_data=data)
        return parse_call_logs(log_list)

    # ── Config ──────────────────────────────────────────────────────

    async def get_config(self) -> dict[str, Any]:
        return await self._get("/api/config/get")

    async def set_config(self, settings: dict[str, str]) -> None:
        await self._post_json("/api/config/set", settings)

    # ── Experimental / unverified ───────────────────────────────────

    async def reboot(self) -> bool:
        """Attempt to reboot the device.

        TODO: Endpoint path is unverified. Trying common patterns.
        This may not work on all models/firmware versions.
        """
        logger.warning("reboot_attempt", host=self._settings.host,
                       note="Unverified endpoint — may fail")
        try:
            await self._post("/api/system/reboot")
            return True
        except DeviceError:
            # Try alternative path
            try:
                await self._post_json("/api/system/reboot", {"action": "reboot"})
                return True
            except Exception:
                return False

    # ── Raw exploration helpers ─────────────────────────────────────

    async def raw_get(self, path: str, **params: Any) -> dict[str, Any]:
        """Make a raw GET request — useful for endpoint exploration."""
        return await self._get(path, **params)

    async def raw_post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """Make a raw POST request — useful for endpoint exploration."""
        return await self._post_json(path, body)
