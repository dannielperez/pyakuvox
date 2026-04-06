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

import asyncio
from typing import Any

import httpx
import structlog

from pyakuvox.capabilities import Provider, SupportLevel, build_default_matrix
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
    ExperimentalFeatureWarning,
    ParseError,
    TimeoutError,
    UnsupportedFeatureError,
)
from pyakuvox.logging_config import redact_headers
from pyakuvox.models.device import DeviceInfo, DeviceStatus, RelayState
from pyakuvox.models.events import CallEvent, DoorEvent, RelayActionResult
from pyakuvox.models.firmware import FirmwareInfo
from pyakuvox.models.schedules import Schedule
from pyakuvox.models.users import UserCode

logger = structlog.get_logger(__name__)

# Transient HTTP status codes eligible for retry.
_TRANSIENT_STATUS_CODES = frozenset({502, 503, 504})

# Default retry configuration.
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_RETRY_BACKOFF = 0.5  # seconds; doubles each attempt

# Pagination hard ceiling to prevent infinite loops on misbehaving devices.
_MAX_PAGES = 100


class LocalClient(AkuvoxClientBase):
    """HTTP client for direct LAN communication with Akuvox devices.

    Args:
        settings: Connection settings (host, port, auth, timeouts).
        max_retries: Number of retries for transient transport failures (0 = disable).
        retry_backoff: Initial backoff in seconds; doubles on each retry.
    """

    def __init__(
        self,
        settings: LocalSettings,
        *,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        retry_backoff: float = _DEFAULT_RETRY_BACKOFF,
    ) -> None:
        self._settings = settings
        self._base_url = settings.base_url
        self._auth = build_auth(settings)
        self._client: httpx.AsyncClient | None = None
        self._max_retries = max_retries
        self._retry_backoff = retry_backoff
        self._capability_matrix = build_default_matrix()

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

    # ── Capability guardrails ───────────────────────────────────────

    def _check_capability(self, feature: str) -> None:
        """Check the capability matrix before executing an operation.

        Raises UnsupportedFeatureError for UNSUPPORTED features.
        Logs a warning for UNVERIFIED features but allows execution.
        """
        cap = self._capability_matrix.get(feature, Provider.LOCAL_HTTP)
        if cap is None:
            return  # Unknown feature — allow optimistically
        if cap.level == SupportLevel.UNSUPPORTED:
            raise UnsupportedFeatureError(feature, Provider.LOCAL_HTTP)
        if cap.level == SupportLevel.UNVERIFIED:
            logger.warning(
                "experimental_feature",
                feature=feature,
                notes=cap.notes,
                msg=f"Feature '{feature}' is UNVERIFIED — may fail or behave unexpectedly",
            )

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

        Handles:
        - Error mapping: HTTP errors → our exception hierarchy
        - Retry with exponential backoff for transient transport/5xx failures
        - Request/response logging with redacted secrets
        - Response shape validation
        """
        if not self._client:
            raise ConnectionError("Client not initialized — use 'async with' context manager")

        log = logger.bind(method=method, path=path, host=self._settings.host)
        log.debug("request_start", params=params, has_body=json_body is not None or data is not None)

        last_exc: Exception | None = None
        for attempt in range(1, self._max_retries + 2):  # attempt 1 = initial, rest = retries
            try:
                response = await self._client.request(
                    method,
                    path,
                    params=params,
                    data=data,
                    json=json_body,
                )
            except httpx.ConnectError as exc:
                last_exc = exc
                if attempt <= self._max_retries:
                    wait = self._retry_backoff * (2 ** (attempt - 1))
                    log.warning("connection_failed_retrying", error=str(exc), attempt=attempt, wait=wait)
                    await asyncio.sleep(wait)
                    continue
                log.error("connection_failed", error=str(exc), attempts=attempt)
                raise ConnectionError(f"Cannot reach {self._base_url}: {exc}") from exc
            except httpx.TimeoutException as exc:
                last_exc = exc
                if attempt <= self._max_retries:
                    wait = self._retry_backoff * (2 ** (attempt - 1))
                    log.warning("timeout_retrying", error=str(exc), attempt=attempt, wait=wait)
                    await asyncio.sleep(wait)
                    continue
                log.error("request_timeout", error=str(exc), attempts=attempt)
                raise TimeoutError(f"Request to {path} timed out after {attempt} attempt(s)") from exc

            log.debug(
                "response_received",
                status=response.status_code,
                headers=redact_headers(dict(response.headers)),
                content_length=len(response.content),
            )

            # Retry on transient server errors
            if response.status_code in _TRANSIENT_STATUS_CODES and attempt <= self._max_retries:
                wait = self._retry_backoff * (2 ** (attempt - 1))
                log.warning(
                    "transient_error_retrying",
                    status=response.status_code,
                    attempt=attempt,
                    wait=wait,
                )
                await asyncio.sleep(wait)
                continue

            # Non-retryable status codes
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

            # Validate response body before JSON parsing
            body_text = response.text.strip()
            if not body_text:
                raise ParseError(f"Empty response body from {method} {path}", raw_data="")

            try:
                result = response.json()
            except Exception as exc:
                log.error("json_parse_failed", body_preview=body_text[:200])
                raise ParseError(
                    f"Invalid JSON from {path}", raw_data=body_text[:500]
                ) from exc

            if not isinstance(result, dict):
                raise ParseError(
                    f"Expected JSON object from {path}, got {type(result).__name__}",
                    raw_data=result,
                )

            # Check for device-level error codes (retcode != 0)
            retcode = result.get("retcode")
            if retcode is not None and retcode != 0:
                error_msg = result.get("message", result.get("msg", f"retcode={retcode}"))
                raise DeviceError(f"Device error on {method} {path}: {error_msg}")

            return result

        # Should not reach here, but just in case
        raise ConnectionError(f"Request to {path} failed after retries") from last_exc

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

        WARNING: Endpoint path is UNVERIFIED. Tries common patterns.
        This may not work on all models/firmware versions.

        The capability matrix marks this as ``UNVERIFIED`` — a warning
        is logged but execution is allowed.
        """
        self._check_capability("reboot")
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

    # ── Paginated fetch helpers ─────────────────────────────────────

    async def _fetch_all_pages(
        self,
        path: str,
        list_key: str,
        parser: Any,
        *,
        max_pages: int = _MAX_PAGES,
    ) -> list[Any]:
        """Fetch all pages of a paginated endpoint.

        Stops when a page returns an empty list or ``max_pages`` is reached.

        Args:
            path: API endpoint path.
            list_key: JSON key containing the list (e.g. "UserList").
            parser: Callable that converts ``list[dict]`` → ``list[Model]``.
            max_pages: Safety ceiling to prevent infinite loops.
        """
        all_items: list[Any] = []
        for page in range(1, max_pages + 1):
            data = await self._get(path, page=page)
            raw_list = data.get(list_key, data) if isinstance(data, dict) else data
            if not isinstance(raw_list, list):
                raise ParseError(f"Expected list under '{list_key}'", raw_data=data)
            if not raw_list:
                break
            all_items.extend(parser(raw_list))
            # If this page returned fewer items than previous pages, assume last page.
            # Also stop if the response indicates no more pages.
            total = data.get("Total") or data.get("total")
            if total is not None and len(all_items) >= int(total):
                break
        logger.debug("pagination_complete", path=path, total_items=len(all_items))
        return all_items

    async def list_all_users(self) -> list[UserCode]:
        """Fetch all users across all pages."""
        return await self._fetch_all_pages("/api/user/list", "UserList", parse_users)

    async def list_all_schedules(self) -> list[Schedule]:
        """Fetch all schedules across all pages."""
        return await self._fetch_all_pages("/api/schedule/list", "ScheduleList", parse_schedules)

    async def list_all_door_logs(self) -> list[DoorEvent]:
        """Fetch all door log entries across all pages."""
        return await self._fetch_all_pages("/api/log/door", "DoorLog", parse_door_logs)

    async def list_all_call_logs(self) -> list[CallEvent]:
        """Fetch all call log entries across all pages."""
        return await self._fetch_all_pages("/api/log/call", "CallLog", parse_call_logs)
