"""Unit tests for LocalClient with mocked httpx responses.

Covers: success paths, malformed JSON, 401/403, 5xx, timeouts,
connection errors, pagination, retry/backoff, response validation,
and capability guardrails.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from pyakuvox.clients.local.client import LocalClient
from pyakuvox.config import LocalAuthType, LocalSettings
from pyakuvox.exceptions import (
    AuthenticationError,
    ConnectionError,
    DeviceError,
    ParseError,
    TimeoutError,
    UnsupportedFeatureError,
)


# ── Helpers ─────────────────────────────────────────────────────────


def _settings(**overrides: object) -> LocalSettings:
    defaults: dict[str, object] = {
        "host": "192.168.1.100",
        "port": 80,
        "username": "admin",
        "password": "admin",
        "auth_type": LocalAuthType.BASIC,
        "timeout": 5,
    }
    defaults.update(overrides)
    return LocalSettings(**defaults)  # type: ignore[arg-type]


def _response(
    status: int = 200,
    json_body: dict | list | None = None,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response."""
    if json_body is not None:
        content = json.dumps(json_body).encode()
        _headers = {"content-type": "application/json"}
    else:
        content = text.encode()
        _headers = {"content-type": "text/plain"}
    if headers:
        _headers.update(headers)
    return httpx.Response(
        status_code=status,
        content=content,
        headers=_headers,
        request=httpx.Request("GET", "http://test/"),
    )


# Canonical device-info response from real Akuvox hardware.
_DEVICE_INFO_RESPONSE = {
    "retcode": 0,
    "Status": {
        "MAC": "AA:BB:CC:DD:EE:FF",
        "Model": "X916S",
        "FirmwareVersion": "916.30.10.114",
        "HardwareVersion": "1.0",
        "Uptime": "3d 2h",
    },
}

_DEVICE_STATUS_RESPONSE = {
    "retcode": 0,
    "SystemTime": "1700000000",
    "UpTime": "86400",
}

_RELAY_STATUS_RESPONSE = {
    "retcode": 0,
    "Relay1": "closed",
    "Relay2": "open",
}

_USER_LIST_RESPONSE = {
    "retcode": 0,
    "UserList": [
        {"ID": "1", "Name": "Alice", "UserID": "001", "PrivatePIN": "1234"},
        {"ID": "2", "Name": "Bob", "UserID": "002", "CardCode": "ABCD"},
    ],
}

_SCHEDULE_LIST_RESPONSE = {
    "retcode": 0,
    "ScheduleList": [
        {"ID": "1", "Name": "Business", "Type": "1", "TimeStart": "09:00", "TimeEnd": "17:00"},
    ],
}

_DOOR_LOG_RESPONSE = {
    "retcode": 0,
    "DoorLog": [
        {"ID": "1", "Date": "2024-01-15", "Time": "10:30", "Name": "Alice", "Status": "ok"},
    ],
}

_CALL_LOG_RESPONSE = {
    "retcode": 0,
    "CallLog": [
        {"ID": "1", "Date": "2024-01-15", "Time": "11:00", "Name": "Lobby", "Type": "in"},
    ],
}

_CONFIG_RESPONSE = {
    "retcode": 0,
    "SIP.Port": "5060",
    "Network.DHCP": "1",
}

_RELAY_TRIGGER_RESPONSE = {"retcode": 0}


# ── Fixture ─────────────────────────────────────────────────────────


@pytest.fixture()
def client():
    """Provide a LocalClient with retry disabled for deterministic tests."""
    return LocalClient(_settings(), max_retries=0)


@pytest.fixture()
def retry_client():
    """Provide a LocalClient with retry enabled (max 2 retries, fast backoff)."""
    return LocalClient(_settings(), max_retries=2, retry_backoff=0.01)


# ── Success path tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_device_info_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_DEVICE_INFO_RESPONSE))
        info = await client.get_device_info()
    assert info.identity.mac_address == "AA:BB:CC:DD:EE:FF"
    assert info.identity.model == "X916S"
    assert info.firmware_version == "916.30.10.114"


@pytest.mark.asyncio
async def test_get_device_status_success(client):
    async with client:
        client._client = AsyncMock()
        # get_device_status calls _get twice (status + info for MAC)
        client._client.request = AsyncMock(
            side_effect=[
                _response(json_body=_DEVICE_STATUS_RESPONSE),
                _response(json_body=_DEVICE_INFO_RESPONSE),
            ]
        )
        status = await client.get_device_status()
    assert status.uptime_seconds == 86400
    assert status.unix_time == 1700000000


@pytest.mark.asyncio
async def test_get_firmware_info_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_DEVICE_INFO_RESPONSE))
        fw = await client.get_firmware_info()
    assert fw.current_version == "916.30.10.114"
    assert fw.model == "X916S"


@pytest.mark.asyncio
async def test_get_relay_status_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_RELAY_STATUS_RESPONSE))
        relays = await client.get_relay_status()
    assert len(relays) == 2


@pytest.mark.asyncio
async def test_trigger_relay_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_RELAY_TRIGGER_RESPONSE))
        result = await client.trigger_relay(relay_num=1, delay=5)
    assert result.success is True
    assert result.relay_number == 1


@pytest.mark.asyncio
async def test_list_users_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_USER_LIST_RESPONSE))
        users = await client.list_users()
    assert len(users) == 2
    assert users[0].name == "Alice"


@pytest.mark.asyncio
async def test_list_schedules_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_SCHEDULE_LIST_RESPONSE))
        schedules = await client.list_schedules()
    assert len(schedules) == 1
    assert schedules[0].name == "Business"


@pytest.mark.asyncio
async def test_get_door_logs_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_DOOR_LOG_RESPONSE))
        logs = await client.get_door_logs()
    assert len(logs) == 1
    assert logs[0].user_name == "Alice"


@pytest.mark.asyncio
async def test_get_call_logs_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_CALL_LOG_RESPONSE))
        logs = await client.get_call_logs()
    assert len(logs) == 1


@pytest.mark.asyncio
async def test_get_config_success(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body=_CONFIG_RESPONSE))
        cfg = await client.get_config()
    assert cfg["SIP.Port"] == "5060"


@pytest.mark.asyncio
async def test_set_config_success(client):
    async with client:
        mock = AsyncMock()
        mock.request = AsyncMock(return_value=_response(json_body={"retcode": 0}))
        client._client = mock
        await client.set_config({"SIP.Port": "5060"})
    mock.request.assert_called_once()


@pytest.mark.asyncio
async def test_raw_get(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body={"retcode": 0, "foo": "bar"}))
        data = await client.raw_get("/api/custom/endpoint")
    assert data["foo"] == "bar"


@pytest.mark.asyncio
async def test_raw_post(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body={"retcode": 0}))
        data = await client.raw_post("/api/custom/endpoint", {"key": "val"})
    assert data["retcode"] == 0


# ── Error handling tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_401_raises_auth_error(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(status=401, text="Unauthorized"))
    with pytest.raises(AuthenticationError, match="Authentication failed"):
        async with client:
            client._client = AsyncMock()
            client._client.request = AsyncMock(return_value=_response(status=401, text="Unauthorized"))
            await client.get_device_info()


@pytest.mark.asyncio
async def test_403_raises_auth_error(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(status=403, text="Forbidden"))
        with pytest.raises(AuthenticationError, match="forbidden"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_404_raises_device_error(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(status=404, text="Not Found"))
        with pytest.raises(DeviceError, match="404"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_500_raises_device_error(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(status=500, text="Internal Error"))
        with pytest.raises(DeviceError, match="500"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_connection_error(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(ConnectionError, match="Cannot reach"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_timeout_error(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(side_effect=httpx.ReadTimeout("timed out"))
        with pytest.raises(TimeoutError, match="timed out"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_malformed_json_raises_parse_error(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(
            return_value=_response(text="<html>not json</html>")
        )
        with pytest.raises(ParseError, match="Invalid JSON"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_empty_response_raises_parse_error(client):
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(text=""))
        with pytest.raises(ParseError, match="Empty response"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_non_dict_json_raises_parse_error(client):
    """Response is valid JSON but an array instead of an object."""
    resp = _response(json_body=[1, 2, 3])  # type: ignore[arg-type]
    # Override content to be a JSON array
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=httpx.Response(
            status_code=200,
            content=b"[1,2,3]",
            headers={"content-type": "application/json"},
            request=httpx.Request("GET", "http://test/"),
        ))
        with pytest.raises(ParseError, match="Expected JSON object"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_device_retcode_error(client):
    """Device returns 200 OK but retcode != 0."""
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(
            return_value=_response(json_body={"retcode": -1, "message": "sensor failure"})
        )
        with pytest.raises(DeviceError, match="sensor failure"):
            await client.get_device_info()


@pytest.mark.asyncio
async def test_client_not_initialized():
    client = LocalClient(_settings(), max_retries=0)
    with pytest.raises(ConnectionError, match="not initialized"):
        await client.get_device_info()


# ── Retry / backoff tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_retry_on_connect_error(retry_client):
    """Retry succeeds after transient connect failure."""
    mock = AsyncMock()
    mock.request = AsyncMock(
        side_effect=[
            httpx.ConnectError("temporary"),
            _response(json_body=_DEVICE_INFO_RESPONSE),
        ]
    )
    async with retry_client:
        retry_client._client = mock
        info = await retry_client.get_device_info()
    assert info.identity.model == "X916S"
    assert mock.request.call_count == 2


@pytest.mark.asyncio
async def test_retry_on_timeout(retry_client):
    """Retry succeeds after transient timeout."""
    async with retry_client:
        retry_client._client = AsyncMock()
        retry_client._client.request = AsyncMock(
            side_effect=[
                httpx.ReadTimeout("timed out"),
                _response(json_body=_DEVICE_INFO_RESPONSE),
            ]
        )
        info = await retry_client.get_device_info()
    assert info.identity.model == "X916S"


@pytest.mark.asyncio
async def test_retry_on_503(retry_client):
    """Retry succeeds after transient 503."""
    async with retry_client:
        retry_client._client = AsyncMock()
        retry_client._client.request = AsyncMock(
            side_effect=[
                _response(status=503, text="Service Unavailable"),
                _response(json_body=_DEVICE_INFO_RESPONSE),
            ]
        )
        info = await retry_client.get_device_info()
    assert info.identity.model == "X916S"


@pytest.mark.asyncio
async def test_retry_exhausted_raises(retry_client):
    """After max retries are exhausted, exception is raised."""
    mock = AsyncMock()
    mock.request = AsyncMock(
        side_effect=httpx.ConnectError("persistent failure")
    )
    async with retry_client:
        retry_client._client = mock
        with pytest.raises(ConnectionError):
            await retry_client.get_device_info()
    # initial + 2 retries = 3 total calls
    assert mock.request.call_count == 3


@pytest.mark.asyncio
async def test_retry_timeout_exhausted(retry_client):
    """Timeout retries exhaust and raise TimeoutError."""
    async with retry_client:
        retry_client._client = AsyncMock()
        retry_client._client.request = AsyncMock(
            side_effect=httpx.ReadTimeout("persistent")
        )
        with pytest.raises(TimeoutError, match="after 3 attempt"):
            await retry_client.get_device_info()


@pytest.mark.asyncio
async def test_no_retry_on_401(retry_client):
    """Auth errors are never retried."""
    mock = AsyncMock()
    mock.request = AsyncMock(
        return_value=_response(status=401, text="Unauthorized")
    )
    async with retry_client:
        retry_client._client = mock
        with pytest.raises(AuthenticationError):
            await retry_client.get_device_info()
    # Should be called exactly once — no retries
    assert mock.request.call_count == 1


@pytest.mark.asyncio
async def test_no_retry_on_404(retry_client):
    """Client errors (non-5xx) are not retried."""
    mock = AsyncMock()
    mock.request = AsyncMock(
        return_value=_response(status=404, text="Not Found")
    )
    async with retry_client:
        retry_client._client = mock
        with pytest.raises(DeviceError):
            await retry_client.get_device_info()
    assert mock.request.call_count == 1


# ── Pagination tests ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_all_users_pagination(client):
    """list_all_users fetches pages until an empty list."""
    page1 = {"retcode": 0, "UserList": [
        {"ID": "1", "Name": "Alice", "UserID": "001"},
        {"ID": "2", "Name": "Bob", "UserID": "002"},
    ]}
    page2 = {"retcode": 0, "UserList": [
        {"ID": "3", "Name": "Charlie", "UserID": "003"},
    ]}
    page3 = {"retcode": 0, "UserList": []}

    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(
            side_effect=[
                _response(json_body=page1),
                _response(json_body=page2),
                _response(json_body=page3),
            ]
        )
        users = await client.list_all_users()
    assert len(users) == 3
    assert users[2].name == "Charlie"


@pytest.mark.asyncio
async def test_list_all_users_with_total_field(client):
    """Pagination stops when Total is reached."""
    page = {"retcode": 0, "Total": 2, "UserList": [
        {"ID": "1", "Name": "Alice", "UserID": "001"},
        {"ID": "2", "Name": "Bob", "UserID": "002"},
    ]}
    mock = AsyncMock()
    mock.request = AsyncMock(return_value=_response(json_body=page))
    async with client:
        client._client = mock
        users = await client.list_all_users()
    assert len(users) == 2
    # Only one page fetched since Total matches count
    assert mock.request.call_count == 1


@pytest.mark.asyncio
async def test_list_all_schedules_pagination(client):
    page1 = {"retcode": 0, "ScheduleList": [
        {"ID": "1", "Name": "Weekday", "Type": "1"},
    ]}
    page2 = {"retcode": 0, "ScheduleList": []}

    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(
            side_effect=[
                _response(json_body=page1),
                _response(json_body=page2),
            ]
        )
        schedules = await client.list_all_schedules()
    assert len(schedules) == 1


@pytest.mark.asyncio
async def test_list_all_door_logs_pagination(client):
    page1 = {"retcode": 0, "DoorLog": [
        {"ID": "1", "Date": "2024-01-01", "Time": "10:00", "Name": "A", "Status": "ok"},
    ]}
    page2 = {"retcode": 0, "DoorLog": []}

    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(
            side_effect=[
                _response(json_body=page1),
                _response(json_body=page2),
            ]
        )
        logs = await client.list_all_door_logs()
    assert len(logs) == 1


@pytest.mark.asyncio
async def test_list_all_call_logs_pagination(client):
    page1 = {"retcode": 0, "CallLog": [
        {"ID": "1", "Date": "2024-01-01", "Time": "11:00", "Name": "Lobby", "Type": "in"},
    ]}
    page2 = {"retcode": 0, "CallLog": []}

    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(
            side_effect=[
                _response(json_body=page1),
                _response(json_body=page2),
            ]
        )
        logs = await client.list_all_call_logs()
    assert len(logs) == 1


# ── Capability guardrail tests ─────────────────────────────────────


@pytest.mark.asyncio
async def test_reboot_warns_unverified(client):
    """Reboot is UNVERIFIED — should warn but not refuse."""
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=_response(json_body={"retcode": 0}))
        result = await client.reboot()
    assert result is True


@pytest.mark.asyncio
async def test_capability_unsupported_raises():
    """Directly calling _check_capability with an unsupported feature raises."""
    client = LocalClient(_settings(), max_retries=0)
    with pytest.raises(UnsupportedFeatureError):
        client._check_capability("temp_key_list")


# ── Trigger relay failure path ──────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_relay_failure_returns_result(client):
    """trigger_relay returns a failure result instead of raising."""
    async with client:
        client._client = AsyncMock()
        client._client.request = AsyncMock(side_effect=httpx.ConnectError("down"))
        result = await client.trigger_relay(relay_num=2, delay=3)
    assert result.success is False
    assert result.relay_number == 2


# ── Page parameter forwarding ──────────────────────────────────────


@pytest.mark.asyncio
async def test_list_users_page_param(client):
    """list_users(page=2) sends the page parameter."""
    mock = AsyncMock()
    mock.request = AsyncMock(return_value=_response(json_body=_USER_LIST_RESPONSE))
    async with client:
        client._client = mock
        await client.list_users(page=2)
    call_kwargs = mock.request.call_args
    assert call_kwargs[1]["params"] == {"page": 2}


@pytest.mark.asyncio
async def test_list_users_no_page_param(client):
    """list_users() without page sends no params."""
    mock = AsyncMock()
    mock.request = AsyncMock(return_value=_response(json_body=_USER_LIST_RESPONSE))
    async with client:
        client._client = mock
        await client.list_users()
    call_kwargs = mock.request.call_args
    assert call_kwargs[1]["params"] is None
