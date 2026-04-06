"""CLI tests using Typer's CliRunner + mocks."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from pyakuvox.cli.main import app
from pyakuvox.clients.local.webui import FirmwareAuthMode, HttpApiConfig
from pyakuvox.discovery import DiscoveredDevice
from pyakuvox.exceptions import AuthenticationError, ConnectionError, TimeoutError
from pyakuvox.models.device import (
    DeviceIdentity,
    DeviceInfo,
    DeviceSource,
    DeviceStatus,
    OnlineStatus,
    RelayState,
)
from pyakuvox.models.events import (
    CallEvent,
    DoorEvent,
    EventSource,
    EventType,
    RelayActionResult,
)
from pyakuvox.models.firmware import FirmwareInfo
from pyakuvox.models.schedules import Schedule, ScheduleType
from pyakuvox.models.users import UserCode

runner = CliRunner()


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture()
def mock_local_client():
    """Patch LocalClient so all commands hit a mock instead of a real device."""
    client = AsyncMock()

    # async context-manager protocol
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    with patch("pyakuvox.cli.local_cmd._get_client", return_value=client):
        yield client


@pytest.fixture()
def mock_webui_client():
    """Patch WebUIClient for webui commands."""
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.is_authenticated = True

    with (
        patch("pyakuvox.cli.webui_cmd._get_webui_client", return_value=client),
        patch("pyakuvox.cli.webui_cmd._get_creds", return_value=("admin", "admin")),
    ):
        yield client


# ── Sample data ─────────────────────────────────────────────────────

_DEVICE_INFO = DeviceInfo(
    identity=DeviceIdentity(mac_address="AA:BB:CC:DD:EE:FF", model="X916S"),
    firmware_version="916.30.10.114",
    ip_address="192.168.1.100",
    source=DeviceSource.LOCAL,
)

_DEVICE_STATUS = DeviceStatus(
    mac_address="AA:BB:CC:DD:EE:FF",
    unix_time=1700000000,
    uptime_seconds=86400,
    online=OnlineStatus.ONLINE,
)

_FIRMWARE_INFO = FirmwareInfo(
    mac_address="AA:BB:CC:DD:EE:FF",
    current_version="916.30.10.114",
    hardware_version="1.0",
    model="X916S",
)

_RELAY_STATES = [
    RelayState(number=1, state="closed", name="Front Door"),
    RelayState(number=2, state="closed", name="Gate"),
]

_RELAY_RESULT = RelayActionResult(
    relay_number=1,
    success=True,
    message="Relay 1 triggered for 5s",
    delay_seconds=5,
    source="local",
)

_USERS = [
    UserCode(name="Alice", user_id="001", private_pin="1234"),
    UserCode(name="Bob", user_id="002", card_code="ABCD"),
]

_SCHEDULES = [
    Schedule(id="1", name="Business Hours", schedule_type=ScheduleType.WEEKLY, time_start="09:00", time_end="17:00"),
]

_DOOR_EVENTS = [
    DoorEvent(
        event_type=EventType.DOOR_ACCESS,
        date_str="2024-01-15",
        time_str="10:30:00",
        user_name="Alice",
        status="success",
    ),
]

_CALL_EVENTS = [
    CallEvent(
        date_str="2024-01-15",
        time_str="11:00:00",
        caller_name="Front Desk",
        call_type="incoming",
        count="1",
    ),
]

_CONFIG = {"SIP.Port": "5060", "Network.DHCP": "1"}

_HTTP_API_CONFIG = HttpApiConfig(
    enabled=True,
    auth_mode=FirmwareAuthMode.DIGEST,
    username="admin",
    password_set=True,
    whitelist_ips=["192.168.1.10"],
)


# ── Root / help tests ──────────────────────────────────────────────


def test_root_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "akuvox" in result.output.lower() or "Akuvox" in result.output


def test_local_help():
    result = runner.invoke(app, ["local", "--help"])
    assert result.exit_code == 0
    assert "device-info" in result.output


def test_webui_help():
    result = runner.invoke(app, ["webui", "--help"])
    assert result.exit_code == 0
    assert "login-check" in result.output


def test_discover_help():
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_raw_help():
    result = runner.invoke(app, ["raw", "--help"])
    assert result.exit_code == 0
    assert "get" in result.output


# ── Local commands ──────────────────────────────────────────────────


def test_device_info(mock_local_client):
    mock_local_client.get_device_info.return_value = _DEVICE_INFO
    result = runner.invoke(app, ["local", "device-info"])
    assert result.exit_code == 0
    assert "X916S" in result.output


def test_device_info_json(mock_local_client):
    mock_local_client.get_device_info.return_value = _DEVICE_INFO
    result = runner.invoke(app, ["--json", "local", "device-info"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["identity"]["model"] == "X916S"


def test_status(mock_local_client):
    mock_local_client.get_device_status.return_value = _DEVICE_STATUS
    result = runner.invoke(app, ["local", "status"])
    assert result.exit_code == 0
    assert "86400" in result.output


def test_firmware(mock_local_client):
    mock_local_client.get_firmware_info.return_value = _FIRMWARE_INFO
    result = runner.invoke(app, ["local", "firmware"])
    assert result.exit_code == 0
    assert "916.30.10.114" in result.output


def test_relay_status(mock_local_client):
    mock_local_client.get_relay_status.return_value = _RELAY_STATES
    result = runner.invoke(app, ["local", "relay-status"])
    assert result.exit_code == 0
    assert "Front Door" in result.output


def test_unlock(mock_local_client):
    mock_local_client.trigger_relay.return_value = _RELAY_RESULT
    result = runner.invoke(app, ["local", "unlock"])
    assert result.exit_code == 0
    assert "triggered" in result.output.lower() or "✓" in result.output


def test_unlock_with_options(mock_local_client):
    mock_local_client.trigger_relay.return_value = _RELAY_RESULT
    result = runner.invoke(app, ["local", "unlock", "--relay", "2", "--delay", "10"])
    assert result.exit_code == 0
    mock_local_client.trigger_relay.assert_called_once_with(relay_num=2, delay=10)


def test_users_list(mock_local_client):
    mock_local_client.list_users.return_value = _USERS
    result = runner.invoke(app, ["local", "users", "list"])
    assert result.exit_code == 0
    assert "Alice" in result.output


def test_users_list_all(mock_local_client):
    mock_local_client.list_all_users.return_value = _USERS
    result = runner.invoke(app, ["local", "users", "list-all"])
    assert result.exit_code == 0
    assert "Alice" in result.output
    mock_local_client.list_all_users.assert_called_once()


def test_schedules_list(mock_local_client):
    mock_local_client.list_schedules.return_value = _SCHEDULES
    result = runner.invoke(app, ["local", "schedules", "list"])
    assert result.exit_code == 0
    assert "Business Hours" in result.output


def test_schedules_list_all(mock_local_client):
    mock_local_client.list_all_schedules.return_value = _SCHEDULES
    result = runner.invoke(app, ["local", "schedules", "list-all"])
    assert result.exit_code == 0
    assert "Business Hours" in result.output
    mock_local_client.list_all_schedules.assert_called_once()


def test_door_logs(mock_local_client):
    mock_local_client.get_door_logs.return_value = _DOOR_EVENTS
    result = runner.invoke(app, ["local", "door-logs"])
    assert result.exit_code == 0
    assert "Alice" in result.output


def test_door_logs_all(mock_local_client):
    mock_local_client.list_all_door_logs.return_value = _DOOR_EVENTS
    result = runner.invoke(app, ["local", "door-logs", "--all"])
    assert result.exit_code == 0
    assert "Alice" in result.output
    mock_local_client.list_all_door_logs.assert_called_once()


def test_call_logs(mock_local_client):
    mock_local_client.get_call_logs.return_value = _CALL_EVENTS
    result = runner.invoke(app, ["local", "call-logs"])
    assert result.exit_code == 0
    assert "Front Desk" in result.output


def test_call_logs_all(mock_local_client):
    mock_local_client.list_all_call_logs.return_value = _CALL_EVENTS
    result = runner.invoke(app, ["local", "call-logs", "--all"])
    assert result.exit_code == 0
    assert "Front Desk" in result.output
    mock_local_client.list_all_call_logs.assert_called_once()


def test_config_get(mock_local_client):
    mock_local_client.get_config.return_value = _CONFIG
    result = runner.invoke(app, ["local", "config", "get"])
    assert result.exit_code == 0
    assert "SIP.Port" in result.output


def test_config_set(mock_local_client):
    mock_local_client.set_config.return_value = None
    result = runner.invoke(app, ["local", "config", "set", "SIP.Port=5060"])
    assert result.exit_code == 0
    mock_local_client.set_config.assert_called_once_with({"SIP.Port": "5060"})


def test_config_set_multiple(mock_local_client):
    mock_local_client.set_config.return_value = None
    result = runner.invoke(app, ["local", "config", "set", "A=1", "B=2"])
    assert result.exit_code == 0
    mock_local_client.set_config.assert_called_once_with({"A": "1", "B": "2"})


def test_reboot_with_yes(mock_local_client):
    mock_local_client.reboot.return_value = True
    result = runner.invoke(app, ["local", "reboot", "--yes"])
    assert result.exit_code == 0


def test_reboot_aborted(mock_local_client):
    result = runner.invoke(app, ["local", "reboot"], input="n\n")
    assert result.exit_code != 0


# ── JSON output mode ───────────────────────────────────────────────


def test_users_list_json(mock_local_client):
    mock_local_client.list_users.return_value = _USERS
    result = runner.invoke(app, ["--json", "local", "users", "list"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert data[0]["name"] == "Alice"


def test_config_get_json(mock_local_client):
    mock_local_client.get_config.return_value = _CONFIG
    result = runner.invoke(app, ["--json", "local", "config", "get"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["SIP.Port"] == "5060"


# ── WebUI commands ──────────────────────────────────────────────────


def test_webui_login_check(mock_webui_client):
    mock_webui_client.login.return_value = "abc12345deadbeef"
    result = runner.invoke(app, ["webui", "login-check"])
    assert result.exit_code == 0
    assert "Login OK" in result.output


def test_webui_get_http_api_config(mock_webui_client):
    mock_webui_client.login.return_value = "session123"
    mock_webui_client.get_http_api_config.return_value = _HTTP_API_CONFIG
    result = runner.invoke(app, ["webui", "get-http-api-config"])
    assert result.exit_code == 0
    assert "admin" in result.output


def test_webui_enable_api(mock_webui_client):
    mock_webui_client.login.return_value = "session123"
    mock_webui_client.enable_api_access.return_value = _HTTP_API_CONFIG
    result = runner.invoke(
        app,
        ["webui", "enable-api", "--username", "admin", "--password", "secret", "--yes"],
    )
    assert result.exit_code == 0


# ── Discovery commands ──────────────────────────────────────────────


def test_discover_scan():
    devices = [
        DiscoveredDevice(ip="192.168.1.10", model="X916S", mac_address="AA:BB:CC:DD:EE:FF"),
    ]
    with patch("pyakuvox.cli.discover_cmd.scan_targets", new_callable=AsyncMock, return_value=devices):
        result = runner.invoke(app, ["discover", "scan", "192.168.1.0/24"])
    assert result.exit_code == 0
    assert "X916S" in result.output


def test_discover_scan_json():
    devices = [
        DiscoveredDevice(ip="192.168.1.10", model="X916S", mac_address="AA:BB:CC:DD:EE:FF"),
    ]
    with patch("pyakuvox.cli.discover_cmd.scan_targets", new_callable=AsyncMock, return_value=devices):
        result = runner.invoke(app, ["--json", "discover", "scan", "192.168.1.0/24"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data[0]["model"] == "X916S"


# ── Capabilities command ────────────────────────────────────────────


def test_capabilities():
    result = runner.invoke(app, ["capabilities"])
    assert result.exit_code == 0
    assert "device_info" in result.output


def test_capabilities_filter_feature():
    result = runner.invoke(app, ["capabilities", "--feature", "device_info"])
    assert result.exit_code == 0
    assert "device_info" in result.output


def test_capabilities_filter_provider():
    result = runner.invoke(app, ["capabilities", "--provider", "local_http"])
    assert result.exit_code == 0
    assert "local_http" in result.output


def test_capabilities_json():
    result = runner.invoke(app, ["--json", "capabilities"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert any(c["feature"] == "device_info" for c in data)


# ── Raw commands ────────────────────────────────────────────────────


def test_raw_get():
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.raw_get.return_value = {"retcode": 0, "data": {"foo": "bar"}}
    with patch("pyakuvox.cli.raw_cmd._get_client", return_value=client):
        result = runner.invoke(app, ["raw", "get", "/api/system/info"])
    assert result.exit_code == 0
    assert "foo" in result.output


def test_raw_post():
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.raw_post.return_value = {"retcode": 0}
    with patch("pyakuvox.cli.raw_cmd._get_client", return_value=client):
        result = runner.invoke(app, ["raw", "post", "/api/relay/trigger", "--body", '{"num":1}'])
    assert result.exit_code == 0


# ── Error handling ──────────────────────────────────────────────────


def test_auth_error_exit_code(mock_local_client):
    mock_local_client.get_device_info.side_effect = AuthenticationError("bad creds")
    result = runner.invoke(app, ["local", "device-info"])
    assert result.exit_code == 2


def test_connection_error_exit_code(mock_local_client):
    mock_local_client.get_device_info.side_effect = ConnectionError("unreachable")
    result = runner.invoke(app, ["local", "device-info"])
    assert result.exit_code == 3


def test_timeout_error_exit_code(mock_local_client):
    mock_local_client.get_device_info.side_effect = TimeoutError("timed out")
    result = runner.invoke(app, ["local", "device-info"])
    assert result.exit_code == 4


# ── Verbose / debug flags ──────────────────────────────────────────


def test_verbose_flag(mock_local_client):
    mock_local_client.get_device_info.return_value = _DEVICE_INFO
    result = runner.invoke(app, ["--verbose", "local", "device-info"])
    assert result.exit_code == 0


def test_debug_http_flag(mock_local_client):
    mock_local_client.get_device_info.return_value = _DEVICE_INFO
    result = runner.invoke(app, ["--debug-http", "local", "device-info"])
    assert result.exit_code == 0
