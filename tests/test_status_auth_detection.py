"""Native status uses the same bounded authentication policy as identity reads."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyakuvox.clients.local.parsers import parse_device_info
from pyakuvox.config import LocalAuthType, LocalSettings
from pyakuvox.exceptions import AuthenticationError, DeviceError, ParseError
from pyakuvox.operations import read_status_with_auth_detection


def client():
    result = MagicMock()
    result.__aenter__ = AsyncMock(return_value=result)
    result.__aexit__ = AsyncMock(return_value=False)
    result.get_device_info = AsyncMock(return_value="identity")
    result.get_relay_status = AsyncMock(return_value=["relay"])
    return result


@pytest.mark.parametrize("failed_read", ["get_device_info", "get_relay_status"])
async def test_rejected_basic_read_reuses_transport_and_credentials(failed_read):
    first, second = client(), client()
    getattr(first, failed_read).side_effect = AuthenticationError("rejected")
    settings = LocalSettings(host="192.0.2.1", port=443, use_ssl=True, password="synthetic")
    with patch("pyakuvox.clients.local.client.LocalClient", side_effect=[first, second]) as build:
        assert await read_status_with_auth_detection(settings) == ("identity", ["relay"])
    assert build.call_count == 2
    detected = build.call_args.args[0]
    assert detected.auth_type == LocalAuthType.DIGEST
    assert detected.password == settings.password
    assert detected.host == settings.host and detected.port == 443 and detected.use_ssl
    assert settings.auth_type == LocalAuthType.BASIC
    assert all(c.kwargs == {"max_retries": 0} for c in build.call_args_list)


@pytest.mark.parametrize("error", [ParseError("bad shape"), DeviceError("failed"), OSError()])
async def test_non_auth_failures_are_not_retried(error):
    mock = client()
    mock.get_device_info.side_effect = error
    with (
        patch("pyakuvox.clients.local.client.LocalClient", return_value=mock) as build,
        pytest.raises(type(error)),
    ):
        await read_status_with_auth_detection(LocalSettings(host="192.0.2.1"))
    build.assert_called_once()
    mock.get_relay_status.assert_not_awaited()


async def test_explicit_digest_rejection_does_not_fallback():
    mock = client()
    mock.get_device_info.side_effect = AuthenticationError("rejected")
    with (
        patch("pyakuvox.clients.local.client.LocalClient", return_value=mock) as build,
        pytest.raises(AuthenticationError),
    ):
        await read_status_with_auth_detection(
            LocalSettings(host="192.0.2.1", auth_type=LocalAuthType.DIGEST)
        )
    build.assert_called_once()


async def test_deadline_includes_relay_read_and_closes_client():
    mock = client()

    async def wait():
        await asyncio.Event().wait()

    mock.get_relay_status.side_effect = wait
    settings = LocalSettings(host="192.0.2.1").model_copy(update={"timeout": 0.01})
    with (
        patch("pyakuvox.clients.local.client.LocalClient", return_value=mock),
        pytest.raises(TimeoutError),
    ):
        await read_status_with_auth_detection(settings)
    mock.__aexit__.assert_awaited_once()


def test_s539_wrapped_identity_retains_hardware_and_uptime():
    info = parse_device_info(
        {
            "retcode": 0,
            "data": {
                "Status": {
                    "MAC": "00:11:22:33:44:55",
                    "Model": "S539",
                    "HardwareVersion": "539.1.0.0",
                    "FirmwareVersion": "539.30.10.523",
                    "Uptime": "up 0 weeks, 1 day",
                }
            },
        }
    )
    assert info.identity.model == "S539"
    assert info.identity.hardware_version == "539.1.0.0"
    assert info.firmware_version == "539.30.10.523"
    assert info.uptime == "up 0 weeks, 1 day"
