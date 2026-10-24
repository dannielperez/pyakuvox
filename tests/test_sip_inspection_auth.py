"""Read-only authentication compatibility never spills into mutation retries."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyakuvox.config import LocalAuthType, LocalSettings
from pyakuvox.exceptions import AuthenticationError, DeviceError
from pyakuvox.operations import inspect_sip_with_auth_detection


@pytest.mark.asyncio
@pytest.mark.parametrize("auth", [LocalAuthType.BASIC, LocalAuthType.DIGEST])
async def test_rejected_basic_only_falls_back_to_digest(auth):
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=object())
    context.__aexit__ = AsyncMock(return_value=None)
    report = {"call_state": "TALKING", "accounts": [], "mac": "00:11:22:33:44:55"}
    with (
        patch("pyakuvox.clients.local.client.LocalClient", return_value=context) as client,
        patch("pyakuvox.sip_recovery.inspect_sip", new_callable=AsyncMock) as inspect,
    ):
        inspect.side_effect = [AuthenticationError("rejected"), report]
        settings = LocalSettings(host="192.0.2.1", auth_type=auth)
        if auth == LocalAuthType.DIGEST:
            with pytest.raises(AuthenticationError):
                await inspect_sip_with_auth_detection(settings)
            assert client.call_count == 1
        else:
            assert await inspect_sip_with_auth_detection(settings) == report
            assert client.call_count == 2
            assert client.call_args.args[0].auth_type == LocalAuthType.DIGEST
            assert settings.auth_type == LocalAuthType.BASIC
        assert all(call.kwargs["max_retries"] == 0 for call in client.call_args_list)


@pytest.mark.asyncio
async def test_other_failures_do_not_change_auth_or_retry():
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=object())
    context.__aexit__ = AsyncMock(return_value=None)
    with (
        patch("pyakuvox.clients.local.client.LocalClient", return_value=context) as client,
        patch("pyakuvox.sip_recovery.inspect_sip", AsyncMock(side_effect=DeviceError("failed"))),
    ):
        with pytest.raises(DeviceError):
            await inspect_sip_with_auth_detection(LocalSettings(host="192.0.2.1"))
        assert client.call_count == 1


@pytest.mark.asyncio
async def test_overall_deadline_cancels_the_read_and_closes_client():
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=object())
    context.__aexit__ = AsyncMock(return_value=None)

    async def wait(client):
        await asyncio.Event().wait()

    with (
        patch("pyakuvox.clients.local.client.LocalClient", return_value=context) as client,
        patch("pyakuvox.sip_recovery.inspect_sip", side_effect=wait),
    ):
        with pytest.raises(TimeoutError):
            await inspect_sip_with_auth_detection(
                LocalSettings(host="192.0.2.1"), timeout_seconds=0.01
            )
        assert client.call_count == 1
        context.__aexit__.assert_awaited_once()
