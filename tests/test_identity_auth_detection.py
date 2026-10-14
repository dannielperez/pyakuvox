from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyakuvox.config import LocalAuthType, LocalSettings
from pyakuvox.exceptions import AuthenticationError
from pyakuvox.operations import read_device_info_with_auth_detection


def client(result):
    mock = MagicMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    mock.get_device_info = AsyncMock(
        side_effect=result if isinstance(result, Exception) else None, return_value=result
    )
    return mock


@pytest.mark.asyncio
async def test_basic_rejection_uses_same_credentials_with_digest():
    settings = LocalSettings(host="192.0.2.1", username="user", password="synthetic")
    with patch(
        "pyakuvox.clients.local.client.LocalClient",
        side_effect=[client(AuthenticationError("rejected")), client("identity")],
    ) as build:
        assert await read_device_info_with_auth_detection(settings) == "identity"
    assert build.call_args_list[1].args[0].auth_type == LocalAuthType.DIGEST
    assert build.call_args_list[1].args[0].password == settings.password
    assert settings.auth_type == LocalAuthType.BASIC


@pytest.mark.asyncio
async def test_explicit_digest_does_not_retry_rejected_credentials():
    settings = LocalSettings(host="192.0.2.1", auth_type=LocalAuthType.DIGEST)
    with (
        patch(
            "pyakuvox.clients.local.client.LocalClient",
            return_value=client(AuthenticationError("rejected")),
        ) as build,
        pytest.raises(AuthenticationError),
    ):
        await read_device_info_with_auth_detection(settings)
    build.assert_called_once()
