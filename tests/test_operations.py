from unittest.mock import AsyncMock, patch

import pytest

from pyakuvox.clients.local.webui import (
    ConfigPasswordEncoding,
    SIPAccountStatus,
    SIPRegistrationStatus,
)
from pyakuvox.exceptions import UnsupportedFeatureError
from pyakuvox.operations import read_sip_account_status


@pytest.mark.asyncio
async def test_x916_status_uses_https_and_model_selected_client() -> None:
    expected = SIPAccountStatus(2, "700", "192.0.2.11", SIPRegistrationStatus.REGISTERED, "2")
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.get_sip_account_status.return_value = expected

    with patch("pyakuvox.operations.WebUIClient", return_value=client) as client_class:
        result = await read_sip_account_status(
            "192.0.2.241",
            2,
            username="admin",
            password="secret",
            model="X916",
        )

    assert result is expected
    client_class.assert_called_once_with(
        host="192.0.2.241",
        port=443,
        use_ssl=True,
        verify_ssl=False,
        timeout=15,
        password_encoding=ConfigPasswordEncoding.X916,
    )
    client.login.assert_awaited_once_with("admin", "secret")
    client.get_sip_account_status.assert_awaited_once_with(2)


@pytest.mark.asyncio
async def test_unknown_model_status_is_not_guessed() -> None:
    with patch("pyakuvox.operations.identify", new=AsyncMock()) as identify_mock:
        identify_mock.return_value.model = ""
        with pytest.raises(UnsupportedFeatureError):
            await read_sip_account_status(
                "192.0.2.10",
                1,
                username="admin",
                password="secret",
            )
