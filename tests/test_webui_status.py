from unittest.mock import AsyncMock

import pytest

from pyakuvox.clients.local.webui import SIPRegistrationStatus, WebUIClient


@pytest.mark.asyncio
async def test_get_sip_account_status_normalizes_registered_account() -> None:
    client = WebUIClient("192.0.2.10")
    client._session_id = "test-session"
    client._read_page = AsyncMock(
        return_value={
            "hcAccountNum": "2",
            "hcAccountName": "&700",
            "hcAccountServer": "&192.0.2.11",
            "hcAccountStatus": "-1&2",
        }
    )

    result = await client.get_sip_account_status(2)

    assert result.username == "700"
    assert result.server == "192.0.2.11"
    assert result.status is SIPRegistrationStatus.REGISTERED
    assert result.raw_status == "2"


@pytest.mark.asyncio
async def test_get_sip_account_status_rejects_missing_account() -> None:
    client = WebUIClient("192.0.2.10")
    client._session_id = "test-session"
    client._read_page = AsyncMock(return_value={"hcAccountNum": "1"})

    with pytest.raises(ValueError, match="unavailable"):
        await client.get_sip_account_status(2)
