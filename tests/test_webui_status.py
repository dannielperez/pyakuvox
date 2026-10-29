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


@pytest.mark.asyncio
async def test_x916_homepage_account_writes_only_selector_and_verifies():
    client = WebUIClient("192.0.2.10")
    client._read_page = AsyncMock(
        side_effect=[{"hcBuildingDialType": "0"}, {"hcBuildingDialType": "2"}]
    )
    client._write_page = AsyncMock(return_value=200)
    result = await client.ensure_x916_homepage_dial_account(2, apply=True)
    assert result["verdict"] == "set-verified"
    client._write_page.assert_awaited_once_with(
        "id=130&id=19", "begin&Operation=Submit&cBuildingDialType=2&SubmitData=end"
    )


@pytest.mark.asyncio
async def test_x916_homepage_account_already_set_does_not_write():
    client = WebUIClient("192.0.2.10")
    client._read_page = AsyncMock(return_value={"hcBuildingDialType": "2"})
    client._write_page = AsyncMock()
    result = await client.ensure_x916_homepage_dial_account(2, apply=True)
    assert result["verdict"] == "already-set"
    client._write_page.assert_not_awaited()


@pytest.mark.asyncio
async def test_x916_homepage_account_missing_surface_is_not_success():
    client = WebUIClient("192.0.2.10")
    client._read_page = AsyncMock(return_value={})
    client._write_page = AsyncMock()
    result = await client.ensure_x916_homepage_dial_account(2, apply=True)
    assert result["verdict"] == "unsupported-firmware"
    client._write_page.assert_not_awaited()


@pytest.mark.asyncio
async def test_x916_homepage_account_requires_readback():
    client = WebUIClient("192.0.2.10")
    client._read_page = AsyncMock(return_value={"hcBuildingDialType": "0"})
    client._write_page = AsyncMock(return_value=200)
    result = await client.ensure_x916_homepage_dial_account(2, apply=True)
    assert result["verdict"] == "set-did-not-stick"
