"""Consumer-contract tests mirroring UniqueOS's pyakuvox boundary.

The replay fixtures are sanitized and all transport is in-process. These tests
pin the exports, exceptions, settings, and typed results that UniqueOS consumes
through ``uniqueos.devices.services.akuvox_sdk``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock

import httpx
from pydantic import SecretStr

import pyakuvox
from pyakuvox import (
    AkuvoxDevice,
    AkuvoxError,
    ApiDialect,
    AuthenticationError,
    ConnectionError,
    DeviceIdentity,
    LocalAuthType,
    LocalClient,
    LocalSettings,
    SetVerdict,
    TimeoutError,
    UnsupportedDialectError,
    identify,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "uniqueos"


def _fixture(name: str) -> dict[str, object]:
    return cast(
        "dict[str, object]",
        json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8")),
    )


def _response(payload: dict[str, object]) -> httpx.Response:
    return httpx.Response(
        status_code=200,
        json=payload,
        request=httpx.Request("GET", "http://device.example.invalid/api/system/info"),
    )


class TestPublicBoundary:
    """Pin the names and error hierarchy imported by UniqueOS."""

    def test_consumer_critical_names_are_exported(self) -> None:
        required = {
            "AkuvoxDevice",
            "AkuvoxError",
            "AuthenticationError",
            "ConnectionError",
            "DeviceIdentity",
            "LocalAuthType",
            "LocalClient",
            "LocalSettings",
            "SetVerdict",
            "TimeoutError",
            "UnsupportedDialectError",
            "identify",
        }

        assert required <= set(pyakuvox.__all__)
        assert all(getattr(pyakuvox, name) is not None for name in required)

    def test_consumer_catch_hierarchy_is_stable(self) -> None:
        for error_type in (
            AuthenticationError,
            ConnectionError,
            TimeoutError,
            UnsupportedDialectError,
        ):
            assert issubclass(error_type, AkuvoxError)

    def test_guided_action_verdict_vocabulary_is_stable(self) -> None:
        assert {verdict.value for verdict in SetVerdict} == {
            "would-change",
            "already-set",
            "set-verified",
            "set-did-not-stick",
            "account-disabled",
        }


class TestConsumerConstruction:
    """Mirror the settings/client construction used by UniqueOS adapters."""

    def test_settings_accept_the_consumer_keyword_contract(self) -> None:
        settings = LocalSettings(
            host="device.example.invalid",
            port=8443,
            username="operator",
            password=SecretStr("synthetic-password"),
            auth_type=LocalAuthType.DIGEST,
            use_ssl=True,
            verify_ssl=False,
            timeout=7,
        )

        assert settings.base_url == "https://device.example.invalid:8443"
        assert settings.auth_type is LocalAuthType.DIGEST
        assert settings.timeout == 7

    def test_from_client_reuses_settings_without_identification_probe(self) -> None:
        client = LocalClient(
            LocalSettings(
                host="device.example.invalid",
                port=80,
                password=SecretStr("synthetic-password"),
                auth_type=LocalAuthType.BASIC,
            ),
            max_retries=0,
        )

        device = AkuvoxDevice.from_client(client)

        assert device.identity == DeviceIdentity(
            host="device.example.invalid",
            port=80,
            reachable=True,
            dialect=ApiDialect.DIGEST_API,
        )


class TestSanitizedReplay:
    """Replay canonical responses through the same typed SDK seams."""

    def test_local_device_info_replay_returns_typed_identity(self) -> None:
        async def exercise() -> None:
            client = LocalClient(
                LocalSettings(
                    host="device.example.invalid",
                    password=SecretStr("synthetic-password"),
                ),
                max_retries=0,
            )
            client._client = AsyncMock()
            client._client.request = AsyncMock(
                return_value=_response(_fixture("device_info.json")),
            )

            info = await client.get_device_info()

            assert info.identity.model == "X916S"
            assert info.identity.normalized_mac() == "02:00:00:00:00:01"
            assert info.firmware_version == "916.30.10.114"
            assert info.identity.hardware_version == "1.0"

        asyncio.run(exercise())

    def test_unauthenticated_identification_replay_returns_typed_result(self) -> None:
        payload = _fixture("identify_web_api.json")

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/system/info":
                return httpx.Response(308, headers={"location": "/"})
            if request.url.path == "/api/web/system/info":
                return httpx.Response(200, json=payload)
            return httpx.Response(404)

        identity = asyncio.run(
            identify(
                "device.example.invalid",
                transport=httpx.MockTransport(handler),
            ),
        )

        assert isinstance(identity, DeviceIdentity)
        assert identity.reachable is True
        assert identity.dialect.value == "web_api"
        assert identity.model == "S539"
        assert identity.firmware == "539.30.10.428"
        assert identity.hardware == "1.0"
        assert identity.headless_manageable is False
