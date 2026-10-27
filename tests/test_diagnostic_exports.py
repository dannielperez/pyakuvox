import gzip
import tarfile
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from pyakuvox.config import LocalSettings
from pyakuvox.diagnostic_exports import DiagnosticArtifact, export_path, export_system_log


def test_artifact_repr_does_not_disclose_contents():
    artifact = DiagnosticArtifact("system_log", "mac", "model", "fw", "hash", b"secret")
    assert "secret" not in repr(artifact)


@pytest.mark.parametrize(
    "path",
    [
        "https://elsewhere/download/a",
        "//elsewhere/download/a",
        "/download/../secret",
        "/download/%2e%2e/secret",
        "/download/%252e%252e/secret",
        "/download/a?token=x",
        "/download/a#fragment",
        "/download/a\\b",
        "/other/file",
        "1",
    ],
)
def test_rejects_unsafe_download_paths(path):
    with pytest.raises(ValueError):
        export_path(f"<input id=hcExportLog_Div value='{path}'>", "ExportLog")


def test_exact_operation_and_html_attribute_formats():
    assert (
        export_path("<input id=hcExportLog_Div value='/download/PhoneLog.tgz'>", "ExportLog")
        == "/download/PhoneLog.tgz"
    )
    with pytest.raises(ValueError):
        export_path("<input id=hcExportConfig_Div value='/download/file'>", "ExportLog")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["ok", "tar", "identity", "changed_identity", "oversized", "html", "redirect", "truncated"],
)
async def test_export_checks_identity_and_bounded_stream(case):
    payload = gzip.compress(b"x" * 30) if case != "html" else b"<html>login</html>"
    if case == "tar":
        output = BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            member = tarfile.TarInfo("log.txt")
            member.size = 5
            archive.addfile(member, BytesIO(b"hello"))
        payload = output.getvalue()
    if case == "truncated":
        payload = payload[:-4]
    web = MagicMock()
    web.base_url = "http://192.0.2.1:80"
    web.login = AsyncMock()
    web._get = AsyncMock(
        side_effect=[
            httpx.Response(200, text="<input id=BtnExportLog value=Export>"),
            httpx.Response(200, text="<input id=hcExportLog_Div value='/download/PhoneLog.tgz'>"),
        ]
    )
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302 if case == "redirect" else 200, content=payload)
        )
    )
    web._ensure_client.return_value = client
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=web)
    context.__aexit__ = AsyncMock(return_value=None)
    info = SimpleNamespace(
        identity=SimpleNamespace(
            model="R29C",
            normalized_mac=lambda: "DIFFERENT" if case == "identity" else "00:11:22:33:44:55",
        ),
        firmware_version="29.30.10.19",
    )
    after = SimpleNamespace(identity=SimpleNamespace(normalized_mac=lambda: "CHANGED"))
    with (
        patch("pyakuvox.diagnostic_exports.WebUIClient", return_value=context),
        patch(
            "pyakuvox.diagnostic_exports.read_device_info_with_auth_detection",
            AsyncMock(side_effect=[info, after if case == "changed_identity" else info]),
        ),
    ):
        try:
            if case in {"ok", "tar"}:
                result = await export_system_log(
                    LocalSettings(host="192.0.2.1"), expected_mac="00:11:22:33:44:55"
                )
                assert result.data == payload
            else:
                from pyakuvox.diagnostic_exports import DiagnosticExportBusyError

                with pytest.raises(DiagnosticExportBusyError if case == "busy" else ValueError):
                    await export_system_log(
                        LocalSettings(host="192.0.2.1"),
                        expected_mac="00:11:22:33:44:55",
                        max_bytes=4 if case == "oversized" else 1024,
                    )
            if case == "identity":
                web.login.assert_not_called()
        finally:
            await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "ok",
        "absolute_url",
        "identity",
        "changed_identity",
        "oversized",
        "html",
        "redirect",
        "failed",
        "busy",
        "missing_code",
        "bool_code",
        "missing_path",
        "foreign_path",
        "traversal",
    ],
)
async def test_s539_uses_only_native_system_log_export(case):
    payload = gzip.compress(b"native system log") if case != "html" else b"<html>login</html>"
    web = MagicMock()
    web.base_url = "https://192.0.2.1:443"
    web.login = AsyncMock()
    body = {"retcode": 0, "data": {"url": "/download/systemlog.tgz"}}
    if case == "absolute_url":
        body["data"]["url"] = "http://192.0.2.1/download/systemlog.tgz"
    elif case == "failed":
        body["retcode"] = -1
    elif case == "busy":
        body["retcode"] = -101
    elif case == "missing_code":
        del body["retcode"]
    elif case == "bool_code":
        body["retcode"] = False
    elif case == "missing_path":
        body["data"] = {}
    elif case == "foreign_path":
        body["data"]["url"] = "https://elsewhere/download/file"
    elif case == "traversal":
        body["data"]["url"] = "/download/%2e%2e/file"
    web._post = AsyncMock(return_value=httpx.Response(200, json=body))
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            302 if case == "redirect" else 200,
            content=payload,
            headers={"location": "https://elsewhere/private"} if case == "redirect" else {},
        )

    # Match the SPA session: redirect following is normally enabled there.
    client = httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=True)
    web._ensure_client.return_value = client
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=web)
    context.__aexit__ = AsyncMock(return_value=None)
    info = SimpleNamespace(
        identity=SimpleNamespace(
            model="S539",
            normalized_mac=lambda: "WRONG" if case == "identity" else "00:11:22:33:44:55",
        ),
        firmware_version="539.30.10.523",
    )
    changed = SimpleNamespace(identity=SimpleNamespace(normalized_mac=lambda: "CHANGED"))
    with (
        patch("pyakuvox.diagnostic_exports.WebApiClient", return_value=context),
        patch("pyakuvox.diagnostic_exports.WebUIClient") as legacy,
        patch(
            "pyakuvox.diagnostic_exports.read_device_info_with_auth_detection",
            AsyncMock(side_effect=[info, changed if case == "changed_identity" else info]),
        ),
    ):
        try:
            if case in {"ok", "absolute_url"}:
                artifact = await export_system_log(
                    LocalSettings(host="192.0.2.1"),
                    expected_mac="00:11:22:33:44:55",
                )
                assert artifact.data == payload
                assert artifact.model == "S539"
                assert str(requests[0].url) == "https://192.0.2.1/download/systemlog.tgz"
            else:
                from pyakuvox.diagnostic_exports import DiagnosticExportBusyError

                with pytest.raises(DiagnosticExportBusyError if case == "busy" else ValueError):
                    await export_system_log(
                        LocalSettings(host="192.0.2.1"),
                        expected_mac="00:11:22:33:44:55",
                        max_bytes=4 if case == "oversized" else 1024,
                    )
            legacy.assert_not_called()
            if case == "identity":
                web.login.assert_not_called()
            else:
                web.login.assert_awaited_once_with("admin", "admin", encoding="cryptojs_aes")
                web._post.assert_awaited_once_with(
                    "/api/web/upgrade_advance/export",
                    {
                        "target": "upgrade_advance",
                        "action": "export",
                        "data": {"type": "systemlog"},
                    },
                )
            if case == "redirect":
                assert len(requests) == 1
        finally:
            await client.aclose()


@pytest.mark.asyncio
async def test_unverified_s539_firmware_does_not_submit_web_credentials():
    from pyakuvox.exceptions import UnsupportedFeatureError

    info = SimpleNamespace(
        identity=SimpleNamespace(model="S539", normalized_mac=lambda: "00:11:22:33:44:55"),
        firmware_version="539.99.0.1",
    )
    with (
        patch(
            "pyakuvox.diagnostic_exports.read_device_info_with_auth_detection",
            AsyncMock(return_value=info),
        ),
        patch("pyakuvox.diagnostic_exports.WebApiClient") as web,
    ):
        with pytest.raises(UnsupportedFeatureError):
            await export_system_log(
                LocalSettings(host="192.0.2.1"), expected_mac="00:11:22:33:44:55"
            )
        web.assert_not_called()


@pytest.mark.parametrize(
    "value",
    [
        "http://192.0.2.1/download/PhoneLog.tgz",
        "https://192.0.2.1/download/PhoneLog.tgz",
        "/download/PhoneLog.tgz",
    ],
)
def test_spa_export_link_uses_only_same_device_download_path(value):
    from pyakuvox.diagnostic_exports import _spa_download_path

    assert _spa_download_path(value, "192.0.2.1") == "/download/PhoneLog.tgz"


@pytest.mark.parametrize(
    "value",
    [
        "http://foreign/download/PhoneLog.tgz",
        "http://192.0.2.1@foreign/download/PhoneLog.tgz",
        "http://user:secret@192.0.2.1/download/PhoneLog.tgz",
        "http://192.0.2.1:9999/download/PhoneLog.tgz",
        "http://192.0.2.1:invalid/download/PhoneLog.tgz",
        "http://[invalid/download/PhoneLog.tgz",
        "http://192.0.2.1/download/%2e%2e/private",
        "http://192.0.2.1/download/PhoneLog.tgz?token=secret",
        "http://192.0.2.1/download/PhoneLog.tgz#fragment",
        "//192.0.2.1/download/PhoneLog.tgz",
    ],
)
def test_spa_export_link_rejects_unsafe_authority_and_path(value):
    from pyakuvox.diagnostic_exports import DiagnosticExportError, _spa_download_path

    with pytest.raises(DiagnosticExportError) as caught:
        _spa_download_path(value, "192.0.2.1")
    assert caught.value.code == "unsafe_download_path"
    assert str(caught.value) == "unsafe_download_path"
    assert value not in str(caught.value)
