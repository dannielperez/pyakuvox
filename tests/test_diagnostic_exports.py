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
                with pytest.raises(ValueError):
                    await export_system_log(
                        LocalSettings(host="192.0.2.1"),
                        expected_mac="00:11:22:33:44:55",
                        max_bytes=4 if case == "oversized" else 1024,
                    )
            if case == "identity":
                web.login.assert_not_called()
        finally:
            await client.aclose()
