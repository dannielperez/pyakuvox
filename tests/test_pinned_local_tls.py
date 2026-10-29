"""Real loopback TLS proves trust rejection occurs before sending HTTP bytes."""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import ssl
from contextlib import asynccontextmanager, suppress

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pyakuvox.clients.local.client import LocalClient
from pyakuvox.clients.local.tls import PinnedLocalTransport, PinnedTLSError
from pyakuvox.clients.local.webapi import WebApiClient
from pyakuvox.clients.local.webui import WebUIClient
from pyakuvox.config import LocalSettings


@asynccontextmanager
async def panel(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-panel")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    received = []
    tasks = set()

    async def handle(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=2)
            if data:
                received.append(data)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                await writer.drain()
        except ConnectionResetError:
            pass  # A rejected TLS pin closes before HTTP bytes are sent.
        finally:
            writer.close()
            with suppress(ConnectionResetError):
                await writer.wait_closed()
            tasks.discard(task)

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    try:
        yield (
            port,
            hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
            received,
        )
    finally:
        server.close()
        await server.wait_closed()
        if tasks:
            await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_wrong_pin_sends_no_credentials_or_post(tmp_path):
    async with panel(tmp_path) as (port, _pin, received):
        transport = PinnedLocalTransport(host="127.0.0.1", port=port, fingerprint="0" * 64)
        async with httpx.AsyncClient(transport=transport, auth=("test", "private")) as client:
            with pytest.raises(PinnedTLSError, match="pin mismatch"):
                await client.post(f"https://127.0.0.1:{port}/test", json={"action": "test"})
    assert received == []


@pytest.mark.asyncio
async def test_matching_pin_accepts_self_signed_and_checks_each_connection(tmp_path):
    async with panel(tmp_path) as (port, pin, received):
        transport = PinnedLocalTransport(host="127.0.0.1", port=port, fingerprint=pin)
        async with httpx.AsyncClient(transport=transport) as client:
            assert (await client.get(f"https://127.0.0.1:{port}/test")).status_code == 200
            transport._fingerprint = "0" * 64
            with pytest.raises(PinnedTLSError):
                await client.get(f"https://127.0.0.1:{port}/test")
    assert len(received) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url", ["http://127.0.0.1/test", "https://example.com/test", "https://127.0.0.1:444/test"]
)
async def test_rejects_endpoint_changes_before_connect(url):
    async with PinnedLocalTransport(host="127.0.0.1", port=443, fingerprint="0" * 64) as transport:
        with pytest.raises(PinnedTLSError, match="endpoint mismatch"):
            await transport.handle_async_request(httpx.Request("GET", url))


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["local", "webapi", "webui"])
async def test_all_local_clients_use_pin_transport(tmp_path, kind):
    async with panel(tmp_path) as (port, pin, received):
        options = dict(
            host="127.0.0.1", port=port, use_ssl=True, verify_ssl=True, tls_certificate_sha256=pin
        )
        client = (
            LocalClient(LocalSettings(**options))
            if kind == "local"
            else {"webapi": WebApiClient, "webui": WebUIClient}[kind](**options)
        )
        async with client:
            response = await client._client.get(f"https://127.0.0.1:{port}/test")
            assert response.status_code == 200
    assert len(received) == 1


def test_malformed_pin_fails_closed():
    with pytest.raises(ValueError, match="SHA-256"):
        PinnedLocalTransport(host="127.0.0.1", port=443, fingerprint="")


def test_webui_positional_password_encoding_remains_compatible():
    from pyakuvox.clients.local.webui import ConfigPasswordEncoding

    client = WebUIClient("127.0.0.1", 443, True, True, 5, ConfigPasswordEncoding.X916)
    assert client._password_encoding == ConfigPasswordEncoding.X916
    assert client._tls_certificate_sha256 is None
