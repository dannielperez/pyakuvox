"""Akuvox device discovery via network scanning.

Discovers Akuvox devices on the LAN by probing IP ranges with TCP
connect scans followed by HTTP fingerprinting. Works over VPN and
across subnets (no multicast/broadcast required).

Discovery strategy:
  1. TCP connect scan on port 80 (fast — eliminates dead IPs)
  2. HTTP fingerprint on responders: GET /api/system/info
     → Akuvox devices return 401 with realm="HTTP API"
  3. Optionally authenticate to pull full device info (model, MAC, FW)

Multicast-based discovery (SSDP, mDNS, WS-Discovery) is not supported
by Akuvox devices based on testing against X916S and R29C firmware.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import httpx
import structlog

logger = structlog.get_logger(__name__)

# Akuvox devices return this realm on the HTTP API endpoint.
_AKUVOX_REALM_PATTERN = re.compile(r'realm="HTTP API"', re.IGNORECASE)

# Known Akuvox HTTP server strings (from real device testing).
_KNOWN_SERVERS = {"lighttpd/1.4.30", "EasyHttpServer"}

# Default ports to probe — 80 is standard for Akuvox HTTP API.
_DEFAULT_PORTS = [80]

_JSON_DECODER = json.JSONDecoder()


def _parse_api_json(text: str) -> dict[str, Any] | None:
    """Parse JSON from an Akuvox API response.

    Some firmware versions append trailing HTTP data after the JSON body.
    Uses raw_decode to handle that gracefully.
    """
    text = text.lstrip()
    if not text.startswith("{"):
        return None
    try:
        obj, _ = _JSON_DECODER.raw_decode(text)
        return obj  # type: ignore[no-any-return]
    except (json.JSONDecodeError, ValueError):
        return None


@dataclass
class DiscoveredDevice:
    """A device found during network scanning."""

    ip: str
    port: int = 80
    server: str = ""
    model: str = ""
    mac_address: str = ""
    firmware_version: str = ""
    hardware_version: str = ""
    authenticated: bool = False

    @property
    def display_name(self) -> str:
        parts = [self.model or "Unknown", f"@ {self.ip}"]
        if self.mac_address:
            parts.append(f"({self.mac_address})")
        return " ".join(parts)


@dataclass
class ScanConfig:
    """Configuration for a discovery scan."""

    targets: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=lambda: list(_DEFAULT_PORTS))
    tcp_timeout: float = 1.0
    http_timeout: float = 3.0
    max_concurrent: int = 50
    username: str | None = None
    password: str | None = None


def expand_targets(targets: list[str]) -> list[str]:
    """Expand target specifications into individual IP addresses.

    Supports:
      - Single IPs: "192.0.2.10"
      - CIDR ranges: "192.0.2.0/24"
      - Hyphenated ranges: "192.0.2.1-254"
      - Mixed list: ["192.0.2.0/24", "192.0.2.20"]
    """
    ips: list[str] = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips.extend(str(host) for host in network.hosts())
            except ValueError:
                logger.warning("invalid_cidr", target=target)
        elif "-" in target.split(".")[-1]:
            # Hyphenated range: 192.0.2.1-254
            parts = target.rsplit(".", 1)
            if len(parts) == 2:
                prefix = parts[0]
                range_part = parts[1]
                if "-" in range_part:
                    start_s, end_s = range_part.split("-", 1)
                    try:
                        start, end = int(start_s), int(end_s)
                        for i in range(start, end + 1):
                            ips.append(f"{prefix}.{i}")
                    except ValueError:
                        logger.warning("invalid_range", target=target)
        else:
            try:
                ipaddress.ip_address(target)
                ips.append(target)
            except ValueError:
                logger.warning("invalid_ip", target=target)
    return ips


async def _tcp_probe(ip: str, port: int, timeout: float) -> bool:
    """Check if a TCP port is open on a host."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def _http_fingerprint(
    client: httpx.AsyncClient,
    ip: str,
    port: int,
) -> DiscoveredDevice | None:
    """Probe an IP with HTTP to check if it's an Akuvox device.

    Sends an unauthenticated GET to /api/system/info. Akuvox devices
    return 401 with ``WWW-Authenticate: Digest realm="HTTP API"``.
    """
    url = f"http://{ip}:{port}/api/system/info"
    try:
        resp = await client.get(url)
    except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
        return None

    server = resp.headers.get("server", "")
    www_auth = resp.headers.get("www-authenticate", "")

    # Primary fingerprint: realm="HTTP API" in WWW-Authenticate
    if resp.status_code == 401 and _AKUVOX_REALM_PATTERN.search(www_auth):
        return DiscoveredDevice(ip=ip, port=port, server=server)

    # Secondary: if auth is disabled (mode 0), the API returns JSON directly
    if resp.status_code == 200:
        data = _parse_api_json(resp.text)
        if data and data.get("retcode") == 0 and "data" in data:
            status = data["data"].get("Status", {})
            return DiscoveredDevice(
                ip=ip,
                port=port,
                server=server,
                model=status.get("Model", ""),
                mac_address=status.get("MAC", ""),
                firmware_version=status.get("FirmwareVersion", ""),
                hardware_version=status.get("HardwareVersion", ""),
                authenticated=False,
            )

    return None


async def _authenticate_device(
    ip: str,
    port: int,
    username: str,
    password: str,
    timeout: float,
) -> DiscoveredDevice | None:
    """Authenticate with a confirmed Akuvox device to pull full info."""
    auth = httpx.DigestAuth(username, password)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), verify=False, auth=auth
    ) as client:
        try:
            resp = await client.get(f"http://{ip}:{port}/api/system/info")
        except (httpx.ConnectError, httpx.TimeoutException):
            return None

        if resp.status_code != 200:
            return None

        data = _parse_api_json(resp.text)
        if not data:
            return None
        status = data.get("data", {}).get("Status", {})
        return DiscoveredDevice(
            ip=ip,
            port=port,
            server=resp.headers.get("server", ""),
            model=status.get("Model", ""),
            mac_address=status.get("MAC", ""),
            firmware_version=status.get("FirmwareVersion", ""),
            hardware_version=status.get("HardwareVersion", ""),
            authenticated=True,
        )


async def scan(config: ScanConfig) -> list[DiscoveredDevice]:
    """Run a full discovery scan and return all found Akuvox devices.

    Steps:
      1. Expand target IPs from CIDR/ranges
      2. TCP probe open ports (concurrent, rate-limited)
      3. HTTP fingerprint responders
      4. Optionally authenticate to pull device details
    """
    all_ips = expand_targets(config.targets)
    if not all_ips:
        logger.warning("scan_no_targets")
        return []

    log = logger.bind(target_count=len(all_ips), ports=config.ports)
    log.info("scan_start")

    # Phase 1: TCP probe
    semaphore = asyncio.Semaphore(config.max_concurrent)

    async def _guarded_tcp(ip: str, port: int) -> tuple[str, int] | None:
        async with semaphore:
            if await _tcp_probe(ip, port, config.tcp_timeout):
                return (ip, port)
            return None

    tcp_tasks = [
        _guarded_tcp(ip, port)
        for ip in all_ips
        for port in config.ports
    ]
    tcp_results = await asyncio.gather(*tcp_tasks)
    open_hosts = [r for r in tcp_results if r is not None]
    log.info("scan_tcp_done", open_count=len(open_hosts))

    if not open_hosts:
        return []

    # Phase 2: HTTP fingerprint
    devices: list[DiscoveredDevice] = []
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.http_timeout), verify=False, follow_redirects=False
    ) as client:

        async def _guarded_http(ip: str, port: int) -> DiscoveredDevice | None:
            async with semaphore:
                return await _http_fingerprint(client, ip, port)

        http_tasks = [_guarded_http(ip, port) for ip, port in open_hosts]
        http_results = await asyncio.gather(*http_tasks)
        devices = [d for d in http_results if d is not None]

    log.info("scan_fingerprint_done", akuvox_count=len(devices))

    # Phase 3: Authenticate (optional)
    if config.username and config.password and devices:
        log.info("scan_authenticating", count=len(devices))

        async def _guarded_auth(dev: DiscoveredDevice) -> DiscoveredDevice:
            async with semaphore:
                result = await _authenticate_device(
                    dev.ip, dev.port,
                    config.username, config.password,  # type: ignore[arg-type]
                    config.http_timeout,
                )
                return result or dev

        auth_tasks = [_guarded_auth(d) for d in devices]
        devices = list(await asyncio.gather(*auth_tasks))

    log.info("scan_complete", found=len(devices))
    return devices


async def scan_targets(
    targets: list[str],
    *,
    username: str | None = None,
    password: str | None = None,
    ports: list[int] | None = None,
    tcp_timeout: float = 1.0,
    http_timeout: float = 3.0,
    max_concurrent: int = 50,
) -> list[DiscoveredDevice]:
    """Convenience wrapper — scan targets and return discovered devices.

    Args:
        targets: IP addresses, CIDR ranges, or hyphenated ranges.
        username: Credentials for pulling full device info.
        password: Credentials for pulling full device info.
        ports: TCP ports to probe (default: [80]).
        tcp_timeout: Seconds to wait for TCP connect.
        http_timeout: Seconds to wait for HTTP response.
        max_concurrent: Max concurrent probes.
    """
    return await scan(ScanConfig(
        targets=targets,
        ports=ports or list(_DEFAULT_PORTS),
        tcp_timeout=tcp_timeout,
        http_timeout=http_timeout,
        max_concurrent=max_concurrent,
        username=username,
        password=password,
    ))


async def scan_iter(config: ScanConfig) -> AsyncIterator[DiscoveredDevice]:
    """Streaming variant — yields devices as they're discovered.

    Useful for CLI progress display or large subnet scans.
    """
    all_ips = expand_targets(config.targets)
    if not all_ips:
        return

    semaphore = asyncio.Semaphore(config.max_concurrent)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.http_timeout), verify=False, follow_redirects=False
    ) as client:
        for ip in all_ips:
            for port in config.ports:
                async with semaphore:
                    if not await _tcp_probe(ip, port, config.tcp_timeout):
                        continue
                    device = await _http_fingerprint(client, ip, port)
                    if device is None:
                        continue
                    if config.username and config.password:
                        authed = await _authenticate_device(
                            ip, port,
                            config.username, config.password,
                            config.http_timeout,
                        )
                        if authed:
                            device = authed
                    yield device
