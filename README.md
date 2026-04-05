# akuvox-api

Proof-of-concept Python library for Akuvox intercom device integration via the local HTTP API.

Reverse-engineered from real hardware (X916S, R29C) — no official Akuvox SDK or documentation was used.

## Features

### Local HTTP API Client

Communicate directly with Akuvox devices on the LAN via their built-in HTTP API.

```python
from akuvox_api.clients.local import LocalClient
from akuvox_api.config import get_settings

settings = get_settings()
async with LocalClient(settings.local) as client:
    info = await client.get_device_info()       # model, MAC, firmware
    relays = await client.get_relay_status()     # relay states
    await client.trigger_relay(1, delay=5)       # unlock door
    users = await client.list_users()            # PIN/card codes
    logs = await client.get_door_logs()          # access history
```

**Supported endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/system/info` | Device identity, firmware, network |
| GET | `/api/system/status` | Uptime, system time |
| GET | `/api/relay/status` | Relay states |
| POST | `/api/relay/trig` | Trigger relay (unlock door) |
| GET | `/api/user/list` | User/PIN list |
| POST | `/api/user/add` | Add user |
| POST | `/api/user/set` | Modify user |
| POST | `/api/user/del` | Delete user |
| GET | `/api/schedule/list` | Schedules |
| GET | `/api/log/door` | Door access log |
| GET | `/api/log/call` | Call log |
| GET | `/api/config/get` | Full device config |
| POST | `/api/config/set` | Update device config |

### Web UI Configuration Client

Configure the device's HTTP API settings (auth mode, credentials, IP whitelist) via the web management interface. This is needed before the API client can connect — Akuvox devices ship with IP whitelist auth that blocks all API access.

```python
from akuvox_api.clients.local import WebUIClient, FirmwareAuthMode

async with WebUIClient(host="192.168.1.100") as webui:
    await webui.login("admin", "password")

    # Read current HTTP API config
    config = await webui.get_http_api_config()

    # Enable API with Digest auth (recommended)
    await webui.enable_api_access("admin", "password")

    # Or set specific config
    await webui.set_http_api_config(
        auth_mode=FirmwareAuthMode.DIGEST,
        username="admin",
        password="password",
        whitelist_ips=["192.168.1.50"],
    )
```

**HTTP API auth modes** (reverse-engineered from firmware):

| Mode | Name | Status |
|------|------|--------|
| 0 | None | Works — no auth required (insecure) |
| 1 | Basic Auth | Broken on some firmware versions |
| 2 | IP WhiteList | Factory default — blocks API if list is empty |
| 3 | Digest (server) | Returns 401 even with correct credentials |
| 4 | **Digest Auth** | **Recommended** — works reliably |
| 5 | Basic + Digest | Works with Basic credentials |

### Device Discovery

Scan the network for Akuvox devices using TCP connect probes and HTTP fingerprinting. Works over VPN (no multicast/broadcast required).

```python
from akuvox_api.discovery import scan_targets

# Scan a subnet
devices = await scan_targets(
    ["192.168.1.0/24"],
    username="admin",
    password="password",
)
for device in devices:
    print(f"{device.model} @ {device.ip} ({device.mac_address})")
```

**Supports:**
- Single IPs: `192.168.1.100`
- CIDR ranges: `192.168.1.0/24`
- Hyphenated ranges: `192.168.1.1-254`
- Authenticated enrichment (pulls model, MAC, firmware when credentials provided)

## Installation

```bash
pip install -e .
```

Or with development dependencies:

```bash
pip install -e ".[dev]"
```

## Configuration

Copy `.env.example` to `.env` and fill in your device details:

```bash
cp .env.example .env
```

Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `AKUVOX_LOCAL_HOST` | `192.168.1.100` | Device IP |
| `AKUVOX_LOCAL_PORT` | `80` | HTTP port |
| `AKUVOX_LOCAL_USERNAME` | `admin` | API username |
| `AKUVOX_LOCAL_PASSWORD` | `admin` | API password |
| `AKUVOX_LOCAL_AUTH_TYPE` | `basic` | `none`, `allowlist`, `basic`, or `digest` |
| `AKUVOX_LOCAL_USE_SSL` | `false` | Use HTTPS |
| `AKUVOX_DEBUG` | `false` | Enable debug logging |

## Project Structure

```
akuvox_api/
├── clients/
│   ├── base.py              # Abstract client interface
│   └── local/
│       ├── auth.py           # HTTP auth handlers (Basic/Digest)
│       ├── client.py         # Local HTTP API client
│       ├── encoding.py       # Akuvox PostEncode utilities
│       ├── parsers.py        # Response → Pydantic model parsers
│       └── webui.py          # Web UI configuration client
├── models/
│   ├── device.py             # Device identity, status, relay models
│   ├── events.py             # Door/call event models
│   ├── firmware.py           # Firmware info model
│   ├── schedules.py          # Schedule models
│   ├── session.py            # Cloud session models (experimental)
│   └── users.py              # User/PIN code models
├── capabilities.py           # Feature support matrix
├── config.py                 # Pydantic-settings configuration
├── discovery.py              # Network device scanner
├── exceptions.py             # Exception hierarchy
└── logging_config.py         # Structured logging setup
```

## Tested Hardware

| Model | Firmware | Server | Notes |
|-------|----------|--------|-------|
| X916S | 916.30.10.114 | lighttpd/1.4.30 | Video intercom panel |
| R29C | 29.30.10.239 | EasyHttpServer | Video intercom |

## Status

Alpha — local API client and web UI config are functional against real hardware. Cloud integration is experimental/unimplemented.

## License

[GPL-3.0](LICENSE)
