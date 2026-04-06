# pyakuvox

Python library and CLI for Akuvox intercom device management via the local HTTP API.

Reverse-engineered from real hardware (X916S, R29C) — no official Akuvox SDK or documentation exists.

## Features

- **Local HTTP API client** — async, production-grade with retry/backoff, response validation, and capability checks
- **Operator CLI** — human-friendly tables by default, `--json` for automation
- **Web UI configuration** — enable/configure HTTP API access remotely
- **Network discovery** — scan subnets for Akuvox devices (works over VPN)
- **Pydantic models** — typed domain objects for all device data
- **Capability matrix** — honest tracking of what works, what's partial, and what's untested

## Quick Start

### Install

```bash
pip install -e .
```

Or with dev dependencies:

```bash
pip install -e ".[dev]"
```

### Configure

```bash
cp .env.example .env
# Edit .env with your device details
```

Key environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AKUVOX_LOCAL_HOST` | `192.168.1.100` | Device IP address |
| `AKUVOX_LOCAL_PORT` | `80` | HTTP port |
| `AKUVOX_LOCAL_USERNAME` | `admin` | API username |
| `AKUVOX_LOCAL_PASSWORD` | `admin` | API password |
| `AKUVOX_LOCAL_AUTH_TYPE` | `basic` | `none`, `allowlist`, `basic`, or `digest` |
| `AKUVOX_LOCAL_USE_SSL` | `false` | Use HTTPS |
| `AKUVOX_DEBUG` | `false` | Enable debug logging |

## CLI Usage

```bash
akuvox --help
```

### Device Information

```bash
akuvox local device-info          # identity, firmware, network
akuvox local status               # uptime, system time
akuvox local firmware             # firmware version details
```

### Relay / Door Control

```bash
akuvox local relay-status         # current relay states
akuvox local unlock               # unlock relay 1 (default)
akuvox local unlock --relay 2 --delay 10
```

### Users & Schedules

```bash
akuvox local users list           # single page
akuvox local users list-all       # fetch all pages
akuvox local schedules list
akuvox local schedules list-all
```

### Logs

```bash
akuvox local door-logs            # single page
akuvox local door-logs --all      # fetch all pages
akuvox local call-logs
akuvox local call-logs --all
```

### Device Configuration

```bash
akuvox local config get           # dump full config
akuvox local config set SIP.Port=5060 Network.DHCP=1
akuvox local reboot --yes
```

### Web UI Configuration

```bash
akuvox webui login-check          # verify credentials
akuvox webui get-http-api-config  # read current API config
akuvox webui enable-api --username admin --password secret --yes
```

### Network Discovery

```bash
akuvox discover scan 192.168.1.0/24
akuvox discover scan 10.0.0.1-50 --username admin --password admin
```

### Raw HTTP (Research / Debugging)

```bash
akuvox raw get /api/system/info
akuvox raw post /api/relay/trigger --body '{"num": 1}'
```

### Capability Matrix

```bash
akuvox capabilities                           # full matrix
akuvox capabilities --feature device_info     # filter by feature
akuvox capabilities --provider local_http     # filter by provider
```

### Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Output structured JSON instead of tables |
| `--verbose` / `-v` | Enable DEBUG logging |
| `--debug-http` | Log full HTTP request/response details |

## Python API

```python
from pyakuvox.clients.local import LocalClient
from pyakuvox.config import get_settings

settings = get_settings()
async with LocalClient(settings.local) as client:
    info = await client.get_device_info()
    relays = await client.get_relay_status()
    await client.trigger_relay(1, delay=5)
    users = await client.list_all_users()       # paginated bulk fetch
    logs = await client.list_all_door_logs()
```

### Supported Local API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/system/info` | Device identity, firmware, network |
| GET | `/api/system/status` | Uptime, system time |
| GET | `/api/relay/status` | Relay states |
| POST | `/api/relay/trig` | Trigger relay (unlock door) |
| GET | `/api/user/list` | User/PIN list (paginated) |
| POST | `/api/user/add` | Add user |
| POST | `/api/user/set` | Modify user |
| POST | `/api/user/del` | Delete user |
| GET | `/api/schedule/list` | Schedules (paginated) |
| GET | `/api/log/door` | Door access log (paginated) |
| GET | `/api/log/call` | Call log (paginated) |
| GET | `/api/config/get` | Full device config |
| POST | `/api/config/set` | Update device config |

### Web UI Client

Configure the device's HTTP API via the web management interface. This is needed before the local API client can connect — Akuvox devices ship with IP whitelist auth that blocks API access by default.

```python
from pyakuvox.clients.local import WebUIClient, FirmwareAuthMode

async with WebUIClient(host="192.168.1.100") as webui:
    await webui.login("admin", "password")
    config = await webui.get_http_api_config()
    await webui.enable_api_access("admin", "password")
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

### Network Discovery

```python
from pyakuvox.discovery import scan_targets

devices = await scan_targets(
    ["192.168.1.0/24"],
    username="admin",
    password="password",
)
```

Supports single IPs, CIDR ranges (`/24`), and hyphenated ranges (`1-254`). Works over VPN (no multicast required).

## Client Features

The `LocalClient` is production-grade:

- **Retry with backoff** — automatic retry on `ConnectError`, `TimeoutException`, and 502/503/504
- **Response validation** — rejects empty body, malformed JSON, non-dict responses, and device-level errors (`retcode != 0`)
- **Capability checks** — consults the feature matrix before executing experimental endpoints
- **Pagination helpers** — `list_all_users()`, `list_all_schedules()`, `list_all_door_logs()`, `list_all_call_logs()` with safety ceiling
- **Structured logging** — request tracing with content length, attempt count, and secret redaction

## Project Structure

```
pyakuvox/
├── cli/
│   ├── main.py               # CLI entrypoint, global flags
│   ├── local_cmd.py           # Local device commands
│   ├── webui_cmd.py           # Web UI commands
│   ├── discover_cmd.py        # Network scan commands
│   ├── raw_cmd.py             # Raw HTTP commands
│   └── output.py              # Output formatting (tables / JSON)
├── clients/
│   ├── base.py                # Abstract client interface
│   └── local/
│       ├── client.py          # Local HTTP API client
│       ├── auth.py            # HTTP auth handlers (Basic/Digest)
│       ├── encoding.py        # Akuvox PostEncode utilities
│       ├── parsers.py         # Response → model parsers
│       └── webui.py           # Web UI configuration client
├── models/
│   ├── device.py              # Device identity, status, relay models
│   ├── events.py              # Door/call event models
│   ├── firmware.py            # Firmware info model
│   ├── schedules.py           # Schedule models
│   ├── session.py             # Cloud session models (experimental)
│   └── users.py               # User/PIN code models
├── capabilities.py            # Feature × provider support matrix
├── config.py                  # pydantic-settings configuration
├── discovery.py               # Network device scanner
├── exceptions.py              # Exception hierarchy
└── logging_config.py          # Structured logging setup
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

84 tests covering CLI commands, client retry/backoff, pagination, response validation, capability guards, and error handling.

## Tested Hardware

| Model | Firmware | Server | Notes |
|-------|----------|--------|-------|
| X916S | 916.30.10.114 | lighttpd/1.4.30 | Video intercom panel |
| R29C | 29.30.10.239 | EasyHttpServer | Video intercom |

## Status

Alpha — local API client, CLI, and web UI config are functional against real hardware. Cloud integration is experimental/unimplemented.

## License

This project is licensed under the [MIT License](LICENSE).
Previous versions were released under GPLv3.
