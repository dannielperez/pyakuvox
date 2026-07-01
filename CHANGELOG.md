# Changelog

## 0.2.0

### Added — multi-firmware "bridge engine"
- `pyakuvox.identify`: **unauthenticated** device identification. `identify(host)` /
  `identify_many(hosts)` return a `DeviceIdentity` with the `ApiDialect`
  (`DIGEST_API` / `WEB_API` / `LEGACY_WEB` / `FCGI_WEB`) plus model & firmware where
  the firmware leaks them without login. Implements the status-code decision tree
  validated against real hardware (`/api/system/info`: 401-realm→digest, 200→digest-open,
  30x→SPA, 403→E18C-or-whitelist-blocked). `dialect_for_model()` maps a model string.
- `pyakuvox.AkuvoxDevice`: high-level facade — `AkuvoxDevice.connect(host, user, pw)`
  auto-identifies, connects over the right transport, and exposes firmware-agnostic
  helpers: `account_sip(n)` and `make_vpn_only(n, apply=)` that resolve the
  `Config.Account{n}.*` (multi-account) vs `Config.Account.*` (E18C single-account)
  key-namespace difference automatically. Async context manager.

### Changed
- `discovery`: SPA (30x) and E18C/whitelist-blocked (403) panels are no longer dropped
  as "not Akuvox" — they're returned tagged with a `dialect`, so a follow-up `identify()`
  finishes the job. `DiscoveredDevice` gains a `dialect` field.
- `LocalClient` now raises `ApiAccessForbiddenError` (subclass of `AuthenticationError`,
  so existing handlers still catch it) on HTTP 403 with an actionable message — a 403 is
  a WhiteList/None auth-mode block (wrong dialect/mode), not a bad password.

### New exceptions
- `ApiAccessForbiddenError`, `UnsupportedDialectError`.

## 0.1.0

- Initial release: local HTTP API client, web UI configuration, network discovery
- Operator CLI with Typer (device info, relay control, users, schedules, logs, config, raw HTTP)
- Production-grade LocalClient with retry/backoff, response validation, and capability checks
- Pydantic v2 domain models for all device data
- Changed license from GPLv3 to MIT
