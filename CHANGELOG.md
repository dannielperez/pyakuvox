# Changelog

## Unreleased

### Added — consumer ergonomics for the typed setters
- `pyakuvox.SetVerdict` (`StrEnum`): the `set_sip_server` / `set_reg_period` /
  `set_sip_failover` verdict vocabulary (`would-change` / `already-set` /
  `set-verified` / `set-did-not-stick` / `account-disabled`) as importable members —
  consumers stop hand-copying literals. The result dicts now carry the members
  directly; they compare and JSON-serialize exactly like the historical strings,
  so `result["verdict"] == "set-verified"` keeps working unchanged.
- `AkuvoxDevice.from_client(client)`: wrap an already-configured, caller-managed
  `LocalClient` (custom auth_type/SSL/timeout) without an identify probe or
  `connect()`'s digest-only auth — derives the `DeviceIdentity` from the client's
  settings. The caller keeps client lifecycle ownership.

### Added — typed SIP failover configuration (field-validated recipe)
- `AkuvoxDevice.set_reg_period(account, seconds=30, apply=)`: typed setter for
  `Config.Account{n}.REG.Timeout`/`.Timeout2` — the registration period gates how fast the
  device fails over to its secondary SIP server (the 1800s default was the slow-failover root
  cause; 30s is the field-validated value). Dry-run plan by default, verify-after-apply.
- `AkuvoxDevice.set_sip_failover(account, primary, failover, reg_period_sec=30, apply=,
  reboot=True)`: one-shot resilient-calling recipe — primary server + failover server +
  registration period in a SINGLE config write, verify read, then reboot-after-apply
  (these devices can lose unsaved config on power loss). Same E18C apply refusal and
  dry-run default as `set_sip_server`.
- `AkuvoxDevice.account_sip()` now also returns `reg_timeout`/`reg_timeout2`.

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
