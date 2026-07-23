# Consumer contract replay fixtures

Sanitized Akuvox response shapes used to pin the SDK's public API. They contain
no credentials, customer names, real network addresses, or device identifiers.

- `device_info.json` is the canonical local-API device-information response.
- `identify_web_api.json` is the unauthenticated SPA identification response.

The values use synthetic identifiers while preserving the vendor field names
and nesting that the parsers must accept. Tests replay these files entirely
in-process; they never contact a device.

