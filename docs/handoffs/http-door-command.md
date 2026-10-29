# Separate HTTP-door configuration

Adds `configure_http_door` for the verified S535 535.30.10.282 web configuration
schema. It configures only RelayOnWeb, RelayOnWebSessionCheck, RelayOnWebUser and
RelayOnWebPwd, preserving all relay output/mode/timing values. Both credential
fields are Base64 encoded, as in the firmware web application. Preview never
writes; apply writes once then requires exact readback. Masked readback and
uncertain writes are not success and are not retried. TLS requires normal trust
or an explicit endpoint certificate pin. Unknown models/firmware fail closed.

Existing API/media credential alignment also updates HTTP-door credentials when
the feature is already enabled; it never enables the feature during rotation.

Validation: 504 SDK tests passed. New module and tests pass Ruff. Live read-only
web configuration confirmed all four fields are present but unconfigured on the
observed S535; no relay command or device configuration write was issued.

This is configuration preparation, not an opening transport or physical safety
acceptance. `/api/relay/trigger` and `/fcgi/OpenDoor` must not be treated as
interchangeable. Authentication negotiation and command response semantics of
`/fcgi/OpenDoor` still require installed-device validation before enabling an
opening adapter. No fallback between physical command dialects is implemented.

Reference: https://knowledge.akuvox.com/docs/open-door-via-http-command
