# Authenticated web relay preparation

Adds `pyakuvox.relay_access.configure_web_relay_access`: explicit HTTPS/trust, model profile, requested relay numbers, preview by default, and explicit apply. Reuses existing FCGI and SPA configuration clients; writes only API enable/Digest/credentials. A fresh non-retried local API identity/status read verifies the model and outputs. No relay command, DTMF edit, hold-time edit or reboot is called. Already-configured access is a no-op; failure after a write raises AmbiguousMutationError without replay.

Results omit raw fields and credentials. Missing configuration fields and unknown model strategies fail closed. This does not configure external web relays, impose device-level per-output ACLs, or prove physical gate behavior.

Validation: simulated transports only. New tests cover preview, successful configuration, idempotence, missing fields, missing outputs, model mismatch, TLS refusal, invalid relay selection, SPA dispatch and ambiguous failures. No device mutation was performed during development.
