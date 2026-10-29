# Explicit certificate trust for private local endpoints

Adds optional `LocalSettings.tls_certificate_sha256` and the same keyword on
WebApiClient/WebUIClient. Supply a reviewed SHA-256 leaf certificate fingerprint
out of band. There is no automatic enrollment or trust-on-first-use.

PinnedLocalTransport validates the certificate at TLS handshake completion,
before HTTP request headers. It enforces an exact HTTPS host/port, disables
proxy inheritance and transport retries, and disables keepalive so each request
has its own verified handshake. A pin mismatch raises PinnedTLSError (not a
retryable HTTP transport error). A second guard refuses headers without a
successful check. Legacy TLS cannot be combined with a pin.

A pin explicitly replaces public CA/hostname trust for that connection. It does
not establish unique device identity when a manufacturer shares a certificate
across devices, and does not independently authorize access or physical actions.
Consumers still need reviewed endpoint/identity binding, scoped credentials and
physical safety acceptance. Unique per-device certificates remain preferable.
Certificate changes require explicit re-enrollment; no fallback is attempted.

Propagated trust through local API, web configuration, relay preview, credential
rotation, and existing settings-based web operations. Existing callers without
a pin retain their existing behavior. No device writes were used for validation.

Validation: all 491 SDK tests passed, including real loopback TLS tests proving
wrong pins send zero HTTP bytes, endpoint changes fail before connect, changed
pins fail on later requests, and all three clients use the pinned transport.
New files pass Ruff/format. Existing touched files have baseline lint findings;
a code/message comparison against HEAD found no introduced findings. Test runner
warns about existing unset asyncio fixture loop scope.

A field read using the new transport and existing SDK parsers returned device
identity and relay status successfully on a self-signed S535 endpoint. No relay
command or persistent configuration was issued. No site data/credentials live in
this SDK repository. Consumers must pin a commit containing this change before
saving a certificate pin; older SDKs may ignore unknown model fields.
