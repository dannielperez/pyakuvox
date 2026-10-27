# S539 same-device export URLs and structured failures

S539 539.30.10.523 returns an absolute HTTP URL for system-log export even when
the management session is HTTPS. The observed web frontend uses a same-origin
download. Accept an HTTP/HTTPS URL only for the configured host, without user
info, nonstandard port, query or fragment, and validate its /download/ path.
Download through the existing authenticated base URL; never downgrade transport
or follow redirects. Existing relative paths remain supported. Foreign URLs,
traversal and malformed authorities fail closed.

DiagnosticExportError retains ValueError compatibility and exposes an enum code
for identity, path, export response, download, size and archive failures. Error
messages contain only that fixed code, not response bodies, filenames or secrets.
The existing busy exception remains distinct; it does not prove call state.

Validation: 462 tests pass; Ruff and diff checks pass. Tests verify absolute HTTP
export URLs are fetched over the configured HTTPS session, unsafe URLs remain
blocked, malformed ports/authorities are sanitized, and existing bounds hold.

Live evidence: an S539 returned a same-device absolute HTTP /download/PhoneLog.tgz
URL with retcode 0. The earlier client rejected that URL. A later export reported
busy. A direct read of the previously generated file over HTTPS returned 200
application/x-tgz but was rejected before archive validation completed. Successful end-to-end export
remains unverified; do not claim the call defect is fixed. Header/prefix
inspection subsequently confirmed a 15,443,456-byte plain TAR. Raise the
opt-in SDK maximum to 16 MiB (default unchanged), retaining archive validation
and the 16 MiB expanded gzip limit. A synthetic TAR above 8 MiB is covered. No device settings, firmware, restart, logging level or trace changes.
