# S539 native diagnostics

The S539 539.30.10.523 SPA uses CryptoJS AES over JSON.stringify(password)
with the login nonce as passphrase. The existing base64 nonce+password flow
fails authentication on this firmware. WebApiClient now accepts an explicit
cryptojs_aes encoding; the existing default and FCGI AES plaintext are unchanged.
No password retry/fallback is added.

System-log export selects this encoding only for that exact model/firmware,
uses the observed upgrade_advance/export systemlog request, and preserves
pre/post MAC verification, total deadline, download and expanded archive bounds.
Downloads reject redirects and unsafe paths. Configuration/user-data exports,
trace activation, reboot and credential changes are not performed.

Live evidence: AES login returned a token; export returned -101, which the
installed frontend maps to PhoneTalkingWarning. A later native state read was
READY; a later export attempt timed out. Do not interpret the refusal as proof
of a current call or a stuck call. DiagnosticExportBusyError preserves that
specific refusal. Successful download/archive format remains unverified live;
unknown firmware and unexpected download paths/formats fail closed.

Validation: 447 tests passed; changed Python files pass Ruff. Synthetic tests
cover independent OpenSSL vectors, Unicode/quotes/newline password encoding,
one credential submission, unknown firmware, native request selection, busy,
identity changes, size, login HTML, redirects and unsafe response paths.
