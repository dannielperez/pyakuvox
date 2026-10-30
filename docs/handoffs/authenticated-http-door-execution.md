# Authenticated HTTP-door execution

Adds `open_http_door` for the observed S535 firmware and Relay A. Reads identity,
HTTP-door credential configuration, relay mode, trigger delay and pulse duration
before any actuation. Uses verified HTTPS, header authentication and a single
GET to the vendor-documented `/fcgi/OpenDoor` route. Generic GET retry logic and
cross-dialect fallback are deliberately excluded. Unknown responses, redirects,
transport failures and cancellation report ambiguous physical outcome.

The literal `Success` acknowledgement is a conservative candidate contract,
covered by synthetic tests, **not yet captured from installed firmware**. Do not
represent this as hardware acceptance. First field validation must reconcile
provider response with an independently observed gate movement before enabling
unattended operation. No live command was issued to establish this parser.

Source: https://knowledge.akuvox.com/docs/open-door-via-http-command
The source documents the command route and authentication, not response syntax.

Validation: full suite before four additional transport tests: 514 passed.
Final targeted suite: 22 passed, including real httpx Digest challenge/submission,
503/redirect/timeout no-retry, no credentials in URLs, wrong pulse/mode denial,
and no configuration writes. Changed modules Ruff/format passed.
