# FCGI transport and uncertain-write handling

## Findings

A read-only probe of an X916S exposed HTTP 308 to HTTPS, an FCGI login page advertising AESEncrypt, and HTTP 403 on /api/system/info. Current identification correctly chose fcgi_web; AES login support already exists. These observations do not establish the cause of a historical provisioning failure or validate authenticated configuration changes.

Code review and mocked failures establish independent defects: WebUIClient translated only ConnectError on initial login reads; ReadTimeout and protocol errors leaked outside the SDK hierarchy. A config response/readback failure needs an uncertain-write result, not a retry using another password encoding. Config debug logging also included raw field values.

## Changes

- Translate read/login HTTP transport errors to ConnectionError with exception class only.
- Surface config POST transport failures and post-write readback failures as AmbiguousMutationError.
- Stop encoding/dialect retries and return ambiguous-write when a config outcome is unknown.
- Log field names rather than config values.

No SIP, relay, firmware, credential, or live configuration write was performed in validating this patch. No firmware version or successful authenticated session was obtained. Public device page analysis alone is not hardware certification.

## Validation

256 SDK tests pass with network I/O mocked, including five new cases for transport and uncertain writes. Changed-file Ruff check and format pass. Live read-only identification passed. Downstream consumer must translate ambiguous-write into actionable inspect-before-retry guidance.

## Remaining work

Authenticate to an authorized test panel, read HTTP API state, reproduce activation and verify Digest independently. The available browser's credential-checkout confirmation could not be completed through its dialog API; user intervention was requested. Do not report this patch as proof of the historical incident's root cause.
