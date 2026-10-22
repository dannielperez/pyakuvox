# SPA access/media credential preparation

## Changes and evidence
- Browser-compatible SDK user agent selects the S535 SPA login route; the previous agent received a Digest 401 at the nonce endpoint. Changing only User-Agent produced HTTP 200.
- Authenticated S5 model identity selects the SPA credential path. Required config fields and the ONVIF surface are checked before writes.
- API password and RTSP username/password use firmware Base64 encoding. ONVIF uses DoorOnvifServer commontool with encoded DeviceUser/DevicePwd and DeviceMode=0, rather than native AutoP fields.
- Partial/uncertain writes raise AmbiguousMutationError and are not replayed. A fresh Digest connection remains the consumer's responsibility.
- Native model behavior stays covered. No visitor screen or physical relay mapping is added.

## Validation
- Full pytest: 333 passed.
- Ruff lint and format checks pass for all four changed Python files.
- Repository-wide lint/format checks report existing failures outside changed files (15 unformatted files); no unrelated cleanup included.
- S535 firmware 535.30.10.245: isolated staged process completed credential alignment and subsequent authenticated SIP write/readback. No call or relay actuation tested.
- origin/main fetched before push: only merge commit 446a848 beyond base 8b01aed1; trees have no differences, so no refresh required.

## Risks and next steps
SPA preparation spans two firmware transactions, so interruptions may leave partial state. Do not blindly retry an ambiguous mutation. Validate API authentication after preparation before saving credentials. Existing visitor preset support is X916-only; S535 layouts require a separate audited adapter and explicit physical relay intent.
