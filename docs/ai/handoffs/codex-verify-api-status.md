# Verify successful API identity before reporting readiness

The Digest readiness probe previously accepted every non-empty HTTP 200 JSON object,
including application errors. `flip.py` now requires a successful response containing
nonempty Model or MAC identity in the same envelopes supported by the device-info
parser. A MAC is not required. No public signatures or configuration payloads change.

Validation: 269 SDK tests passed with all device I/O mocked. Nine new regression
cases failed before the fix. Ruff and formatting pass for flip.py, exceptions.py, and the updated tests.
Repository-wide Ruff reports 74 pre-existing errors (13 in unchanged lines of
client.py); format check reports 16 pre-existing files needing formatting. No live device writes were performed.

Risk: unsupported firmware with no Model or MAC in system info will no longer be
reported ready. That outcome is intentional: an arbitrary success message is not
proof the required system-info API is usable. This does not establish the cause of
any historical device failure. Human review and merge remain pending.

Also remove the unsupported claim that HTTP 403 establishes WhiteList/None mode
and rules out credential problems. Preserve the existing typed exception and
provide configuration checks without asserting an unverified cause.
