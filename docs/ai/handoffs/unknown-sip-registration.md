# Preserve unknown SIP registration observations

Owned branch fix/unknown-sip-registration, based on SDK main b48a889.

Inspection previously compared status directly with string '2', mapping missing
accounts, missing status and unfamiliar values to False; malformed account entries
could raise AttributeError. Normalize known string/integer codes to bool and all
other shapes/values to None. Never expose raw unfamiliar response content. Existing
renewal truth checks cannot accept None as registration success. No change to write,
idle, identity, retry or rollback rules.

62 mocked SIP recovery/identification tests passed, including malformed/missing
statuses, known code parity and unknown post-write status refusing success with
conditional restoration. Changed SDK files pass Ruff/format. Existing pytest
asyncio configuration warning only; tests use asyncio.run. No live firmware call.
Consumers must treat registered as bool | None rather than assuming False means
all non-success observations. No downstream-specific code or identifiers added.
