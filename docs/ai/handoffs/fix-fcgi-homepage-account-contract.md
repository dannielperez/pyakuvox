# Native homepage outgoing account repair

The native homepage selector now supports R29C as well as X916, includes the required Operation=Submit field, and retains read-after-write verification. The old X916 method remains a compatibility alias. Only the outgoing account selector is submitted; SIP credentials and button definitions are not rewritten.

Evidence: R29C firmware 29.30.10.203 returned HTTP 200 without persisting a selector write lacking Operation=Submit. Adding that field persisted account 2 while the other homepage fields remained unchanged. This does not establish who originally changed any SIP credentials.

Validation: full SDK suite, 506 passed; changed-file Ruff checks pass. Regression coverage includes model dispatch, idempotence, missing fields, exact submit payload, and a successful HTTP response whose change does not persist. All automated tests use mocks.

Limitations: this adds selector support, not a full R29C homepage/relay preset adapter. Firmware without the selector returns unsupported. No deployment is included.
