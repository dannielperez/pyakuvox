# S539 HTTP-door preparation and execution

Verified native S539 539.30.10.523 schema uses HttpTrig, SessionCheck,
UserName and Password under Config.DoorSetting.RELAY, AES login and Base64
configuration credentials. Only these four fields are changed; timing/modes
remain untouched. Configuration allows selecting visible A/B/C for preparation.
Execution admits Relay A only, checks hold5 against requested pulse, mode0 and
trigger delay0, and sends one authenticated HTTPS OpenDoor request without retry,
redirect or fallback. Unknown firmware, relay inventory, credentials and replies
fail closed. S535 retains its separate configuration schema. A subsequent live S535
535.30.10.282 test returned the same JSON acknowledgement, correcting the old
synthetic-only literal Success assumption for both firmware versions.

Live S539 preparation readback succeeded. Two deliberately separated, audited
Relay A field tests returned the same 29-byte JSON acknowledgement:
{"retcode":0, "message":"OK"}
SHA256 09a49d536e6c4f28b8f92c893a0f8da6a06a46b4077056db01418669c7ea65a5.
Camera evidence from the first showed a gate cycle after the command. The second
was a separate acceptance request after reviewing that cycle, not an automatic
retry. The parser requires exact keys, integer zero and message OK. It does not
interpret HTTP200, JSON false, an error, or a login page as success.

535 SDK tests passed; changed files Ruff/format checks pass. No physical tests
of B/C; no claim of gate-position feedback or automatic vehicle authorization.
Consumers must retain audit, deduplication, fresh arrival and site/lane controls.
