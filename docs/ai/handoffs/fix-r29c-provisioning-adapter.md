# R29C intercom configuration and native registration status

Adds an explicit R29C adapter and R29/R29C native FCGI SIP-status profiles. Existing transport endpoint order remains unchanged. No device writes were performed to validate this patch; protocol mapping was checked against read-only native firmware UI/config evidence for 29.30.10 firmware.

The six-key theme uses speed dial=5, PIN=2, disabled=7. Value 6 is a relay action and must not be used as a disabled button. The relay map is A/B/C plus security A (CodeSA, TriggerDelaySA, HoldDelaySA), not a fourth physical relay D. Security-relay enablement is preserved. WhitelistEnable=1 means all numbers in the native UI. X916-only name/building requirements are rejected. Missing firmware fields fail closed before any write; the facade retains its GET/POST/GET verification contract.

Validation: all 556 SDK tests passed with external I/O mocked (`pytest -q -m 'not integration'`). Changed Python files pass Ruff lint and format. Repository-wide Ruff has 73 pre-existing lint findings and 14 existing format differences outside changed files. No dependencies or schema changes. Origin/main advanced by unrelated video-plan commits b2dfdc8/e12eef6; this fix is still absent and does not overlap those files.

Risk: physical relay behavior and successful calling require hardware acceptance after deployment. R29 inventory aliases support status reading; intercom writes require actual identity R29C and the full expected firmware surface. Human review/merge is next; deployment is downstream-owned.
