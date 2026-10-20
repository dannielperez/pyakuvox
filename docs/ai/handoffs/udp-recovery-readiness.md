# UDP recovery configuration readiness

Branch: feat/udp-recovery-readiness, based on origin/main cc3fa89.

inspect_sip now exposes udp_recovery_supported and udp_recovery_reason per account.
These describe configuration support only, not idle state, account authorization,
registration success or permission to mutate. A shared internal port selector serves
both inspection and renew_udp_flow so fixed-port, unknown other-account ranges,
invalid ranges and exhausted replacement ports are rejected consistently. Existing
non-retry, identity, 60-second idle, readback and conditional rollback rules remain.

Tests cover read-only blocker reporting, execution refusal parity, active-call
refusal despite supported configuration, and existing renewal/rollback cases.
All network I/O mocked. No live firmware validation. Consumers must treat missing
readiness fields as unknown and refresh observations after SDK rollout. Additive
report fields; no changed renewal call signature. Final test count recorded in PR.
