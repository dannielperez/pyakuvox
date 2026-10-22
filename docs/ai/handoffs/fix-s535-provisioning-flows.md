# S535 SIP and visitor configuration

S535 535.30.10.245 native config accepted and echoed a raw SIP password but the SIP engine failed authentication. The SPA frontend encodes GENERAL.Pwd with Base64. Route authenticated S535 writes through that interface and require runtime registration for end-to-end password verification. Do not skip the encoded write merely because native config echoes the requested password.

Added S535 runtime status parsing (0 disabled, 1 registering, 2 registered, 3 failed; all others unknown), homepage account selection, and four-button building-theme adapter. Extra active caller keys are rejected; trailing disabled keys are omitted. Cloud button 6, other SIP accounts, and security-relay enablement are preserved. Standard relay A/B and security-relay SA/SB codes are caller-owned. Required fields are checked before mutation and read back afterward. The homepage call action disables local relay/HTTP actions.

Validation: 345 tests pass, changed-file Ruff lint/format pass. Live isolated validation changed failed SIP authentication to registered within five seconds; independent PBX contact reported reachable. Full consumer provisioning completed with SIP, visitor homepage, DTMF and account selection all verified. No physical relay or phone call was actuated.

Risks: exact model S535 only; new firmware can fail surface validation. Configuration verification is not a physical wiring/audio acceptance test. Unconfirmed SIP mutations raise AmbiguousMutationError with no replay.

Before push origin/main was fetched; the merge commits beyond the prior SDK base introduce no additional tree changes. Review/merge before consumer pin deployment.
