# Bounded diagnostic export handoff

Adds `diagnostic_exports.py`, mocked contract tests and README guidance. The public
operation exports current R29 logs through authenticated observed FCGI controls,
checks hardware identity before/after, limits transfer size and elapsed time, and
returns private bytes with a checksum. Plain TAR under a `.tgz` filename is handled
without extraction. No configuration changes, packet-capture start, reboot or retry.

Validation: full non-integration suite 382 passed. New files pass Ruff lint/format.
Whole-repository Ruff has 74 pre-existing findings and 15 pre-existing files needing
formatting; the two new files add none. `origin/main` has the same tree as the pinned
base `fd008c9` (only merge history differs). No shared branch was modified.

A consented read-only R29C firmware 29.30.10.19 capability probe exported a 4,670,464
byte plain TAR successfully, with identity verified on both reads. No private bytes
were retained in this review artifact. An earlier identity read failed; failures
propagate with no automatic retry. Consumers own encrypted storage, permissions and
retention. Other model layouts, native display screenshots, configuration backup,
and bounded packet capture remain unsupported by this operation.

Next: review and merge this additive SDK contract before a consumer deploys its pin.
