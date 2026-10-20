# Management transport identification

The unauthenticated identifier always sent HTTP to the supplied port, including
443, and its fallback only recognized HTTPS SPA firmware. HTTPS digest devices
could therefore be reported unreachable or misclassified.

Add explicit use_ssl/verify_ssl options, report the observed scheme and port,
and probe same-host HTTPS digest on HTTP failure/redirect. Keep custom ports,
never downgrade explicit TLS, and never follow redirect hosts. Secondary web
probes retain the selected authority. Require device evidence instead of treating
arbitrary HTML 200, redirects or generic 403 responses as a recognized API.

Validation: mocked identify tests, Ruff lint/format and diff whitespace checks.
No real device calls or configuration writes. Existing callers retain HTTP
primary behavior; configured TLS callers must pass use_ssl=True. Consumers can
use the returned transport for authenticated identity verification before storing
any configuration change. TLS verification defaults preserve compatibility.
