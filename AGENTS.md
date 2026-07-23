# Repository guidance

## Keep the SDK vendor-neutral

pyakuvox is a standalone SDK. Repository artifacts must describe its public API
and Akuvox behavior without naming or modeling a specific downstream application.

- Use generic terms such as "consumer", "public API", and "integration" in source,
  tests, fixtures, documentation, comments, and examples.
- Keep downstream project names, module paths, organization-specific concepts, and
  application-specific assumptions in the downstream repository.
- Name compatibility fixtures and tests after the SDK contract or protocol behavior
  they exercise, not after the application that supplied the original use case.
- Before submitting a change, search the diff for downstream project names and
  rewrite any accidental coupling in vendor-neutral terms.

