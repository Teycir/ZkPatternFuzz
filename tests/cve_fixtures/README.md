## CVE Fixture Bank

These fixtures are intentionally small, local regression targets for
`templates/known_vulnerabilities.yaml`.

They exist to keep the CVE regression lane portable:

- no external drive mounts
- no workstation-specific absolute paths
- no heavyweight benchmark-only circuits for basic regression wiring

They are not intended to model full production circuits. They provide stable,
in-repo execution targets so the regression database can be exercised on a
clean clone.

`generic_expectation_guard.circom` is the default portable fallback for
abstract CVEs. It encodes a single explicit contract: `expect_invalid=false`
must execute successfully, and `expect_invalid=true` must fail closed.
Backend-specific execution smoke remains covered by dedicated backend tests;
the CVE lane is intentionally optimized for deterministic in-repo replay.
