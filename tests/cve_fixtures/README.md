# CVE Fixture Bank

These circuits are intentionally small regression targets referenced by `templates/known_vulnerabilities.yaml`. Their job is not to model full production systems. Their job is to keep the CVE regression lane deterministic, portable, and runnable on a clean clone.

## Why These Fixtures Exist

- no external drive mounts
- no machine-specific absolute paths
- no benchmark-sized circuits in the default regression lane
- stable replay targets for `cargo test --test cve_regression_runner -- --nocapture`

## Design Contract

Each fixture should satisfy the following:

- compile with the local in-repo test toolchain flow
- ship a checked-in reusable `build/` bundle so the regression lane works on a clean clone
- encode one narrow security contract clearly enough for valid and invalid cases
- stay small enough to be used in repeatable regression runs
- avoid hidden environmental dependencies outside the repository

`generic_expectation_guard.circom` is the default fallback for abstract CVEs. It enforces one explicit contract:

- `expect_invalid=false` must execute successfully
- `expect_invalid=true` must fail closed

That gives the regression database a portable target even when the original real-world circuit is too large or too environment-specific for the default lane.

## Current Fixture Themes

- expectation and validity guards: `generic_expectation_guard.circom`, `generic_portable_valid.circom`
- arithmetic and range guards: `division_denominator_guard.circom`, `range_upper_bound_guard.circom`
- Merkle-path guards: `merkle_binary_indices_guard.circom`, `merkle_path_length_guard.circom`
- nullifier and signature guards: `nullifier_uniqueness_smoke.circom`, `signature_canonical_guard.circom`

## Scope Limits

- These fixtures do not prove real-world exploitability on their own.
- They are not a substitute for replay artifacts against the actual target when a finding graduates from regression coverage to a confirmed vulnerability.
- Backend-specific readiness and heavy execution remain covered by dedicated backend tests and external-target lanes.
