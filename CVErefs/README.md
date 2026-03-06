# CVE Reference Catalog

This directory is the operator-facing index for the curated CVE-style regression set. The authoritative metadata lives in [`templates/known_vulnerabilities.yaml`](../templates/known_vulnerabilities.yaml), while the bundled regression fixtures under [`tests/cve_fixtures`](../tests/cve_fixtures) are the supported in-repo execution path.

`circuit_references.json` is historical provenance for older external target locations. It is not the primary execution path for current regression tests.

## What Is Authoritative Today

- vulnerability metadata: [`templates/known_vulnerabilities.yaml`](../templates/known_vulnerabilities.yaml)
- regression execution: [`tests/cve_regression_runner.rs`](../tests/cve_regression_runner.rs)
- portable fixtures: [`tests/cve_fixtures`](../tests/cve_fixtures)
- reusable CVE-style pattern catalog: [`campaigns/cve/patterns`](../campaigns/cve/patterns)

## Core Bundled Regression Catalog

| CVE ID | Vulnerability Class | Oracle / Attack Type | Pattern / Fixture | Framework | Detection Status |
| --- | --- | --- | --- | --- | --- |
| `ZK-CVE-2022-001` | EdDSA signature malleability | `signature_malleability` / `malleability` | `tests/cve_fixtures/signature_canonical_guard.circom` | `circom` | bundled regression fixture |
| `ZK-CVE-2022-002` | Nullifier collision via weak hash | `nullifier_collision` / `collision` | `tests/cve_fixtures/nullifier_uniqueness_smoke.circom` | `circom` | bundled regression fixture |
| `ZK-CVE-2021-001` | Merkle path length bypass | `merkle_soundness` / `boundary` | `tests/cve_fixtures/merkle_path_length_guard.circom` | `circom` | bundled regression fixture |
| `ZK-CVE-2021-002` | Merkle sibling-order ambiguity | `merkle_soundness` / `underconstrained` | `tests/cve_fixtures/merkle_binary_indices_guard.circom` | `circom` | bundled regression fixture |
| `ZK-CVE-2023-001` | Field overflow in range proofs | `arithmetic_overflow` / `arithmetic_overflow` | `tests/cve_fixtures/range_upper_bound_guard.circom` | `circom` | bundled regression fixture |
| `ZK-CVE-2023-002` | Division by zero not constrained | `boundary` / `boundary` | `tests/cve_fixtures/division_denominator_guard.circom` | `circom` | bundled regression fixture |
| `ZK-CVE-2022-003` | Timing side-channel in witness generation | `timing_side_channel` / `timing_side_channel` | `tests/cve_fixtures/generic_expectation_guard.circom` | `circom` | bundled generic expectation guard |
| `ZK-CVE-2023-003` | Public signal leaks private information | `information_leakage` / `information_leakage` | `tests/cve_fixtures/generic_expectation_guard.circom` | `circom` | bundled generic expectation guard |

## Catalog Notes

- Later `ZK-CVE-2024-*` and `ZK-CVE-2025-*` entries also exist in `known_vulnerabilities.yaml`, but many of them currently share `generic_expectation_guard.circom` rather than a dedicated target-specific fixture.
- The stronger credibility signal is the bundled fixture path, not the historical external-drive mapping.
- If you want to know whether a reference is target-specific or still generic, start with the `regression_test.circuit_path` field in `known_vulnerabilities.yaml`.

## Why This Matters

This catalog is where attack knowledge becomes cumulative:

- a vulnerability class is captured once
- a regression fixture is kept in-repo
- the regression runner enforces it on every future tree

That is a stronger story than ad hoc benchmark screenshots because the mapping between vulnerability class and executable fixture stays versioned with the repository.
