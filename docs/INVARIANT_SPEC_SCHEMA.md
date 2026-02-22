# Invariant Specification YAML Schema

This document defines the current `invariants:` schema used by ZkPatternFuzz v2 campaigns.

The implementation source of truth is:
- `src/config/v2.rs` (`Invariant`, `InvariantType`, `InvariantOracle`, relation parser)
- `src/bin/validate_yaml.rs` (evidence-mode validation expectations)

## Top-Level Shape

```yaml
invariants:
  - name: "unique_invariant_name"
    invariant_type: "constraint" # optional, defaults to "constraint"
    relation: "x < 2^64"
    oracle: "must_hold"          # optional, defaults to "must_hold"
    transform: null              # optional (metamorphic invariants)
    expected: null               # optional (metamorphic invariants)
    description: "Human-readable rationale"
    severity: "critical"         # optional free-form severity label
```

## Field Reference

- `name` (required, string):
  unique invariant identifier used in reports and evidence output.
- `invariant_type` (optional enum):
  `constraint`, `metamorphic`, `range`, `uniqueness`, `custom`.
- `relation` (required, string):
  expression parsed by `parse_invariant_relation(...)`.
- `oracle` (optional enum):
  `must_hold`, `constraint_check`, `symbolic`, `differential`, `custom`.
- `transform` (optional string):
  transformation definition for metamorphic invariants.
- `expected` (optional string):
  expected post-transform behavior for metamorphic checks.
- `description` (optional string):
  documentation context for operators and reviewers.
- `severity` (optional string):
  severity tag for downstream triage/reporting.

## Relation DSL (Currently Supported)

The current parser supports:
- binary comparisons: `==`, `!=`, `<`, `<=`, `>`, `>=`
- membership: `a in {0,1}` or `a ∈ {0,1}`
- range chains: `0 <= value <= 2^64`
- universal quantifier prefix: `forall i in path: path[i] in {0,1}` (also supports `∀`)
- simple function form: `merkle_root(path, leaf) == root`
- array indexing: `path[i]`
- powers: `2^64`

Notes:
- Evidence-mode validation expects each invariant relation to reference known campaign input labels.
- Relations that parse as `Raw` expressions do not produce identifier extraction and typically fail strict evidence validation.

## Roadmap Example Mapping

Roadmap examples use keys like `id`, `property`, and `oracle_type`.
Current v2 schema mapping is:
- `id` -> `name`
- `property` -> `relation`
- `oracle_type` -> `oracle` (and/or `invariant_type` where appropriate)
- `severity` -> `severity`

## Practical Example

```yaml
invariants:
  - name: "merkle_root_integrity"
    invariant_type: "constraint"
    relation: "computed_root == public_root"
    oracle: "must_hold"
    description: "Proof must bind leaf/path to the declared root"
    severity: "critical"

  - name: "nullifier_uniqueness"
    invariant_type: "uniqueness"
    relation: "nullifier != previous_nullifier"
    oracle: "constraint_check"
    description: "Prevent double-spend via reused nullifier"
    severity: "critical"
```

## Validation Command

Use strict evidence validation in CI/local checks:

```bash
cargo run --bin validate_yaml -- --yaml <campaign.yaml> --require-invariants
```
