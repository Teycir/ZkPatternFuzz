# Semantic Analysis Operator Guide

This guide provides a compact, reproducible workflow for the three semantic-analysis lanes that are live today:

1. Invariants (definition + validation)
2. Witness extension (constraint-subset semantic attack mode)
3. Halo2 lookup coverage (Plookup-style end-to-end checks)

All commands assume repository root (`ZkPatternFuzz`) and should be run in that directory.

## 1) Invariants Workflow

### 1.1 Validate invariant schema and identifiers

```bash
cargo run --quiet --bin validate_yaml -- templates/ai_assisted_audit.yaml --require-invariants
```

Expected result:
- exits `0` when invariant expressions are parseable and reference known inputs.

### 1.2 Run invariant checker regression tests

```bash
cargo test -q --test test_fuzzer_invariant_checker
```

Expected result:
- invariant parsing/evaluation integration remains green before campaign execution.

## 2) Witness Extension Workflow

Witness-extension logic is currently exercised via focused regression tests around semantic-violation generation and bounded runtime behavior.

```bash
cargo test -q --test test_witness_extension_vulns
cargo test -q --test test_witness_extension_performance
```

Expected result:
- vulnerability-oriented witness-extension cases produce findings when constraints are selectively relaxed.
- performance guardrail test confirms bounded runtime behavior for the configured strategy.

Operator notes:
- witness-extension settings live under attack config key `witness_extension` for `constraint_inference`.
- relevant runtime entrypoint is `src/fuzzer/engine/attack_runner_novel.rs` (`run_constraint_inference_witness_extension`).

## 3) Halo2 Lookup Workflow (Plookup Coverage)

### 3.1 Run Halo2 lookup integration tests

```bash
cargo test -q --test test_halo2_lookup_integration
```

Coverage in this test target:
- fixture-backed Halo2 lookup constraint discovery (`tests/halo2_specs/lookup.json`)
- vector lookup + selector-enabled semantics (pass/skip/fail)
- fail-closed behavior when lookup tables are unresolved

### 3.2 Optional cross-check of generic Halo2 executor lookup path

```bash
cargo test -q --test test_executor_mod halo2_plonk_constraint_checking
```

Expected result:
- executor and constraint inspector agree on the baseline lookup-satisfied path.

## 4) Minimal Release-Ready Semantic Checklist

Use this before semantic-related signoff:

1. `validate_yaml --require-invariants` exits `0`.
2. `test_fuzzer_invariant_checker` passes.
3. `test_witness_extension_vulns` and `test_witness_extension_performance` pass.
4. `test_halo2_lookup_integration` passes.

If any step fails, block semantic signoff and fix before release-candidate promotion.
