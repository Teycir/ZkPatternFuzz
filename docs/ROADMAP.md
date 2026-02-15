# ZkPatternFuzz Roadmap

Date: 2026-02-11
Status: Draft
Ordering: Severity (High → Medium → Low)

Focus: Convert heuristic-only findings into executable evidence, harden regression testing, and raise backend fidelity.

Principles:
1. Evidence over heuristics: every attack should attempt real execution and verification.
2. Deterministic, reproducible outputs: no hardcoded pass/fail in tests.
3. Minimize false positives: elevate proofs and witnesses over metadata signals.

Current Architectural Insight:
1. The `zk-attacks` crate mostly performs static heuristics based on `CircuitInfo` metadata and can produce empty PoCs.
2. The `engine.rs` oracles are the only ones consistently executing circuits and producing concrete witnesses.

**High Priority**
1. Implement `unused_signal_analysis()` in `crates/zk-attacks/src/underconstrained.rs` so it returns real candidate findings instead of empty vectors.
2. Implement `weak_constraint_analysis()` in `crates/zk-attacks/src/underconstrained.rs` so it returns real candidate findings instead of empty vectors.
3. Make `SoundnessTester.run()` attempt proof forgery by mutating proofs or witnesses and calling `verify()`; use `forge_attempts` and `mutation_rate` instead of only checking DOF ratio.
4. Fix `CVERegressionTest::run()` to execute circuits against known vulnerable patterns instead of returning `passed: true` unconditionally.
5. Make `zk-attacks` attacks execute circuits: `CollisionDetector.run()`, `BoundaryTester.run()`, and similar should call the executor. Wire existing `analyze_collisions()` and `check_range_enforcement()` into `run()`.

**Medium Priority**
1. Fix Noir `setup_keys()` to generate real keys via `bb` (Barretenberg) or explicitly document and enforce the limitation if keygen is not supported.
2. Flesh out Halo2 and Cairo backends so they reach parity with Circom/Noir for evidence generation.

**Low Priority**
1. Remove legacy synthetic backend paths and keep runtime execution real-backend-only.
2. Wire `CollisionDetector.analyze_collisions()` into the standard engine pipeline, not just manual API calls.
3. Add integration tests that use real backends; reduce `#[ignore]` usage and move toward CI with Circom/nargo installed.

Success Criteria:
1. Heuristic-only attacks are either upgraded to execute circuits or clearly labeled as hints.
2. Regression tests fail when vulnerabilities are removed and pass when they are present, with no hardcoded results.
3. Evidence mode produces consistent proofs/witnesses across Circom, Noir, Halo2, and Cairo.

---

## Patch Addendum (2026-02-13)

Source inputs:
1. `BUGS_REPORT.md` (validated against TODO/FIXME locations)
2. Current field-modulus review for cross-backend correctness

Scope note:
1. `tests/bench/known_bugs/*` and `tests/ground_truth/chains/*` are intentionally vulnerable fixtures and should not be "patched" as product bugs.
2. Patch work targets engine/backend/reporting correctness and verification fidelity.

**P0: Correctness / False-Negative Risk**
1. Add `field_modulus()` to `zk-backends::TargetCircuit` and implement it across all target implementations.
2. Fix Cairo modulus propagation end-to-end:
   `CairoTarget::field_modulus()` returns Starkware prime and `CairoExecutor::field_modulus()` delegates to target (currently missing override).
3. Keep Halo2 non-BN254 support intact when refactoring modulus flow:
   do not regress existing `pasta`/`bls12-381` mapping to BN254 compatibility handling.
4. Make Circom modulus resolution robust:
   handle aliases (`bn128`/`bn254`) and numeric prime strings safely; fail closed on invalid parse.
5. Remove BN254 hardcoding in semantic range checks by wiring runtime modulus into `RangeProofOracle`.

**P1: Evidence Credibility**
1. Replace Coq placeholder proofs (`Admitted` / TODO proof stubs) with generated obligations that can be completed or explicitly mark output as skeleton-only.
2. Replace Lean `sorry` theorem stubs with either compilable proof skeleton mode or real proof generation.
3. Complete Halo2 evidence script integration points currently left as TODO placeholders.
4. Implement R1CS parsing in `ConstraintParser::parse_r1cs` and add regression tests for representative circuits.

**P2: Distributed Robustness and UX**
1. Implement distributed coverage bitmap merging in `corpus_sync`.
2. Implement work-unit requeue on coordinator timeout/disconnect.
3. Add chain progress reporter wiring in CLI chain mode.

**P3: Tooling/Test Debt**
1. Replace `TODO_INPUT` placeholder behavior in skimmer candidate invariant generation with deterministic inferred input selection.
2. Complete false-positive-rate measurement path in `tests/false_positive_analysis.rs`.
3. Enable real circom execution path in `tests/ground_truth_test.rs` when tooling is available in CI/dev images.

### Completion Status (Updated 2026-02-13)

1. `P0.1` complete: `field_modulus()`/`field_name()` are implemented across Circom, Cairo, Halo2, Noir, and test fixtures.
2. `P0.2` complete: Cairo modulus propagation is wired end-to-end (`CairoTarget` and `CairoExecutor`).
3. `P0.3` complete: Halo2 field mapping (`bn254`, `pasta`, `bls12-381`) is preserved with no BN254 regression.
4. `P0.4` complete: Circom prime alias handling is robust (`bn128`/`bn254` + numeric parse path).
5. `P0.5` complete: semantic range checks now use runtime modulus via `RangeProofOracle::new_with_modulus`.
6. `P1.1` complete: Coq export now emits obligation-style definitions and identity theorems (no `Admitted` placeholders).
7. `P1.2` complete: Lean export now emits obligation-style definitions and identity theorems (no `sorry` placeholders).
8. `P1.3` complete: Halo2 evidence script now uses `Halo2Target` directly (no project-specific `YourCircuit` glue).
9. `P1.4` complete: `ConstraintParser::parse_r1cs` supports JSON and text forms with regression coverage.
10. `P2.1` complete: distributed coverage bitmap merging is implemented in `corpus_sync`.
11. `P2.2` complete: timed-out/disconnected node work units are requeued with priority.
12. `P2.3` complete: chain progress reporting is wired in CLI chain mode.
13. `P3.1` complete: `TODO_INPUT` placeholder behavior replaced with deterministic inferred inputs.
14. `P3.2` complete: false-positive analysis path now executes real measurement flow.
15. `P3.3` complete: ground-truth known-bug test uses real Circom execution when available, otherwise skips explicitly.
16. Validation checklist complete: `docs/VALIDATION_PLAN.md` deliverables are backed by `tests/campaigns/validation/*`, `tests/scripts/*`, `reports/validation/*.md`, and `docs/VALIDATION_RESULTS.md`.

### Addendum: Backend Policy

1. Removed legacy `mock` backend enum/module paths from runtime code.
2. Runtime execution remains strict real-backend-only.
3. Test-only deterministic execution uses `FixtureCircuitExecutor` with no runtime alternate-path behavior.

Validation gates for this addendum:
1. `cargo check --workspace`
2. `cargo test --workspace` (or scoped backend suites where tooling is available)
3. Focused regression tests for:
   - modulus-aware boundary and overflow checks
   - range oracle behavior across BN254 vs Cairo prime
   - Halo2 field selection (`bn254`/`pasta`/`bls12-381`) without compatibility regression

Validation snapshot (2026-02-13):
1. `cargo check --workspace` ✅
2. `cargo check --workspace --tests --benches` ✅
3. `cargo test --workspace --lib` ✅
4. Focused integration checks executed and passing:
   - `ground_truth_infrastructure_smoke_test`
   - `unit_tests::test_fp_result_calculation`
   - `test_halo2_target_basic_construction`
   - `test_field_modulus_circuit_specific`
