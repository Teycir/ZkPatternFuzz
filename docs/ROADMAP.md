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
1. Deduplicate mock implementations: consolidate `MockCircuit` and `MockCircuitExecutor` into a single, consistent mock path.
2. Wire `CollisionDetector.analyze_collisions()` into the standard engine pipeline, not just manual API calls.
3. Add integration tests that use real backends; reduce `#[ignore]` usage and move toward CI with Circom/nargo installed.

Success Criteria:
1. Heuristic-only attacks are either upgraded to execute circuits or clearly labeled as hints.
2. Regression tests fail when vulnerabilities are removed and pass when they are present, with no hardcoded results.
3. Evidence mode produces consistent proofs/witnesses across Circom, Noir, Halo2, and Cairo.
