# ZkPatternFuzz Refactoring Roadmap

## Scope
Refactor for production readiness by addressing: engine decomposition, typed config, re-export cleanup, moving large attacks to `zk-attacks`, and minor release fixes.

## Sequence
Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5.
Phases 1-2 are sequential and gated. Phase 3 can overlap with Phase 2 if needed. Phase 4 is API-impacting.

---

## Phase 0: Pre-Flight (0.5-1 day)
- Goals: lock scope, baseline behavior.
- Deliverables: refactor branch, baseline test run notes, list of critical campaigns/tests.
- Exit criteria: `cargo check` + `cargo test --test phase0_integration_tests` pass.

## Phase 1: Engine Decomposition (2-4 weeks)
- Goals: split `src/fuzzer/engine.rs` into cohesive modules without behavior change.
- Deliverables: new `src/fuzzer/engine/` module tree; `FuzzingEngine` remains public facade.
- Exit criteria: `cargo check`, `cargo test --test phase0_integration_tests`, no CLI/report schema changes.

## Phase 2: Typed Config (2-3 weeks)
- Goals: replace `Parameters.additional` HashMap with `AdditionalConfig`.
- Deliverables: `src/config/additional.rs`, updated `src/config/mod.rs`, eliminated `additional_*()` helpers.
- Exit criteria: `cargo check`, `cargo test --test phase0_integration_tests`, unknown keys preserved via `extra`.

## Phase 3: Re-export Cleanup (1 week)
- Goals: remove glob re-exports, reduce API ambiguity.
- Deliverables: explicit re-exports in `src/attacks/` and `src/fuzzer/`; no `ambiguous_glob_reexports`.
- Exit criteria: `cargo check`, `cargo clippy -- -D warnings`.

## Phase 4: Move Large Attacks to `zk-attacks` (1-2 weeks)
- Goals: consistent layering, smaller binary crate surface.
- Deliverables: large attacks moved to `crates/zk-attacks/src/`, re-export stubs in `src/attacks/`.
- Exit criteria: `cargo test --workspace`, `cargo test --test ground_truth_regression`.

## Phase 5: Minor Fixes (1-2 days)
- Goals: release polish and lint hygiene.
- Deliverables: README/CHANGELOG URL fixes, unused parameter cleanup.
- Exit criteria: `cargo check`, `cargo test --test zk0d_realistic_tests`.

---

## Milestones
1. Engine split complete and green tests.
2. Typed config merged without regressions.
3. Public API clarified (no glob re-exports).
4. Attacks relocated to `zk-attacks` with backward-compat stubs.
5. Release docs and lint clean.

## Risks
- Phase 4 breaks direct imports (mitigated by re-export stubs).
- Phase 2 can subtly change config defaults (mitigated by preserving unknown keys and adding tests).
