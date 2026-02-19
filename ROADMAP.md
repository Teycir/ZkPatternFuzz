# ZkPatternFuzz Production Roadmap

Date: 2026-02-17  
Status: Active  
Primary goal: make the scanner production-grade for real multi-target runs with high recall and high runtime stability.

## Latest Progress (2026-02-18)
Completed reliability hardening in Circom backend (`crates/zk-backends/src/circom/mod.rs`):
1. Removed panic-based lock handling in compile/setup/prove/verify/witness paths (poisoned lock now returns `Result` error with context).
2. Replaced several unbounded external command executions with timeout-wrapped execution (`run_with_timeout`) in compile/prove/verify and tool availability checks.
3. Removed panic in output basename derivation by returning structured error instead of `expect`.
4. Improved backend failure diagnostics with richer command-failure context in critical paths.
5. Bounded ptau `curl` download with timeout + explicit command-failure diagnostics (min 300s download timeout).
6. Added batch run reason-code aggregation in `zk0d_batch` from per-template `run_outcome.json` (console scorecard summary + per-template non-success reasons).
7. Added collision-safe automatic scan run-root allocation for parallel scans (atomic reservation under `.scan_run_artifacts`, keeping `scan_runYYYYMMDD_HHMMSS` naming).
8. Added backend preflight hardening for Circom key setup (`circom_require_setup_keys`) and wired scan materialization to enforce key-setup/toolchain readiness up front.
9. Added `zk-fuzzer preflight <campaign.yaml> [--setup-keys]` command for explicit backend/keygen readiness checks.
10. Implemented regex selector policy controls (`selector_policy`) with weighted matching, `k_of_n` thresholds, and optional group-level gates while preserving default behavior (`>=1` match).
11. Added selector-policy regression tests in `src/main.rs` for default compatibility, pass/fail gating, and invalid-policy rejection.
12. Implemented selector synonym bundles (`selector_synonyms` / `synonym_bundles`) with placeholder expansion (`{{bundle}}`) and optional normalization controls (`selector_normalization.synonym_flexible_separators`) for style-tolerant matching.
13. Added selector normalization/synonym regression tests in `src/main.rs` (bundle expansion pass, normalization toggle, unknown-bundle validation).
14. Added `zk-fuzzer bins bootstrap` command to internalize local Circom dependencies under `bins/`:
   - Circom release download from GitHub assets with SHA-256 digest verification.
   - Local `snarkjs` install/link under `bins/node_modules` and `bins/bin`.
   - ptau install from verified local fixture or URL+checksum.
15. Added deterministic ptau autodiscovery precedence in Circom executor (`ZKF_PTAU_PATH` override, local `bins/ptau` first) with regression tests.
16. Added full logic audit report (2026-02-18 snapshot) with severity-ranked findings and prioritized remediation queue.
17. Fixed adaptive orchestrator budget wiring (`src/fuzzer/adaptive_orchestrator.rs`): scheduler allocations are now enforced through per-attack phase execution instead of being computed and ignored.
18. Fixed adaptive scheduler budget semantics (`src/fuzzer/adaptive_attack_scheduler.rs`): clamped fractions are normalized and rounded with largest-remainder allocation so total allocated time equals requested budget exactly.
19. Added timeout-wrapped external command execution in proof forgery detector (`crates/zk-constraints/src/proof_forgery.rs`) for `snarkjs wtns import`, `groth16 prove`, and `groth16 verify` with kill-on-timeout behavior.
20. Fixed Cairo executor always-fail path (`src/executor/mod.rs`) by using deterministic output-hash coverage fallback when constraint-level coverage is unavailable, plus regression test.
21. Added Noir constraint caching (`src/executor/mod.rs`) via `OnceLock<Vec<ConstraintEquation>>` to avoid repeated disk loads/parsing in `get_constraints` and `check_constraints`.
22. Removed panic fallback in `engagement_dir_name` (`src/main.rs`) and replaced with deterministic sanitized fallback directory naming.
23. Removed panic on invalid `CIRCOM_INCLUDE_PATHS` decoding (`src/executor/mod.rs`) and switched to non-panicking warning + fallback path resolution.
24. Removed runtime `set_var` in Circom execution path by switching to command-local PATH injection in backend command builders (`crates/zk-backends/src/circom/mod.rs`) and dropping runtime env mutation in CLI timeout alignment (`src/main.rs`).
25. Hardened Circom external-timeout env parsing to warn-and-fallback defaults instead of panicking on invalid values.
26. Added `zk0d_matrix` multi-target runner (`src/bin/zk0d_matrix.rs`) with `jobs`/`batch-jobs`/`workers` guardrails, parallel target execution, and per-target reason-code aggregation from `zk0d_batch --emit-reason-tsv`.
27. Added default matrix config template (`targets/zk0d_matrix.yaml`) and target-matrix usage docs (`docs/TARGETS.md`).
28. Added retry-on-transient-setup policy in `zk0d_batch` (`src/bin/zk0d_batch.rs`) with one retry and configurable backoff (`--retry-transient-setup`, `--retry-backoff-secs`), keyed by stable reason-code classification.
29. Completed repeated-trial benchmark harness for vulnerable/safe suites (`src/bin/zk0d_benchmark.rs`, `targets/benchmark_suites.yaml`): env-aware path expansion, non-dropped failed trials, recall/precision/safe-FPR metrics with 95% Wilson confidence intervals, and benchmark run docs in `docs/TARGETS.md`.
30. Added CI benchmark regression gates (`.github/workflows/ci.yml`, `scripts/ci_benchmark_gate.sh`) using `zk0d_benchmark` summary metrics with explicit thresholds for completion/recall/precision/safe-FPR and artifact upload of benchmark outputs.
31. Added explicit environment config separation for dev/prod benchmark and batch runs:
   - `zk0d_batch --config-profile <dev|prod>` registry defaults (`targets/fuzzer_registry.dev.yaml`, `targets/fuzzer_registry.prod.yaml`)
   - `zk0d_benchmark --config-profile <dev|prod>` suites/registry defaults (`targets/benchmark_suites.{dev,prod}.yaml`, `targets/benchmark_registry.{dev,prod}.yaml`)
   - Dev profile wired as CI default for fast/stable regression gating.
32. Hardened ptau validation to reject truncated/corrupt files by size + header in Circom backend (`crates/zk-backends/src/circom/mod.rs`), preventing false-valid 263-byte ptau cache entries from causing repeated keygen failures.
33. Added scan/report contract compatibility assertions in CLI smoke regression (`tests/mode123_nonregression.rs`) to lock stable scan-mode artifact filenames and required JSON fields in `summary.json` + `misc/run_outcome.json`.
34. Hardened run-document command extraction (`src/main.rs`) to avoid panic-on-missing-`command` in panic/signal artifacts by falling back to `context.command` (or `unknown`), with regression tests.
35. Added production release checklist (`docs/RELEASE_CHECKLIST.md`) covering toolchain gates, regression/benchmark gates, migration notes, artifact verification, and rollback readiness.
36. Added troubleshooting playbook (`docs/TROUBLESHOOTING_PLAYBOOK.md`) for keygen failures, include-path errors, output-lock contention, timeout tuning, and reason-code triage.
37. Replaced split benchmark/nightly jobs with a unified release-hardening CI matrix in `.github/workflows/ci.yml`:
   - `fast-smoke` lane for push/PR (blocking regression gate, dev profile).
   - `deep-scheduled` lane for nightly schedule (prod profile, trend artifacts + warning alerts on regression).
38. Added release-candidate consecutive-pass gate script (`scripts/release_candidate_gate.sh`) to enforce "last N benchmark summaries pass" checks (default `N=2`).
39. Added rollback validation script (`scripts/rollback_validate.sh`) using isolated git worktree build/smoke checks for a previous stable ref.
40. Extended benchmark gate script (`scripts/ci_benchmark_gate.sh`) with optional explicit summary path override to support multi-summary release gating.
41. Added dedicated manual release validation workflow (`.github/workflows/release_validation.yml`) to run:
   - consecutive benchmark pass gate (`required_passes=2` by default),
   - rollback validation against a specified stable ref.
42. Added release-validation invocation docs in `docs/TARGETS.md` with `gh workflow run` + `gh run watch` command templates and required `workflow_dispatch` inputs.
43. Added `README.md` "Release Ops" section linking release checklist, release-validation workflow docs, and troubleshooting playbook for gate failures.
44. Added nightly failure-class dashboard generation (`scripts/benchmark_failure_dashboard.py`) and wired it into deep-scheduled CI matrix runs to emit pass/fail by failure class under `artifacts/benchmark_trends/`.
45. Added configurable failure-class threshold overrides for nightly dashboard gating:
   - Script supports environment overrides (`ZKF_FAILURE_MAX_RATE_*`) and repeatable CLI overrides (`--threshold class=rate`).
   - Deep-scheduled CI lane now reads optional GitHub Actions repository variables for threshold tuning.
   - Dashboard evaluation applies overrides while preserving existing artifact paths and output schema.
46. Added dashboard threshold and schema regression tests (`tests/test_benchmark_failure_dashboard.py`):
   - Validates default/env/CLI threshold resolution and CLI-over-env precedence.
   - Fails fast on invalid threshold inputs.
   - Locks dashboard payload top-level schema keys to preserve report contract stability.
47. Wired failure-dashboard regression tests into release-hardening CI matrix (`.github/workflows/ci.yml`) before benchmark execution.
   - Added explicit malformed-threshold unit test (`--threshold` without `=`) to tighten input contract checks.
48. Fixed hardcoded seed=42 in adaptive orchestrator phases to use random seed per phase, preserving user seed control.
49. Removed `.max(1)` floor on new_coverage in adaptive orchestrator to allow scheduler decay branch to function correctly.
50. Replaced Hamming distance with arithmetic distance in near-miss field_difference() for reliable near-miss detection.
51. Added min_value boundary check in near-miss detector to catch lower-bound proximity signals.
52. Applied largest-remainder method to chain scheduler budget allocation to match adaptive scheduler fairness.
53. Removed `?` from regex safety validator dangerous quantifier list (lazy/optional patterns are safe).
54. Replaced O(n) Vec::remove(0) with Vec::drain(0..1) in range oracle hot path.
55. Changed kill_existing_instances to use `pgrep -x` instead of `pgrep -f` to avoid over-matching.
56. Fixed regex safety validator compile regression in `src/main.rs` by restoring `anyhow::bail!` callsite.
57. Added targeted regression coverage for recent logic hardening:
   - Chain scheduler largest-remainder allocation now has exact-budget/fairness assertion.
   - Near-miss detector min-boundary proximity + arithmetic-distance semantics are covered by dedicated tests.
   - Regex safety tests now explicitly allow optional quantifiers while still rejecting truly nested quantifiers.
58. Hardened adaptive zero-day confirmation matching (`src/fuzzer/adaptive_orchestrator.rs`) from category-only to content-aware scoring:
   - Added token/keyword/location-based hint-to-finding match scoring.
   - Enforced one-to-one matching so one finding cannot confirm multiple hints.
   - Fixed unconfirmed-hint accounting to track hint identity instead of category-only keys.
59. Documented and contained dynamic log routing transition window (`src/main.rs`, `docs/TROUBLESHOOTING_PLAYBOOK.md`):
   - Added immediate best-effort log-file rebind on run-log context updates to reduce cross-run spillover.
   - Added explicit operator guidance on residual transition-window behavior and run-artifact source-of-truth.
   - Added release checklist gate item for session-log routing caveat documentation.
60. Closed remaining panic-path hardening item (`M-1`, `L-2`) with explicit regression coverage:
   - Added `engagement_dir_name` invalid-run-id non-panicking regression in `src/main.rs`.
   - Added invalid UTF-8 `CIRCOM_INCLUDE_PATHS` non-panicking regression in `src/executor/mod.rs` (Unix).
61. Started run lifecycle deduplication for CLI campaign modes (`src/main.rs`) as groundwork for `I-1`/`I-2`:
   - Extracted shared run-log context helpers (`set_run_log_context_for_campaign`, `RunLogContextGuard`) used by both `run_campaign` and `run_chain_campaign`.
   - Extracted shared output-lock acquisition + failure artifact handling (`acquire_output_lock_or_write_failure`) used by both modes.
62. Continued run lifecycle deduplication (`src/main.rs`) by extracting shared running-artifact seeding:
   - Added `seed_running_run_artifact(...)` helper for common `status=running` artifact shape + run-window fields.
   - Replaced duplicated initial running-artifact blocks in `run_campaign` and `run_chain_campaign` with helper calls.
63. Continued run lifecycle deduplication (`src/main.rs`) by extracting shared early failure artifact emission:
   - Added `write_failed_run_artifact_with_error(...)` helper for common early-failure metadata fields.
   - Replaced duplicated load-config failure paths in `run_campaign` and `run_chain_campaign`.
   - Replaced duplicated profile-parse failure path in `run_campaign`.
64. Continued run lifecycle deduplication (`src/main.rs`) by extracting shared post-lock failure doc construction:
   - Added `failed_run_doc_with_window(...)` helper for common failed-run metadata + run-window fields.
   - Replaced duplicated preflight/readiness/backend failure doc builders in `run_campaign`.
   - Replaced duplicated backend-preflight failure doc builder in `run_chain_campaign`.
65. Continued run lifecycle deduplication (`src/main.rs`) by reusing shared running-artifact seeding for stage transitions:
   - Replaced duplicated `stage="starting_engine"` running-artifact builders in `run_campaign` and `run_chain_campaign`.
   - Reused `seed_running_run_artifact(...)` while preserving each mode's options payload shape.
66. Continued run lifecycle deduplication (`src/main.rs`) by extracting chain-parse failure doc construction:
   - Replaced duplicated `parse_chains` failed-run doc builder in `run_chain_campaign` with `failed_run_doc_with_window(...)`.
   - Preserved existing operator-facing reason text and dry-run artifact behavior.
67. Continued run lifecycle deduplication (`src/main.rs`) by collapsing remaining runtime/report failure doc builders:
   - Replaced duplicated chain preflight-readiness failure doc builder with `failed_run_doc_with_window(...)`.
   - Replaced duplicated chain runtime/report failure doc builders (`engine_init`, `engine_run_chains`, `save_chain_reports`, `save_standard_report`) with `failed_run_doc_with_window(...)`.
   - Replaced duplicated run-mode runtime/report failure doc builders (`engine_run`, `save_report`) with `failed_run_doc_with_window(...)`.
68. Accelerated run lifecycle deduplication with shared running/completed doc helpers (`src/main.rs`):
   - Added `running_run_doc_with_window(...)` and `completed_run_doc_with_window(...)` for common status metadata + run-window fields.
   - Refactored `seed_running_run_artifact(...)` to reuse `running_run_doc_with_window(...)`.
   - Replaced remaining inline `status="running"` doc builders (`engine_progress`, `engine_run`) with `running_run_doc_with_window(...)`.
   - Replaced duplicated completion doc builders in both `run_campaign` and `run_chain_campaign` with `completed_run_doc_with_window(...)`.
69. Batched failure-emission helper extraction to remove repeated post-lock boilerplate (`src/main.rs`):
   - Added `write_failed_mode_run_artifact_with_error(...)` for standard `failed + error` artifact emission with run-window fields.
   - Added `write_failed_mode_run_artifact_with_reason(...)` for standard `failed + reason (+ readiness)` artifact emission with run-window fields.
   - Replaced duplicated post-lock failure emitters across run/chain stages (`preflight_*`, `engine_*`, `save_*`, and chain-parse checks) with helper calls.
70. Continued multi-task lifecycle deduplication with shared strict-readiness and backend-preflight gates (`src/main.rs`):
   - Added `require_evidence_readiness_or_emit_failure(...)` to centralize strict readiness fail/emit/bail behavior.
   - Added `run_backend_preflight_or_emit_failure(...)` to centralize backend preflight fail/emit behavior.
   - Replaced duplicated readiness and backend-preflight gate blocks in both `run_campaign` and `run_chain_campaign` with helper calls.
71. Continued lifecycle deduplication with shared pre-run setup orchestration (`src/main.rs`):
   - Added `initialize_campaign_run_lifecycle(...)` to centralize output lock acquisition, stale-run marking, run-context binding, running-artifact seeding, and build-path normalization.
   - Replaced duplicated pre-run setup blocks in both `run_campaign` and `run_chain_campaign` with helper calls returning `(output_dir, output_lock)`.
72. Separated production and test concerns for CLI selector/command regressions (`src/main.rs`, `src/scan_selector_tests.rs`):
   - Moved `scan_selector_tests` module out of `src/main.rs` into dedicated test file `src/scan_selector_tests.rs`.
   - Kept production `src/main.rs` lean by replacing the inline test module with `#[cfg(test)] mod scan_selector_tests;`.
   - Preserved existing test names/coverage (including `run_doc_command_extraction_*`) while removing test bodies from production source.
73. Enforced strict repository-wide separation of test bodies from production source (`src/`, `crates/`):
   - Extracted inline `#[cfg(test)] mod ... { ... }` blocks into dedicated sibling `*_tests.rs` files across the workspace.
   - Replaced in-source test bodies with lightweight `#[cfg(test)]` module declarations using explicit `#[path = \"...\"]` links.
   - Fixed bin-target edge cases by relocating extracted bin tests to `src/bin/<bin_name>/<bin_name>_tests.rs` so Cargo does not treat them as extra binaries.
   - Verified no production file outside `*_tests.rs` contains inline `#[test]` functions or `mod tests { ... }` bodies.
74. Continued production-path factorization by isolating run-option payload construction (`src/main.rs`):
   - Added `campaign_run_options_doc(...)` and `chain_run_options_doc(...)` helpers to centralize run artifact options-shape construction.
   - Replaced duplicated inline option JSON payload builders in lifecycle initialization and `starting_engine` stage updates for both `run_campaign` and `run_chain_campaign`.
   - Reduced lifecycle orchestration callsites to orchestration intent without embedded payload-building details.
75. Continued production-path factorization by extracting non-orchestration runtime helpers into focused modules (`src/main.rs`, `src/runtime_misc.rs`, `src/scan_progress.rs`, `src/scan_output.rs`):
   - Moved config validation/minimization/init-template/banner/run-window helpers from `main.rs` into `runtime_misc`.
   - Moved scan progress polling + findings-summary readers into `scan_progress`.
   - Moved scan output-suffix isolation/allocation/summary helpers into `scan_output`.
   - Kept `main.rs` focused on command dispatch and run orchestration by importing these modules.
76. Deleted legacy attack-module and mode naming surfaces instead of hiding them (`src/lib.rs`, `src/oracles/`, `src/main.rs`, `tests/mode123_nonregression.rs`):
   - Removed `src/attacks` module path by renaming it to `src/oracles` and updating all internal/external imports from `attacks` to `oracles`.
   - Removed hardcoded legacy engagement folders `mode1/mode2/mode3`; runtime now uses command-native folders `scan/chains/misc`.
   - Updated scan campaign command labeling to emit `command="scan"` in run artifacts so engagement summaries route to `modes.scan`.
   - Updated non-regression engagement contract fixture to assert `scan/` paths and `modes.scan` instead of legacy `misc` fallback.
77. Enforced stricter config test separation under a dedicated config-test module boundary (`src/config/`):
   - Moved all config test files out of production config root into `src/config/tests/`.
   - Updated production config modules to reference test files via explicit `#[cfg(test)] #[path = "tests/..."]`.
   - Added dedicated config test fixture module `src/config/tests/test_config.rs` and wired `suggester` tests to use shared fixture YAML.
   - Kept production config root (`src/config/*.rs`) focused on runtime config logic while isolating test assets in `src/config/tests/`.
78. Continued CLI factorization by extracting run-outcome, output-lock, and backend-preflight helpers into dedicated modules (`src/main.rs`, `src/run_outcome_docs.rs`, `src/output_lock.rs`, `src/preflight_backend.rs`):
   - Moved run-window/doc builders and reason-code classification logging from `main.rs` to `run_outcome_docs`.
   - Moved output lock wait/retry policy from `main.rs` to `output_lock`.
   - Moved backend preflight option parsing and campaign preflight execution from `main.rs` to `preflight_backend`.
   - Kept run orchestration callsites in `main.rs` behavior-preserving while reducing mixed concerns.
79. Continued CLI factorization by extracting engagement artifact/signal/snapshot helpers into dedicated module (`src/main.rs`, `src/engagement_artifacts.rs`):
   - Moved run artifact JSON/JSONL writers, mode-folder routing, output snapshot mirroring, and engagement summary generation from `main.rs` to `engagement_artifacts`.
   - Moved run-signal + run-artifact emission wrappers (including scan timestamp total log update) into `engagement_artifacts`.
   - Kept lifecycle/orchestration callsites in `main.rs` behavior-preserving while shrinking mixed I/O/reporting logic.
   - Updated selector/command regression tests to import `get_command_from_doc` from the extracted module boundary.
80. Accelerated attack execution coverage by wiring previously non-executed attack families into runtime dispatch (`src/fuzzer/engine/mod.rs`, `src/fuzzer/engine/attack_runner.rs`, `src/fuzzer/phased_scheduler.rs`, `crates/zk-core/src/types.rs`, `crates/zk-attacks/src/batch_verification.rs`):
   - Added direct engine dispatch for existing variants that previously fell through as "not yet implemented": `TrustedSetup`, `ConstraintBypass`, `Malleability`, `ReplayAttack`, `WitnessLeakage`, `Mev`, `FrontRunning`, `ZkEvm`, and `BatchVerification`.
   - Added runtime wrappers for MEV/front-running/zkEVM/batch-verification attack execution with YAML-config overrides and evidence-compatible finding emission.
   - Made batch-verification runner accept trait-object executors (`E: CircuitExecutor + ?Sized`) so engine-level dispatch can invoke it.
   - Extended phased scheduler string parsing to include broader attack-type aliases so configured phases can schedule these families.
   - Extended `Finding` deserialization to recognize Phase-3 attack variants (`Mev`, `FrontRunning`, `ZkEvm`, `BatchVerification`) and added regression coverage.
81. Accelerated advanced-security roadmap implementation with first-class runtime wiring and YAML scaffolding (`crates/zk-core/src/types.rs`, `src/fuzzer/engine/{mod.rs,attack_runner.rs}`, `src/fuzzer/{phased_scheduler.rs,oracle_validation.rs,oracle_correlation.rs}`, `src/reporting/sarif.rs`, `templates/attacks/`, `campaigns/examples/`, `tests/phase0_integration_tests.rs`):
   - Added core/runtime support for `SidechannelAdvanced`, `QuantumResistance`, `PrivacyAdvanced`, and `DefiAdvanced` (type system, scheduler aliases, oracle grouping/validation family mapping, SARIF rule mapping, and engine dispatch).
   - Added runtime runner implementations for the four advanced families and bridged them to existing lower-level detectors for immediate execution coverage.
   - Completed all five planned YAML attack templates and all five example audit campaigns under `campaigns/examples/`.
   - Added targeted integration dispatch coverage for Phase-3 + advanced families and expanded finding-deserialization coverage.
82. Implemented dedicated advanced attack modules in `zk-attacks` and switched engine advanced runners to these reusable primitives (`crates/zk-attacks/src/{sidechannel_advanced.rs,quantum_resistance.rs,privacy_advanced.rs,defi_advanced.rs}`, `src/oracles/mod.rs`, `src/fuzzer/engine/attack_runner.rs`):
   - Added first-class module APIs + unit tests for side-channel advanced, quantum-resistance, privacy advanced, and DeFi advanced.
   - Added thin `src/oracles/` re-export wrappers so runtime/import surface stays consistent with existing module organization.
   - Refactored engine advanced attack runners to use these module APIs rather than inlined ad-hoc logic.
83. Added static-first Circom lint lane and fail-fast severity gating to accelerate early detection (`crates/zk-attacks/src/circom_static_lint.rs`, `src/fuzzer/engine/attack_runner.rs`, `src/config/v2.rs`, `src/fuzzer/phased_scheduler.rs`, `templates/traits/static_first_pass.yaml`):
   - Added new `AttackType::CircomStaticLint` with full runtime wiring (scheduler parsing, engine dispatch, SARIF mapping, finding deserialization).
   - Implemented heuristic Circom static checks: `UnusedSignal`, `UnconstrainedOutput`, `DivisionBySignal`, `MissingConstraint`.
   - Added schedule-level fail-fast severities (`fail_on_findings`) and enabled static prepass fail-fast on `critical`/`high`.
   - Hardened static quantum scan to use word-boundary matching and avoid unnecessary witness generation.
84. Accelerated generator-driven adoption and static-evidence handling for early-pass attacks (`src/config/generator.rs`, `src/fuzzer/engine/attack_runner.rs`, `src/config/tests/generator_tests.rs`, `src/fuzzer/engine/attack_runner_tests.rs`):
   - Added first-class generator pattern matchers for `quantum_resistance` and `trusted_setup` indicators.
   - Added auto-attack injection + phase scheduling hooks so generator output includes these attacks when patterns are detected.
   - Updated static-evidence retention to treat `CircomStaticLint` findings with source locations as concrete evidence (not downgraded/dropped heuristic hints).
   - Added targeted regression coverage for both matcher detection and static evidence classification.
85. Closed the remaining security-roadmap Rust implementation gap with a first-class trusted-setup module (`crates/zk-attacks/src/trusted_setup.rs`, `src/oracles/setup_poisoning.rs`, `src/fuzzer/engine/attack_runner.rs`):
   - Added `TrustedSetupAttack` and `TrustedSetupConfig` in `zk-attacks` for reusable cross-setup poisoning checks.
   - Preserved backward compatibility via `SetupPoisoningDetector` compatibility wrapper.
   - Switched runtime oracle surface to re-export trusted-setup primitives from `zk-attacks` instead of maintaining a separate local implementation.
   - Fixed trusted-setup runner finding-family mapping so configured `trusted_setup` runs emit findings under the expected attack type.
86. Continued CLI modularization for run lifecycle helpers (`src/main.rs`, `src/run_lifecycle.rs`):
   - Extracted lifecycle artifact emitters (`running`, `failed/error`, `failed/reason`) from `main.rs` into a dedicated module.
   - Extracted strict-readiness and backend-preflight fail/emit wrappers into the same module.
   - Kept `run_campaign`/`run_chain_campaign` behavior unchanged while shrinking orchestration surface in `main.rs`.
87. Continued CLI modularization by extracting stale-run and early-failure helpers (`src/main.rs`, `src/run_lifecycle.rs`):
   - Moved stale-run detection/marker emission (`pid_is_alive`, `mark_stale_previous_run_if_any`) into `run_lifecycle`.
   - Moved early failure artifact emitters (`write_failed_run_artifact`, `write_failed_run_artifact_with_error`) into `run_lifecycle`.
   - Updated panic/signal and early-config-failure callsites to use shared lifecycle helper module.
88. Continued CLI modularization by extracting output-lock failure helper (`src/main.rs`, `src/run_lifecycle.rs`):
   - Moved `acquire_output_lock_or_write_failure` from `main.rs` into `run_lifecycle`.
   - Reused the shared early-failure artifact emitter from lifecycle module for lock-failure reporting.
   - Kept pre-run lifecycle initialization flow unchanged in `initialize_campaign_run_lifecycle`.
89. Continued CLI modularization by extracting lifecycle initialization helper (`src/main.rs`, `src/run_lifecycle.rs`):
   - Moved `initialize_campaign_run_lifecycle` from `main.rs` into `run_lifecycle`.
   - Kept run-log context binding + stale-run marking behavior unchanged by reusing shared hooks (`set_run_log_context_for_campaign`, `normalize_build_paths`).
   - Preserved existing callsites in `run_campaign` and `run_chain_campaign` while reducing orchestration code in `main.rs`.
90. Continued main-surface reduction by localizing scan summary append helper (`src/main.rs`, `src/scan_output.rs`):
   - Moved `best_effort_append_text_line` from `main.rs` into `scan_output`.
   - Replaced cross-module `crate::best_effort_append_text_line(...)` calls with module-local helper usage.
   - Removed now-unused `std::io::Write` import from `main.rs`.
91. Continued main-surface reduction by extracting pattern-only YAML validation (`src/main.rs`, `src/scan_dispatch.rs`):
   - Moved `validate_pattern_only_yaml` from `main.rs` into `scan_dispatch`.
   - Kept scan command behavior unchanged by importing and reusing the extracted helper at existing callsites.
   - Reduced scan dispatch validation logic remaining in `main.rs` without changing pattern contract checks.
92. Continued scan modularization by wiring `main.rs` to the dedicated selector module (`src/main.rs`, `src/scan_selector.rs`):
   - Removed duplicated in-file selector type/function implementations from `main.rs`.
   - Imported selector loading/evaluation and summary types from `scan_selector`.
   - Preserved scan behavior and selector test surface while materially shrinking `main.rs`.
93. Continued scan modularization by extracting scan campaign materialization into dispatch module (`src/main.rs`, `src/scan_dispatch.rs`):
   - Moved `ScanTarget` and `materialize_scan_pattern_campaign(...)` from `main.rs` to `scan_dispatch`.
   - Kept regex-selector metadata stripping, include-path rewriting, and scan parameter injection behavior unchanged.
   - Updated selector regression tests to use explicit `std::fs` import instead of relying on `main.rs` wildcard imports.
94. Continued scan modularization by extracting selector gating + mismatch diagnostics (`src/main.rs`, `src/scan_selector.rs`):
   - Added `evaluate_scan_selectors_or_bail(...)` in `scan_selector` to centralize selector pass/fail orchestration.
   - Moved selector-threshold failure-detail construction out of `run_scan` into module-local helper logic.
   - Kept selector evaluation semantics and mismatch error text shape unchanged while reducing `run_scan` branching complexity.
95. Batched scan modularization by extracting family-resolution policy from `run_scan` (`src/main.rs`, `src/scan_dispatch.rs`):
   - Added `resolve_scan_family(...)` to centralize regex-mode mono forcing and `--family`/`chains` consistency checks.
   - Moved complexity-gate dispatch (`validate_scan_pattern_complexity` vs regex-mode skip) behind the same helper.
   - Kept existing operator-facing diagnostics unchanged while removing family-branching boilerplate from `main.rs`.
96. Batched scan modularization by extracting scan-target construction (`src/main.rs`, `src/scan_dispatch.rs`):
   - Added `build_scan_target(...)` for framework parsing + target struct assembly from CLI scan args.
   - Removed direct `ScanTarget` construction and framework parsing details from `run_scan`.
   - Preserved target materialization inputs and framework validation behavior.
97. Batched scan modularization by extracting shared scan-mode progress wrapper (`src/main.rs`, `src/scan_progress.rs`):
   - Added `run_scan_mode_with_progress(...)` to centralize `SCAN START/END`, periodic progress, and findings summary emission.
   - Replaced duplicated mono/multi run-shell logic in `run_scan` with a shared helper call.
   - Kept multi-scan corpus guardrail behavior unchanged.
98. Continued scan modularization by extracting family-run dispatch orchestration (`src/main.rs`, `src/scan_progress.rs`):
   - Added `dispatch_scan_family_run(...)` to centralize `mono`/`multi` scan execution branching.
   - Moved mono-only corpus guardrail enforcement into the shared dispatch helper.
   - Reduced `run_scan` to pure scan preparation/orchestration while preserving runtime behavior.
99. Continued scan modularization by extracting scan-preparation orchestration (`src/main.rs`, `src/scan_dispatch.rs`):
   - Added `prepare_scan_dispatch(...)` to centralize pattern-only validation, selector config load/evaluation, family resolution, target construction, and campaign materialization.
   - Added `PreparedScanDispatch` to return normalized scan execution inputs (`family` + materialized campaign path).
   - Reduced `run_scan` to dispatch-only orchestration while preserving selector and materialization behavior.
100. Continued scan modularization by isolating scan-run orchestration into a dedicated runner module (`src/main.rs`, `src/scan_runner.rs`):
   - Added `scan_runner::run_scan(...)` to centralize prepared-scan orchestration and family run dispatch.
   - Kept `main.rs::run_scan` as a thin wrapper that binds module orchestration to existing `run_campaign`/`run_chain_campaign` execution paths.
   - Preserved scan behavior while further shrinking command-dispatch logic in `main.rs`.
101. Continued CLI modularization by extracting campaign bootstrap helpers (`src/main.rs`, `src/run_bootstrap.rs`):
   - Added `announce_report_dir_and_bind_log_context(...)` to centralize report-dir announcement and early run-log context binding.
   - Added `load_campaign_config_with_optional_profile(...)` to centralize YAML load, optional profile apply, scan output suffix handling, and early failure artifact emission.
   - Replaced duplicated bootstrap blocks in both `run_campaign` and `run_chain_campaign` with helper calls while preserving behavior.
   - Removed stale stage pre-initialization and unused lifecycle import introduced by the extraction.
102. Batched CLI modularization by extracting run identity and path helpers (`src/main.rs`, `src/run_identity.rs`, `src/run_paths.rs`):
   - Added `run_identity` module for slug normalization and run-id generation (`sanitize_slug`, `make_run_id`).
   - Added `run_paths` module for env/path resolution and build-path normalization (`read_optional_env`, `run_signal_dir`, `engagement_root_dir`, `normalize_build_paths`, engagement-dir naming helpers).
   - Removed duplicated helper bodies from `main.rs` and re-exported needed helpers at crate root to preserve existing module callsites.
   - Kept panic/signal handling, scan suffix handling, and lifecycle paths behavior-preserving while shrinking `main.rs`.

Validation:
1. `cargo check -p zk-backends` passed.
2. `cargo test -p zk-backends circom::tests:: -- --test-threads=1` passed.
3. Note: existing unrelated failure remains in `halo2::tests::test_halo2_execute_metadata_only_spec_returns_public_projection`.
4. `cargo check` passed.
5. `cargo test -q adaptive_attack_scheduler::tests::test_budget_allocation -- --test-threads=1` passed.
6. `cargo test -q adaptive_orchestrator::tests:: -- --test-threads=1` passed.
7. `cargo test -q -p zk-constraints proof_forgery::tests:: -- --test-threads=1` passed.
8. `cargo test -q test_coverage_fallback_uses_output_hash_when_constraints_missing -- --test-threads=1` passed.
9. `cargo test -q test_execution_result -- --test-threads=1` passed after executor/main hardening changes.
10. `cargo check -q -p zk-backends -p zk-constraints` passed.
11. `cargo check -q --bin zk0d_matrix` passed.
12. `cargo test -q --bin zk0d_matrix -- --test-threads=1` passed.
13. `cargo run --quiet --bin zk0d_matrix -- --dry-run --jobs 1 --batch-jobs 1 --workers 1` smoke run passed.
14. `cargo check -q --bin zk0d_batch` passed.
15. `cargo test -q --bin zk0d_batch -- --test-threads=1` passed.
16. `cargo check -q --bin zk0d_benchmark` passed.
17. `cargo test -q --bin zk0d_benchmark -- --test-threads=1` passed.
18. `cargo run --quiet --bin zk0d_benchmark -- --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1` smoke run passed.
19. Real non-dry benchmark run executed (`jobs=2`, `batch_jobs=1`, `workers=2`, `iterations=10000`, `timeout=900`) with `CIRCOM_INCLUDE_PATHS=third_party:node_modules`; outcome saved at `artifacts/benchmark_runs/benchmark_20260218_130428/summary.json`.
20. Local gate check run (`./scripts/ci_benchmark_gate.sh`) failed as expected on current baseline: completion=0.0%, recall=0.0%, precision=0.0% (safe FPR=0.0%).
21. Profile validation commands passed:
    - `cargo run --quiet --bin zk0d_batch -- --config-profile dev --list-catalog`
    - `cargo run --quiet --bin zk0d_batch -- --config-profile prod --list-catalog`
    - `cargo run --quiet --bin zk0d_benchmark -- --config-profile dev --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1`
    - `cargo run --quiet --bin zk0d_benchmark -- --config-profile prod --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1`
22. Scan/report contract compatibility test command:
    - `cargo test -q --test mode123_nonregression mode123_cli_smoke_non_regression -- --test-threads=1`
23. Deterministic contract + command-fallback regression commands:
    - `cargo test -q --test mode123_nonregression scan_engagement_contract_fixture_passes -- --test-threads=1`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
24. CI matrix validation command:
    - `python3 -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text())"`
25. Release-exit scripts syntax validation:
    - `bash -n scripts/ci_benchmark_gate.sh`
    - `bash -n scripts/release_candidate_gate.sh`
    - `bash -n scripts/rollback_validate.sh`
26. Release-validation workflow YAML validation:
    - `python3 -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release_validation.yml').read_text())"`
27. Failure dashboard script validation:
    - `python3 scripts/benchmark_failure_dashboard.py --benchmark-root artifacts/benchmark_runs --output-dir artifacts/benchmark_trends`
28. Failure dashboard threshold override validation:
    - `python3 scripts/benchmark_failure_dashboard.py --benchmark-root artifacts/benchmark_runs --output-dir artifacts/benchmark_trends --threshold setup_tooling=0.20 --threshold timeouts=0.12`
29. Failure dashboard unit regression tests:
    - `python3 -m unittest -q tests/test_benchmark_failure_dashboard.py`
30. Release-hardening CI YAML validation after dashboard-test step wiring:
    - `python3 -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text())"`
31. Chain scheduler largest-remainder regression test:
    - `cargo test -q chain_fuzzer::scheduler::tests::test_largest_remainder_allocation_preserves_total_and_fairness -- --test-threads=1`
32. Near-miss min-boundary regression test:
    - `cargo test -q fuzzer::near_miss::tests::test_range_near_miss_detects_min_boundary_proximity -- --test-threads=1`
33. Near-miss arithmetic-distance regression test:
    - `cargo test -q fuzzer::near_miss::tests::test_range_near_miss_uses_arithmetic_distance_not_bit_hamming -- --test-threads=1`
34. Regex safety selector tests for optional-vs-nested quantifiers:
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
35. Workspace compile verification after regex safety fix:
    - `cargo check -q`
36. Adaptive zero-day confirmation regression tests:
    - `cargo test -q adaptive_orchestrator::tests:: -- --test-threads=1`
37. Main binary compile verification after log-routing containment:
    - `cargo check -q --bin zk-fuzzer`
38. `engagement_dir_name` invalid run-id panic-path regression:
    - `cargo test -q engagement_dir_name_invalid_run_id_never_panics -- --test-threads=1`
39. `CIRCOM_INCLUDE_PATHS` invalid UTF-8 panic-path regression:
    - `cargo test -q test_circom_include_paths_invalid_utf8_does_not_panic -- --test-threads=1`
40. Main binary compile verification after lifecycle dedup helper extraction:
    - `cargo check -q --bin zk-fuzzer`
41. Main binary + command-fallback regression checks after running-artifact dedup:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
42. Main binary + command-fallback regression checks after early-failure helper extraction:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
43. Main binary + command-fallback regression checks after post-lock failure helper extraction:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
44. Main binary + command-fallback regression checks after starting-engine artifact dedup:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
45. Main binary + command-fallback regression checks after chain parse failure dedup:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
46. Main binary + command-fallback regression checks after runtime/report failure-doc dedup batch:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
47. Main binary + command-fallback regression checks after running/completed doc-helper batch:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
48. Main binary + command-fallback regression checks after failed-emitter helper batch:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
49. Main binary + command-fallback regression checks after readiness/preflight gate helper batch:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
50. Main binary + command-fallback regression checks after pre-run lifecycle helper extraction:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
51. Main binary + selector/command regression checks after test-file separation:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
52. Workspace compile + test-target compile checks after strict test-body separation:
    - `cargo check -q --workspace`
    - `cargo test -q --workspace --no-run`
53. Repository audit checks confirming no inline test bodies outside dedicated `*_tests.rs` files:
    - `rg -n --glob '!target/**' --glob '!tests/**' --glob '!**/tests/**' --glob '!**/*_tests.rs' '^\\s*#\\[test\\]' src crates`
    - `rg -n --glob '!target/**' --glob '!tests/**' --glob '!**/tests/**' --glob '!**/*_tests.rs' '^\\s*mod\\s+tests\\s*\\{' src crates`
54. Main binary + command-fallback regression checks after run-option payload factorization:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
55. Main binary + selector/command regression checks after runtime helper module extraction:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
    - `cargo test -q scan_selector_regex_safety_ -- --test-threads=1`
56. Full selector regression suite spot-check after runtime helper module extraction:
    - `cargo test -q scan_selector_tests:: -- --test-threads=1`
57. Compile + contract checks after deleting legacy `attacks` module path and mode folder names:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo test -q --test mode123_nonregression scan_engagement_contract_fixture_passes -- --test-threads=1`
    - `cargo test -q --test integration_tests test_underconstrained_detector -- --test-threads=1`
58. Workspace + oracle import regression checks after `attacks` -> `oracles` migration:
    - `cargo check -q --workspace`
    - `cargo test -q --test new_scanners_tests test_canonicalization_checker_detects_non_canonical -- --test-threads=1`
    - `cargo test -q --test batch_verification_tests test_batch_mixing_detection_integration -- --test-threads=1`
59. Config test-module separation validation:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo check -q --workspace`
    - `cargo test -q test_suggester_creation -- --test-threads=1`
    - `cargo test -q test_expand_zero -- --test-threads=1`
    - `cargo test -q test_profile_parsing -- --test-threads=1`
    - `cargo test -q test_missing_circuit_path_is_critical -- --test-threads=1`
    - `cargo test -q test_parse_equals_invariant -- --test-threads=1`
60. Main CLI compile + selector/command regression checks after helper-module extraction batch:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo check -q --workspace`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
61. Main CLI compile + selector/command regression checks after engagement-artifact helper extraction batch:
    - `cargo check -q --bin zk-fuzzer`
    - `cargo check -q --workspace`
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
62. Runtime attack-dispatch coverage hardening validation:
    - `cargo check`
    - `cargo test test_parse_attack_type`
    - `cargo test -p zk-core deserialize_finding_supports_phase3_and_advanced_attack_variants`
    - `cargo test -p zk-attacks test_batch_verifier_creation`
63. Advanced attack runtime wiring + scaffolding validation:
    - `cargo check`
    - `cargo test test_parse_attack_type -- --test-threads=1`
    - `cargo test -p zk-core deserialize_finding_supports_phase3_and_advanced_attack_variants -- --test-threads=1`
    - `cargo test --test phase0_integration_tests test_phase3_and_advanced_attack_dispatch -- --test-threads=1`
64. Advanced attack module extraction + runner refactor validation:
    - `cargo check`
    - `cargo test -p zk-attacks sidechannel_advanced_ -- --test-threads=1`
    - `cargo test -p zk-attacks privacy_advanced_ -- --test-threads=1`
    - `cargo test -p zk-attacks quantum_resistance_ -- --test-threads=1`
    - `cargo test -p zk-attacks defi_advanced_ -- --test-threads=1`
    - `cargo test --test phase0_integration_tests test_phase3_and_advanced_attack_dispatch -- --test-threads=1`
    - `cargo test -p zk-core deserialize_finding_supports_phase3_and_advanced_attack_variants -- --test-threads=1`
65. Static-first lint/fail-fast acceleration validation:
    - `cargo check`
    - `cargo test -p zk-attacks circom_static_lint_ -- --test-threads=1`
    - `cargo test -p zk-attacks quantum_resistance_ -- --test-threads=1`
    - `cargo test test_schedule_fail_on_findings_severity -- --test-threads=1`
    - `cargo test test_parse_attack_type -- --test-threads=1`
    - `cargo test --test phase0_integration_tests test_phase3_and_advanced_attack_dispatch -- --test-threads=1`
    - `cargo test -p zk-core deserialize_finding_supports_phase3_and_advanced_attack_variants -- --test-threads=1`
66. Generator + static-evidence acceleration validation:
    - `cargo check -q`
    - `cargo test -q test_quantum_vulnerable_pattern_detection -- --test-threads=1`
    - `cargo test -q test_quantum_pattern_detection_uses_word_tokens -- --test-threads=1`
    - `cargo test -q test_trusted_setup_pattern_detection -- --test-threads=1`
    - `cargo test -q test_generate_from_source_adds_quantum_and_trusted_setup_attacks -- --test-threads=1`
    - `cargo test -q has_static_source_evidence_ -- --test-threads=1`
67. Trusted-setup module extraction + runtime mapping validation:
    - `cargo check -q`
    - `cargo test -q -p zk-attacks trusted_setup_ -- --test-threads=1`
    - `cargo test -q -p zk-attacks setup_poisoning_detector_compatibility_api_still_works -- --test-threads=1`
    - `cargo test -q test_setup_poisoning_detector_detects_cross_setup -- --test-threads=1`
    - `cargo test -q --test phase0_integration_tests test_phase3_and_advanced_attack_dispatch -- --test-threads=1`
68. Main CLI compile verification after run-lifecycle helper module extraction:
    - `cargo check -q`
69. Main CLI compile verification after stale-run/early-failure helper extraction:
    - `cargo check -q`
70. Main CLI compile verification after output-lock helper extraction:
    - `cargo check -q`
71. Main CLI compile verification after lifecycle initialization helper extraction:
    - `cargo check -q`
72. Main CLI compile verification after scan-output helper localization:
    - `cargo check -q`
73. Main CLI compile verification after pattern-only validation helper extraction:
    - `cargo check -q`
74. Main CLI compile verification after selector-module wiring:
    - `cargo check -q`
75. Selector safety regression spot-check after selector-module wiring:
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
76. Main CLI compile verification after scan materialization extraction:
    - `cargo check -q`
77. Selector safety regression spot-check after scan materialization extraction:
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
78. Main CLI compile verification after selector-gating extraction:
    - `cargo check -q`
79. Selector safety regression spot-check after selector-gating extraction:
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
80. Main CLI compile verification after batched scan-family/target/progress helper extraction:
    - `cargo check -q`
81. Selector safety regression spot-check after batched scan-family/target/progress helper extraction:
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
82. Main CLI compile verification after scan-family dispatch extraction:
    - `cargo check -q`
83. Selector safety regression spot-check after scan-family dispatch extraction:
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
84. Main CLI compile verification after scan-preparation helper extraction:
    - `cargo check -q`
85. Selector safety regression spot-check after scan-preparation helper extraction:
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
86. Main CLI compile verification after scan-runner module extraction:
    - `cargo check -q`
87. Selector safety regression spot-check after scan-runner module extraction:
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
88. Main CLI compile verification after run-bootstrap extraction:
    - `cargo check -q`
89. Selector/command regression spot-check after run-bootstrap extraction:
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
90. Main CLI compile verification after run-identity/run-path extraction:
    - `cargo check -q`
91. Selector/command regression spot-check after run-identity/run-path extraction:
    - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`
    - `cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1`
92. Engagement-dir panic-path regression spot-check after run-path extraction:
    - `cargo test -q engagement_dir_name_invalid_run_id_never_panics -- --test-threads=1`

## Status Checklist (2026-02-18)

Phase implementation progress:
- [x] Phase 0: Reliability Blockers (implementation items completed)
- [x] Phase 1: Detection Recall Upgrade (implementation items completed)
- [x] Phase 2: Real Backend Internalization (implementation items completed)
- [x] Phase 3: Multi-Target Execution Engine (implementation items completed)
- [x] Phase 3A: Logic Correctness Hardening (implementation items completed)
- [x] Phase 4: Validation/Stats tooling implementation (harness + CI gate + reason codes)
- [x] Phase 5: Release Hardening (implementation items completed; exit criteria pending)

Exit criteria progress:
- [ ] Phase 0 exit criteria fully met on 20-run matrix
- [ ] Phase 1 exit criteria fully met (recall uplift and bounded high-confidence FP)
- [ ] Phase 2 exit criteria fully met on fresh clone baseline
- [ ] Phase 3 exit criteria fully met on 10-target wall-clock benchmark
- [ ] Phase 3A exit criteria fully met in integrated campaign runs
- [ ] Phase 4 exit criteria fully met (`recall >= 80%`, `safe high-confidence FPR <= 5%`)
- [ ] Phase 5 exit criteria met (release candidate pass twice + rollback validation)

Definition of Done progress:
- [ ] Stability: >=95% scan completion on production multi-target runs
- [ ] Multi-target: 10+ target matrix with `jobs=2`/`workers=2` without collisions
- [ ] Detection: measurable recall uplift on known vulnerable targets
- [ ] Operability: single bootstrap path validated on fresh environments
- [x] Quality gates: nightly regression dashboard with pass/fail by failure class (implemented; pending sustained production evidence)

## Audit Intake (2026-02-18)
Source: 2026-02-18 logic audit snapshot (13 findings total: High=3, Medium=5, Low=3, Info=2).

P0 (must-fix before broader tuning) — Completed:
1. Wire adaptive scheduler allocations into engine execution (`H-2`).
2. Add timeout-wrapped external command execution in proof forgery detector (`H-3`).

P1 (next correctness/stability wave) — Completed:
1. Normalize adaptive budget allocations to exact total budget (`H-1`).
2. Fix Cairo executor always-fail coverage path (`M-3`).
3. Cache Noir constraints to avoid per-exec disk reloads (`M-4`).
4. Remove runtime `std::env::set_var` hazards in multi-threaded paths (`M-2`).

P2/P3 (defensive + maintainability):
1. Remove panic fallback in `engagement_dir_name` and env parsing panic paths (`M-1`, `L-2`) — Completed.
2. Improve zero-day confirmation matching from category-only to content-aware (`L-3`) — Completed.
3. Document/contain dynamic log file routing edge window (`M-5`) — Completed.
4. CLI modularization and run lifecycle deduplication (`I-1`, `I-2`) — In progress (shared run-lifecycle helpers extracted in `src/main.rs`).

## Product Principles
1. YAML-first scanning remains the primary interface.
2. Pattern matching is target-agnostic and regex-driven, not tied to exact CVE strings.
3. Real backend execution is required for evidence (`circom` and other supported frameworks).
4. Report/output schemas and output roots remain stable unless explicitly approved.
5. Recall-first tuning is allowed in scan mode (slightly higher low-confidence false positives to reduce misses).

## Baseline Snapshot (from recent real runs)
Source: `artifacts/real_runs_20260217_231138_elev/`
1. Selector matching works on most targets (4/5 had non-zero regex hits).
2. Findings are still 0/5 in this matrix.
3. 3/5 runs failed early due output lock contention on shared `/home/teycir/ZkFuzz`.
4. Remaining runs hit key setup failure and then timed out before first attack execution.

## Definition Of Done (Production Grade)
1. Stability: >=95% scan completion rate on multi-target batch runs.
2. Multi-target: 10+ target matrix with `jobs=2` and `--workers 2` runs without lock collisions.
3. Detection: measurable recall uplift on known vulnerable targets, with controlled low-confidence FPR.
4. Operability: single bootstrap path for required binaries and ptau assets.
5. Quality gates: nightly regression dashboard with pass/fail by failure class.

## Phase 0: Reliability Blockers (P0, 1 week)
Goal: stop easy breakage before tuning detection quality.

Implementation:
1. Add per-run output root isolation for parallel scans by default in batch mode.
2. Classify run outcomes explicitly (`completed`, `locked_output`, `keygen_failed`, `timeout_pre_attack`, `pattern_miss`).
3. Add preflight for toolchain/keygen readiness and fail fast with actionable reason.
4. Preserve output schema while adding stable reason codes in summary metadata.

Exit Criteria:
1. 20-run matrix on 5 local targets has 0 output-lock failures.
2. >=90% runs reach attack execution stage (not blocked in setup).

## Phase 1: Detection Recall Upgrade (P0/P1, 1-2 weeks)
Goal: reduce missed true positives while keeping YAML workflow.

Implementation:
1. Extend YAML selector semantics with weighted regex groups and `k-of-n` matching.
2. Add lexical normalization before regex matching (case/style/token normalization).
3. Support optional synonym bundles per pattern family.
4. Keep current recall bias defaults, but make them profile-controlled and auditable in logs.
5. Keep summary output focused on matched pattern IDs and frequency counts.

Exit Criteria:
1. Selector hit-rate >=90% on intended target set.
2. Recall improves by >=20 percentage points over current baseline on known vulnerable matrix.
3. High-confidence false positives remain bounded (target <=5% on safe suite).

## Phase 2: Real Backend Internalization (P0/P1, 1-2 weeks)
Goal: avoid environment fragility across circuits.

Implementation:
1. Add `bins bootstrap` command for circom/snarkjs/ptau acquisition with checksum verification.
2. Standardize include-path and binary-path resolution to local `bins/` first.
3. Add ptau discovery policy with deterministic precedence and clear warnings.
4. Ensure local binary assets remain untracked by git (already enforced via `.gitignore`).

Exit Criteria:
1. Fresh clone + bootstrap can run 5-target matrix without manual tool installation.
2. Keygen readiness preflight passes on at least 4/5 baseline targets.

## Phase 3: Multi-Target Execution Engine (P1, 2 weeks)
Goal: make large real-world test campaigns predictable and parallel-safe.

Implementation:
1. Build matrix runner for target lists (`/media/elements/Repos/zk0d`) with bounded parallelism.
2. Separate process parallelism (`jobs`) from scan worker parallelism (`--workers`) with guardrails.
3. Emit per-target outcome table and aggregate campaign scorecard.

Exit Criteria:
1. 10-target run completes with zero filesystem collisions.
2. Parallel run wall-clock speedup >=1.7x over serial baseline.

## Phase 3A: Logic Correctness Hardening (P0/P1, 1 week)
Goal: close audit-confirmed semantic bugs before scaling campaign volume.

Implementation:
1. Make adaptive orchestrator actually enforce scheduler allocations per attack phase.
2. Add hard timeout wrappers to proof forgery `snarkjs` subprocesses.
3. Normalize allocation fractions post-clamp so sums match total budget exactly.
4. Fix Cairo execution fallback/coverage behavior so non-empty execution paths are possible.
5. Cache Noir constraints (OnceLock) to remove repeated disk parse overhead.
6. Replace runtime global env mutation paths (`set_var`) with startup-time/static configuration.

Exit Criteria:
1. `AdaptiveOrchestrator` integration tests validate allocation enforcement.
2. Proof forgery detector cannot hang indefinitely on subprocesses.
3. Cairo backend can execute and report non-empty coverage/failure semantics deterministically.
4. Noir backend execution throughput improves measurably on repeated runs.

## Phase 4: Validation And Statistical Confidence (P1, 2 weeks)
Goal: prove detection quality with statistically meaningful results.

Implementation:
1. Curate vulnerable matrix (minimum 5 known vulnerable targets) and safe matrix (minimum 5 clean targets).
2. Run repeated trials with fixed seeds and report confidence intervals for recall/precision.
3. Add regression gates that fail on recall regression or stability regression.
4. Publish detection reasons for misses (`pattern_miss`, `keygen_failed`, `timeout_pre_attack`, `no_violation_found`).

Exit Criteria:
1. Vulnerable-set recall >=80%.
2. Safe-set high-confidence FPR <=5%.
3. Every miss has machine-readable root-cause category.

## Phase 5: Release Hardening (P2, 1 week)
Goal: production operations and predictable upgrades.

Implementation:
1. Add release checklist (toolchain, regression matrix, docs, migration notes).
2. Freeze public scan/report contract and add compatibility tests.
3. Add troubleshooting playbook for keygen, includes, lock contention, and timeout tuning.
4. Add nightly CI matrix (fast smoke + deep scheduled).

Progress:
- [x] Add release checklist (toolchain, regression matrix, docs, migration notes).
- [x] Freeze public scan/report contract and add compatibility tests (`tests/mode123_nonregression.rs`).
- [x] Add troubleshooting playbook for keygen, includes, lock contention, and timeout tuning.
- [x] Add nightly CI matrix (fast smoke + deep scheduled).

Exit Criteria:
1. Versioned release candidate passes all gates twice consecutively.
2. Rollback strategy documented and tested.

## Execution Backlog (Immediate Top 12)
- [x] Add CI gates for stability/recall regression using `zk0d_benchmark` summary metrics.
- [x] Add nightly benchmark trend artifacts (completion, recall, precision, safe FPR) and regression alerts.
