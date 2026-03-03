# Security Threat Model

Date: 2026-02-21  
Scope: ZkPatternFuzz runtime, backend toolchain execution, evidence/reporting pipeline.

## 1. System Boundaries

In-scope components:
- Rust binaries and libraries in this repository (`zk-fuzzer`, `zk0d_*`, backend crates).
- Local filesystem artifacts produced under configured output roots.
- External backend tool invocations (`circom`, `snarkjs`, `nargo`, `scarb`, `cargo`) launched by framework adapters.
- Evidence generation and report export paths (JSON/Markdown/SARIF).

Out-of-scope components:
- Security of third-party circuit projects under test.
- Security posture of upstream toolchain maintainers and package registries.
- Host OS hardening beyond documented prerequisites.

## 2. Assets

Primary assets:
- Finding integrity: severity, confidence, oracle agreement, reason classification.
- Reproducibility artifacts: witnesses, logs, backend outputs, command traces.
- Campaign configs and pattern libraries (YAML + CVE patterns).
- Toolchain binaries and proving artifacts used for backend execution.

Secondary assets:
- Runtime availability (no hangs, bounded execution, deterministic outcomes).
- CI gate correctness for release readiness claims.

## 3. Trust Assumptions

Hard assumptions:
- The host running ZkPatternFuzz controls repository contents and configured toolchain paths.
- Required backend tools are intentionally installed; missing tools are treated as failure, not bypassed.
- Output directories are writable and isolated per run.

Soft assumptions:
- External tools are not malicious but may crash, hang, or emit malformed output.
- Target circuits may be adversarial and should be treated as untrusted input.

## 4. Threat Actors

- Malicious circuit author attempting to hide vulnerabilities or poison findings.
- Compromised/misbehaving backend toolchain executable.
- Operator error (misconfiguration, stale tool versions, incorrect include paths).
- Supply-chain drift (dependency/tool updates changing semantics unexpectedly).

## 5. Threats and Mitigations

### T1: False confidence via partial execution
Risk:
- Runs appear "green" while selector mismatch or missing outcome classes hide failures.
Mitigations:
- Backend readiness dashboard with selector-matching completion gates.
- Explicit reason-code closure and release-gate enforcement.

### T2: Toolchain missing/drift causing silent degradation
Risk:
- Execution falls back or skips evidence generation.
Mitigations:
- Strict fail-fast backend behavior (no non-strict runtime mode).
- Preflight checks and release lane enforcement for required backends.

### T3: External command hangs or resource exhaustion
Risk:
- Campaign starvation, CI timeouts, unavailable service.
Mitigations:
- Timeout-wrapped command execution.
- Bounded lane iterations/timeouts in readiness and release scripts.

### T4: Artifact tampering or ambiguity
Risk:
- Unreliable evidence provenance.
Mitigations:
- Per-run output isolation.
- Stable report schema and machine-readable classification fields.

### T5: Panic-surface regressions in production code
Risk:
- Crash-on-input paths introduced by new `.unwrap()`/`.expect()` usage.
Mitigations:
- CI panic-surface gate with explicit allowlist and stale-entry checks.

### T6: Dependency security regressions
Risk:
- Vulnerable/unmaintained dependencies in critical decode paths.
Mitigations:
- Security audit workflow (`cargo audit`).
- Migration off unmaintained crates in security-sensitive paths (e.g., ACIR decode bincode migration).

## 6. Security Invariants

Release-critical invariants:
- Non-Circom readiness lanes (Noir/Cairo/Halo2) must pass enforced thresholds.
- No unresolved `run_outcome_missing` debt above configured gate thresholds.
- Evidence generation failures are classified as failures, not silently skipped.
- New panic-surface entries in production code must be intentionally reviewed via allowlist updates.

## 7. Residual Risks

- External backend tools run with host privileges unless an explicit sandbox wrapper is enabled.
- Supply-chain compromise in upstream binaries/crates remains possible.
- Heuristic/static pattern matching can still miss novel vulnerability classes.

## 8. Operational Controls

- Run `cargo run --bin zkf_checks -- panic-surface --repo-root . --fail-on-stale` in CI and before release tagging.
- Run `cargo audit` in CI security lane.
- Track upstream readiness/dependency drift with:
  - `scripts/track_zkevm_releases.py`
  - `scripts/evaluate_arkworks_upgrade_path.py`
  - `scripts/build_z3_compatibility_matrix.py`

## 9. Planned Hardening

- Enforced external-tool sandbox mode for backend command execution.
- Continued reduction of allowlisted panic surfaces where invariants can be encoded as recoverable errors.
- Periodic threat-model review tied to release milestones.
