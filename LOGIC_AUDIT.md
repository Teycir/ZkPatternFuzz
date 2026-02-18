# Full Logic Audit — ZkPatternFuzz

**Date:** 2026-02-18  
**Scope:** All Rust source files in `src/`, `crates/`  
**Methodology:** Manual code review of control flow, data integrity, concurrency, error handling, security, and correctness

---

## Executive Summary

The codebase is a **mature, production-oriented** ZK circuit security testing framework. A prior audit (`CODE_AUDIT_FIXES.md`) addressed surface-level clippy/safety issues. This audit goes deeper into **logic correctness, semantic bugs, concurrency hazards, data integrity, and design-level risks**. 

**Overall verdict:** The code is well-structured and defensively written, but there are **13 findings** across 4 severity tiers that warrant attention.

| Severity | Count | Category |
|----------|-------|----------|
| 🔴 High | 3 | Logic correctness, data integrity |
| 🟠 Medium | 5 | Concurrency, robustness, subtle bugs |
| 🟡 Low | 3 | Edge cases, defensive hardening |
| ⚪ Info | 2 | Design observations, maintainability |

---

## 🔴 HIGH Severity Findings

### H-1: Budget Allocation Can Exceed Total Budget (Overspend)

**File:** `src/fuzzer/adaptive_attack_scheduler.rs:228-246`

The `allocate_budget()` method clamps each attack type's fraction independently to `[min_budget_fraction, max_budget_fraction]` but **never normalizes the sum**. With `N` attack types and `min_budget_fraction = 0.05`, the minimum total allocation is `N * 0.05`. For 20 attack types, that's 100% minimum — leaving no room for the max-budget clamping to take effect. More critically, the sum of clamped fractions can exceed `1.0`, meaning **the total allocated time exceeds the actual available budget**.

```rust
// Current: each fraction clamped independently
let fraction = (score / total_score)
    .max(self.config.min_budget_fraction)
    .min(self.config.max_budget_fraction);
let millis = (fraction * total_millis) as u64;
```

**Impact:** The fuzzing engine may plan more work than the time budget allows. In practice this likely manifests as the last few attacks receiving truncated budgets from the outer `while start.elapsed() < budget` loop, but it means the scheduler's allocation is semantically incorrect and not trustworthy for reporting/analytics.

**Fix:** After clamping, normalize the allocations so they sum to `total_millis`:
```rust
// Collect raw fractions, then normalize
let raw_sum: f64 = raw_fractions.values().sum();
for (_, frac) in raw_fractions.iter_mut() {
    *frac /= raw_sum;
}
```

---

### H-2: Adaptive Orchestrator Ignores `allocations` From Scheduler

**File:** `src/fuzzer/adaptive_orchestrator.rs:338-402`

Inside `fuzz_circuit()`, the code calls `scheduler.allocate_budget(...)` and stores the result in `allocations`, but then **never uses it**. Instead, it calls `engine.run(None).await` which runs the entire engine with no per-attack budget control:

```rust
let allocations = scheduler.allocate_budget(remaining.min(Duration::from_secs(60)));
if allocations.is_empty() { break; }

// ❌ `allocations` is never passed to the engine
let phase_report = engine.run(None).await?;
```

**Impact:** The adaptive scheduling feature — the core value proposition of the `AdaptiveOrchestrator` — is effectively **non-functional**. The scheduler updates scores correctly, but the budget allocations it computes are discarded. Every attack type gets equal time regardless of effectiveness.

**Fix:** Either pass `allocations` to the engine's `run()` method to control per-attack budget, or remove the `allocate_budget` call and document that the scheduler is informational-only.

---

### H-3: Proof Forgery Detector Runs External Commands Without Timeout

**File:** `crates/zk-constraints/src/proof_forgery.rs:349-407`

The `verify_forged_proof()` method spawns three external `npx snarkjs` commands (`wtns import`, `groth16 prove`, `groth16 verify`) via `Command::new("npx")` with no timeout wrapping. While the rest of the Circom backend has been hardened with `run_with_timeout` (per `ROADMAP.md` progress), this module was missed.

```rust
let import_output = Command::new("npx")
    .args(["snarkjs", "wtns", "import", ...])
    .output()  // ← unbounded wait
    .context("Failed to run snarkjs wtns import")?;
```

**Impact:** A malicious or malformed circuit could cause `snarkjs` to hang indefinitely, freezing the detector thread with no way to recover. In a batch scan, this blocks the entire process.

**Fix:** Use the same `run_with_timeout` pattern used elsewhere in the Circom backend, with `self.solver_timeout_ms` as the ceiling.

---

## 🟠 MEDIUM Severity Findings

### M-1: `engagement_dir_name()` Panics on Invalid Run IDs

**File:** `src/main.rs:449-456`

When neither `ZKF_ENGAGEMENT_EPOCH` nor `ZKF_ENGAGEMENT_NAME` is set, the function falls through to `run_id_epoch_dir()`. If that returns `None` (run_id is too short or has an invalid timestamp prefix), the code **panics**:

```rust
match run_id_epoch_dir(run_id) {
    Some(dir_name) => dir_name,
    None => panic!(
        "Run id '{}' does not contain a valid timestamp prefix",
        run_id
    ),
}
```

**Impact:** The `make_run_id()` function always generates valid 15+ char IDs, so this shouldn't trigger in normal operation. However, if `run_id` is ever constructed from user input or a corrupted env var, this is an unrecoverable panic in production.

**Fix:** Return an `anyhow::Result` or use a fallback slug like `format!("report_{}", run_id)`.

---

### M-2: `std::env::set_var` Is Unsound in Multi-Threaded Context

**File:** `src/executor/mod.rs:789` and `src/main.rs:3468`

The code calls `std::env::set_var("PATH", ...)` and `std::env::set_var("ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS", ...)` at runtime. Since Rust 1.66, `set_var` is documented as **unsound** in multi-threaded programs (it mutates global state without synchronization). Since this is a `tokio`-based async application with Rayon parallelism, there are concurrent threads reading `PATH` while it's being mutated.

```rust
// In CircomExecutor::ensure_bins_on_path()
std::env::set_var("PATH", current);  // ← data race risk

// In run_campaign()
std::env::set_var("ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS", ...);
```

**Impact:** Undefined behavior under POSIX `getenv`/`setenv` semantics. In practice, this has caused segfaults in other Rust programs. The risk is low because `ensure_bins_on_path` is typically called early, but it's technically UB.

**Fix:** Move `PATH` setup to process startup (before any threads are spawned), or use a process-local config struct instead of env vars.

---

### M-3: `CairoExecutor` Returns Empty Constraint Data

**File:** `src/executor/mod.rs:1703-1733`

The `CairoExecutor`'s `ConstraintInspector` implementation returns empty vectors for all methods:

```rust
impl ConstraintInspector for CairoExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> { Vec::new() }
    fn check_constraints(&self, _witness: &[FieldElement]) -> Vec<ConstraintResult> { Vec::new() }
    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> { Vec::new() }
}
```

Yet `execute_sync()` calls `coverage_from_results(self.check_constraints(inputs))` and **fails** when it returns `None` (because the empty vec produces `None` from `coverage_from_results`):

```rust
let coverage = match coverage_from_results(self.check_constraints(inputs)) {
    Some(value) => value,
    None => {
        return ExecutionResult::failure(
            "Cairo constraint coverage unavailable: refusing output-hash fallback"...
        )
    }
};
```

**Impact:** **Every Cairo execution always fails** with a coverage-unavailable error. The Cairo backend is non-functional for fuzzing.

**Fix:** Either implement real constraint checking for Cairo/STARK, or return a minimal synthetic coverage when constraints aren't available (with a warning), to allow output-based testing.

---

### M-4: `NoirExecutor` Reloads Constraints on Every `check_constraints` Call

**File:** `src/executor/mod.rs:1340-1411`

Unlike `CircomExecutor` which caches constraints in a `OnceLock`, the `NoirExecutor` calls `self.target.load_constraints()` on every invocation of `get_constraints()` and `check_constraints()`. This involves re-parsing constraint files from disk.

```rust
impl ConstraintInspector for NoirExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        match self.target.load_constraints() {  // ← disk I/O every call
            Ok(constraints) => constraints,
            Err(err) => { ... Vec::new() }
        }
    }
}
```

**Impact:** Significant performance degradation during fuzzing. `check_constraints` is called on every execution, so for 100K iterations this means 100K+ disk reads and parses. This likely explains why Noir fuzzing campaigns are slower than expected.

**Fix:** Add an `OnceLock<Vec<ConstraintEquation>>` cache to `NoirExecutor`, mirroring the `CircomExecutor` pattern.

---

### M-5: Race Condition in `DynamicTeeWriter` Log File Path Switching

**File:** `src/main.rs:46-98`

`DynamicTeeWriter::with_log_file()` checks whether the log file path has changed and re-opens the file if so. The path is determined by `DynamicTeeWriter::desired_log_path()`, which reads from `RUN_LOG_CONTEXT` (a `OnceLock<Mutex<Option<RunLogContext>>>`). However, `tracing_subscriber` can invoke `make_writer()` from any thread at any time. If two threads call `with_log_file()` concurrently during a path switch, they serialize on the `DYNAMIC_LOG_FILE` mutex, but:

1. Thread A sees `need_reopen = true`, opens new file
2. Thread B enters, sees the path is now correct, writes to new file
3. Meanwhile, any log messages generated **between** the `set_run_log_context` call and the first `with_log_file` reopen could briefly write to the old file

**Impact:** A few log lines may land in the wrong session log file during the transition. This is a minor data integrity issue in log routing, not a crash risk.

**Fix:** Acceptable as-is for logging, but document the brief window of inconsistency.

---

## 🟡 LOW Severity Findings

### L-1: `quick_underconstrained_check` Uses a Simplistic Heuristic

**File:** `crates/zk-constraints/src/proof_forgery.rs:439-451`

The heuristic `ratio > 2.0` (wires-to-constraints ratio) is very rough. Many real-world circuits legitimately have ratios above 2.0 (e.g., circuits with many internal wires for bit decomposition). This can produce false positives.

```rust
let ratio = total_signals as f64 / constraints as f64;
ratio > 2.0
```

**Impact:** The function is named `quick_underconstrained_check` and is clearly documented as a heuristic, so the impact is low. However, if used as a gate for skipping deeper analysis, it could cause false negatives (if the threshold were inverted) or wasted work on false positives.

**Fix:** Consider using a more nuanced heuristic that accounts for public inputs/outputs, or rename to `quick_underconstrained_heuristic` to further clarify.

---

### L-2: `CIRCOM_INCLUDE_PATHS` Panics on Invalid Unicode

**File:** `src/executor/mod.rs:833`

```rust
Err(e) => panic!("Invalid CIRCOM_INCLUDE_PATHS value: {}", e),
```

This panics if `CIRCOM_INCLUDE_PATHS` contains invalid UTF-8. While unlikely, other env var handlers in the codebase (`read_optional_env`) handle this gracefully with `process::exit(2)`.

**Fix:** Replace with `eprintln!` + `process::exit(2)` for consistency.

---

### L-3: `check_confirmed_zero_days` Uses Category Matching, Not Content Matching

**File:** `src/fuzzer/adaptive_orchestrator.rs:419-465`

The zero-day confirmation logic matches findings to hints purely by category-to-attack-type mapping (e.g., `MissingConstraint` → `Underconstrained`). It doesn't check whether the finding is actually related to the specific hint (e.g., same wire, same constraint). This means:

- A generic `Underconstrained` finding from any input could "confirm" a specific `MissingConstraint` hint about a specific wire
- Multiple hints of the same category would all be "confirmed" by a single finding

**Impact:** Over-counting of confirmed zero-days in campaign reports. Since this affects analytics/reporting rather than security testing behavior, the impact is low.

**Fix:** Add content-based matching (e.g., compare wire indices, constraint IDs, or description substrings).

---

## ⚪ INFO / Design Observations

### I-1: `main.rs` Is 5,477 Lines — Extract CLI Module

`main.rs` contains CLI argument parsing, scan orchestration, engagement lifecycle management, regex selector evaluation, campaign materialization, chain fuzzing orchestration, and banner printing. This is a maintenance burden. Consider extracting into:
- `src/cli/mod.rs` — CLI arg parsing and dispatch
- `src/cli/scan.rs` — Scan command logic
- `src/cli/campaign.rs` — Campaign run logic
- `src/cli/chain.rs` — Chain fuzzing logic
- `src/cli/engagement.rs` — Report/signal lifecycle

### I-2: Redundant Code in `run_campaign` and `run_chain_campaign`

The two functions (`run_campaign` ~700 lines, `run_chain_campaign` ~1000 lines) share ~60% identical boilerplate:
- Run log context setup
- Output lock acquisition
- Stale run detection
- Backend preflight
- Run artifact writing (start/fail/complete)
- Progress monitoring

This should be extracted into a shared `EngagementRunner` struct that handles the lifecycle, with `run_campaign` and `run_chain_campaign` providing only the engine-specific logic.

---

## Previously Audited (Verified Fixed)

The following items from `CODE_AUDIT_FIXES.md` were verified as correctly fixed:

| # | Fix | Status |
|---|-----|--------|
| 1 | Boolean simplification in circom/mod.rs | ✅ Verified |
| 2 | Single-element loop removal in executor/mod.rs | ✅ Verified |
| 3 | Struct initialization pattern in main.rs | ✅ Verified |
| 4 | NaN-safe `partial_cmp` in adaptive_attack_scheduler.rs:258 | ✅ Verified |
| 5 | `unwrap()` → `unwrap_or_default()` in adaptive_orchestrator.rs:279 | ✅ Verified |
| 6 | `unwrap()` → `expect()` in range_oracle.rs:215-216 | ✅ Verified |
| 7 | `matches!` macro for option checking in range_oracle.rs:79 | ✅ Verified |
| 8 | `matches!` macro in proof_forgery.rs:209,288 | ✅ Verified |

---

## Recommendations Summary (Priority Order)

| # | Finding | Effort | Priority |
|---|---------|--------|----------|
| H-2 | Wire scheduler allocations to engine | Medium | P0 — Core feature is non-functional |
| H-3 | Add timeouts to proof forgery commands | Low | P0 — Hang risk in production |
| M-3 | Fix Cairo executor always-fail | Medium | P1 — Backend is broken |
| M-4 | Cache Noir constraints | Low | P1 — Perf regression |
| H-1 | Normalize budget allocations | Low | P1 — Incorrect semantics |
| M-2 | Move `set_var` to pre-thread startup | Low | P1 — UB risk |
| M-1 | Remove panic in `engagement_dir_name` | Low | P2 — Defensive |
| L-2 | Remove panic on invalid env var | Low | P2 — Consistency |
| L-3 | Improve zero-day confirmation matching | Medium | P2 — Analytics accuracy |
| L-1 | Refine underconstrained heuristic | Low | P3 — Nice to have |
| I-1 | Extract CLI from main.rs | High | P3 — Maintainability |
| I-2 | Deduplicate campaign/chain boilerplate | Medium | P3 — Maintainability |
| M-5 | Document log path switch window | Low | P3 — Documentation |

---

## Test Coverage Notes

The codebase has **303+ tests** (unit + integration). Coverage is strong for:
- Adaptive scheduler scoring and budget allocation
- Regex selector policy evaluation (comprehensive edge cases)
- Constraint checking (R1CS, PLONK, ACIR)
- Proof forgery detection (with synthetic R1CS)
- Config parsing and validation

Coverage gaps:
- No integration tests for the full `run_scan` → `run_campaign` pipeline with a real circuit
- No tests for `CairoExecutor` execution path (which is currently broken)
- No tests for `AdaptiveOrchestrator.fuzz_circuit()` (the broken allocation path)
- Signal handler behavior is untested (acceptable for signal handlers)

---

*End of audit.*
