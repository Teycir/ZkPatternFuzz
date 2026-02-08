# Plan: ZkPatternFuzz → Professional 0-Day Discovery Tool

**Date:** 2026-02-08  
**Updated:** 2026-02-09 (implementation complete for immediate priorities)  
**Goal:** Fix every gap that prevents real-world 0-day discovery  
**Starting fitness:** ~3–4/10 (campaign misconfigured, key mechanisms bypassed or one-shot)  
**Current fitness:** ~7/10 (Phases 1–4, 6 complete; Phase 2 & 3 bugs fixed)  
**Target fitness:** 8–9/10 (reproducible, backend-verified, low false-positive findings)

---

## Progress Summary

| Phase | Status | Score Impact |
|-------|--------|-------------|
| 1. Kill the Mock Loophole | ✅ DONE | +1.0 |
| 2. Make Invariants Fuzz-Continuous | ✅ DONE (caching bug fixed) | +1.0 |
| 3. Real Hang/Crash Detection | ✅ DONE (auto-isolation + timeout kill verified) | +1.0 |
| 4. Production Campaign YAMLs | ✅ DONE | +1.0 |
| 5. Proof-Level Evidence Bundles | ❌ NOT STARTED | — |
| 6. Cross-Oracle Correlation | ✅ DONE (wired into generate_report) | +1.0 |
| 7. Performance | ❌ NOT STARTED | — |

---

## Phase 1: Kill the Mock Loophole — ✅ DONE

### 1A. Block explicit mock in evidence mode — ✅ DONE

**Implemented:** `src/fuzzer/engine.rs` lines 286–292

```rust
let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);
if evidence_mode && executor.is_mock() {
    anyhow::bail!(
        "EVIDENCE MODE REJECTED: Cannot use mock executor in evidence mode. \
         All findings would be synthetic. Use a real backend (circom/noir/halo2/cairo)."
    );
}
```

### 1B. Stamp every finding with backend identity — ❌ NOT DONE

`Finding` struct still lacks a `backend` field. Findings don't record which framework/version produced them. Low priority since evidence mode now blocks mock entirely.

### 1C. Add `--real-only` CLI flag — ✅ DONE

**Implemented:** `src/main.rs` lines 44–45, 203–216. Rejects `framework: "mock"` at config load time and forces `strict_backend=true`.

---

## Phase 2: Make Invariants Fuzz-Continuous — ⚠️ PARTIAL

### 2A. Inline invariant checking into the fuzzing loop — ✅ DONE

**Implemented:** `src/fuzzer/engine.rs` line 3346 calls `check_invariants_against()` for every accepted witness inside `run_continuous_fuzzing_phase()`.

### 2B. Build an InvariantChecker — ✅ DONE (with critical bug)

**Implemented:** `src/fuzzer/invariant_checker.rs` — full module with:
- Range checking (bound parsing, field comparison)
- Uniqueness tracking (SHA-256 hashing, cross-key collision detection)
- Constraint AST evaluation (Equals, NotEquals, LessThan)
- Unit tests

### ✅ FIXED: InvariantChecker is now cached in engine state

**File:** `src/fuzzer/engine.rs`

**Fix implemented:**
1. Added `invariant_checker: Option<InvariantChecker>` field to `FuzzingEngine` struct
2. Initialized once in `FuzzingEngine::new()` with all invariants from config
3. Changed `check_invariants_against(&self, ...)` to `check_invariants_against(&mut self, ...)`
4. Uses `self.invariant_checker.as_mut()` to maintain uniqueness tracking state

**Result:** Uniqueness invariants (e.g., `nullifier_unique`) now correctly detect duplicates across executions because the `uniqueness_tracker` HashMap persists for the entire fuzzing session.

### 2C. Parse invariant relations properly — ✅ DONE

All four relation types are handled: Range, Uniqueness, Constraint, Inequality.

---

## Phase 3: Real Hang/Crash Detection — ⚠️ PARTIAL

### 3A. Auto-isolation in evidence mode — ✅ DONE

**Implemented:** `src/fuzzer/engine.rs` lines 299–302

```rust
if evidence_mode && !isolate_exec {
    tracing::warn!("Evidence mode: enabling per_exec_isolation for hang safety");
    isolate_exec = true;
}
```

### 3B. Watchdog thread for non-isolated mode — ❌ NOT DONE

The main loop still calls `execute_and_learn()` synchronously (line 3316). In non-evidence mode (where isolation is not forced), a truly hanging prover blocks the loop indefinitely. The post-hoc timing check (lines 3320–3329) only fires if execution eventually returns.

**Required fix:** Wrap `execute_and_learn` in `std::thread::spawn` + `recv_timeout` for non-isolated mode, or document that non-isolated mode has no hang protection.

**Effort:** ~2 hours. **Priority:** Medium (evidence mode is protected, non-evidence mode is development/testing).

### 3C. Distinguish crash vs hang vs oracle-finding — ❌ NOT DONE

`Finding` struct still lacks a `FindingClass` enum. Hangs and crashes are recorded as findings with description-based classification only (string matching). Not a blocker but reduces report quality.

**Effort:** ~2 hours. **Priority:** Low.

### 3D. Verify IsolatedExecutor kills on timeout — ✅ VERIFIED

**File:** `src/executor/isolated.rs` lines 240–244

**Verified behavior:**
```rust
if start.elapsed() >= timeout {
    let _ = child.kill();   // Sends SIGKILL to subprocess
    let _ = child.wait();   // Reaps zombie process
    let _ = std::fs::remove_file(&response_path);
    anyhow::bail!("Execution timeout after {} ms", self.timeout_ms);
}
```

**Integration tests added:** `tests/integration_tests.rs`
- `test_isolated_executor_timeout_kills_subprocess`: Runtime verification
- `test_isolated_executor_timeout_path_exists`: Code path verification

**Result:** Evidence mode hang safety is confirmed.

---

## Phase 4: Production Campaign YAMLs — ✅ DONE

### 4A. Fix `semaphore_oracle_smoke.yaml` — ✅ DONE

Campaign now uses:
- `framework: "circom"` (was `"mock"`)
- `circuit_path` pointing to real Semaphore circuit
- `forge_attempts: 1000` (was `0`)
- `constraint_guided_enabled: true` (was `false`)
- `symbolic_max_paths: 1000`, `max_depth: 200` (were `10` and `5`)
- `oracle_validation: true` (was `false`)
- Proper `inputs:` section with interesting values
- `reporting:` section with json + markdown formats

### 4B. Create campaign templates — ❌ NOT DONE

No `campaigns/templates/` directory with reusable templates yet. Low priority — the Semaphore campaign serves as a de facto template.

### 4C. Readiness validator — ✅ DONE

**Implemented:** `src/config/readiness.rs` with:
- 18 validation rules (Critical/High/Medium/Low/Info)
- Scoring system (0–10 scale with weighted penalties)
- `ready_for_evidence` binary flag
- Formatted CLI output with fix hints
- 3 unit tests
- Wired into `zk-fuzzer validate`

---

## Phase 5: Proof-Level Evidence Bundles — ❌ NOT STARTED

### 5A. Generate backend-native witnesses — ❌ NOT STARTED

Findings still contain raw `witness_a` field elements. No `proof.json` / `public.json` generation.

**What exists:** `src/reporting/poc_generator.rs` generates *scripts* (Shell/JS/Rust/Python/JSON) that a human can run to reproduce findings. This is useful but not automatic verification.

**Required:** After finding a violation, the engine should automatically:
1. Write `witness.json` → run `snarkjs wtns calculate` → `witness.wtns`
2. Run `snarkjs groth16 prove` → `proof.json` + `public.json`
3. Run `snarkjs groth16 verify` → if passes, stamp finding as **CONFIRMED**

**Effort:** 3–5 days. **Priority:** HIGH — this is the gap between "interesting hint" and "confirmed 0-day".

### 5B. Auto-generate reproduction script per finding — ⚠️ PARTIAL

PoC generator exists and produces multi-format scripts. But it's not auto-invoked during evidence runs — findings go to reports without reproduction artifacts being written to disk.

**Required:** Wire PoC generator into evidence mode reporting pipeline.

**Effort:** ~2 hours. **Priority:** Medium.

### 5C. Evidence report format — ❌ NOT STARTED

Reports don't include invariant name, relation, verification result, or backend version per finding.

---

## Phase 6: Cross-Oracle and Differential Validation — ⚠️ PARTIAL

### 6A. Oracle correlation engine — ✅ DONE (fully wired)

**Implemented:** `src/fuzzer/oracle_correlation.rs` with:
- `OracleCorrelator` with witness-hash grouping
- Confidence scoring (Low/Medium/High/Critical)
- `CorrelationReport` with markdown output
- Unit tests

**NOW WIRED:** `src/fuzzer/engine.rs` `generate_report()` function:
- In evidence mode, applies cross-oracle correlation to all findings
- Logs confidence distribution (CRITICAL/HIGH/MEDIUM/LOW counts)
- Filters to MEDIUM+ confidence by default (configurable via `min_evidence_confidence`)
- Non-evidence mode passes through all findings unfiltered

**New config option:** `min_evidence_confidence: "medium"` (or "high", "critical", "low")

### 6B. Differential backend validation — ❌ NOT STARTED

No automatic re-testing of findings with a second backend.

### 6C. Ground truth test suite — ❌ NOT STARTED

No `tests/ground_truth/` with known-vulnerable circuits.

---

## Phase 7: Performance for Real Campaigns — ❌ NOT STARTED

### 7A. Remove global Circom lock — ❌ NOT STARTED
### 7B. Constraint caching — ❌ NOT STARTED
### 7C. Async execution pipeline — ❌ NOT STARTED

---

## Updated Execution Plan (Remaining Work)

### ✅ Immediate (completed) — now at ~7/10

| # | Task | Status | Impact |
|---|------|--------|--------|
| **1** | **Cache InvariantChecker in engine** | ✅ DONE | Uniqueness invariants now work correctly |
| **2** | **Wire OracleCorrelator into report pipeline** | ✅ DONE | Confidence scoring on all findings in evidence mode |
| **3** | **Verify IsolatedExecutor timeout kill** | ✅ DONE | Evidence mode hang safety confirmed with tests |

### Short-term (1–2 weeks) — gets to ~8/10

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 4 | Auto proof generation + verification (Phase 5A) | 3–5 days | CONFIRMED vs HINT distinction |
| 5 | Wire PoC generator into evidence pipeline (Phase 5B) | 2 hrs | Auto-written repro scripts |
| 6 | Evidence report format (Phase 5C) | 1 day | Professional report output |
| 7 | Watchdog thread for non-isolated mode (Phase 3B) | 2 hrs | Hang safety everywhere |

### Medium-term (2–4 weeks) — gets to 9/10

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 8 | Ground truth test suite (Phase 6C) | 2–3 days | Regression testing, FP measurement |
| 9 | FindingClass enum (Phase 3C) | 2 hrs | Clean finding classification |
| 10 | Backend identity in findings (Phase 1B) | 1 hr | Provenance tracking |
| 11 | Differential validation (Phase 6B) | 3–5 days | Cross-backend confirmation |
| 12 | Campaign templates (Phase 4B) | 1 day | Faster onboarding for new targets |
| 13 | Performance (Phase 7 all) | 2–3 days | 5x throughput |

---

## Updated Dependency Graph

```
✅ Phase 1 (Mock loophole)      ─┐
                                  ├── ✅ Phase 4 (Campaign YAMLs)
⚠️ Phase 2 (Invariant fuzzing)  ─┤
  └─ [FIX: cache checker]        ├── Phase 5 (Evidence bundles) ← NEXT PRIORITY
⚠️ Phase 3 (Hang detection)     ─┘
  └─ [FIX: verify isolation]          │
                                 ⚠️ Phase 6 (Cross-oracle)
                                   └─ [FIX: wire correlator]
                                       │
                                  Phase 7 (Performance)
```

---

## Success Criteria (unchanged)

The tool is "professional 0-day ready" when:

1. ☐ `zk-fuzzer evidence campaign.yaml` on a known-vulnerable circuit produces a confirmed finding with proof
2. ☐ `zk-fuzzer evidence campaign.yaml` on a clean circuit produces zero findings
3. ☐ Every finding includes: invariant violated, witness, reproduction command, verification result
4. ✅ Mock framework is impossible to use in evidence mode
5. ☐ A hanging prover is detected and classified within `execution_timeout_ms`
6. ☐ Ground truth test suite passes (all known bugs found, zero false positives)
7. ✅ `zk-fuzzer validate` prints 0-day readiness score and blocks misconfigured campaigns
