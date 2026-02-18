# Logic Errors Audit — ZkPatternFuzz

**Date:** 2026-02-18  
**Scope:** All Rust source files in `src/`, `crates/`  
**Methodology:** Manual code review of control flow, data integrity, semantic correctness, and algorithmic soundness  
**Relationship:** Supplements `LOGIC_AUDIT.md` (which was completed earlier today). This audit focuses on **new findings** not covered by the prior audit or the fixes documented in `ROADMAP.md`.

---

## Executive Summary

After a deep review of the entire codebase, **10 new logic errors** were identified across 4 severity tiers. Most of the High-severity findings from the prior audit (`LOGIC_AUDIT.md`) have been addressed per `ROADMAP.md` entries #17–#24. This audit surfaces residual and previously undetected logic issues.

| Severity | Count | Category |
|----------|-------|----------|
| 🔴 High | 2 | Correctness, data integrity |
| 🟠 Medium | 4 | Semantic bugs, algorithmic flaws |
| 🟡 Low | 3 | Edge cases, performance |
| ⚪ Info | 1 | Design observation |

---

## 🔴 HIGH Severity Findings

### H-1: Hardcoded `seed=42` in Adaptive Orchestrator Nullifies Exploration Diversity

**File:** `src/fuzzer/adaptive_orchestrator.rs:348, 398`

Both `FuzzingEngine::new()` calls inside `fuzz_circuit()` use a hardcoded `Some(42)` seed:

```rust
// Line 348 (non-adaptive mode)
let mut phase_engine = FuzzingEngine::new(phase_config, Some(42), self.config.workers)?;

// Line 398 (adaptive mode, per-attack phase)
let mut phase_engine = FuzzingEngine::new(phase_config, Some(42), self.config.workers)?;
```

The user-configured seed from the CLI (`--seed`) is available in `self.config` but is never propagated to the per-phase engines. Furthermore, in the adaptive loop where multiple phases run sequentially, **every phase starts with identical RNG state**, meaning:

1. All phases generate the same initial corpus and mutation sequence
2. Multi-circuit campaigns that fuzz circuit A then circuit B use identical random inputs for both, reducing cross-circuit diversity
3. Reproduction is misleading — the user may specify `--seed 999` but the engine always uses `42`

**Impact:** The adaptive orchestrator's multi-phase fuzzing is significantly less effective than it appears. A campaign that runs 10 adaptive phases essentially re-runs the same exploration 10 times with different budget constraints but identical random inputs.

**Fix:** Accept and propagate the seed from the orchestrator config. For multi-phase diversity, derive per-phase seeds: `seed.map(|s| s.wrapping_add(phase_index as u64))`.

---

### H-2: `new_coverage` Always ≥ 1, Preventing Scheduler Decay

**File:** `src/fuzzer/adaptive_orchestrator.rs:361, 410`

When building `AttackResults` to feed into `scheduler.update_scores()`, the coverage is floored to 1:

```rust
new_coverage: (phase_report.statistics.coverage_percentage as usize).max(1),
```

In `adaptive_attack_scheduler.rs:177-189`, the score update logic branches on `new_coverage > 0`:

```rust
if results.new_coverage > 0 {
    score_delta += self.config.coverage_gain_points * results.new_coverage as f64;
    self.iterations_without_progress.insert(attack_type.clone(), 0);
} else {
    // Decay path — NEVER REACHED because .max(1) ensures new_coverage >= 1
    let stale_iters = ...;
    *stale_iters += results.iterations;
    score_delta -= self.config.decay_per_iteration * (*stale_iters as f64 / 100.0);
}
```

Because `.max(1)` guarantees `new_coverage >= 1`, the decay branch is **dead code**. This means:

- Attack types that produce zero new coverage never get penalized
- The `iterations_without_progress` counter is reset to 0 every round
- Budget reallocation never shifts away from unproductive attacks
- The scheduler degenerates to near-uniform allocation over time

**Impact:** The adaptive scheduler's core feedback loop (reward productive attacks, penalize unproductive ones) is broken. The scheduler cannot learn which attack types are effective, undermining the entire adaptive fuzzing strategy.

**Fix:** Use the actual new coverage from `phase_report.statistics`, not a floored value. If coverage percentage is 0 and no new constraints were hit, `new_coverage` should be `0`.

---

## 🟠 MEDIUM Severity Findings

### M-1: Near-Miss `field_difference` Uses Hamming Distance Instead of Arithmetic Distance

**File:** `src/fuzzer/near_miss.rs:311-324`

The `field_difference()` method computes bitwise XOR and counts differing bits (Hamming distance in bit-space):

```rust
fn field_difference(&self, a: &FieldElement, b: &FieldElement) -> f64 {
    let a_bytes = a.to_bytes();
    let b_bytes = b.to_bytes();
    let total_bits = a_bytes.len() * 8;
    let differing_bits: usize = a_bytes.iter().zip(b_bytes.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize).sum();
    differing_bits as f64 / total_bits as f64
}
```

This is **semantically wrong** for detecting arithmetic nearness in a finite field:

- Values `127` (`0111_1111`) and `128` (`1000_0000`) differ in **all 8 bits** (max Hamming distance = 1.0) despite being adjacent integers
- Values `0` and `128` differ in only **1 bit** (Hamming distance ≈ 0.004) despite being 128 apart
- Values `p-1` and `0` differ in many bits despite being 1 apart in the field

This function is used in `check_invariant_near_miss()` (line 287) to determine if an invariant is "almost violated." With Hamming distance, two values that are arithmetically adjacent could appear maximally distant, and vice versa.

**Impact:** The near-miss detector generates **false negatives** (misses values that are truly close to boundary violations) and **false positives** (flags values that are far from boundaries but happen to share bit patterns). This degrades the quality of near-miss-guided mutation.

**Fix:** Compute arithmetic distance: `|a - b| / max(a, b)` or `|a - b| / field_modulus`. For field elements, use `BigUint` subtraction modulo p and normalize by the modulus.

---

### M-2: Near-Miss Detector Ignores `min_value` Boundary

**File:** `src/fuzzer/near_miss.rs:220-274`

The `check_range_near_miss()` method checks for proximity to the upper bound (`bit_length` and `max_value`) but **never checks against `min_value`**:

```rust
fn check_range_near_miss(&self, value: &FieldElement, constraint: &RangeConstraint) -> Option<NearMiss> {
    // Checks bit_length (upper bound) ✓
    if let Some(bit_length) = constraint.bit_length { ... }
    
    // Checks max_value (upper bound) ✓
    if let Some(ref max_val) = constraint.max_value { ... }
    
    // ❌ Never checks min_value
    
    None
}
```

When a `RangeConstraint` has `min_value: Some(100)` and a witness value of `101`, this is 1% from the lower boundary — a classic near-miss that should be detected and used to guide mutations toward boundary-crossing inputs.

**Impact:** The fuzzer misses an entire class of near-miss signals (lower-bound proximity), reducing the effectiveness of near-miss-guided mutation for range proof testing. Bugs related to underflow or values below minimum thresholds are harder to discover.

**Fix:** Add a `min_value` check after the `max_value` check:
```rust
if let Some(ref min_val) = constraint.min_value {
    let diff = self.field_difference(value, min_val);
    if diff < self.config.range_threshold {
        return Some(NearMiss { is_upper: false, ... });
    }
}
```

---

### M-3: Chain Scheduler Budget Allocation Loses Milliseconds to Integer Truncation

**File:** `src/chain_fuzzer/scheduler.rs:119-133`

The priority-based budget allocation truncates fractional milliseconds:

```rust
let allocated_remaining = (remaining as f64 * priority_share) as u64;
let total_budget = guaranteed_per_chain + allocated_remaining;
```

The `as u64` cast truncates toward zero. For N chains, up to N-1 milliseconds are silently lost. For a 60-second budget with 20 chains, this loses up to 19ms per allocation round. Over many re-allocation rounds in a long campaign, this can accumulate.

Notably, the `AdaptiveScheduler` in `adaptive_attack_scheduler.rs:260-279` was fixed with **largest-remainder rounding** (per ROADMAP #18) to guarantee `sum(allocations) == total_budget`. This fix was not applied to the `ChainScheduler`.

**Impact:** Total chain fuzzing time is slightly less than the requested budget. In strict engagement mode, this could cause the engagement contract validator to flag insufficient coverage time.

**Fix:** Apply the same largest-remainder rounding pattern used in `AdaptiveScheduler::allocate_budget()`.

---

### M-4: Regex Safety Validation Falsely Rejects Lazy Quantifier `?`

**File:** `src/main.rs:2124`

The regex pattern safety check treats `?` as a dangerous quantifier:

```rust
let is_quantifier = ch == b'*' || ch == b'+' || ch == b'{' || ch == b'?';
if is_quantifier && !paren_stack.is_empty() {
    if let Some(last) = paren_stack.last_mut() {
        *last = true;
    }
}
```

Later at line 2125, when a `)` is encountered, if the group has a quantifier inside AND the closing paren has a quantifier after it, the pattern is rejected as "potentially dangerous nested quantifier." However:

1. `?` after a quantifier (`+?`, `*?`) makes it lazy (non-greedy) — this is **not** dangerous and doesn't cause catastrophic backtracking
2. `(a+)?` is safe — optional group with a quantified element inside has no nested-quantifier backtracking risk
3. `(a?)+` could be flagged correctly, but `(a+)?` should not be

**Impact:** Valid and safe regex patterns in scan selectors may be rejected by the safety validator. For example, `(?:foo)?bar` would mark the inner group as having a quantifier (`?`), and if the outer context adds another quantifier, it would be falsely flagged.

**Fix:** Don't classify `?` as a quantifier for the nested-quantifier safety analysis, or only flag it when it appears as a standalone quantifier (`a?`) rather than a lazy modifier (`a+?`).

---

## 🟡 LOW Severity Findings

### L-1: Range Oracle Uses O(n) `Vec::remove(0)` on Hot Path

**File:** `src/fuzzer/oracles/range_oracle.rs:263`

```rust
if self.accepted_values.len() > 100 {
    self.accepted_values.remove(0);  // O(n) shift of all elements
}
```

`Vec::remove(0)` shifts all remaining elements left, costing O(n) per call. This is called on every oracle check after the first 100 accepted values. In a fuzzer running millions of iterations, this creates unnecessary overhead.

**Fix:** Use `VecDeque` instead of `Vec`, or use a circular buffer approach with a write index.

---

### L-2: `time_to_discovery` Measures Total Campaign Time, Not Per-Circuit Time

**File:** `src/fuzzer/adaptive_orchestrator.rs:569`

```rust
confirmed.push(ConfirmedZeroDay {
    hint: hint.clone(),
    finding: finding.clone(),
    circuit: circuit_name.to_string(),
    time_to_discovery: self.start_time.map(|s| s.elapsed()).unwrap_or_default(),
});
```

For the third circuit in a multi-circuit campaign, `time_to_discovery` includes all time spent on the first two circuits. This makes the metric misleading for per-circuit analysis and benchmarking. A bug found 5 seconds into circuit C's fuzzing would be reported as taking 3605 seconds if circuits A and B took 3600 seconds combined.

**Fix:** Track per-circuit start time and use `circuit_start.elapsed()` instead of `campaign_start.elapsed()`.

---

### L-3: `kill_existing_instances` Uses Overly Broad Process Matching

**File:** `src/main.rs:1669`

```rust
let pgrep_output = std::process::Command::new("pgrep")
    .args(["-f", "zk-fuzzer"])
    .output();
```

`pgrep -f` matches against the entire command line, not just the process name. This can match:
- Text editors with `zk-fuzzer` files open
- Shell sessions with `zk-fuzzer` in their history or environment
- Scripts that reference `zk-fuzzer`

Additionally, the SIGKILL phase (lines 1700-1726) reuses the original PID list without re-checking, though the 2-second window makes PID recycling unlikely.

**Fix:** Use `pgrep -x "zk-fuzzer"` for exact process name matching, or match against the binary path.

---

## ⚪ INFO / Design Observation

### I-1: Chain Runner Has Redundant Post-Timeout Check

**File:** `src/chain_fuzzer/runner.rs:287-309`

After `execute_step_with_timeout()` returns successfully (meaning the step completed within the timeout), there's a second timeout check:

```rust
let (result, execution_time_ms) = match self.execute_step_with_timeout(...) {
    Ok(done) => done,       // Step completed within timeout
    Err(step_time) => { ... return failure; }  // Timeout already handled
};

// Second check — can this ever fire after execute_step_with_timeout returned Ok?
if timeout_ms > 0 && u128::from(execution_time_ms) > timeout_ms {
    // ... return failure
}
```

The `execute_step_with_timeout()` method uses `mpsc::recv_timeout(self.timeout_per_step)` which will return `Err(Timeout)` if the step exceeds the deadline. The only scenario where the second check fires is if the thread completed the `mpsc::send()` just before the timeout, but the elapsed `execution_time_ms` (measured from step start) exceeds the timeout. This is a marginal edge case and the second check acts as a safety net.

**Impact:** No functional impact — the redundant check is a minor code clarity issue. It could be removed or documented as a belt-and-suspenders safety check.

---

## Relationship to Prior Audit Findings

The following findings from `LOGIC_AUDIT.md` have been **verified as fixed** per `ROADMAP.md`:

| Prior Finding | ROADMAP Fix | Status |
|---------------|-------------|--------|
| H-1: Budget overspend | #18: Largest-remainder normalization | ✅ Fixed |
| H-2: Scheduler allocations ignored | #17: Per-attack phase execution | ✅ Fixed |
| H-3: Proof forgery no timeout | #19: Timeout-wrapped commands | ✅ Fixed |
| M-1: `engagement_dir_name` panics | #22: Sanitized fallback | ✅ Fixed |
| M-2: `set_var` unsound | #24: Command-local PATH injection | ✅ Fixed |
| M-3: Cairo always-fail | #20: Output-hash coverage fallback | ✅ Fixed |
| M-4: Noir constraint reload | #21: OnceLock caching | ✅ Fixed |
| L-2: CIRCOM_INCLUDE_PATHS panic | #23: Warning + fallback | ✅ Fixed |

---

## Recommendations Summary (Priority Order)

| # | Finding | Effort | Priority |
|---|---------|--------|----------|
| H-2 | Remove `.max(1)` on `new_coverage` — scheduler decay is dead code | Trivial | P0 — Core adaptive feature broken |
| H-1 | Propagate user seed to per-phase engines | Low | P0 — Exploration diversity crippled |
| M-1 | Replace Hamming distance with arithmetic distance in `field_difference` | Low | P1 — Near-miss signals unreliable |
| M-2 | Add `min_value` boundary check in near-miss detector | Low | P1 — Missing near-miss class |
| M-3 | Apply largest-remainder rounding to chain scheduler | Low | P1 — Budget consistency |
| M-4 | Exclude `?` from nested-quantifier danger classification | Low | P2 — False pattern rejections |
| L-1 | Replace `Vec::remove(0)` with `VecDeque` in range oracle | Low | P2 — Hot path performance |
| L-2 | Track per-circuit start time for `time_to_discovery` | Low | P3 — Metrics accuracy |
| L-3 | Use exact-name pgrep matching | Trivial | P3 — Safety |
| I-1 | Remove or document redundant timeout check in chain runner | Trivial | P3 — Code clarity |

---

*End of audit.*
