# Bug Report - ZkPatternFuzz

**Generated:** 2026-02-13

**Project:** ZkPatternFuzz - Security Fuzzing Framework for Zero-Knowledge Circuits

**Summary:** This report catalogs all known bugs, vulnerabilities, and technical debt items across the codebase that require attention.

---

## Table of Contents

1. [Known Vulnerabilities (Benchmark Suite)](#1-known-vulnerabilities-benchmark-suite)
2. [Ground Truth Chain Bugs](#2-ground-truth-chain-bugs)
3. [Source Code TODOs/FIXMEs](#3-source-code-todosfixmes)
4. [Test Suite Issues](#4-test-suite-issues)
5. [Implementation Gaps](#5-implementation-gaps)
6. [Priority Matrix](#6-priority-matrix)

---

## 1. Known Vulnerabilities (Benchmark Suite)

These are deliberately vulnerable circuits used to validate the fuzzer's detection capabilities.

### 1.1 Signature Bypass Vulnerability
**Location:** `tests/bench/known_bugs/signature_bypass/`

**Severity:** CRITICAL

**Description:** The circuit claims to verify EdDSA signatures but doesn't perform real verification. Any signature is accepted as valid.

**Root Causes:**
- Message hash is computed but never used in signature validation
- `nonZeroS` signal uses witness assignment (`<--`) instead of constrained assignment (`<==`)
- Core EdDSA verification equation is completely missing
- Circuit returns `valid <== 1` unconditionally

**Impact:** Complete authentication bypass - any user can forge valid proofs for messages they didn't sign.

**Expected Detection:**
- Fuzzer should detect that `valid` output is always 1
- Should detect that different signatures produce identical outputs
- Should identify missing signature verification equation

---

### 1.2 Arithmetic Overflow Bug
**Location:** `tests/bench/known_bugs/arithmetic_overflow/`

**Severity:** CRITICAL

**Description:** Circuit performs arithmetic operations without proper range checks, causing wrap-around behavior in finite field arithmetic.

**Root Causes:**
- No range checks on inputs (e.g., balance, amount)
- Uses `<--` (witness computation) instead of `<==` (constrained assignment)

**Exploit Scenario:**
1. User has balance = 100
2. User withdraws amount = 101
3. newBalance wraps to `p - 1` (field modulus minus 1)
4. User now has effectively infinite balance

**Fix Required:**
```circom
// Add range checks
component leq = LessEqThan(64);
leq.in[0] <== amount;
leq.in[1] <== balance;
leq.out === 1;
```

---

### 1.3 Soundness Violation Bug
**Location:** `tests/bench/known_bugs/soundness_violation/`

**Severity:** CRITICAL

**Description:** Circuit contains unconstrained signals allowing multiple valid witnesses for the same public statement.

**Root Causes:**
- Unused private input signals
- Non-binary selectors not constrained to {0, 1}

**Impact:** Violates witness uniqueness property - provers can create multiple valid proofs for the same statement.

**Fix Required:**
```circom
// Constrain unused signals
unused === 0;

// Add binary constraints
selector * (1 - selector) === 0;
```

---

### 1.4 Nullifier Collision Bug
**Location:** `tests/bench/known_bugs/nullifier_collision/`

**Severity:** CRITICAL

**Description:** Nullifier derivation only uses part of secret material (ignores `randomness`), allowing collisions.

**Root Cause:**
```circom
// Bug: Only uses secret
nullHasher.inputs[0] <== secret;

// Should be:
// nullHasher.inputs[0] <== secret;
// nullHasher.inputs[1] <== randomness;
```

**Impact:**
- Double-spending attacks possible
- Transaction linkability via nullifier patterns
- Front-running attacks

---

### 1.5 Range Check Bypass Bug
**Location:** `tests/bench/known_bugs/range_bypass/`

**Severity:** HIGH

**Description:** Range check circuit decomposes value into bits but fails to verify bit decomposition equals original value.

**Root Cause:** Missing constraint tying bits back to original value:
```circom
// Missing:
var sum = 0;
for (var i = 0; i < n; i++) {
    sum = sum + bits[i] * (1 << i);
}
sum === value;
```

**Impact:** Can pass any value and claim it's in range by providing arbitrary bits.

---

### 1.6 Underconstrained Merkle Tree Bug
**Location:** `tests/bench/known_bugs/underconstrained_merkle/`

**Severity:** CRITICAL

**Description:** Merkle tree path verification doesn't constrain `pathIndices` to be binary (0 or 1).

**Impact:**
- Membership proof forgery
- Path manipulation with arbitrary field elements as indices

**Fix Required:**
```circom
pathIndices[i] * (1 - pathIndices[i]) === 0;
```

---

## 2. Ground Truth Chain Bugs

These bugs are designed to test multi-step circuit chain detection.

### 2.1 Deposit-Withdraw Nullifier Reuse
**Location:** `tests/ground_truth/chains/deposit_withdraw/`

**Bug Class:** Nullifier Reuse Across Steps

**Description:** Deposit circuit computes `nullifier = Poseidon(nonce)` instead of `nullifier = Poseidon(secret, nonce)`. Different users with different secrets but the same nonce produce identical nullifiers.

**Impact:** Double-spend attacks, loss of funds.

**Expected L_min:** 2 (requires both deposit and withdraw steps)

**Violated Assertion:** `unique(step[*].out[0])`

---

### 2.2 Signature Verification Ignores Message
**Location:** `tests/ground_truth/chains/sign_verify/`

**Description:** Verify circuit only checks that signature components are non-zero and ignores the message input. A signature for one message verifies for a different message.

**Detection:** Chain verifies same signature against tampered message and expects failure.

---

### 2.3 Root Propagation Breaks
**Location:** `tests/ground_truth/chains/update_verify/`

**Description:** `update_root` circuit computes newRoot using `oldRoot` and `pathIndex` instead of the leaf. The `verify_root` circuit recomputes root from leaf and pathIndex, causing divergence.

**Detection:** Chain asserts `update_root.newRoot == verify_root.computedRoot`.

---

### 2.4 Root Update Ignores Leaf
**Location:** `tests/ground_truth/chains/update_update_verify/`

**Description:** `update_root` circuit hashes `oldRoot` with `pathIndex` and ignores the leaf. When two updates use same `oldRoot` and `pathIndex` but different leaves, both produce same `newRoot`.

**Detection:** Chain assertion detects first and third-step roots should diverge.

---

### 2.5 Nullifier Reuse Across Repeated Withdrawals
**Location:** `tests/ground_truth/chains/deposit_withdraw_triple/`

**Description:** Withdraw circuit outputs nullifier input unchanged. When second withdrawal step reuses prior nullifier output, chain produces identical nullifiers across withdrawals.

**Impact:** Enables double-withdrawal in multi-step workflows.

---

## 3. Source Code TODOs/FIXMEs

### 3.1 Formal Verification Exporters (Resolved 2026-02-13)

**Locations:**
- `src/formal/coq.rs`
- `src/formal/lean.rs`

**Resolution:** Exporters now emit obligation-style definitions plus identity theorems with no `Admitted`/`sorry` placeholders in generated output.

**Status:** Closed.

---

### 3.2 Constraint Type Implementation Gap
**Location:** `crates/zk-constraints/src/constraint_types.rs:476`

**TODO:** "Implement R1CS parsing"

**Impact:** R1CS constraint system not fully supported.

---

### 3.3 Symbolic Execution - Missing Implementation

**Location:** `crates/zk-symbolic/src/enhanced.rs:235`

**TODO:** "Implement proper constraint subsumption checking"

**Location:** `crates/zk-symbolic/src/enhanced.rs:1130`

**TODO:** "Track cache hits in solver"

---

### 3.4 Concolic Execution Placeholder
**Location:** `crates/zk-symbolic/src/concolic.rs:251`

**TODO:** "In a real implementation, we would:"

**Note:** Indicates mock/stub implementation for concolic execution.

---

### 3.5 Progress Reporting (Resolved 2026-02-13)
**Location:** `src/main.rs`

**Resolution:** Chain mode now wires `ProgressReporter` in `run_chain_campaign`.

**Status:** Closed.

---

### 3.6 zk0d Skimmer Placeholder (Resolved 2026-02-13)
**Location:** `src/bin/zk0d_skimmer.rs`

**Resolution:** `TODO_INPUT` fallback replaced with deterministic inferred input names.

**Status:** Closed.

---

### 3.7 Benchmark Integration
**Location:** `benches/chain_benchmark.rs:127`

**TODO:** "Integrate with actual chain fuzzing when circuits are compiled"

---

### 3.8 Corpus Synchronization (Resolved 2026-02-13)
**Location:** `src/distributed/corpus_sync.rs`

**Resolution:** Coverage bitmap merging is implemented via byte-level OR with new-bit accounting.

**Status:** Closed.

---

### 3.9 Work Unit Re-queue (Resolved 2026-02-13)
**Location:** `src/distributed/coordinator.rs`

**Resolution:** Timed-out/disconnected node work is re-queued at high priority while skipping completed units.

**Status:** Closed.

---

### 3.10 Halo2 Evidence Script Glue Requirement (Resolved 2026-02-13)

**Location:** `src/reporting/evidence_halo2.rs`

**Resolution:** Generated `verify_halo2.rs` now uses `Halo2Target` directly, including witness parsing and prove/verify flow, with no project-specific `YourCircuit` placeholder wiring.

**Status:** Closed.

---

### 3.11 Ground Truth Test
**Location:** `tests/ground_truth_test.rs:339`

**TODO:** "When circom is available, run actual fuzzing"

---

### 3.12 False Positive Analysis
**Location:** `tests/false_positive_analysis.rs:403`

**TODO:** "measure FP rate" - Threshold testing incomplete.

---

## 4. Test Suite Issues

### 4.1 Intentional Bugs in Test Circuits
**Location:** `tests/realistic_testing.rs`

These are deliberate bugs for testing fuzzer detection:

**Bug A - Underconstrained Inputs (Line 25):**
```rust
// BUG: a and b are not constrained!
c <== 1;
```

**Bug B - Missing Range Check (Line 61):**
```rust
// BUG: Should check value < 2^8 but doesn't
isValid <== 1;
```

---

## 5. Implementation Gaps

### 5.1 Validation Plan Checklist (Resolved 2026-02-13)
**Location:** `docs/VALIDATION_PLAN.md`

**Resolution:** Checklist items are now completed with repository artifacts:
- `tests/campaigns/validation/`
- `tests/scripts/`
- `reports/validation/*.md`
- `docs/VALIDATION_RESULTS.md`

**Status:** Closed.

---

### 5.2 Evidence Mode Completeness

The evidence generation modules contain comments indicating they distinguish between:
- `CONFIRMED BUG` - Real vulnerability
- `Not a real bug` - False positive

However, the actual verification logic may need strengthening.

**Locations:**
- `src/reporting/evidence.rs:25`
- `src/reporting/evidence_noir.rs:14`
- `src/reporting/evidence_halo2.rs:18`
- `src/reporting/evidence_cairo.rs:14`

---

## 6. Priority Matrix

| Priority | Item | Location | Effort | Impact |
|----------|------|----------|--------|--------|
| **P0** | Implement R1CS parsing | `crates/zk-constraints/src/constraint_types.rs:476` | Medium | Required for full framework support |
| **P1** | Constraint subsumption checking | `crates/zk-symbolic/src/enhanced.rs:235` | High | Improves symbolic execution accuracy |
| **P2** | Cache hit tracking | `crates/zk-symbolic/src/enhanced.rs:1130` | Low | Performance metrics |

---

## Appendix: File Locations Summary

### Benchmark Bugs
```
tests/bench/known_bugs/
├── signature_bypass/bug_description.md
├── arithmetic_overflow/bug_description.md
├── soundness_violation/bug_description.md
├── nullifier_collision/bug_description.md
├── range_bypass/bug_description.md
└── underconstrained_merkle/bug_description.md
```

### Ground Truth Chains
```
tests/ground_truth/chains/
├── deposit_withdraw/bug_description.md
├── sign_verify/bug_description.md
├── update_verify/bug_description.md
├── update_update_verify/bug_description.md
└── deposit_withdraw_triple/bug_description.md
```

### TODO Locations
```
src/main.rs:763
crates/zk-constraints/src/constraint_types.rs:476
crates/zk-symbolic/src/concolic.rs:251
crates/zk-symbolic/src/enhanced.rs:235,1130
benches/chain_benchmark.rs:127
tests/ground_truth_test.rs:339
tests/false_positive_analysis.rs:403
```

---

*End of Bug Report*
