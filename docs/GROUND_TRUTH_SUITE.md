# Ground Truth Test Suite

**Version:** 1.0  
**Status:** Milestone 0.5  
**Purpose:** Prove ZkPatternFuzz detection capability on known vulnerabilities

---

## Overview

The Ground Truth Test Suite contains **10 known-vulnerable circuits** that serve as:
- **Validation**: Prove the fuzzer detects real vulnerabilities
- **Regression testing**: Ensure attack implementations remain effective
- **Benchmarking**: Measure detection rate (target: 90%+)
- **Credibility**: Evidence for bug bounties and audit engagements

## Circuit Catalog

| # | Circuit | Vulnerability | CVE Reference | Attack Type | Severity |
|---|---------|---------------|---------------|-------------|----------|
| 1 | `merkle_unconstrained.circom` | Path index not binary constrained | ZK-CVE-2021-001 | Underconstrained | Critical |
| 2 | `eddsa_malleability.circom` | S component not range-checked | ZK-CVE-2022-001 | Boundary | Critical |
| 3 | `range_overflow.circom` | Range allows values >= 2^n | ZK-CVE-2023-001 | ArithmeticOverflow | High |
| 4 | `nullifier_collision.circom` | Nullifier computation allows collision | ZK-CVE-2022-002 | Collision | Critical |
| 5 | `bit_decomposition.circom` | Missing recomposition constraint | Synthetic | Underconstrained | Critical |
| 6 | `commitment_binding.circom` | Commitment not binding | Synthetic | Underconstrained | High |
| 7 | `public_input_leak.circom` | Private input leaks to output | Synthetic | InformationLeakage | High |
| 8 | `division_by_zero.circom` | No zero divisor check | Synthetic | ArithmeticOverflow | Medium |
| 9 | `hash_length_extension.circom` | Hash length extension weakness | Synthetic | Soundness | High |
| 10 | `multiexp_soundness.circom` | Unconstrained scalar multiplication | Synthetic | Underconstrained | Critical |

## Detailed Vulnerability Descriptions

### 1. Merkle Path Index Unconstrained

**Location:** `tests/ground_truth_circuits/merkle_unconstrained.circom`

**Bug:** Path indices used as selectors are not constrained to be binary (0 or 1). An attacker can use path_indices[i] = 2, 3, or any field element to compute different "roots" from the same leaf.

**Missing Constraint:**
```circom
// Should be present but is NOT:
for (var i = 0; i < levels; i++) {
    path_indices[i] * (1 - path_indices[i]) === 0;  // Force binary
}
```

**Impact:** Critical - allows forging Merkle proofs.

**Expected Detection:** UnderconstrainedOracle should find inputs where `path_indices[i] ∉ {0, 1}`.

---

### 2. EdDSA Signature Malleability

**Location:** `tests/ground_truth_circuits/eddsa_malleability.circom`

**Bug:** EdDSA signature S component is not range-checked to be less than the curve order. This allows signature malleability.

**Missing Constraint:**
```circom
// S must be < L (curve order)
component lt = LessThan(254);
lt.in[0] <== S;
lt.in[1] <== L;
lt.out === 1;
```

**Impact:** Critical - allows signature forgery and replay attacks.

**Expected Detection:** BoundaryOracle or SoundnessOracle should detect S values >= L that still pass verification.

---

### 3. Range Proof Overflow

**Location:** `tests/ground_truth_circuits/range_overflow.circom`

**Bug:** Range proof checks `value < 2^n` but due to field arithmetic, values that wrap around can pass the check.

**Impact:** High - allows bypassing range checks in financial circuits.

**Expected Detection:** ArithmeticOverflowOracle or BoundaryOracle should find values >= 2^n that pass.

---

### 4. Nullifier Collision

**Location:** `tests/ground_truth_circuits/nullifier_collision.circom`

**Bug:** Nullifier computation uses weak hashing or insufficient input binding, allowing two different notes to produce the same nullifier.

**Impact:** Critical - allows double-spending in privacy systems.

**Expected Detection:** CollisionOracle should find distinct inputs producing same nullifier.

---

### 5. Bit Decomposition Missing Recomposition

**Location:** `tests/ground_truth_circuits/bit_decomposition.circom`

**Bug:** Bits are constrained to be binary (0 or 1) but the recomposition constraint `sum(bits[i] * 2^i) === value` is missing.

**Impact:** Critical - allows claiming arbitrary bit representations.

**Expected Detection:** UnderconstrainedOracle should find multiple valid decompositions for the same value.

---

### 6. Commitment Not Binding

**Location:** `tests/ground_truth_circuits/commitment_binding.circom`

**Bug:** Commitment scheme allows multiple (value, randomness) pairs to produce the same commitment.

**Impact:** High - breaks commitment hiding/binding properties.

**Expected Detection:** UnderconstrainedOracle or CollisionOracle should find collisions.

---

### 7. Public Input Leak

**Location:** `tests/ground_truth_circuits/public_input_leak.circom`

**Bug:** Private input is directly copied to or derivable from public output.

**Impact:** High - breaks zero-knowledge property.

**Expected Detection:** UnderconstrainedOracle should detect correlation between private inputs and public outputs.

---

### 8. Division by Zero

**Location:** `tests/ground_truth_circuits/division_by_zero.circom`

**Bug:** Division constraint `a = b * c` doesn't check that `b != 0`.

**Impact:** Medium - can cause undefined behavior or assertion failures.

**Expected Detection:** ArithmeticOverflowOracle or BoundaryOracle should find `b = 0` inputs.

---

### 9. Hash Length Extension

**Location:** `tests/ground_truth_circuits/hash_length_extension.circom`

**Bug:** Hash function implementation is vulnerable to length extension attacks.

**Impact:** High - allows forging hashes for extended messages.

**Expected Detection:** SoundnessOracle should detect hash weaknesses.

---

### 10. Multiexp Soundness

**Location:** `tests/ground_truth_circuits/multiexp_soundness.circom`

**Bug:** Multi-scalar multiplication with unconstrained scalars allows computing arbitrary group elements.

**Impact:** Critical - breaks soundness of proof systems.

**Expected Detection:** UnderconstrainedOracle should find scalar manipulation opportunities.

---

## Running the Tests

### Full Suite
```bash
# Run all ground truth regression tests
cargo test ground_truth --release -- --ignored

# With verbose output
cargo test ground_truth --release -- --ignored --nocapture
```

### Individual Tests
```bash
# Run specific test
cargo test test_detects_merkle_unconstrained --release -- --ignored

# Run detection rate measurement
cargo test test_ground_truth_detection_rate --release -- --ignored --nocapture
```

### With Real Backend
```bash
# Use Circom backend instead of mock
ZKPF_BACKEND=circom cargo test ground_truth --release -- --ignored
```

## Detection Rate Metrics

| Date | Version | Detection Rate | Notes |
|------|---------|----------------|-------|
| Feb 2026 | 1.0 | TBD | Initial baseline |

**Target:** 90%+ detection rate on ground truth suite

## Adding New Circuits

1. Create vulnerable circuit in `tests/ground_truth_circuits/`
2. Document the vulnerability in this file
3. Add test case in `tests/ground_truth_regression.rs`
4. Verify detection: `cargo test test_detects_<name> --release -- --ignored`
5. Update detection rate metrics

## Test Configuration

Each ground truth test uses:
- **Iterations:** 10,000 (sufficient for most detections)
- **Seed:** 42 (deterministic for reproducibility)
- **Backend:** Mock (fast) or real (accurate)
- **Timeout:** 60 seconds per circuit

## Integration with CI

The ground truth suite runs in CI on every PR:
```yaml
- name: Ground Truth Regression
  run: cargo test ground_truth --release -- --ignored
  continue-on-error: false  # Failures block merge
```

## References

- [tests/ground_truth_circuits/README.md](../tests/ground_truth_circuits/README.md)
- [tests/ground_truth_regression.rs](../tests/ground_truth_regression.rs)
- [ROADMAP.md - Milestone 0.5](../ROADMAP.md)

---

*This document is part of Milestone 0.5: Ground Truth Test Suite*
