# Ground Truth Test Circuits

This directory contains known-vulnerable circuits for testing ZkPatternFuzz's
detection capabilities. Each circuit has a documented vulnerability that the
fuzzer should detect.

## Purpose

- Validate fuzzer detection rates
- Regression testing for attack implementations
- Benchmark false positive/negative rates

## Circuits

### 1. merkle_unconstrained.circom
**Vulnerability:** Path index not constrained to binary values
**CVE Reference:** ZK-CVE-2021-001 (synthetic)
**Attack Type:** Underconstrained
**Expected Detection:** ✓ Should detect non-binary path indices

### 2. eddsa_malleability.circom
**Vulnerability:** EdDSA signature S component not range-checked
**CVE Reference:** ZK-CVE-2022-001 (synthetic)
**Attack Type:** Boundary, Soundness
**Expected Detection:** ✓ Should detect signature malleability

### 3. range_overflow.circom
**Vulnerability:** Range proof allows values >= 2^n due to missing constraint
**CVE Reference:** ZK-CVE-2023-001 (synthetic)
**Attack Type:** ArithmeticOverflow, Boundary
**Expected Detection:** ✓ Should detect overflow condition

### 4. nullifier_collision.circom
**Vulnerability:** Nullifier computation allows collision
**CVE Reference:** ZK-CVE-2022-002 (synthetic)
**Attack Type:** Collision
**Expected Detection:** ✓ Should detect hash collision

### 5. bit_decomposition.circom
**Vulnerability:** Missing constraint that bits sum to original value
**CVE Reference:** Synthetic
**Attack Type:** Underconstrained
**Expected Detection:** ✓ Should detect multiple valid decompositions

### 6. commitment_binding.circom
**Vulnerability:** Commitment scheme not binding (multiple openings)
**CVE Reference:** Synthetic
**Attack Type:** Underconstrained, Collision
**Expected Detection:** ✓ Should detect non-binding commitment

### 7. public_input_leak.circom
**Vulnerability:** Private input leaks through public output
**CVE Reference:** Synthetic
**Attack Type:** InformationLeakage
**Expected Detection:** ✓ Should detect information leakage

### 8. division_by_zero.circom
**Vulnerability:** Division constraint doesn't check for zero divisor
**CVE Reference:** Synthetic
**Attack Type:** ArithmeticOverflow
**Expected Detection:** ✓ Should detect division by zero

### 9. hash_length_extension.circom
**Vulnerability:** Hash function vulnerable to length extension
**CVE Reference:** Synthetic
**Attack Type:** Soundness
**Expected Detection:** ✓ Should detect hash weakness

### 10. multiexp_soundness.circom
**Vulnerability:** Multi-scalar multiplication with unconstrained scalars
**CVE Reference:** Synthetic
**Attack Type:** Underconstrained
**Expected Detection:** ✓ Should detect scalar manipulation

## Running Tests

```bash
# Run all ground truth regression tests
cargo test ground_truth --release

# Run with verbose output
cargo test ground_truth --release -- --nocapture

# Run specific test
cargo test test_detects_merkle_unconstrained --release
```

## Detection Rate Target

- **Target:** 90%+ detection rate on ground truth suite
- **Current:** Run `cargo test ground_truth` to measure

## Adding New Circuits

1. Create circuit file in this directory
2. Document the vulnerability in this README
3. Add test case in `../ground_truth_regression.rs`
4. Verify detection with `cargo test`
