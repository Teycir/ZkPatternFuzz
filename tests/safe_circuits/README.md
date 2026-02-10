# Safe Circuit Test Suite (Phase 1: Milestone 1.2)

This directory contains known-safe circuits for measuring the false positive rate
of ZkPatternFuzz. Each circuit has been either:

1. Professionally audited and patched
2. Formally verified with Picus or similar tools
3. Implemented following best practices with no known vulnerabilities

## Purpose

- Measure false positive rate (target: <10% in evidence mode)
- Tune oracle confidence thresholds
- Identify which attack types generate most FPs
- Validate oracle calibration

## Circuits

### Audited Production Circuits

1. **tornado_withdraw_fixed.circom** - Patched Tornado Cash withdraw
2. **semaphore_v2_secure.circom** - Semaphore v2 with all security patches
3. **poseidon_standard.circom** - Standard Poseidon from circomlib
4. **merkle_tree_secure.circom** - Properly constrained Merkle tree
5. **range_proof_secure.circom** - Secure range proof with recomposition

### Formally Verified Circuits

6. **picus_verified_merkle.circom** - Picus verified: no underconstraint
7. **picus_verified_range.circom** - Picus verified: range bounds correct
8. **picus_verified_hash.circom** - Picus verified: hash collision-free

### Best Practice Implementations

9. **eddsa_canonical.circom** - EdDSA with canonical S enforcement
10. **nullifier_secure.circom** - Nullifier with proper hash and binding

## Running False Positive Analysis

```bash
# Run FP analysis suite
cargo test false_positive --release -- --nocapture

# Run on specific circuit
cargo test test_fp_rate_audited_circuits --release -- --nocapture

# Generate FP report
cargo test test_fp_rate_by_attack_type --release -- --nocapture
```

## Interpreting Results

- **FP Rate < 10%**: Target achieved, oracles well-calibrated
- **FP Rate 10-20%**: Acceptable for exploration mode
- **FP Rate > 20%**: Oracles need tuning, investigate specific attack types

## Adding New Circuits

1. Ensure circuit has audit report or formal verification
2. Create circuit file in this directory
3. Add test case in `../false_positive_analysis.rs`
4. Document verification source in this README
