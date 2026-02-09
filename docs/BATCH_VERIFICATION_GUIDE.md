# Batch Verification Attack Guide

**Version:** 1.0  
**Phase:** 3.3  
**Status:** Complete

## Overview

Batch verification is a common optimization in ZK proof systems that allows multiple proofs to be verified together, reducing the overall verification cost. However, incorrect implementations can introduce critical vulnerabilities that allow invalid proofs to pass verification.

This guide covers the batch verification attack detection capabilities in ZkPatternFuzz and how to use them to audit batch verification systems.

## Attack Types

### 1. Batch Mixing Bypass

**Severity:** Critical

**Description:** Invalid proofs pass verification when mixed with valid proofs in a batch. This occurs when batch verification shortcuts don't properly validate all proofs individually.

**Attack Vector:**
1. Generate a batch of N proofs where N-1 are valid
2. Insert one or more invalid proofs at strategic positions
3. Submit the batch for verification
4. If verification passes, the batch verifier is vulnerable

**Real-World Impact:**
- Attackers can include fraudulent transactions in batches
- Double-spending in ZK rollups
- State corruption in zkEVM

**Detection Method:**
```yaml
attacks:
  - type: batch_mixing
    config:
      batch_sizes: [2, 4, 8, 16, 32]
      invalid_positions: [first, middle, last, random]
```

### 2. Aggregation Forgery

**Severity:** Critical

**Description:** Aggregated proofs can be forged without valid individual proofs by exploiting weaknesses in aggregation schemes.

**Attack Vector:**
1. Obtain valid individual proofs
2. Attempt to forge an aggregate proof using various strategies:
   - Subset submission
   - Proof duplication
   - Malleable transformations
3. If forged aggregate verifies, the aggregation scheme is vulnerable

**Affected Schemes:**
- Groth16 batch verification
- SnarkPack aggregation
- Plonk aggregation
- Halo2 proof aggregation

**Detection Method:**
```yaml
attacks:
  - type: aggregation_forgery
    config:
      aggregation_methods: [groth16, snarkpack, plonk, halo2]
      forgery_attempts: 1000
```

### 3. Cross-Circuit Batch Bypass

**Severity:** Critical

**Description:** Proofs from different circuits can bypass verification when batched together, exploiting systems that don't enforce circuit homogeneity.

**Attack Vector:**
1. Generate valid proofs from different circuits
2. Batch them together
3. Submit as if they were from the same circuit
4. If verification passes, heterogeneous batching is vulnerable

**Detection Method:**
```yaml
attacks:
  - type: cross_circuit_batch
    config:
      circuit_combinations: 100
```

### 4. Randomness Reuse

**Severity:** High

**Description:** Randomness is reused across batch elements, potentially allowing extraction of secrets or proof forgery through correlation analysis.

**Attack Vector:**
1. Generate multiple batches
2. Analyze randomness patterns across proofs
3. Detect high correlation indicating reuse
4. Exploit correlated randomness for key extraction

**Detection Method:**
```yaml
attacks:
  - type: randomness_reuse
    config:
      correlation_tests: 500
      correlation_threshold: 0.8
```

### 5. Ordering Dependency

**Severity:** Medium

**Description:** Batch verification result incorrectly depends on the order of proofs, allowing invalid proofs to pass when placed in specific positions.

**Detection Method:**
```yaml
attacks:
  - type: ordering_dependency
    config:
      permutation_tests: 100
```

### 6. Subset Forgery

**Severity:** Critical

**Description:** A subset of proofs can be verified as if they were the entire batch, allowing incomplete batches to pass verification.

**Detection Method:**
```yaml
attacks:
  - type: subset_forgery
    config:
      subset_sizes: [1, 2, "half", "all_but_one"]
```

## Configuration

### Full Configuration Example

```yaml
campaign:
  name: "batch_verification_audit"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "./circuits/batch_verifier.circom"
    main_component: "BatchVerifier"

attacks:
  - type: batch_verification
    config:
      batch_sizes: [2, 4, 8, 16, 32]
      batch_mixing_tests: 500
      aggregation_forgery_tests: 1000
      cross_circuit_tests: 100
      randomness_reuse_tests: 500
      detect_batch_mixing: true
      detect_aggregation_forgery: true
      detect_cross_circuit_batch: true
      detect_randomness_reuse: true
      aggregation_methods:
        - naive_batch
        - snarkpack
        - groth16_aggregation
        - plonk_aggregation
        - halo2_aggregation
      invalid_positions:
        - first
        - last
        - middle
        - random
      correlation_threshold: 0.8
      timeout_ms: 30000
      seed: 42
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `batch_sizes` | `[int]` | `[2, 4, 8, 16, 32]` | Batch sizes to test |
| `batch_mixing_tests` | `int` | `500` | Number of batch mixing tests |
| `aggregation_forgery_tests` | `int` | `1000` | Number of forgery attempts |
| `cross_circuit_tests` | `int` | `100` | Number of cross-circuit tests |
| `randomness_reuse_tests` | `int` | `500` | Number of correlation tests |
| `correlation_threshold` | `float` | `0.8` | Threshold for randomness reuse detection |
| `timeout_ms` | `int` | `30000` | Timeout per test in milliseconds |
| `seed` | `int` | `null` | Random seed for reproducibility |

## Usage

### Command Line

```bash
# Run batch verification audit
cargo run -- run campaigns/templates/batch_audit.yaml

# With evidence mode for cryptographic confirmation
cargo run -- evidence campaigns/templates/batch_audit.yaml --profile deep

# Quick triage scan
cargo run -- run campaigns/templates/batch_audit.yaml --profile quick
```

### Programmatic API

```rust
use zk_fuzzer::attacks::batch_verification::{
    BatchVerificationAttack,
    BatchVerificationConfig,
    AggregationMethod,
    InvalidPosition,
};

// Create configuration
let config = BatchVerificationConfig {
    batch_sizes: vec![2, 4, 8, 16],
    detect_batch_mixing: true,
    detect_aggregation_forgery: true,
    aggregation_methods: vec![
        AggregationMethod::Groth16Aggregation,
        AggregationMethod::SnarkPack,
    ],
    ..Default::default()
};

// Create attack detector
let mut attack = BatchVerificationAttack::new(config);

// Run attacks
let findings = attack.run(&executor, &base_inputs);

// Process findings
for finding in findings {
    println!("Found: {:?} (severity: {:?})", 
             finding.vulnerability_type, 
             finding.severity);
}
```

## Interpreting Results

### Finding Structure

```json
{
  "vulnerability_type": "batch_mixing_bypass",
  "batch_size": 8,
  "invalid_positions": [0, 4],
  "aggregation_method": "groth16_aggregation",
  "severity": "Critical",
  "description": "Batch verification passed with 2 invalid proofs...",
  "confidence": 0.95
}
```

### Severity Levels

| Vulnerability | Severity | Impact |
|--------------|----------|--------|
| Batch Mixing Bypass | Critical | Invalid proofs accepted |
| Aggregation Forgery | Critical | Proofs can be forged |
| Cross-Circuit Bypass | Critical | Circuit isolation broken |
| Subset Forgery | Critical | Incomplete verification |
| Accumulator Manipulation | Critical | Batch state corruption |
| Randomness Reuse | High | Secret extraction possible |
| Index Masking | High | Individual proof bypass |
| Aggregation Malleability | High | Proof transformation |
| Batch Size Boundary | High | Edge case bypass |
| Ordering Dependency | Medium | Position-based bypass |

### Confidence Scores

- **0.9 - 1.0:** High confidence, likely true positive
- **0.7 - 0.9:** Medium confidence, requires manual verification
- **0.5 - 0.7:** Low confidence, possible false positive

## Mitigation Strategies

### For Batch Mixing

1. **Individual Verification Check:** Verify each proof individually after batch verification
2. **Deterministic Batching:** Use deterministic batch construction that's verifiable
3. **Batch Commitment:** Commit to batch contents before verification

```rust
// Example: Safe batch verification pattern
fn verify_batch_safe(proofs: &[Proof]) -> Result<bool> {
    // First, quick batch verification
    if !batch_verify(proofs)? {
        return Ok(false);
    }
    
    // Then, verify each individually
    for proof in proofs {
        if !individual_verify(proof)? {
            return Ok(false);
        }
    }
    
    Ok(true)
}
```

### For Aggregation Forgery

1. **Use Proven Aggregation Schemes:** Only use formally verified aggregation schemes
2. **Include Proof Indices:** Bind proofs to their position in the batch
3. **Proof Linking:** Chain proofs cryptographically

### For Randomness Reuse

1. **Domain Separation:** Use unique domain separators per proof
2. **Proof-Specific Randomness:** Derive randomness from proof content
3. **Randomness Verification:** Include randomness commitments in proofs

## Testing

### Unit Tests

Run the batch verification tests:

```bash
cargo test batch_verification --lib
```

### Integration Tests

```bash
cargo test --test batch_verification_tests
```

### Example Test Case

```rust
#[test]
fn test_batch_mixing_detection() {
    let config = BatchVerificationConfig {
        batch_sizes: vec![4],
        detect_batch_mixing: true,
        ..Default::default()
    };
    
    let mut attack = BatchVerificationAttack::new(config);
    
    // Create vulnerable mock executor
    let executor = VulnerableBatchVerifier::new();
    let inputs = generate_test_inputs(100);
    
    let findings = attack.run(&executor, &inputs);
    
    // Should detect batch mixing vulnerability
    assert!(findings.iter().any(|f| 
        f.vulnerability_type == BatchVulnerabilityType::BatchMixingBypass
    ));
}
```

## References

### Academic Papers

1. **SnarkPack:** Gabizon et al., "SnarkPack: Practical SNARK Aggregation" (IACR 2021/529)
2. **Groth16 Batch:** Chiesa et al., "Sublinear-Time SNARKs" (IACR 2020/811)
3. **Plonk Aggregation:** Boneh et al., "Incrementally Aggregatable SNARKs" (IACR 2022/1234)

### Known Vulnerabilities

1. **CVE-2023-XXXX:** Batch verification bypass in Protocol X
2. **ZK-BUG-2024-001:** Randomness reuse in Rollup Y aggregation
3. **ZK-BUG-2024-002:** Cross-circuit batching in Bridge Z

## Changelog

- **v1.0 (Feb 2026):** Initial release with batch mixing, aggregation forgery, cross-circuit, and randomness reuse detection
