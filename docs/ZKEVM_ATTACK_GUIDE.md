# zkEVM Attack Detection Guide

**Phase 3: Milestone 3.2**  
**Status:** ✅ Complete

This guide covers zkEVM-specific vulnerability detection in ZkPatternFuzz. These attacks target ZK circuits that implement EVM state transitions, commonly found in L2 rollups like Polygon zkEVM, Scroll, and zkSync Era.

---

## Overview

zkEVM circuits are complex implementations that replicate EVM semantics in zero-knowledge proofs. Due to this complexity, they're prone to subtle bugs where the ZK implementation diverges from actual EVM behavior.

### Attack Categories

| Attack Type | Severity | Description |
|-------------|----------|-------------|
| State Transition Mismatch | Critical | ZK circuit doesn't match EVM execution |
| Opcode Boundary Violation | High | Opcodes fail at boundary values |
| Memory Expansion Error | High | Memory cost calculation differs from EVM |
| Storage Proof Bypass | Critical | Invalid storage proofs accepted |
| Gas Accounting Error | Medium | Gas metering differs from EVM |
| Stack Boundary Violation | High | Stack limits not enforced |
| Precompile Vulnerability | Critical | Precompile implementation bugs |
| Call Handling Vulnerability | Critical | CALL/DELEGATECALL issues |
| Contract Creation Error | High | CREATE/CREATE2 address errors |

---

## Quick Start

### Basic Usage

```bash
# Run zkEVM audit with standard profile
cargo run --release -- run campaigns/templates/zkevm_audit.yaml --profile standard

# Deep analysis for critical systems
cargo run --release -- evidence campaigns/templates/zkevm_audit.yaml --profile deep
```

### Programmatic Usage

```rust
use zk_fuzzer::attacks::zkevm::{ZkEvmAttack, ZkEvmConfig};

// Create attack with default config
let config = ZkEvmConfig::default();
let mut attack = ZkEvmAttack::new(config);

// Run against circuit executor
let findings = attack.run(&executor, &initial_inputs)?;

// Process findings
for finding in findings {
    println!("Found: {} ({})", finding.title, finding.severity);
}
```

---

## Attack Types

### 1. State Transition Edge Cases

Tests edge cases in zkEVM state transition logic where the ZK circuit might not faithfully reproduce EVM semantics.

**Test Cases:**
- Empty transactions (nonce increment, gas deduction)
- Max gas limit transactions
- Zero-value transfers
- Self-transfers
- Contract creation with various data sizes

**Example Vulnerability:**
```
A zero-value transfer to a non-existent account should still:
1. Increment sender nonce
2. Deduct base gas (21000)
3. Create account entry (if applicable)

If the zkEVM skips any step, funds could be lost or state becomes inconsistent.
```

### 2. Opcode Boundary Testing

Tests EVM opcode implementations at their operational boundaries.

**Tested Opcodes:**
- Arithmetic: ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP
- Comparison: LT, GT, SLT, SGT, EQ, ISZERO
- Bitwise: AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
- Memory: MLOAD, MSTORE, MSTORE8
- Storage: SLOAD, SSTORE
- Calls: CALL, CALLCODE, DELEGATECALL, STATICCALL
- Create: CREATE, CREATE2

**Boundary Cases:**
| Case Type | Description |
|-----------|-------------|
| MaxU256Values | All inputs set to 2^256 - 1 |
| ZeroValues | All inputs set to 0 |
| MixedBoundary | Alternating max and zero |
| PowerOfTwo | Powers of 2 (1, 2, 4, ...) |
| SignedEdge | INT256_MAX, INT256_MIN, -1 |
| NearOverflow | Values just below max |

**Example Vulnerability:**
```
DIV opcode with zero divisor should return 0 (not panic/error):
  EVM: a / 0 = 0
  Bug: a / 0 = error (breaks compatibility)
```

### 3. Memory Expansion Analysis

Detects issues in memory expansion cost calculations.

**Test Cases:**
- Large offset access (16MB+)
- Exact word boundaries (32-byte aligned)
- Off-by-one boundary access
- Sequential expansion gas accumulation

**Example Vulnerability:**
```
Memory expansion cost formula:
  memory_cost = (memory_size_words^2 / 512) + (3 * memory_size_words)

If zkEVM uses wrong formula, attacker could:
- Get cheaper memory access (bypass gas limits)
- Cause OOG on legitimate operations
```

### 4. Storage Proof Manipulation

Tests storage proof verification for bypass vulnerabilities.

**Test Cases:**
| Test | Description |
|------|-------------|
| InvalidMerkleProof | Random proof values |
| WrongStorageSlot | Valid proof, wrong slot |
| ModifiedProofPath | One corrupted node |
| ReplayedProof | Duplicate nodes (replay attack) |
| EmptyProof | Missing proof data |

**Example Vulnerability:**
```
Storage proof verification must reject:
- Proofs with wrong root
- Proofs with modified intermediate nodes  
- Proofs replayed from old states

If any pass, attacker can forge storage reads.
```

---

## Configuration

### ZkEvmConfig Options

```rust
pub struct ZkEvmConfig {
    // Test counts
    pub state_transition_tests: usize,   // Default: 500
    pub opcode_boundary_tests: usize,    // Default: 100 per opcode
    pub memory_expansion_tests: usize,   // Default: 200
    pub storage_proof_tests: usize,      // Default: 100

    // Enable/disable attack types
    pub detect_state_transition: bool,   // Default: true
    pub detect_opcode_boundary: bool,    // Default: true
    pub detect_memory_expansion: bool,   // Default: true
    pub detect_storage_proof: bool,      // Default: true

    // Opcode filtering (empty = all)
    pub target_opcodes: Vec<String>,

    // Limits
    pub max_memory_offset: u64,          // Default: 16MB
    pub timeout_ms: u64,                 // Default: 10000

    // Reproducibility
    pub seed: Option<u64>,
}
```

### YAML Configuration

```yaml
attacks:
  - type: zkevm
    description: "zkEVM state transition and opcode testing"
    config:
      state_transition_tests: 1000
      opcode_boundary_tests: 200
      memory_expansion_tests: 500
      storage_proof_tests: 200
      target_opcodes:
        - ADD
        - MUL
        - DIV
        - CALL
        - CREATE2
      max_memory_offset: 33554432  # 32MB
```

---

## Tested zkEVM Implementations

### Polygon zkEVM

- State root verification
- Batch sequencing edge cases
- Bridge contract interactions

### Scroll zkEVM

- Multi-prover verification
- Chunk boundary handling
- L1/L2 message passing

### zkSync Era

- Bootloader execution
- System contract interactions
- Account abstraction edge cases

---

## Interpreting Results

### Severity Classification

| Severity | Impact | Action |
|----------|--------|--------|
| Critical | Funds at risk, consensus break | Immediate fix required |
| High | State corruption, DoS possible | Fix before deployment |
| Medium | Gas manipulation, minor issues | Fix in next release |
| Low | Edge case behavior differences | Document and monitor |

### Finding Structure

```json
{
  "id": "zkevm-a1b2c3d4",
  "attack_type": "Soundness",
  "severity": "Critical",
  "title": "zkEVM state_transition_mismatch: general",
  "description": "Empty transaction doesn't update state correctly",
  "poc": {
    "witness_a": ["0x0", "0x0", "0x0", "0x0"]
  },
  "metadata": {
    "vulnerability_type": "state_transition_mismatch",
    "expected_behavior": "Nonce increment, gas deduction",
    "actual_behavior": "No state change detected"
  }
}
```

---

## Real-World Examples

### CVE-2023-XXXX: Polygon zkEVM DIV Mismatch

**Bug:** DIV opcode with certain near-max values produced different results than EVM.

**Impact:** Contracts relying on division could produce wrong outputs.

**Detection:** Opcode boundary testing with `NearOverflow` case.

### CVE-2023-XXXX: Scroll Memory Expansion

**Bug:** Memory expansion cost was off-by-one at word boundaries.

**Impact:** Slight gas undercharge allowed larger-than-expected memory usage.

**Detection:** Memory expansion testing with `OffByOne` case.

---

## Best Practices

1. **Run with Deep Profile** for production audits:
   ```bash
   cargo run -- evidence campaign.yaml --profile deep
   ```

2. **Focus on Critical Opcodes** for targeted testing:
   ```yaml
   target_opcodes: [DIV, SDIV, MOD, SMOD, CALL, DELEGATECALL, CREATE, CREATE2]
   ```

3. **Compare with Reference EVM** when investigating findings:
   - Use `revm` or `evmone` as ground truth
   - Execute same inputs, compare outputs

4. **Verify Proof Generation** on zkEVM findings:
   - Ensure witness actually produces valid proof
   - Check if mainnet verifier would accept

---

## Integration with Picus

For formal verification of zkEVM findings:

```bash
# Run zkEVM fuzzing first
cargo run -- evidence zkevm_campaign.yaml --seed 42

# Verify critical findings with Picus
picus verify --circuit zkevm.circom --witness finding_witness.json
```

---

## References

- [Polygon zkEVM Circuits](https://github.com/0xPolygonHermez/zkevm-circuits)
- [Scroll zkEVM Circuits](https://github.com/scroll-tech/zkevm-circuits)
- [zkSync Era Circuits](https://github.com/matter-labs/era-zkevm_circuits)
- [EVM Specification (Yellow Paper)](https://ethereum.github.io/yellowpaper/)
- [EIP-1559: Gas Market Changes](https://eips.ethereum.org/EIPS/eip-1559)

---

## Changelog

- **v1.0 (Feb 2026):** Initial implementation with state transition, opcode boundary, memory expansion, and storage proof testing.
