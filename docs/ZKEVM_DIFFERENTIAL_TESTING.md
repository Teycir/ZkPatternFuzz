# zkEVM Differential Testing (Phase 5: Milestone 5.2)

**Status:** ✅ Complete  
**Priority:** P1 - HIGH for zkEVM audit accuracy

## Overview

This document describes the zkEVM differential testing system that compares zkEVM circuit execution against a reference EVM implementation to detect semantic mismatches.

## Problem Statement

The previous zkEVM attack detection used ad-hoc checks without a reference EVM, leading to:

- **Missed deep zkEVM bugs**: Subtle semantic differences not caught by pattern matching
- **False positives on valid EVM behavior**: Ad-hoc checks may flag compliant behavior
- **No ground truth for validation**: No authoritative source to verify circuit correctness

## Solution Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    zkEVM Differential Testing System                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │                    Test Transaction Generator                      │     │
│   │   • Random transactions  • Edge cases  • Precompile calls          │     │
│   └───────────────────────────────┬───────────────────────────────────┘     │
│                                   │                                          │
│                                   ▼                                          │
│   ┌─────────────────────┐                   ┌─────────────────────┐         │
│   │   zkEVM Circuit     │                   │   Reference EVM     │         │
│   │   (Executor)        │                   │   (revm/Mock)       │         │
│   └──────────┬──────────┘                   └──────────┬──────────┘         │
│              │                                         │                     │
│              ▼                                         ▼                     │
│   ┌─────────────────────┐                   ┌─────────────────────┐         │
│   │   ExecutionTrace    │                   │   ExecutionTrace    │         │
│   │   • gas_used        │                   │   • gas_used        │         │
│   │   • state_root      │                   │   • state_root      │         │
│   │   • storage_changes │                   │   • storage_changes │         │
│   │   • return_data     │                   │   • return_data     │         │
│   └──────────┬──────────┘                   └──────────┬──────────┘         │
│              │                                         │                     │
│              └─────────────────┬───────────────────────┘                     │
│                                ▼                                             │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │                    Differential Comparator                         │     │
│   │   • State root comparison    • Storage slot comparison             │     │
│   │   • Gas accounting check     • Return data comparison              │     │
│   │   • Balance comparison       • Log comparison                      │     │
│   └───────────────────────────────┬───────────────────────────────────┘     │
│                                   │                                          │
│                                   ▼                                          │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │                    Mismatch Classification                         │     │
│   │   • OutcomeMismatch (Critical)  • StorageMismatch (High)           │     │
│   │   • BalanceMismatch (High)      • GasMismatch (Low-Medium)         │     │
│   │   • ReturnDataMismatch (Medium) • LogMismatch (Medium)             │     │
│   └───────────────────────────────────────────────────────────────────┘     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. ZkEvmDifferentialTester

Main entry point for differential testing:

```rust
use zk_fuzzer::attacks::zkevm_differential::{
    ZkEvmDifferentialTester, ZkEvmDifferentialConfig
};

let config = ZkEvmDifferentialConfig::default();
let mut tester = ZkEvmDifferentialTester::new(config);

// Run tests
let findings = tester.run(&executor, 1000)?;

// Get summary
let summary = tester.summary();
println!("Tests: {}, Mismatches: {}", summary.total_tests, summary.mismatch_count);
```

### 2. ReferenceEvm Trait

Interface for reference EVM implementations:

```rust
pub trait ReferenceEvm: Send + Sync {
    /// Execute a transaction and return the trace
    fn execute(&self, tx: &TestTransaction, state: &EvmState) -> Result<ExecutionTrace>;
    
    /// Get the EVM implementation name
    fn name(&self) -> &str;
    
    /// Check if the EVM is available
    fn is_available(&self) -> bool;
}
```

### 3. ExecutionTrace

Captures execution result for comparison:

```rust
pub struct ExecutionTrace {
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub success: bool,
    pub revert_reason: Option<String>,
    pub storage_changes: HashMap<[u8; 20], HashMap<[u8; 32], [u8; 32]>>,
    pub account_changes: HashMap<[u8; 20], AccountState>,
    pub logs: Vec<EvmLog>,
    pub state_root: [u8; 32],
}
```

## Configuration

```rust
pub struct ZkEvmDifferentialConfig {
    /// Number of differential tests to run
    pub num_tests: usize,
    
    /// Enable state root comparison
    pub compare_state_root: bool,
    
    /// Enable storage slot comparison
    pub compare_storage: bool,
    
    /// Enable gas usage comparison
    pub compare_gas: bool,
    
    /// Enable return data comparison
    pub compare_return_data: bool,
    
    /// Gas tolerance for comparison (percentage)
    pub gas_tolerance_percent: f64,
    
    /// Timeout per test in milliseconds
    pub timeout_ms: u64,
    
    /// Opcodes to focus on (empty = all)
    pub target_opcodes: Vec<u8>,
    
    /// Precompile addresses to test
    pub target_precompiles: Vec<[u8; 20]>,
}
```

## Mismatch Types

| Type | Severity | Description |
|------|----------|-------------|
| `OutcomeMismatch` | Critical | Success/failure differs between implementations |
| `StateRootMismatch` | Critical | Post-execution state root differs |
| `StorageMismatch` | High | Storage slot values differ |
| `BalanceMismatch` | High | Account balances differ |
| `ReturnDataMismatch` | Medium | Transaction return data differs |
| `LogMismatch` | Medium | Emitted logs differ |
| `GasMismatch` | Low-High | Gas usage differs (severity based on %) |

## Precompile Testing

Special attention is given to precompile contracts (0x01-0x09):

```rust
pub mod precompiles {
    pub const ECRECOVER: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01];
    pub const SHA256: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x02];
    pub const RIPEMD160: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x03];
    pub const IDENTITY: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x04];
    pub const MODEXP: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x05];
    pub const ECADD: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x06];
    pub const ECMUL: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x07];
    pub const ECPAIRING: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x08];
    pub const BLAKE2F: [u8; 20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x09];
}
```

The `PrecompileTestGenerator` creates edge case inputs for each precompile:

- **ECRECOVER**: Invalid signatures, malformed v values
- **SHA256/RIPEMD160**: Empty input, max length input
- **MODEXP**: Large exponents, edge case bases
- **BN256**: Invalid curve points, edge cases

## Usage Example

### Basic Differential Test

```rust
use zk_fuzzer::attacks::zkevm_differential::*;

// Create tester
let config = ZkEvmDifferentialConfig {
    num_tests: 1000,
    compare_state_root: true,
    compare_storage: true,
    compare_gas: true,
    gas_tolerance_percent: 1.0,
    ..Default::default()
};

let mut tester = ZkEvmDifferentialTester::new(config);

// Run with zkEVM executor
let findings = tester.run(&executor, config.num_tests)?;

// Check for critical issues
for finding in &findings {
    if finding.severity == Severity::Critical {
        println!("CRITICAL: {}", finding.description);
    }
}
```

### Focus on Specific Opcodes

```rust
let config = ZkEvmDifferentialConfig {
    target_opcodes: vec![
        0x55, // SSTORE
        0x54, // SLOAD
        0xf1, // CALL
        0xf4, // DELEGATECALL
    ],
    ..Default::default()
};
```

### Precompile-Focused Testing

```rust
let config = ZkEvmDifferentialConfig {
    target_precompiles: vec![
        precompiles::ECRECOVER,
        precompiles::ECPAIRING,
        precompiles::MODEXP,
    ],
    num_tests: 500,
    ..Default::default()
};
```

## Integration with zkevm.rs

The differential tester integrates with the existing `ZkEvmAttack`:

```rust
// In ZkEvmAttack
pub fn run_differential_tests(&mut self, executor: &dyn CircuitExecutor) -> Result<Vec<Finding>> {
    let config = ZkEvmDifferentialConfig::default();
    let mut tester = ZkEvmDifferentialTester::new(config);
    tester.run(executor, self.config.state_transition_tests)
}
```

## Evidence Mode

Findings include reproducible evidence:

```rust
pub struct DifferentialFinding {
    /// The transaction that triggered the mismatch
    pub transaction: TestTransaction,
    /// zkEVM execution trace
    pub zkevm_trace: ExecutionTrace,
    /// Reference EVM execution trace  
    pub reference_trace: ExecutionTrace,
    /// Specific differences found
    pub differences: Vec<Difference>,
    /// Reproduction command
    pub repro_command: String,
}
```

## CLI Usage

```bash
# Run differential tests on a zkEVM circuit
cargo run --release -- evidence zkevm_campaign.yaml \
    --differential \
    --seed 42 \
    --iterations 10000

# Focus on precompiles
cargo run --release -- evidence zkevm_campaign.yaml \
    --differential \
    --precompiles ecrecover,ecpairing,modexp
```

## Testing

```bash
# Run all differential tests
cargo test zkevm_differential --lib

# Run precompile edge case tests
cargo test precompile_generator --lib

# Integration tests (requires executor)
cargo test zkevm_differential --test integration_tests
```

## Performance

| Test Type | Time per Test | Coverage |
|-----------|--------------|----------|
| Simple transfer | ~1ms | State, balance |
| Contract call | ~5ms | State, storage, gas |
| Precompile call | ~2ms | Return data, gas |
| Complex multi-call | ~20ms | All aspects |

## Future Work

1. **Full revm Integration**: Replace mock with actual revm execution
2. **EVM Version Support**: Test against different EVM versions (London, Paris, Shanghai)
3. **State Snapshot Testing**: Test with real mainnet state snapshots
4. **Parallel Execution**: Run zkEVM and reference EVM in parallel

## References

- [revm - Rust EVM Implementation](https://github.com/bluealloy/revm)
- [Polygon zkEVM](https://github.com/0xPolygonHermez/zkevm-circuits)
- [Scroll zkEVM](https://github.com/scroll-tech/zkevm-circuits)
- [zkSync Era](https://github.com/matter-labs/era-zkevm_circuits)
- [EVM Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)

## Changelog

- **v1.0 (Phase 5)**: Initial differential testing implementation
  - ReferenceEvm trait and MockReferenceEvm
  - Precompile edge case generator
  - 6 mismatch types with severity classification
  - Integration with ZkEvmAttack
