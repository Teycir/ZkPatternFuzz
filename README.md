# ZkPatternFuzz

A Zero-Knowledge Proof Security Testing Framework written in Rust.

## Overview

ZkPatternFuzz is a comprehensive fuzzing and security testing framework for ZK circuits across multiple backends:

- **Circom** - R1CS-based circuits (stub implementation)
- **Noir** - ACIR-based circuits (stub implementation)
- **Halo2** - PLONK-based circuits (stub implementation)
- **Mock** - Testing backend (✅ fully implemented)
- **Cairo** (planned)

## Features

- 🔍 **Underconstrained Detection** - Find circuits that allow multiple valid witnesses
- 🛡️ **Soundness Testing** - Attempt to forge proofs for invalid statements
- 🧮 **Arithmetic Analysis** - Test field arithmetic edge cases and overflow conditions
- 🎯 **Witness Validation** - Verify witness consistency and correctness
- 🔬 **Symbolic Execution** - SMT-based constraint analysis using Z3
- 📊 **Coverage Tracking** - Monitor constraint coverage during fuzzing
- 🧪 **Differential Testing** - Compare circuit implementations across backends
- 📝 **Multiple Report Formats** - JSON, Markdown (SARIF planned)
- 🎲 **Advanced Fuzzing** - Corpus management, mutation strategies, and minimization
- 🔄 **Multi-Circuit Testing** - Composition and recursive proof analysis

## Installation

### Prerequisites

- Rust 1.70+ (2021 edition)
- Z3 SMT solver (for symbolic execution features)

### Build

```bash
# Clone the repository
git clone https://github.com/yourusername/ZkPatternFuzz.git
cd ZkPatternFuzz

# Build release version
cargo build --release

# Run tests
cargo test
```

## Usage

### Basic Usage

```bash
# Run a fuzzing campaign
cargo run --release -- --config tests/campaigns/mock_merkle_audit.yaml

# With verbose output
cargo run --release -- --config tests/campaigns/mock_merkle_audit.yaml --verbose

# Dry run (validate config only)
cargo run --release -- --config tests/campaigns/mock_merkle_audit.yaml --dry-run

# Run with custom worker count
cargo run --release -- --config tests/campaigns/mock_merkle_audit.yaml --workers 8

# Run with specific seed for reproducibility
cargo run --release -- --config tests/campaigns/mock_merkle_audit.yaml --seed 12345
```

### CLI Options

```
Options:
  -c, --config <CONFIG>    Path to YAML campaign configuration
  -w, --workers <WORKERS>  Number of parallel workers [default: 4]
  -s, --seed <SEED>        Seed for reproducibility
  -v, --verbose            Verbose output
      --dry-run            Validate config without executing
  -h, --help               Print help
```

## Campaign Configuration

Campaigns are defined in YAML files. See `tests/campaigns/` for examples.

### Basic Structure

```yaml
campaign:
  name: "My Circuit Audit"
  version: "1.0"
  target:
    framework: "circom"  # circom | noir | halo2 | mock
    circuit_path: "./circuits/my_circuit.circom"
    main_component: "MyCircuit"

attacks:
  - type: "underconstrained"
    description: "Find multiple valid witnesses"
    config:
      witness_pairs: 1000

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: "random"

reporting:
  output_dir: "./reports"
  formats: ["json", "markdown"]
```

### Attack Types

| Attack Type | Description | Status |
|-------------|-------------|--------|
| `underconstrained` | Find circuits allowing multiple valid witnesses | ✅ Implemented |
| `soundness` | Attempt to forge proofs | ✅ Implemented |
| `arithmetic_overflow` | Test field arithmetic edge cases | ✅ Implemented |
| `witness_validation` | Verify witness consistency | ✅ Implemented |
| `verification` | Test proof verification edge cases | ✅ Implemented |
| `collision` | Find hash/nullifier collisions | 🚧 Planned |
| `boundary` | Test boundary values | 🚧 Planned |

### Fuzzing Strategies

| Strategy | Description |
|----------|-------------|
| `random` | Generate random field elements |
| `interesting_values` | Use predefined interesting values |
| `mutation` | Mutate values from corpus |
| `exhaustive_if_small` | Enumerate small domains |

## Project Structure

```
ZkPatternFuzz/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library exports
│   ├── errors.rs            # Error types
│   ├── config/              # YAML parsing and configuration
│   ├── fuzzer/              # Core fuzzing engine
│   │   ├── engine.rs        # Main fuzzing loop
│   │   ├── mutators.rs      # Input mutation strategies
│   │   ├── oracle.rs        # Bug detection oracles
│   │   └── constants.rs     # Interesting values
│   ├── attacks/             # Attack implementations
│   │   ├── underconstrained.rs
│   │   ├── soundness.rs
│   │   ├── arithmetic.rs
│   │   ├── witness.rs
│   │   └── verification.rs
│   ├── targets/             # ZK backend integrations
│   │   ├── circom.rs        # Circom support
│   │   ├── noir.rs          # Noir support
│   │   └── halo2.rs         # Halo2 support
│   ├── executor/            # Circuit execution
│   │   ├── mock.rs          # Mock executor for testing
│   │   ├── coverage.rs      # Coverage tracking
│   │   └── traits.rs        # Executor traits
│   ├── corpus/              # Test case management
│   │   ├── storage.rs       # Corpus storage
│   │   └── minimizer.rs     # Test case minimization
│   ├── analysis/            # Advanced analysis
│   │   ├── symbolic.rs      # Symbolic execution (Z3)
│   │   ├── taint.rs         # Taint analysis
│   │   ├── complexity.rs    # Complexity metrics
│   │   └── profiling.rs     # Performance profiling
│   ├── differential/        # Differential testing
│   │   ├── executor.rs      # Multi-backend execution
│   │   └── report.rs        # Diff reporting
│   ├── multi_circuit/       # Multi-circuit analysis
│   │   ├── composition.rs   # Circuit composition
│   │   └── recursive.rs     # Recursive proofs
│   ├── progress/            # Progress tracking
│   └── reporting/           # Report generation
├── tests/
│   ├── campaigns/           # Example campaign files
│   │   ├── mock_merkle_audit.yaml
│   │   ├── mock_nullifier_test.yaml
│   │   ├── mock_range_proof.yaml
│   │   ├── semaphore_audit.yaml
│   │   ├── tornado_core_audit.yaml
│   │   ├── iden3_auth_audit.yaml
│   │   └── polygon_zkevm_audit.yaml
│   ├── integration/         # Integration tests
│   ├── integration_tests.rs
│   └── realistic_testing.rs
├── templates/
│   └── attack_patterns.yaml # Reusable attack patterns
├── circuits/                # Mock circuits for testing
│   ├── mock_merkle.circom
│   ├── mock_nullifier.circom
│   └── mock_range.circom
└── reports/                 # Generated reports
```

## Development

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with logging
RUST_LOG=debug cargo run -- --config tests/campaigns/mock_merkle_audit.yaml

# Run integration tests
cargo test --test integration_tests

# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings

# Generate documentation
cargo doc --open

# Build with symbolic execution features
cargo build --features symbolic
```

## Report Formats

### JSON

Machine-readable format for integration with other tools. Includes:
- Campaign metadata
- Attack results
- Findings with severity levels
- Proof-of-concept test cases
- Coverage statistics

### Markdown

Human-readable report with:
- Executive summary
- Detailed findings
- PoC reproduction steps
- Recommendations

### SARIF (Planned)

Static Analysis Results Interchange Format for IDE integration.

## Example Campaigns

The `tests/campaigns/` directory contains example configurations:

- **mock_merkle_audit.yaml** - Merkle tree proof verification
- **mock_nullifier_test.yaml** - Nullifier uniqueness testing
- **mock_range_proof.yaml** - Range proof validation
- **semaphore_audit.yaml** - Semaphore protocol analysis
- **tornado_core_audit.yaml** - Tornado Cash core circuit
- **iden3_auth_audit.yaml** - Iden3 authentication
- **polygon_zkevm_audit.yaml** - Polygon zkEVM patterns

## Advanced Features

### Symbolic Execution

Use Z3 SMT solver for constraint analysis:

```yaml
attacks:
  - type: "underconstrained"
    config:
      symbolic_execution: true
      z3_timeout: 60
```

### Differential Testing

Compare implementations across backends:

```yaml
differential:
  enabled: true
  backends: ["circom", "noir"]
  tolerance: 0.0001
```

### Corpus Management

Automatic test case minimization and corpus storage:

```yaml
corpus:
  enabled: true
  minimize: true
  max_size: 10000
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `cargo test` and `cargo clippy` pass
5. Submit a pull request

## Roadmap

- [ ] Complete Circom backend integration
- [ ] Complete Noir backend integration
- [ ] Complete Halo2 backend integration
- [ ] Add Cairo support
- [ ] Implement SARIF report format
- [ ] Add collision detection attacks
- [ ] Enhance symbolic execution capabilities
- [ ] Add GUI for campaign management
- [ ] Integrate with CI/CD pipelines

## References

- [Circom Documentation](https://docs.circom.io/)
- [Noir Documentation](https://noir-lang.org/)
- [Halo2 Documentation](https://zcash.github.io/halo2/)
- [Trail of Bits ZK Security](https://blog.trailofbits.com/tag/zero-knowledge-proofs/)

## License

MIT License

## Acknowledgments

Built with:
- [arkworks](https://github.com/arkworks-rs) - ZK cryptography primitives
- [Z3](https://github.com/Z3Prover/z3) - SMT solver for symbolic execution
- [Tokio](https://tokio.rs/) - Async runtime
- [Rayon](https://github.com/rayon-rs/rayon) - Data parallelism
