# ZkPatternFuzz

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-BSL%201.1-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Documentation](https://img.shields.io/badge/docs-architecture-purple.svg)](ARCHITECTURE.md)

A Zero-Knowledge Proof Security Testing Framework written in Rust.

## Overview

ZkPatternFuzz is a comprehensive fuzzing and security testing framework for ZK circuits across multiple backends:

- **Circom** - R1CS-based circuits with snarkjs (✅ fully implemented)
- **Noir** - ACIR-based circuits with Barretenberg (✅ fully implemented)
- **Halo2** - PLONK-based circuits with halo2_proofs (✅ fully implemented)
- **Cairo** - STARK-based programs with stone-prover (✅ fully implemented)
- **Mock** - Testing backend (✅ fully implemented)

## Features

- 🔍 **Underconstrained Detection** - Find circuits that allow multiple valid witnesses
- 🛡️ **Soundness Testing** - Attempt to forge proofs for invalid statements
- 🧮 **Arithmetic Analysis** - Test field arithmetic edge cases and overflow conditions
- 🎯 **Witness Validation** - Verify witness consistency and correctness
- 🔬 **Symbolic Execution** - SMT-based constraint analysis using Z3
- 📊 **Coverage Tracking** - Monitor constraint coverage during fuzzing
- 🧪 **Differential Testing** - Compare circuit implementations across backends
- 📝 **Multiple Report Formats** - JSON, Markdown, SARIF
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
| `collision` | Find hash/nullifier collisions | ✅ Implemented |
| `boundary` | Test boundary values | ✅ Implemented |

### Attack Plugins

Dynamic attack plugins can be loaded at runtime when the `attack-plugins` feature is enabled.

**ABI expectations (important)**:
- Plugins are Rust `cdylib` crates built with the *same* Rust toolchain and compatible dependency versions.
- Plugins must export a symbol named `zk_attacks_plugins` with this signature:
  ```rust
  unsafe extern "C" fn zk_attacks_plugins() -> Vec<Box<dyn AttackPlugin>>
  ```
- Trait object ABI is **not** stable across mismatched toolchains; rebuild plugins when upgrading.

**Build the example plugin**:
```bash
cargo build -p zk-attacks-plugin-example --release
```

**Run with plugins**:
```bash
cargo run --features attack-plugins -- <args>
```

**Config**:
```yaml
campaign:
  parameters:
    attack_plugin_dirs:
      - "./plugins"

attacks:
  - type: boundary
    plugin: example_plugin
```

**Notes**:
- If `plugin` is set, the plugin will run first; if it exists, the built-in attack is skipped.
- If no plugin is specified or it is missing, the built-in attack runs.

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

## Documentation

- **[README.md](README.md)** - Quick start and feature overview (this file)
- **[TUTORIAL.md](docs/TUTORIAL.md)** - Step-by-step guide for beginners
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Deep dive into internal design and extension points
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and release notes
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines
- **[API Documentation](https://docs.rs/zk-fuzzer)** - Generated from source code

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

### SARIF

Static Analysis Results Interchange Format for IDE integration (VS Code, GitHub Code Scanning).

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

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick Start for Contributors:**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure `cargo test` and `cargo clippy` pass
5. Commit your changes (`git commit -m 'feat: add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

**Areas Needing Help:**
- Real backend integration testing (Circom, Noir, Halo2, Cairo)
- Additional attack patterns
- Documentation and examples
- Performance optimizations

## Roadmap

### Completed ✅
- [x] Complete Circom backend integration
- [x] Complete Noir backend integration
- [x] Complete Halo2 backend integration
- [x] Add Cairo support
- [x] Coverage-guided fuzzing
- [x] Power scheduling algorithms
- [x] Structure-aware mutations
- [x] Symbolic execution with Z3
- [x] Enhanced symbolic execution (constraint extraction from R1CS/ACIR, path pruning)
- [x] Taint analysis
- [x] Complexity analysis
- [x] Parallel execution
- [x] Corpus management
- [x] JSON, Markdown, and SARIF reports
- [x] Collision detection attacks
- [x] Boundary value attacks

### In Progress 🚧
- [ ] Real backend integration testing



## References

- [Circom Documentation](https://docs.circom.io/)
- [Noir Documentation](https://noir-lang.org/)
- [Halo2 Documentation](https://zcash.github.io/halo2/)
- [Trail of Bits ZK Security](https://blog.trailofbits.com/tag/zero-knowledge-proofs/)

## License

Business Source License 1.1 - See [LICENSE](LICENSE) for details.

The Licensed Work will convert to Apache License 2.0 on 2028-02-04.

## Acknowledgments

Built with:
- [arkworks](https://github.com/arkworks-rs) - ZK cryptography primitives
- [Z3](https://github.com/Z3Prover/z3) - SMT solver for symbolic execution
- [Tokio](https://tokio.rs/) - Async runtime
- [Rayon](https://github.com/rayon-rs/rayon) - Data parallelism

Inspired by:
- [AFL](https://github.com/google/AFL) - Coverage-guided fuzzing
- [LibFuzzer](https://llvm.org/docs/LibFuzzer.html) - Corpus management
- [Trail of Bits](https://www.trailofbits.com/) - ZK security research
- [0xPARC](https://0xparc.org/) - ZK bug tracking

## Citation

If you use ZkPatternFuzz in your research, please cite:
teycirbensoltane.tn
