# ZK-Fuzzer

A Zero-Knowledge Proof Security Testing Framework written in Rust.

## Overview

ZK-Fuzzer is a comprehensive fuzzing and security testing framework for ZK circuits across multiple backends:

- **Circom** - R1CS-based circuits
- **Noir** - ACIR-based circuits
- **Halo2** - PLONK-based circuits
- **Cairo** (planned)

## Features

- 🔍 **Underconstrained Detection** - Find circuits that allow multiple valid witnesses
- 🛡️ **Soundness Testing** - Attempt to forge proofs for invalid statements
- 🧮 **Arithmetic Analysis** - Test field arithmetic edge cases
- 🎯 **Collision Detection** - Find hash/nullifier collisions
- 📊 **Coverage-Guided Fuzzing** - Maximize constraint coverage
- 📝 **Multiple Report Formats** - JSON, Markdown, SARIF

## Installation

```bash
# Clone the repository
git clone https://github.com/example/zk-fuzzer.git
cd zk-fuzzer

# Build
cargo build --release
```

## Usage

### Basic Usage

```bash
# Run a fuzzing campaign
zk-fuzzer --config tests/campaigns/mock_merkle_audit.yaml

# With verbose output
zk-fuzzer --config tests/campaigns/mock_merkle_audit.yaml --verbose

# Dry run (validate config only)
zk-fuzzer --config tests/campaigns/mock_merkle_audit.yaml --dry-run
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

| Attack Type | Description |
|-------------|-------------|
| `underconstrained` | Find circuits allowing multiple valid witnesses |
| `soundness` | Attempt to forge proofs |
| `arithmetic_overflow` | Test field arithmetic edge cases |
| `collision` | Find hash/nullifier collisions |
| `boundary` | Test boundary values |

### Fuzzing Strategies

| Strategy | Description |
|----------|-------------|
| `random` | Generate random field elements |
| `interesting_values` | Use predefined interesting values |
| `mutation` | Mutate values from corpus |
| `exhaustive_if_small` | Enumerate small domains |

## Project Structure

```
zk-fuzzer/
├── Cargo.toml
├── src/
│   ├── main.rs           # CLI entry point
│   ├── lib.rs            # Library exports
│   ├── config/           # YAML parsing and configuration
│   ├── fuzzer/           # Core fuzzing engine
│   ├── attacks/          # Attack implementations
│   ├── targets/          # ZK backend integrations
│   └── reporting/        # Report generation
├── tests/
│   └── campaigns/        # Example campaign files
├── templates/
│   └── attack_patterns.yaml  # Reusable attack patterns
└── circuits/             # Mock circuits for testing
```

## Development

```bash
# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- --config tests/campaigns/mock_merkle_audit.yaml

# Format code
cargo fmt

# Lint
cargo clippy
```

## Report Formats

### JSON

Machine-readable format for integration with other tools.

### Markdown

Human-readable report with findings and PoC details.

### SARIF

Static Analysis Results Interchange Format for IDE integration.

## License

MIT License
