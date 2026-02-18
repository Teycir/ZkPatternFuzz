# ZkPatternFuzz

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-BSL%201.1-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

A Zero-Knowledge Proof Security Testing Framework written in Rust.

## Overview

ZkPatternFuzz fuzzes ZK circuits to find security vulnerabilities across multiple backends:

- **Circom** - R1CS-based circuits (most mature)
- **Noir** - ACIR-based circuits (partial support)
- **Halo2** - PLONK-based circuits (partial support)
- **Cairo** - STARK-based programs (experimental)
- **Mock** - In-process testing backend

## Installation

### Prerequisites

- Rust 1.70+
- Z3 SMT solver (optional, for symbolic execution)

### Build

```bash
git clone https://github.com/<your-username>/ZkPatternFuzz.git
cd ZkPatternFuzz
cargo build --release
cargo test
```

### Local Circom Toolchain Bootstrap

```bash
# Install/update local circom + snarkjs + ptau under ./bins
cargo run --release --bin zk-fuzzer -- bins bootstrap

# Dry run only
cargo run --release --bin zk-fuzzer -- --dry-run bins bootstrap
```

Notes:
- `circom` is downloaded from official GitHub release assets and SHA-256 verified.
- `snarkjs` is installed locally under `bins/node_modules` and linked to `bins/bin/snarkjs`.
- `ptau` defaults to the repo fixture (`tests/circuits/build/pot12_final.ptau`) with checksum verification.

## Quick Start

```bash
# Run a campaign
cargo run --release -- --config tests/campaigns/mock_merkle_audit.yaml

# With verbose output
cargo run --release -- --config tests/campaigns/mock_merkle_audit.yaml --verbose

# Custom worker count
cargo run --release -- --config tests/campaigns/mock_merkle_audit.yaml --workers 8
```

## Attack Types

| Attack | Description | Status |
|--------|-------------|--------|
| `underconstrained` | Multiple valid witnesses for same public inputs | ✅ |
| `soundness` | Proof forgery attempts | ✅ |
| `arithmetic_overflow` | Field boundary testing | ✅ |
| `collision` | Hash/nullifier collision search | ✅ |
| `boundary` | Edge case exploration | ✅ |
| `verification_fuzzing` | Proof malleability testing | ✅ |
| `witness_fuzzing` | Determinism and consistency checks | ✅ |
| `differential` | Cross-backend comparison | ✅ |
| `circuit_composition` | Multi-circuit chain analysis | ✅ |
| `information_leakage` | Taint analysis | ✅ |
| `timing_sidechannel` | Timing variation detection | ✅ |
| `constraint_inference` | Infer missing constraints | ✅ |
| `metamorphic` | Transform-based oracles | ✅ |
| `spec_inference` | Auto-learn circuit properties | ✅ |
| `mev` | MEV attack detection | ✅ |
| `front_running` | Front-running detection | ✅ |

## Campaign Configuration

Create a YAML file:

```yaml
campaign:
  name: "My Circuit Audit"
  target:
    framework: "circom"
    circuit_path: "./circuits/my_circuit.circom"
    main_component: "MyCircuit"
  parameters:
    timeout_seconds: 300

attacks:
  - type: "underconstrained"
    config:
      witness_pairs: 1000
      public_input_names: ["root", "nullifier"]

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: "random"

reporting:
  output_dir: "./reports"
  formats: ["json", "markdown"]
```

## Key Features

### Detection Techniques

- **Parallel Execution** - Rayon-based thread pool
- **Coverage-Guided Fuzzing** - Constraint-level tracking
- **Symbolic Execution** - Z3-based constraint solving
- **Structure-Aware Mutations** - Understands Merkle paths, signatures
- **Power Scheduling** - FAST/EXPLORE/MMOPT strategies
- **Corpus Management** - Automatic minimization, 100K max size

### Evidence Mode

```yaml
campaign:
  parameters:
    additional:
      evidence_mode: true
      strict_backend: true
      oracle_validation: true
      min_evidence_confidence: "high"
```

**Confidence Levels:**
- **CRITICAL:** 3+ oracles agree
- **HIGH:** 2+ oracles agree
- **MEDIUM:** Single oracle detection
- **LOW:** Heuristic detection

### Optional Scanners

```yaml
attacks:
  - type: soundness
    config:
      proof_malleability:
        enabled: true
        proof_samples: 10
      determinism:
        enabled: true
        repetitions: 5

  - type: underconstrained
    config:
      frozen_wire:
        enabled: true
        min_samples: 100

  - type: collision
    config:
      nullifier_replay:
        enabled: true
        replay_attempts: 50

  - type: boundary
    config:
      canonicalization:
        enabled: true
        sample_count: 20

  - type: differential
    config:
      backends: ["circom", "noir"]
      cross_backend:
        enabled: true
        sample_count: 100
```

## CVE Test Suite

22 real-world vulnerabilities from zkBugs dataset:

```bash
# Verify circuits exist
cargo test --test autonomous_cve_tests test_cve_circuits_exist_in_repo -- --nocapture

# Run full suite
cargo test --test autonomous_cve_tests -- --nocapture
```

**Coverage:**
- 11 Critical severity
- 11 High severity
- 9 projects (Iden3, Self.xyz, SuccinctLabs, etc.)
- Includes CVE-2024-42459 (EdDSA malleability)

See `CVErefs/AUTONOMOUS_TEST_SUITE.md` for details.

## CLI Options

```
Options:
  -c, --config <CONFIG>    Path to YAML campaign configuration
  -w, --workers <WORKERS>  Number of parallel workers [default: 4]
  -s, --seed <SEED>        Seed for reproducibility
  -v, --verbose            Verbose output
      --quiet              Minimal output
      --dry-run            Validate config without executing
  -h, --help               Print help
```

## Project Structure

```
ZkPatternFuzz/
├── src/                     # Main application
├── crates/                  # Workspace crates
│   ├── zk-core/             # Core types
│   ├── zk-attacks/          # Attack implementations
│   ├── zk-fuzzer-core/      # Fuzzing engine
│   ├── zk-symbolic/         # Symbolic execution
│   ├── zk-backends/         # Backend integrations
│   └── zk-constraints/      # Constraint analysis
├── tests/                   # Test suite
├── campaigns/               # Campaign configs
├── circuits/                # Test circuits
├── targets/zkbugs/          # zkBugs dataset (110 vulnerabilities)
├── templates/               # YAML templates
└── docs/                    # Documentation
```

## Documentation

- **[TUTORIAL.md](docs/TUTORIAL.md)** - Step-by-step guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Internal design
- **[ROADMAP.md](ROADMAP.md)** - Development roadmap
- **[RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)** - Production release gate checklist
- **[TROUBLESHOOTING_PLAYBOOK.md](docs/TROUBLESHOOTING_PLAYBOOK.md)** - Keygen/includes/locks/timeouts playbook
- **[TRIAGE_SYSTEM.md](docs/TRIAGE_SYSTEM.md)** - Automated triage
- **[DEFI_ATTACK_GUIDE.md](docs/DEFI_ATTACK_GUIDE.md)** - MEV/front-running detection

## Release Ops

- Use **[docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)** as the source of truth before tagging a release.
- Use **[docs/TARGETS.md](docs/TARGETS.md)** for exact `gh workflow run "Release Validation"` command templates.
- Use **[docs/TROUBLESHOOTING_PLAYBOOK.md](docs/TROUBLESHOOTING_PLAYBOOK.md)** when release gates fail (keygen, includes, lock contention, timeout tuning).

## Development

```bash
# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- --config tests/campaigns/mock_merkle_audit.yaml

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Generate docs
cargo doc --open
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Areas Needing Help:**
- Cairo real-circuit integration
- Additional attack patterns
- Documentation and examples
- Performance optimizations

## License

Business Source License 1.1 - See [LICENSE](LICENSE) for details.

Converts to Apache License 2.0 on 2028-02-04.

## Acknowledgments

Built with: [arkworks](https://github.com/arkworks-rs), [Z3](https://github.com/Z3Prover/z3), [Tokio](https://tokio.rs/), [Rayon](https://github.com/rayon-rs/rayon)

Inspired by: [AFL](https://github.com/google/AFL), [LibFuzzer](https://llvm.org/docs/LibFuzzer.html), [Trail of Bits](https://www.trailofbits.com/), [0xPARC](https://0xparc.org/)

## Citation

If you use ZkPatternFuzz in your research, please contact: teycirbensoltane.tn

```bibtex
@software{zkpatternfuzz2024,
  title={ZkPatternFuzz: A Zero-Knowledge Proof Security Testing Framework},
  author={Ben Soltane, Teycir},
  year={2024},
  url={https://github.com/<your-username>/ZkPatternFuzz}
}
```
