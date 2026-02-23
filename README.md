# ZkPatternFuzz

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-BSL%201.1-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

A Zero-Knowledge Proof Security Testing Framework written in Rust.

## Overview

ZkPatternFuzz is a security testing framework that **automates accumulated audit expertise**. Each vulnerability discovered during manual audits is encoded as an executable YAML pattern, creating a growing knowledge base that automatically detects known vulnerability classes in future audits.

**The Core Concept:**
- Human auditors discover vulnerabilities through manual review
- Vulnerabilities are encoded as YAML detection patterns
- Future audits automatically test for all known patterns
- Knowledge compounds: more audits → more patterns → better coverage

**Current Status (2026-02-23):**
- ✅ Phase 1-6 Complete: Production-ready core functionality
- ✅ Phase 8 Active: Backend maturity program (Circom/Noir/Cairo/Halo2 → 5/5)
- ✅ 80% vulnerable recall, 0% safe FPR on benchmark suite
- ✅ All backends at 5.0/5.0 maturity (streak tracking: 2/14 days for Circom, 1/14 for others)
- ✅ Release candidate validation: consecutive passes with rollback evidence

**Supported Backends:**
- **Circom** - R1CS-based circuits (production-ready, 5.0/5.0 maturity)
- **Noir** - ACIR-based circuits (production-ready, 5.0/5.0 maturity, prove/verify validated)
- **Halo2** - PLONK-based circuits (production-ready, 5.0/5.0 maturity, real execution mode)
- **Cairo** - STARK-based programs (production-ready, 5.0/5.0 maturity, Stone prover integration)

## Installation

### Prerequisites

- Rust 1.70+
- Z3 SMT solver (optional, for symbolic execution)

Z3 setup by OS:
- Linux (dynamic): install `z3` + `libz3-dev` (package names vary by distro).
- macOS (dynamic): `brew install z3`.
- Windows: solver crates default to static-link Z3 to avoid missing `z3.h`/system-lib issues.
  For static builds, install CMake + a C/C++ toolchain (MSVC Build Tools).

### Build

```bash
git clone https://github.com/<your-username>/ZkPatternFuzz.git
cd ZkPatternFuzz
cargo build --release
cargo test
```

For portable static Z3 linking (CI/release-style builds), add `--features z3-static`.

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
cargo run --release -- --config campaigns/example_audit.yaml

# Run with AI assistance (Mistral model)
cargo run --release -- --config templates/ai_assisted_audit.yaml

# With verbose output
cargo run --release -- --config campaigns/example_audit.yaml --verbose

# Custom worker count
cargo run --release -- --config campaigns/example_audit.yaml --workers 8

# Run benchmark suite
cargo run --release --bin zk0d_benchmark -- \
  --config-profile dev \
  --suite safe_regression,vulnerable_ground_truth \
  --trials 2 --workers 4
```

## AI-Assisted Pentesting

ZkPatternFuzz integrates Mistral AI for intelligent security analysis:

**AI Features:**
- **Invariant Generation**: Automatically generate candidate invariants from circuit patterns
- **Result Analysis**: Intelligent analysis of fuzzing results with actionable recommendations
- **Config Suggestions**: AI-generated YAML configuration tailored to your circuit
- **Vulnerability Explanation**: Natural language explanations of found vulnerabilities

**AI Models Supported:**
- Mistral (default) - Optimized for ZK circuit analysis
- Claude - Advanced reasoning capabilities
- GPT-4 - General-purpose AI assistance

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

## How It Works: From Discovery to Automation

### 1. Manual Discovery (Human Expertise)
```
Auditor manually reviews circuit → Finds novel vulnerability → Documents exploit
```

### 2. Pattern Encoding (Knowledge Capture)
```yaml
# patterns/underconstrained_merkle_path.yaml
pattern:
  id: "zero_merkle_path_bypass"
  discovered: "2024-01-15"
  severity: "critical"
  
  detection:
    attack_type: "underconstrained"
    test_cases:
      - name: "all_zero_path"
        inputs:
          pathElements: [0, 0, 0, 0, 0]
          pathIndices: [0, 0, 0, 0, 0]
        expected: "should_fail_but_might_pass"
    
    required_constraint:
      description: "Path elements must be validated"
      check: "pathElements[i] != 0 OR explicit_validation"
```

### 3. Automated Detection (Compound Advantage)
```bash
# Next audit automatically tests this pattern
cargo run -- scan new_client.yaml --patterns ./patterns/

# Output: [CRITICAL] Pattern match: zero_merkle_path_bypass
#         Detected in 0.3 seconds (manual review: 2+ hours)
```

### 4. Knowledge Growth
```
Year 1: 10 patterns  → 10 vulnerability classes detected automatically
Year 2: 30 patterns  → 30 vulnerability classes detected automatically
Year 3: 60 patterns  → 60 vulnerability classes detected automatically
```

**Pattern Sources:**
- Manual audit discoveries (primary source)
- Public CVEs (zkBugs, GitHub advisories)
- Client-reported vulnerabilities
- Research papers (0xPARC, Trail of Bits)

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

### Pattern-Based Detection

**Executable Knowledge Base:**
- YAML-encoded vulnerability patterns from real audits
- Automatic application of accumulated expertise
- Version-controlled pattern library
- Extensible: add new patterns without code changes

**Pattern Library Structure:**
```
patterns/
├── production/              # Battle-tested patterns
│   ├── underconstrained/
│   ├── soundness/
│   ├── collision/
│   └── defi_specific/
├── experimental/            # New patterns under validation
└── cve_signatures/          # Public CVE detection patterns
```

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

22 real-world vulnerabilities from zkBugs dataset, encoded as detection patterns:

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

**These CVEs serve as:**
1. Validation that patterns detect real vulnerabilities
2. Baseline pattern library for new audits
3. Regression tests for pattern accuracy

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
│   ├── bin/                 # Binary executables (zk-fuzzer, zk0d_benchmark, etc.)
│   ├── attacks/             # Attack implementations
│   ├── executor/            # Circuit execution abstraction
│   ├── fuzzer/              # Fuzzing engine
│   ├── analysis/            # Symbolic execution, taint analysis
│   ├── reporting/           # Report generation, evidence collection
│   └── targets/             # Backend integrations
├── crates/                  # Workspace crates
│   ├── zk-core/             # Core types and traits
│   ├── zk-attacks/          # Attack trait and implementations
│   ├── zk-fuzzer-core/      # Fuzzing engine core
│   ├── zk-symbolic/         # Symbolic execution (Z3)
│   ├── zk-backends/         # Backend integrations
│   └── zk-constraints/      # Constraint analysis
├── tests/                   # Test suite
│   ├── campaigns/           # Test campaign configs
│   ├── circuits/            # Test circuits
│   ├── ground_truth/        # Known vulnerable circuits
│   ├── safe_circuits/       # Known safe circuits
│   └── noir_projects/       # Noir test projects
├── targets/                 # Benchmark registries
│   ├── zkbugs/              # zkBugs dataset (110 vulnerabilities)
│   ├── benchmark_suites.yaml # Benchmark suite definitions
│   └── zk0d_catalog.yaml    # Target catalog
├── artifacts/               # Generated validation reports
│   ├── benchmark_runs_fast/ # Benchmark results
│   ├── fresh_clone_validation/ # Bootstrap validation
│   ├── keygen_preflight/    # Keygen readiness reports
│   └── release_candidate_validation/ # Release gate results
├── scripts/                 # Automation scripts
│   ├── fresh_clone_bootstrap_validate.sh
│   ├── keygen_preflight_validate.sh
│   ├── phase3a_validate.sh
│   ├── release_candidate_validate_twice.sh
│   └── rollback_validate.sh
├── campaigns/               # Campaign configs
├── circuits/                # Real-world test circuits
├── CVErefs/                 # CVE test suite (22 vulnerabilities)
├── templates/               # YAML templates
└── docs/                    # Documentation
```

## Documentation

### Core Documentation
- **[INDEX.md](docs/INDEX.md)** - Complete documentation index and navigation guide
- **[TUTORIAL.md](docs/TUTORIAL.md)** - Step-by-step guide with hands-on examples
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Internal design, components, and extension points
- **[ROADMAP.md](ROADMAP.md)** - Development roadmap with Phase 8 maturity tracking

### Operational Guides
- **[RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)** - Production release gate checklist
- **[TROUBLESHOOTING_PLAYBOOK.md](docs/TROUBLESHOOTING_PLAYBOOK.md)** - Keygen/includes/locks/timeouts playbook
- **[TARGETS.md](docs/TARGETS.md)** - Target catalog and workflow commands
- **[TRIAGE_SYSTEM.md](docs/TRIAGE_SYSTEM.md)** - Automated triage system

### Attack & Pattern Guides
- **[PATTERN_LIBRARY.md](docs/PATTERN_LIBRARY.md)** - Pattern-based vulnerability detection
- **[DEFI_ATTACK_GUIDE.md](docs/DEFI_ATTACK_GUIDE.md)** - MEV/front-running detection
- **[ATTACK_DSL_SPEC.md](docs/ATTACK_DSL_SPEC.md)** - Attack configuration DSL reference

### Backend-Specific Guides
- **[NOIR_BACKEND_TROUBLESHOOTING.md](docs/NOIR_BACKEND_TROUBLESHOOTING.md)** - Noir diagnostics and troubleshooting
- **[CAIRO_INTEGRATION_TUTORIAL.md](docs/CAIRO_INTEGRATION_TUTORIAL.md)** - Cairo target integration
- **[HALO2_REAL_EXECUTION_MIGRATION.md](docs/HALO2_REAL_EXECUTION_MIGRATION.md)** - Halo2 migration guide
- **[BACKEND_SETUP.md](docs/BACKEND_SETUP.md)** - Backend installation and configuration

### Advanced Topics
- **[SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md](docs/SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md)** - Semantic analysis workflows
- **[INVARIANT_SPEC_SCHEMA.md](docs/INVARIANT_SPEC_SCHEMA.md)** - Invariant specification format
- **[SECURITY_THREAT_MODEL.md](docs/SECURITY_THREAT_MODEL.md)** - Security assumptions and trust boundaries
- **[PLUGIN_SYSTEM_GUIDE.md](docs/PLUGIN_SYSTEM_GUIDE.md)** - Plugin discovery and safety

## Release Ops

- Use **[docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)** as the source of truth before tagging a release.
- Use **[docs/TARGETS.md](docs/TARGETS.md)** for exact `gh workflow run "Release Validation"` command templates.
- Use **[docs/TROUBLESHOOTING_PLAYBOOK.md](docs/TROUBLESHOOTING_PLAYBOOK.md)** when release gates fail (keygen, includes, lock contention, timeout tuning).

## Development

```bash
# Run tests
cargo test

# Run integration tests
cargo test --test integration_tests

# Run CVE test suite
cargo test --test autonomous_cve_tests -- --nocapture

# Run benchmark validation
scripts/fresh_clone_bootstrap_validate.sh
scripts/keygen_preflight_validate.sh
scripts/release_candidate_validate_twice.sh

# Run with logging
RUST_LOG=debug cargo run -- --config campaigns/example_audit.yaml

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Generate docs
cargo doc --open

# Check repo hygiene
python3 scripts/check_repo_hygiene.py --enforce
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Priority Areas:**
- **Pattern Contributions**: Encode new vulnerability patterns from audits/CVEs
- Cairo real-circuit integration
- Additional attack implementations
- Documentation and examples
- Performance optimizations

**Pattern Contribution Workflow:**
1. Discover vulnerability (manual audit, CVE, research)
2. Create YAML pattern with detection logic
3. Add test cases validating detection
4. Submit for review and integration

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
