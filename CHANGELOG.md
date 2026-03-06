# Changelog

All notable changes to ZkPatternFuzz will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Rough monthly development summary for the current unreleased line.

## [0.3.0] - 2026-03-06

### Added
- Published [VALIDATION_EVIDENCE.md](docs/VALIDATION_EVIDENCE.md) with a deterministic exploit replay for `EXT-003`, exact witness values, replay command, and Picus follow-up status
- Published [GROUND_TRUTH_REPORT.md](docs/GROUND_TRUTH_REPORT.md) with measured benchmark recall, precision, false-positive rates, and confidence intervals
- Expanded the root README with:
  - an index
  - concrete use cases
  - ZK-native comparison coverage including Picus, Circomspect, CIVER, and `circom --inspect`

### Changed
- Hardened repo hygiene defaults so root `.env`, `.z3-trace`, and `node_modules/` are now blocked by `zkf_checks repo-hygiene`
- Added regression coverage proving `.env.example` remains allowed while blocked root artifacts fail the hygiene gate
- Refreshed operator-facing docs and test READMEs to match the current runtime and validation workflow
- Routed `merkle_unconstrained` through dedicated Merkle benchmark templates instead of the generic strict probe and added regression coverage for that suite/catalog wiring
- Fixed quantified-array invariant evaluation for `forall` constraints in both semantic and fuzzer-side invariant engines
- Normalized reconciled indexed inputs so flattened executor schemas preserve base-array invariant checks and scalar field semantics

### Notes
- The current published ground-truth benchmark is intentionally shallow (`50` iterations, `10s` timeout) and should be treated as a fast regression snapshot, not a production-depth effectiveness measurement
- `merkle_unconstrained` remains the named missed target in the published benchmark, but the benchmark suite now carries a dedicated path-binarity invariant for rerun validation
- A focused production-depth rerun (`5000` iterations, `300s` timeout) on the current tree still missed `merkle_unconstrained`, shifting the next diagnosis step toward underconstrained candidate generation and schema reconciliation rather than template selection alone

### 2026-03

#### Changed
- Restructured operator documentation:
  - moved maintained operational docs under `docs/`
  - refreshed the root `README.md` with onboarding, index, use cases, validation references, and tool comparison
  - refreshed test fixture README files for current repo layout and commands
- Standardized CVE regression assets:
  - bundled portable CVE fixtures in-repo
  - standardized regression expectations
  - added Noir-oriented regression coverage
- Hardened repository quality gates and test structure:
  - moved inline production-file tests into dedicated integration tests
  - generalized the `mode123` non-regression flow
  - tightened repo hygiene checks for root-only artifact leaks
- Improved backend and release ergonomics:
  - better Halo2 public-input derivation and command fallback handling
  - CI now installs JavaScript dependencies explicitly
  - project relicensed to MIT

### 2026-02

#### Added
- Evidence-oriented external-target workflow:
  - archived replay bundles and proof-status tracking under `artifacts/external_targets/`
  - deterministic replay artifacts for real targets
  - Picus and solver-backed proof follow-up integrated into triage workflows
- Batch and benchmark operating model:
  - benchmark suites with published summary artifacts
  - standardized smoke/standard/deep run wrappers
  - release-candidate gate and readiness dashboards
- Validation and measurement tooling:
  - recall uplift, miss-reason coverage, backend effectiveness, and semantic-exit reports
  - ground-truth and safe-suite benchmark summaries under `artifacts/benchmark_runs*`
  - backend/tool inventory reporting under `docs/TOOLS_AVAILABLE_ON_HOST.md`

#### Changed
- Expanded the proof/evidence model across reporting and run outcomes:
  - stricter classification of detection, proof, timeout, and readiness states
  - tighter evidence-bundle expectations and replay documentation
- Grew the CVE and external-target catalogs:
  - broader pattern library coverage
  - more real-target intake and archived batch summaries
- Expanded architecture, roadmap, troubleshooting, and backend setup documentation to match the operational workflow now used in the repo

## [0.1.0] - 2024-02-04

### Added

#### Core Features
- Coverage-guided fuzzing engine with parallel execution
- Support for 4 production ZK backends: Circom, Noir, Halo2, Cairo
- Power scheduling algorithms (FAST, COE, EXPLORE, MMOPT, RARE, SEEK)
- Structure-aware mutation for ZK-specific data types
- Corpus management with automatic minimization
- Progress tracking with interactive and simple modes

#### Attack Implementations
- Underconstrained circuit detection
- Soundness testing (proof forgery attempts)
- Arithmetic overflow detection
- Witness validation
- Verification edge case testing
- Collision detection (partial)
- Boundary value testing (partial)

#### Analysis Features
- Symbolic execution integration with Z3 SMT solver
- Taint analysis for information flow tracking
- Complexity analysis with optimization suggestions
- Performance profiling
- Coverage tracking with bitmap-based implementation

#### Backend Integrations
- **Circom**: Full R1CS support via snarkjs
  - Circuit compilation
  - Witness generation via WASM
  - Groth16 proving/verification
  - Signal extraction and analysis
- **Noir**: Full ACIR support via Barretenberg
  - Nargo compilation
  - ABI parsing
  - Proof generation/verification
  - Function signature extraction
- **Halo2**: PLONK support
  - Rust project compilation
  - JSON circuit specification
  - Execution for testing
  - Circuit analysis utilities
- **Cairo**: STARK support for Cairo 0 and Cairo 1
  - Scarb and cairo-compile support
  - Stone-prover integration
  - Execution trace generation
  - Hint detection
- **Fixture**: Testing utility (unit tests only)
  - Configurable constraints
  - Deterministic execution
  - Underconstrained simulation

#### Differential Testing
- Multi-backend execution comparison
- Tolerance-based result matching
- Discrepancy detection and reporting

#### Multi-Circuit Analysis
- Circuit composition testing
- Recursive proof analysis
- Cross-circuit dependency tracking

#### Reporting
- JSON format with detailed findings
- Markdown format with human-readable summaries
- Severity classification (Critical, High, Medium, Low, Info)
- Proof-of-concept test case generation
- Coverage statistics
- Execution metrics

#### CLI Features
- Campaign configuration via YAML
- Multiple subcommands: run, validate, minimize, init
- Worker count configuration
- Deterministic fuzzing with seeds
- Dry-run mode for config validation
- Verbose and quiet modes
- Simple progress mode for CI/CD

#### Configuration
- YAML-based campaign definitions
- Flexible input specification with fuzz strategies
- Attack configuration with custom parameters
- Reporting options
- Framework-specific parameters

### Implementation Details

#### Fuzzing Strategies
- Random field element generation
- Interesting values (0, 1, p-1, p)
- Mutation-based generation
- Exhaustive enumeration for small domains
- Symbolic execution-guided generation

#### Bug Oracles
- Underconstrained oracle (DOF analysis)
- Arithmetic overflow oracle
- Collision oracle
- Taint leak oracle
- Custom oracle support

#### Corpus Features
- Bounded size with smart eviction
- Coverage-based prioritization
- Test case minimization
- Persistent storage
- Deduplication

#### Performance Optimizations
- Parallel worker execution with Rayon
- Lock-free atomic operations where possible
- Efficient bitmap-based coverage tracking
- Exponential moving average for execution time
- Power scheduling for test case prioritization

### Documentation
- Comprehensive README with examples
- API documentation with rustdoc
- Campaign configuration examples
- Integration test suite
- Realistic testing scenarios

### Testing
- Unit tests for core components
- Integration tests for fuzzing engine
- Backend integration tests (marked as ignored)
- Realistic vulnerability detection tests
- Deterministic fuzzing tests

### Dependencies
- Rust 1.70+ (2021 edition)
- Z3 SMT solver for symbolic execution
- Backend-specific tools (circom, nargo, scarb, etc.)

### Known Limitations
- SARIF report format not yet implemented
- Collision attack partially implemented
- Boundary attack partially implemented
- Real backend integration tests require manual setup
- CI/CD integration templates not provided

### Breaking Changes
None (initial release)

### Security
- No known security vulnerabilities
- Fuzzer itself is not security-critical (testing tool)

## Release Notes

### v0.1.0 - Initial Release

This is the first public release of ZkPatternFuzz, a comprehensive security testing framework for zero-knowledge circuits. The framework provides:

- **Multi-Backend Support**: Test circuits across Circom, Noir, Halo2, and Cairo
- **Advanced Fuzzing**: Coverage-guided with power scheduling and structure-aware mutations
- **Symbolic Execution**: Z3-based constraint solving for targeted test generation
- **Comprehensive Analysis**: Taint tracking, complexity analysis, and performance profiling
- **Production Ready**: Parallel execution, deterministic fuzzing, and detailed reporting

The framework has been tested with various circuits and is ready for real-world ZK circuit auditing. Backend integrations are fully implemented but require the respective toolchains to be installed.

### Installation

```bash
git clone https://github.com/teycir/zkpatternfuzz.git
cd ZkPatternFuzz
cargo build --release
```

### Quick Start

```bash
# Run a fuzzing campaign
cargo run --release -- --config campaigns/example_audit.yaml

# Validate configuration
cargo run --release -- validate campaigns/example_audit.yaml

# Generate sample config
cargo run --release -- init --output my_campaign.yaml --framework circom
```

### Upgrade Notes
Not applicable (initial release)

### Contributors
- Initial implementation and design

---

## Version History

- **0.1.0** (2024-02-04): Initial release with full feature set
- **Unreleased**: Documentation improvements

[Unreleased]: https://github.com/teycir/zkpatternfuzz/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/teycir/zkpatternfuzz/releases/tag/v0.1.0
