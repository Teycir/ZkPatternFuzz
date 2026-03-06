<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=50&pause=1000&color=F74C00&center=true&vCenter=true&width=800&height=120&lines=ZkPatternFuzz;Zero-Knowledge+Security;Fuzzing+Framework" alt="ZkPatternFuzz animated title" />

  <p><b>Rust-based security testing for zero-knowledge systems.</b></p>

  <p>
    <a href="https://github.com/Teycir/ZkPatternFuzz/actions/workflows/ci.yml"><img src="https://github.com/Teycir/ZkPatternFuzz/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License" /></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-2021-orange.svg?logo=rust" alt="Rust 2021" /></a>
  </p>
</div>

ZkPatternFuzz is a Rust-based security testing framework for zero-knowledge systems. It combines single-target fuzzing, batch pattern execution, backend readiness checks, and evidence-oriented reporting for Circom, Cairo, Noir, and Halo2 targets.

## Index

- [Overview](#overview)
- [Use Cases](#use-cases)
- [Comparison With Related Tools](#comparison-with-related-tools)
- [Mode 2 Evidence Campaigns](#mode-2-evidence-campaigns)
- [Semantic Analysis Lane](#semantic-analysis-lane)
- [Requirements](#requirements)
- [Build And Validation](#build-and-validation)
- [Runtime Environment](#runtime-environment)
- [Quick Start](#quick-start)
- [Standardized Routine Runs](#standardized-routine-runs)
- [Circuit Generation](#circuit-generation)
- [Plugin API](#plugin-api)
- [Direct Batch Runs](#direct-batch-runs)
- [Local Circom Bootstrap](#local-circom-bootstrap)
- [Benchmarks And Repo Checks](#benchmarks-and-repo-checks)
- [Repository Layout](#repository-layout)
- [Documentation](#documentation)
- [License](#license)

## Overview

- `zk-fuzzer`: single-target scanning, legacy campaign execution, preflight checks, and tool bootstrap helpers.
- `zkpatternfuzz`: batch execution across a target registry and pattern catalog.
- `zk0d_benchmark`: repeated benchmark-suite runner.
- `zkf_checks`: repository hygiene and policy checks.
- `zk-circuit-gen`: adversarial circuit generation, compiler differential testing, and semantic-intent matching for hostile target creation.

The project is built for proof-oriented security work. A finding is only useful if it ends in one of two states:

- deterministic exploit replay with reproducible artifacts, or
- bounded non-exploitability evidence with clear assumptions.

The main moat is not just "fuzzing." It is the accumulation of operator-reviewed security knowledge as reusable assets: YAML attack patterns, bundled CVE fixtures, benchmark suites, and replay-oriented evidence bundles. That lets one audit's edge cases become the next audit's default checks.

Operator docs live under [docs/INDEX.md](docs/INDEX.md). Validation artifacts and replay bundles are stored under `artifacts/`.

## Use Cases

- Audit a single Circom, Cairo, Noir, or Halo2 target with one reproducible scan command.
- Run standardized `smoke`, `standard`, and `deep` campaigns against a fixed target registry without rebuilding long CLI invocations.
- Regress known CVE-style patterns against portable in-repo fixtures before touching heavier external targets.
- Generate replayable findings and proof-status artifacts instead of stopping at hint-only detections.
- Preflight backend readiness, key setup, and local tooling before spending time on long fuzzing campaigns.
- Track batch outcomes across aliases, catalogs, and timestamped artifact bundles during repeated security work.
- Generate adversarial circuits and compiler-regression corpora instead of relying only on hand-written benchmark targets.

## Comparison With Related Tools

These tools are complementary rather than interchangeable. For ZK work, the important distinction is whether a tool is doing runtime discovery, static analysis, or formal safety verification.

### ZK-Native Tools

| Tool | Primary scope | Analysis style | Main strength | Best fit |
| --- | --- | --- | --- | --- |
| `ZkPatternFuzz` | Circom, Cairo, Noir, Halo2, and batch ZK target registries | Pattern-guided fuzzing plus replay/evidence orchestration | Cross-backend discovery with reproducible scan, batch, and replay workflows | ZK audits, regression lanes, and operator-driven triage |
| [`Picus`](https://docs.veridise.com/picus/) | Circom / R1CS safety analysis | Formal verification | Proves or refutes weak/strong safety and can produce concrete counterexamples for underconstraint bugs | Confirming or disproving safety properties after discovery |
| [`Circomspect`](https://github.com/trailofbits/circomspect) | Circom source code | Static analysis and linting | Fast source-level checks for common Circom mistakes and vulnerability patterns | Early CI linting and developer feedback before heavy runs |
| [`CIVER`](https://github.com/costa-group/circom_civer) | Circom circuits and safety specifications | SMT-backed formal verification | Checks weak safety, tags, and pre/postconditions with modular analysis | Determinism and specification checking in Circom-heavy codebases |
| [`circom --inspect`](https://docs.circom.io/circom-language/code-quality/inspect/) | Circom compilation flow | Built-in compiler inspection | Cheap first-pass warnings for potentially underconstrained or unused signals | Baseline hygiene checks during everyday circuit development |

### Adjacent Smart Contract And Audit Tools

| Tool | Primary scope | Analysis style | Main strength | Best fit |
| --- | --- | --- | --- | --- |
| `Echidna` | Solidity / EVM contracts | Property-based fuzzing | Invariant-driven contract fuzzing with shrinking | Solidity invariant testing |
| `Medusa` | Solidity / EVM contracts | Coverage-guided mutational fuzzing | Parallel worker-based contract fuzzing | Larger EVM fuzz workloads |
| `Halmos` | Solidity / Foundry EVM tests | Symbolic testing | Solver-backed exploration of EVM properties | Targeted proof-style checks for Solidity tests |
| `Foundry / Forge` | Solidity development and testing | Unit, fuzz, and invariant testing | Tight developer loop inside Solidity repos | App-dev feedback loops and contract test suites |
| `Slither` | Solidity and Vyper review | Static analysis | Fast detector-based audit triage and code comprehension | Static review and CI policy gates |

## Mode 2 Evidence Campaigns

`campaigns/mode2/patterns/` is the deep single-target evidence lane. These patterns are heavier than the lightweight benchmark templates and are meant to surface high-signal single-circuit bugs before you move to Mode 3 chain fuzzing.

Current Mode 2 bundles include:

- `underconstrained_witness_deep.yaml`: deep witness-pair search plus semantic cross-checks
- `soundness_forge_deep.yaml`: deeper proof-forgery and verification-soundness pressure

Use Mode 2 when you want stronger single-circuit evidence and broader attack coverage than the standard benchmark templates, but you do not yet need multi-step protocol chains. For chain-focused work, step up to Mode 3 and the workflow in [docs/CHAIN_FUZZING_GUIDE.md](docs/CHAIN_FUZZING_GUIDE.md).

## Semantic Analysis Lane

The semantic lane is wired into the repository as a checked-in campaign flow rather than a crate example only:

- wrapper: `scripts/run_semantic_exit_sample.sh`
- checked-in execution evidence: `campaigns/semantic/semantic_exit_sample.execution_evidence.json`
- runner: `cargo run -p zk-track-semantic --example semantic_exit_campaign -- ...`
- aggregate report: `artifacts/semantic_exit/latest_report.json`

Use this path when the security question is about intended behavior versus accepted behavior, not just constraint-level attack findings. That is the lane for "the circuit compiles, witnesses satisfy constraints, but the accepted behavior still violates the documented security model."

The operator workflow and manual-label precision loop are documented in [docs/SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md](docs/SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md) and [campaigns/semantic/README.md](campaigns/semantic/README.md).

## Requirements

- Rust toolchain with Cargo
- Node.js and `npm` for Circom-related fixtures and local JavaScript dependencies
- Z3 for symbolic execution and solver-backed checks
- backend tools as needed for the targets you run: `circom`, `snarkjs`, `nargo`, `scarb`, and/or Halo2 Rust toolchains

Use [docs/TOOLS_AVAILABLE_ON_HOST.md](docs/TOOLS_AVAILABLE_ON_HOST.md) for the verified tool inventory in this workspace.

## Build And Validation

```bash
git clone https://github.com/Teycir/ZkPatternFuzz.git
cd ZkPatternFuzz
cp .env.example .env
npm ci
cargo build --release --bins
cargo test
```

`npm ci` installs the small dependency surface used by local Circom fixtures and benchmark lanes. `node_modules/` is intentionally ignored and should not be committed.

Generate local API docs when needed:

```bash
cargo doc --workspace --no-deps
```

## Runtime Environment

The tracked `.env.example` is the supported baseline for both wrapper scripts and direct batch runs:

```bash
cp .env.example .env
set -a
source .env
set +a
```

That loads the writable output roots, build cache paths, and the required `zkpatternfuzz` batch timeout settings. Override values in `.env` only when you need a different local output root or a different standardized target binding.

## Quick Start

Generate a pattern template:

```bash
target/release/zk-fuzzer init --output /tmp/zkf_sample.yaml --framework circom
```

Validate a real scan in dry-run mode against the local Cairo readiness target:

```bash
target/release/zk-fuzzer scan \
  tests/patterns/scan_smoke_mono.yaml \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --main-component main \
  --framework cairo \
  --workers 2 \
  --iterations 50 \
  --timeout 30 \
  --dry-run
```

Run a backend preflight for a legacy campaign:

```bash
target/release/zk-fuzzer preflight campaigns/examples/defi_audit.yaml --setup-keys
```

List the bundled CVE patterns:

```bash
target/release/zk-fuzzer --list-patterns
```

## Standardized Routine Runs

For daily `smoke`, `standard`, and `deep` runs, use the fixed wrappers instead of rebuilding long CLI invocations:

```bash
scripts/run_std_smoke.sh
scripts/run_std_standard.sh
scripts/run_std_deep.sh
scripts/monitor_std_run.sh
```

The target bindings for those wrappers are the three `.env` keys below:

- `ZKF_STD_TARGET_SMOKE`
- `ZKF_STD_TARGET_STANDARD`
- `ZKF_STD_TARGET_DEEP`

The operational contract for these profiles is documented in [docs/STANDARDIZED_RUN_PROFILES.md](docs/STANDARDIZED_RUN_PROFILES.md).

## Circuit Generation

`zk-circuit-gen` is the circuit-generation and compiler-testing lab that sits alongside the fuzzer. It generates hostile circuits, mutation-based corpora, semantic-intent checks, compiler crash probes, and differential compiler/version matrices across Circom, Noir, Halo2, and Cairo.

Useful entrypoints:

```bash
cargo run -q -p zk-circuit-gen --example generate_bulk_corpus -- --help
cargo run -q -p zk-circuit-gen --example generate_adversarial_corpus -- --help
cargo run -q -p zk-circuit-gen --example run_differential_version_matrix -- --help
cargo run -q -p zk-circuit-gen --example run_compiler_crash_detector -- --help
```

Use [docs/CIRCUIT_GEN.md](docs/CIRCUIT_GEN.md) for the operator-facing overview and artifact layout.

## Plugin API

External attack plugins are supported through the `attack-plugins` feature and the example crate `crates/zk-attacks-plugin-example`. The short contract is:

- build the host with `--features attack-plugins`
- ship plugins as `cdylib`
- export `zk_attacks_plugins`
- implement `AttackPlugin` metadata plus an `Attack` implementation

Use [docs/PLUGIN_API.md](docs/PLUGIN_API.md) for the minimal contract and [docs/PLUGIN_SYSTEM_GUIDE.md](docs/PLUGIN_SYSTEM_GUIDE.md) for discovery, strict-mode behavior, and safety notes.

## Direct Batch Runs

After sourcing `.env`, you can inspect the catalog:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias always \
  --jobs 1 \
  --workers 2 \
  --list-catalog
```

Run a dry-run batch against the local Cairo readiness target:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias readiness_cairo \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --main-component main \
  --framework cairo \
  --jobs 1 \
  --workers 2 \
  --iterations 50 \
  --timeout 30 \
  --dry-run \
  --emit-reason-tsv
```

Batch runs write timestamped bundles under `ZKF_SCAN_OUTPUT_ROOT/ResultJsonTimestamped/` and per-template artifacts under `.scan_run_artifacts/`.

## Local Circom Bootstrap

To internalize local Circom assets under `./bins`:

```bash
target/release/zk-fuzzer bins bootstrap
```

This stages:

- `circom` from `PATH`
- `snarkjs` from `PATH`
- `pot12_final.ptau` from the local test fixture

## Benchmarks And Repo Checks

Benchmark runner:

```bash
target/release/zk0d_benchmark --help
scripts/run_benchmarks.sh --help
```

Release gate:

```bash
scripts/release_candidate_gate.sh --help
```

Repo policy checks:

```bash
target/release/zkf_checks --help
```

For a local coverage artifact:

```bash
cargo llvm-cov --all-features --lcov --output-path lcov.info
```

## Repository Layout

```text
ZkPatternFuzz/
├── src/                       # Primary Rust crate and CLI entrypoints
├── crates/                    # Workspace crates (core, backends, attacks, symbolic, tracks)
├── campaigns/                 # YAML patterns and campaign configs
├── scripts/                   # Operational wrappers and release/readiness utilities
├── targets/                   # Registries, matrices, benchmark suites
├── tests/                     # Integration tests and portable local fixtures
├── artifacts/                 # Generated reports, validation evidence, and run outputs
├── docs/                      # Operator docs and technical reference
└── bins/                      # Internalized local tooling assets
```

## Documentation

Start with:

- [docs/INDEX.md](docs/INDEX.md)
- [docs/TUTORIAL.md](docs/TUTORIAL.md)
- [docs/TARGETS.md](docs/TARGETS.md)
- [docs/TROUBLESHOOTING_PLAYBOOK.md](docs/TROUBLESHOOTING_PLAYBOOK.md)
- [docs/BACKEND_SETUP.md](docs/BACKEND_SETUP.md)

Operational references:

- [docs/STANDARDIZED_RUN_PROFILES.md](docs/STANDARDIZED_RUN_PROFILES.md)
- [docs/TOOLS_AVAILABLE_ON_HOST.md](docs/TOOLS_AVAILABLE_ON_HOST.md)
- [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)

Validation references:

- [docs/VALIDATION_EVIDENCE.md](docs/VALIDATION_EVIDENCE.md)
- [docs/GROUND_TRUTH_REPORT.md](docs/GROUND_TRUTH_REPORT.md)
- [CVErefs/README.md](CVErefs/README.md)
- [campaigns/semantic/README.md](campaigns/semantic/README.md)

Historical context:

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [ROADMAP.md](ROADMAP.md)
- [docs/CIRCUIT_GEN.md](docs/CIRCUIT_GEN.md)
- [docs/PLUGIN_API.md](docs/PLUGIN_API.md)

## Attribution

Project home: [teycirbensoltane.tn](https://teycirbensoltane.tn)
Contact: `teycir@pxdmail.net`

## License

MIT. See [LICENSE](LICENSE).

## Citation

```bibtex
@software{zkpatternfuzz2024,
  title={ZkPatternFuzz: A Zero-Knowledge Proof Security Testing Framework},
  author={Ben Soltane, Teycir},
  year={2024},
  url={https://github.com/Teycir/ZkPatternFuzz}
}
```
