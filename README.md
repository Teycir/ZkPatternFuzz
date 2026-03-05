<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=50&pause=1000&color=F74C00&center=true&vCenter=true&width=800&height=120&lines=ZkPatternFuzz;Zero-Knowledge+Security;Fuzzing+Framework" alt="ZkPatternFuzz Logo" />

  <p><b>A modern Rust security-testing framework for zero-knowledge systems.</b></p>

  [![Version](https://img.shields.io/badge/version-0.1.0-blue.svg?style=for-the-badge)](CHANGELOG.md)
  [![CI](https://github.com/Teycir/ZkPatternFuzz/actions/workflows/ci.yml/badge.svg)](https://github.com/Teycir/ZkPatternFuzz/actions/workflows/ci.yml)
  [![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
  [![Rust](https://img.shields.io/badge/rust-2021-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
</div>

<br/>

## 🎯 Overview

ZkPatternFuzz supports two main workflows:

- `zk-fuzzer`: single-pattern or legacy campaign execution.
- `zkpatternfuzz`: batch execution across a pattern catalog and target matrix.

The repository also ships supporting binaries:

- `zk0d_benchmark`: repeated benchmark-suite runner.
- `zkf_checks`: repo hygiene and policy checks.

This README avoids point-in-time maturity percentages. For dated validation snapshots, use [docs/ROADMAP.md](docs/ROADMAP.md) and the artifacts under `artifacts/`.

Attribution and contact: [teycirbensoltane.tn](https://teycirbensoltane.tn) | `teycir@pxdmail.net`

## Prerequisites

- Rust toolchain with Cargo
- Z3 for symbolic execution and solver-backed checks
- Backend tools as needed for the targets you run: `circom`, `snarkjs`, `nargo`, `scarb`, and/or Halo2 toolchains

Use [docs/TOOLS_AVAILABLE_ON_HOST.md](docs/TOOLS_AVAILABLE_ON_HOST.md) for the verified host inventory in this workspace.

## Build

```bash
git clone https://github.com/Teycir/ZkPatternFuzz.git
cd ZkPatternFuzz
npm ci
cargo build --release --bins
cargo test
```

`npm ci` installs the small JavaScript dependency surface used by local Circom fixtures and benchmark lanes (`circomlib`, `ffjavascript`). `node_modules/` is intentionally ignored and should not be committed.

Generate local Rust API docs when needed:

```bash
cargo doc --workspace --no-deps
```

## Direct-Run Environment

Create a local `.env` from the tracked template first:

```bash
cp .env.example .env
```

The template uses repo-relative writable paths. The wrapper scripts normalize them against the repository root. For direct CLI examples below, either keep the `.env` defaults or export explicit overrides once per shell:

```bash
export ZKF_SCAN_OUTPUT_ROOT="$PWD/artifacts/manual_runs"
export ZKF_RUN_SIGNAL_DIR="$PWD/artifacts/manual_runs/run_signals"
export ZKF_BUILD_CACHE_DIR="$PWD/artifacts/manual_runs/build_cache"
export ZKF_SHARED_BUILD_CACHE_DIR="$PWD/artifacts/manual_runs/build_cache"
mkdir -p "$ZKF_SCAN_OUTPUT_ROOT" "$ZKF_RUN_SIGNAL_DIR" "$ZKF_BUILD_CACHE_DIR"
```

For direct `zkpatternfuzz` runs, export the batch-stage timeout variables too:

```bash
export ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS=1800
export ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS=3600
export ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS=120
```

## Quick Start

Generate a sample pattern-only YAML file:

```bash
target/release/zk-fuzzer init --output /tmp/zkf_sample.yaml --framework circom
```

`init` creates a pattern template, not a fully bound campaign. Edit its selectors and inputs before using it on a real target.

Validate a real scan in dry-run mode with a known matching local target:

```bash
target/release/zk-fuzzer scan \
  campaigns/cve/patterns/cveX34_cairo_multiplier_assert_readiness_probe.yaml \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --main-component main \
  --framework cairo \
  --workers 2 \
  --iterations 50 \
  --timeout 30 \
  --dry-run
```

Remove `--dry-run` to execute the scan.

Run a legacy campaign preflight:

```bash
target/release/zk-fuzzer preflight campaigns/examples/defi_audit.yaml --setup-keys
```

## Standardized Daily Runs

For smoke, standard, and deep routine runs, use the fixed wrappers instead of rebuilding long batch commands:

```bash
scripts/run_std_smoke.sh
scripts/run_std_standard.sh
scripts/run_std_deep.sh
scripts/monitor_std_run.sh
```

The wrapper target bindings live in `.env`:

- `ZKF_STD_TARGET_SMOKE`
- `ZKF_STD_TARGET_STANDARD`
- `ZKF_STD_TARGET_DEEP`

See [docs/STANDARDIZED_RUN_PROFILES.md](docs/STANDARDIZED_RUN_PROFILES.md) for the operating rules.

## Validation

CI status is published through the `CI` workflow badge above. The workflow currently runs formatting, policy gates, `cargo test --all-features`, real backend integration tests, benchmark smoke lanes, and a Codecov upload from `cargo llvm-cov`.

For a local coverage artifact:

```bash
cargo llvm-cov --all-features --lcov --output-path lcov.info
```

## Direct Batch Runs

List the current catalog:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias always \
  --jobs 1 \
  --workers 2 \
  --list-catalog
```

Run a verified dry-run batch against the local Cairo readiness target:

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

`zkpatternfuzz` writes timestamped bundles under `ZKF_SCAN_OUTPUT_ROOT/ResultJsonTimestamped/` and per-template artifacts under `.scan_run_artifacts/`.

## Local Circom Bootstrap

To internalize local Circom assets under `./bins`:

```bash
target/release/zk-fuzzer bins bootstrap
```

This stages:

- `circom` from `PATH`
- `snarkjs` from `PATH`
- `pot12_final.ptau` from the local test fixture

## Benchmarks And Release Utilities

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
cargo run --release --bin zkf_checks -- --help
```

## Repository Layout

```text
ZkPatternFuzz/
├── src/                       # Primary Rust crate and CLI entrypoints
├── crates/                    # Workspace crates (core, backends, attacks, symbolic, tracks)
├── campaigns/                 # YAML patterns and campaign configs
├── scripts/                   # Operational wrappers and release/readiness utilities
├── targets/                   # Registries, matrices, benchmark suites
├── tests/                     # Integration tests and local fixture targets
├── artifacts/                 # Generated reports and validation evidence
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

The architecture and roadmap files are still useful, but they contain dated snapshots. Read them with the stated dates in mind:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)
- [docs/AGENTS.md](docs/AGENTS.md)

## License

MIT. See [LICENSE](LICENSE).

Attribution and contact: [teycirbensoltane.tn](https://teycirbensoltane.tn) | `teycir@pxdmail.net`

## Citation

```bibtex
@software{zkpatternfuzz2024,
  title={ZkPatternFuzz: A Zero-Knowledge Proof Security Testing Framework},
  author={Ben Soltane, Teycir},
  year={2024},
  url={https://github.com/Teycir/ZkPatternFuzz}
}
```
