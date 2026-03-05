# ZkPatternFuzz

[![CI](https://github.com/Teycir/ZkPatternFuzz/actions/workflows/ci.yml/badge.svg)](https://github.com/Teycir/ZkPatternFuzz/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg?logo=rust)](https://www.rust-lang.org/)

ZkPatternFuzz is a Rust-based security testing framework for zero-knowledge systems. It combines single-target fuzzing, batch pattern execution, backend readiness checks, and evidence-oriented reporting for Circom, Cairo, Noir, and Halo2 targets.

## What The Repository Ships

- `zk-fuzzer`: single-target scanning, legacy campaign execution, preflight checks, and tool bootstrap helpers.
- `zkpatternfuzz`: batch execution across a target registry and pattern catalog.
- `zk0d_benchmark`: repeated benchmark-suite runner.
- `zkf_checks`: repository hygiene and policy checks.

The project is built for proof-oriented security work. A finding is only useful if it ends in one of two states:

- deterministic exploit replay with reproducible artifacts, or
- bounded non-exploitability evidence with clear assumptions.

Operator docs live under [docs/INDEX.md](docs/INDEX.md). Validation artifacts and replay bundles are stored under `artifacts/`.

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

Historical context:

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [ROADMAP.md](ROADMAP.md)

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
