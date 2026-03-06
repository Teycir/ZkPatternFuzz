# Backend Setup Guide

This document reflects the current repository workflow: ZkPatternFuzz assumes the backend tools already exist on the host, then verifies and internalizes the parts it needs. It no longer relies on repo-local installer scripts such as `install_cairo.sh` or `install_halo2.sh`.

## Verified On This Host (2026-03-05)

| Tool | Verified version |
|---|---|
| `circom` | `2.2.3` |
| `snarkjs` | `0.7.6` |
| `nargo` | `1.0.0-beta.18` |
| `scarb` | `2.15.1` |
| `cairo-compile` | `0.14.0.1` |
| `cairo-run` | `0.14.0.1` |
| `z3` | `4.13.0` |

For the full host inventory, see [TOOLS_AVAILABLE_ON_HOST.md](TOOLS_AVAILABLE_ON_HOST.md).

`cairo-lang 0.14.0.1` should be installed with Python 3.10. Its `cairo-run` entrypoint fails on Python 3.11+ because of an upstream dataclass default incompatibility.

## 1. Build The Project

```bash
cargo build --release --bins
```

## 2. Internalize Local Circom Assets

ZkPatternFuzz can stage the locally installed Circom tooling into `./bins`:

```bash
target/release/zk-fuzzer bins bootstrap
```

This command:

- copies or links `circom` from `PATH`,
- copies or links `snarkjs` from `PATH`,
- stages `pot12_final.ptau` from the repository test fixture.

Use `--dry-run` to validate without changing `bins/`:

```bash
target/release/zk-fuzzer bins bootstrap --dry-run
```

## 3. Verify Core Backend Tools

```bash
circom --version
snarkjs --version
nargo --version
scarb --version
cairo-compile --version
cairo-run --version
z3 --version
```

## 4. Run Backend Integration Tests

Noir:

```bash
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_integration -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_local_prove_verify_smoke -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_constraint_coverage -- --exact
```

Cairo:

```bash
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_cairo_integration -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_cairo_stone_prover_prove_verify_smoke -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_cairo1_scarb_prove_verify_smoke -- --exact
```

Halo2:

```bash
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_json_integration -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_real_circuit_constraint_coverage -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_scaffold_execution_stability -- --exact
```

## 5. Use The Readiness Wrappers

The current operational entrypoints for backend readiness are:

```bash
scripts/run_noir_readiness.sh --help
scripts/run_cairo_readiness.sh --help
scripts/run_halo2_readiness.sh --help
scripts/backend_readiness_dashboard.sh --help
```

These wrappers execute integration tests plus the appropriate matrix runs and write artifacts under `artifacts/backend_readiness/`.

## 6. What This Repo Does Not Do

This repo does not currently ship working one-shot installer scripts for:

- Cairo
- Halo2
- external prover toolchains

If a backend binary is missing, install it from its upstream project, then come back and verify it with the commands above.
