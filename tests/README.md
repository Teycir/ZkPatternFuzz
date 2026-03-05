# Test Suite

This directory contains the regression targets, backend fixtures, and integration tests that keep ZkPatternFuzz reproducible on a clean clone. The emphasis is portability first: small in-repo targets should cover default smoke paths, while heavier real-backend validation stays explicit and opt-in.

## Directory Map

- `cve_fixtures/`: tiny portable circuits referenced by `templates/known_vulnerabilities.yaml`.
- `patterns/`: small pattern YAML files used by scan smoke tests and CLI dispatch checks.
- `ground_truth_circuits/`: intentionally vulnerable circuits used to validate detection behavior.
- `safe_circuits/`: fixed or secure reference circuits used to validate false-positive handling.
- `cairo_programs/`, `noir_projects/`, `halo2_real_fixture/`: backend-specific local targets for real execution checks.
- `datasets/`: sampled datasets and fixture corpora used by reporting, extraction, and validation tests.
- `mode123_nonregression.rs`: end-to-end smoke coverage for mono and multi `scan` dispatch.
- `cve_regression_runner.rs`: deterministic execution of the bundled CVE regression fixtures.
- `cve_regression_tests.rs`: schema, matching, oracle, and finding-construction checks for the CVE database.

## High-Signal Commands

Run the full local test suite:

```bash
cargo test
```

Run the unified scan smoke regression:

```bash
cargo test --test mode123_nonregression -- --nocapture
```

Run the bundled CVE fixture replay lane:

```bash
cargo test --test cve_regression_runner -- --nocapture
```

Run the broader CVE metadata and oracle checks:

```bash
cargo test --test cve_regression_tests
```

## Manual Scan Smoke

Build the release binaries first if you want to exercise the same local fixtures outside `cargo test`:

```bash
cp .env.example .env
npm ci
cargo build --release --bins
```

Then run a dry-run single-target scan:

```bash
target/release/zk-fuzzer scan \
  tests/patterns/scan_smoke_mono.yaml \
  --target-circuit tests/ground_truth/chains/mode123_smoke/mode123_main.circom \
  --main-component Mode123Main \
  --framework circom \
  --iterations 50 \
  --timeout 30 \
  --dry-run
```

List the current batch catalog after sourcing `.env`:

```bash
set -a
source .env
set +a
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias always \
  --jobs 1 \
  --workers 2 \
  --list-catalog
```

## Backend Requirements

- `mode123_nonregression` executes real Circom paths and requires both `circom` and `snarkjs` on `PATH`.
- The scan smoke can be skipped in constrained environments with `ZKFUZZ_SKIP_MODE123_SMOKE=1`.
- Cairo, Noir, and Halo2 fixture tests only exercise the relevant lanes when their toolchains are available.

The supported host inventory is tracked in [docs/TOOLS_AVAILABLE_ON_HOST.md](../docs/TOOLS_AVAILABLE_ON_HOST.md).

## Smoke Test Overrides

`tests/mode123_nonregression.rs` exposes the following environment overrides for focused debugging:

- `ZKFUZZ_SCAN_MONO_PATTERN`
- `ZKFUZZ_SCAN_MULTI_PATTERN`
- `ZKFUZZ_SCAN_TARGET_CIRCUIT`
- `ZKFUZZ_SCAN_MAIN_COMPONENT`

Example:

```bash
ZKFUZZ_SCAN_MONO_PATTERN=tests/patterns/scan_smoke_mono.yaml \
ZKFUZZ_SCAN_MULTI_PATTERN=tests/patterns/scan_smoke_multi.yaml \
ZKFUZZ_SCAN_TARGET_CIRCUIT=tests/ground_truth/chains/mode123_smoke/mode123_main.circom \
ZKFUZZ_SCAN_MAIN_COMPONENT=Mode123Main \
cargo test --test mode123_nonregression -- --nocapture
```

## Fixture Rules

- Keep test code in `tests/`; do not mix tests into production source files.
- Prefer repo-relative paths and local fixtures over workstation-specific mounts.
- When a new vulnerability fixture is added, pair it with a regression test or documented replay path.
- Keep portable fixtures minimal. Large benchmark targets belong under dedicated benchmark or external target directories, not in the default regression lane.
