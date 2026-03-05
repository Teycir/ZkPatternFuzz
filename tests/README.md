# ZK-Fuzzer Test Campaigns

This directory contains fuzzing configs for testing real-world ZK circuits.

## Real-World Test Targets

The campaigns in this directory target circuits from `${ZK0D_BASE:-/media/elements/Repos/zk0d}`, organized by category:

## Portable CVE Fixtures

`tests/cve_fixtures/` contains the tiny in-repo circuits used by
`templates/known_vulnerabilities.yaml` so CVE regression wiring can be exercised
without external mounts or workstation-specific hardware layouts.

### Privacy Protocols (`cat3_privacy/`)
| Campaign | Target | Priority |
|----------|--------|----------|
| `semaphore_audit.yaml` | Semaphore identity protocol | Critical |
| `tornado_core_audit.yaml` | Tornado Cash mixer | Critical |
| `iden3_auth_audit.yaml` | Iden3 authentication | High |

### Rollup Infrastructure (`cat2_rollups/`)
| Campaign | Target | Priority |
|----------|--------|----------|
| `polygon_zkevm_audit.yaml` | Polygon zkEVM circuits | Critical |

## Running Scans

### Quick Start

```bash
# Run a single pattern with auto family selection
cargo run --release -- scan tests/patterns/scan_smoke_mono.yaml \
  --target-circuit tests/ground_truth/chains/mode123_smoke/mode123_main.circom \
  --main-component Mode123Main \
  --framework circom

# Validate scan wiring without executing
cargo run --release -- scan tests/patterns/scan_smoke_mono.yaml \
  --target-circuit tests/ground_truth/chains/mode123_smoke/mode123_main.circom \
  --main-component Mode123Main \
  --framework circom \
  --dry-run

# Run with verbose output and custom seed
cargo run --release -- scan tests/patterns/scan_smoke_mono.yaml \
  --target-circuit tests/ground_truth/chains/mode123_smoke/mode123_main.circom \
  --main-component Mode123Main \
  --framework circom \
  --verbose --seed 42
```

### Running Catalog Selections

```bash
# List collections/aliases/templates
cargo run --release --bin zkpatternfuzz -- --list-catalog

# Run always-on mono templates for a mono target
cargo run --release --bin zkpatternfuzz -- \
  --alias always \
  --target-topology mono \
  --target-circuit tests/ground_truth/chains/mode123_smoke/mode123_main.circom \
  --main-component Mode123Main \
  --framework circom
```

### Scan Mono/Multi Non-Regression Smoke

Use the minimal end-to-end mode smoke test to catch regressions in CLI mode wiring:

```bash
cargo test --test mode123_nonregression -- --nocapture
```

To skip this smoke in constrained environments:

```bash
ZKFUZZ_SKIP_MODE123_SMOKE=1 cargo test --test mode123_nonregression
```

The smoke test also skips automatically when `circom` or `snarkjs` is missing from `PATH`.

Optional smoke overrides:

```bash
ZKFUZZ_SCAN_MONO_PATTERN=tests/patterns/scan_smoke_mono.yaml \
ZKFUZZ_SCAN_MULTI_PATTERN=tests/patterns/scan_smoke_multi.yaml \
ZKFUZZ_SCAN_TARGET_CIRCUIT=tests/ground_truth/chains/mode123_smoke/mode123_main.circom \
ZKFUZZ_SCAN_MAIN_COMPONENT=Mode123Main \
cargo test --test mode123_nonregression -- --nocapture
```

## Pattern Structure

Each pattern YAML follows this structure:

```yaml
attacks:
  - type: underconstrained | soundness | collision | arithmetic_overflow | boundary
    description: "What this attack tests"
    config: { ... }

inputs:
  - name: "input_name"
    type: field | array[N] | bytes
    fuzz_strategy: random | mutation | interesting_values

invariants:
  - name: "invariant_name"
    invariant_type: range | constraint | uniqueness | relation
    relation: "..."
    severity: low | medium | high | critical
```

## Attack Types

| Attack Type | Description | Severity |
|-------------|-------------|----------|
| `underconstrained` | Finds multiple witnesses for same output | Critical |
| `soundness` | Attempts to forge invalid proofs | Critical |
| `collision` | Searches for hash/output collisions | Critical |
| `arithmetic_overflow` | Tests field arithmetic boundaries | High |
| `boundary` | Tests input/parameter boundaries | Medium |

## Adding New Patterns

1. Identify the circuit in `${ZK0D_BASE:-/media/elements/Repos/zk0d}/`
2. Analyze the circuit's inputs and outputs
3. Create a pattern YAML with appropriate attacks/invariants
4. Test with `scan --dry-run`
5. Run and iterate on configuration

## Backend Execution

Backend integrations use real backends only:

1. **Circom**: Requires circom compiler and snarkjs
2. **Noir**: Requires Noir compiler (nargo)  
3. **Halo2**: Requires Rust halo2 crate integration

See `src/executor/mod.rs` for backend status.

## Reports

Reports are generated under `~/ZkFuzz` (or OS equivalent) with:
- `findings.json` - Machine-readable vulnerability data
- `report.md` - Human-readable summary
- `corpus/` - Interesting test cases for further analysis
