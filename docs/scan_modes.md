# Scan Modes

This document defines how scanning works in this repo.

## Global Constraints

- Targets are read-only and must come from `/media/elements/Repos/zk0d` unless explicitly approved.
- No mocks or synthetic targets unless explicitly approved.
- Pattern YAML is strictly attack logic only (no hardcoded target/runtime/output fields).

## Scanner Model (YAML-Only)

`zk-fuzzer scan` is a single scanner entry point driven by pattern YAML.

- No built-in Mode 1 pre-pass.
- Every run is selected by YAML family and target topology.
- Universal/simple checks are represented as always-run YAML templates.
- Deeper/less-common checks are added by collection/alias based on the target.

## Pattern Classes

- Always-run simple patterns:
  - Typically `_mono.yaml`
  - Safe baseline checks to run for most targets
- Deep target-dependent patterns:
  - `_mono.yaml` for deeper single-circuit logic
  - `_multi.yaml` for multi-stage chain logic

## Family Dispatch

`zk-fuzzer scan <pattern.yaml> --family <auto|mono|multi> ...`

- `auto`:
  - non-empty `chains` => multi engine
  - no `chains` => mono engine
- `mono`: enforces mono pattern execution
- `multi`: enforces chain/multi execution

Compatibility rule:
- Multi patterns must not be run on mono targets.

## Catalog Concept (SCPF-Style, Applied to Fuzzer)

Use a registry file (`targets/fuzzer_registry.yaml`) with:
- `registries`
- `collections`
- `aliases`

Run via batch catalog runner (`zk0d_batch`):

```bash
# Inspect catalog
cargo run --release --bin zk0d_batch -- --list-catalog

# Run always-on mono collection against a mono target
cargo run --release --bin zk0d_batch -- \
  --alias always \
  --target-topology mono \
  --target-circuit /path/to/target.circom \
  --main-component Main \
  --framework circom

# Run deep multi collection against a multi target
cargo run --release --bin zk0d_batch -- \
  --collection deep_multi \
  --target-topology multi \
  --target-circuit /path/to/target.circom \
  --main-component Main \
  --framework circom
```

## Output Organization

Output paths and report format are code-managed and unchanged.
