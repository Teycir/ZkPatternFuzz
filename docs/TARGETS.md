# Target Execution Model

This document describes how to run reusable attack-pattern YAML against concrete targets.

## Key Separation

- Pattern YAML: attack logic only (reusable)
- Runtime target: passed at execution (`--target-circuit`, `--main-component`, `--framework`)
- Catalog: pattern grouping via `targets/fuzzer_registry.yaml`

## Catalog-Driven Batch Runs

List collections, aliases, and templates:

```bash
cargo run --release --bin zk0d_batch -- --list-catalog
```

Run always-on patterns:

```bash
cargo run --release --bin zk0d_batch -- \
  --alias always \
  --target-circuit /media/elements/Repos/zk0d/path/to/target.circom \
  --main-component Main \
  --framework circom
```

Run additional patterns:

```bash
cargo run --release --bin zk0d_batch -- \
  --alias deep \
  --target-circuit /media/elements/Repos/zk0d/path/to/target.circom \
  --main-component Main \
  --framework circom
```

## Naming Rule

Template filenames must follow:

- `<attacktype>_<attack>.yaml`

The runner always executes in parallel and supports regex-focused dispatch.
