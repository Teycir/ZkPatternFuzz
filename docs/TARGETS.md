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

### Strict 3-Check Gate (Enforced by `zk0d_batch`)

Every batch run enforces:

1. Expected template count before run.
2. Completion check after run (`executed == expected` and `failures == 0`).
3. Artifact reconciliation for this batch window (all expected output suffixes observed under new `scan_run*` artifact roots).

You will see:

```text
Gate 1/3 (expected templates): <N>
Batch complete. Templates executed: <N>, failures: 0
Gate 2/3 (completion line): PASS ...
Gate 3/3 (artifact reconciliation): PASS ...
```

If any gate fails, `zk0d_batch` exits non-zero.

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
