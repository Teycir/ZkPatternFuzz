# Scan Modes

This document defines how scanning works in the repository today.

## Global Constraints

- Pattern YAML is attack logic only.
- Targets are provided at execution time.
- Universal checks live as always-run templates.
- Deeper checks are selected by collection, alias, or explicit pattern path.

## Scanner Model

`zk-fuzzer scan` is the single-pattern entrypoint:

```bash
target/release/zk-fuzzer scan <pattern.yaml> --target-circuit <target> [options]
```

It auto-dispatches mono versus multi execution based on the pattern family and selector fit.

## Pattern Selectors

Pattern YAML may include selector blocks that are evaluated against the target source before execution:

```yaml
patterns:
  - id: contains_nullifier
    kind: regex
    pattern: "\\bnullifier\\b"
    message: "Target contains nullifier logic"
```

Current behavior:

- only `regex` selectors are supported,
- at least one selector must match unless a stricter `selector_policy` is present,
- selector metadata is used at scan time only.

## Family Dispatch

```bash
target/release/zk-fuzzer scan <pattern.yaml> --family <auto|mono|multi> ...
```

When selectors are present, they are the primary dispatch signal.

## Catalog Runner

`zkpatternfuzz` is the batch catalog runner. Export writable output paths and stage timeouts before direct use; see [TARGETS.md](TARGETS.md) for the full environment snippet.

List the catalog:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias always \
  --jobs 1 \
  --workers 2 \
  --list-catalog
```

Run a selected alias:

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
  --dry-run
```

## Output Organization

- output roots are env-managed,
- `zkpatternfuzz` no longer accepts `--output-root` or `--report-json`,
- timestamped result bundles are written under `ZKF_SCAN_OUTPUT_ROOT/ResultJsonTimestamped/`.
