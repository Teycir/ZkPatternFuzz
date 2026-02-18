# Scan Modes

This document defines how scanning works in this repo.

## Global Constraints

- Targets are read-only and must come from `/media/elements/Repos/zk0d` unless explicitly approved.
- No mocks or synthetic targets unless explicitly approved.
- Pattern YAML is strictly attack logic only (no hardcoded target/runtime/output fields).

## Scanner Model (YAML-Only)

`zk-fuzzer scan` is a single scanner entry point driven by pattern YAML.

- No built-in Mode 1 pre-pass.
- Every run is selected by YAML templates and regex selectors.
- Universal/simple checks are represented as always-run YAML templates.
- Deeper/less-common checks are added by collection/alias based on the target.

## Pattern Classes

- Always-run simple patterns:
  - Safe baseline checks to run for most targets
- Optional additional patterns:
  - Enabled by collection/alias when needed

## Regex Pattern Selectors

Pattern YAML may include an optional SCPF-style selector block:

```yaml
patterns:
  - id: contains_nullifier
    kind: regex
    pattern: "\\bnullifier\\b"
    message: "Target contains nullifier logic"
```

- `kind` currently supports only `regex`.
- Selectors are evaluated against the target circuit source before scan execution.
- If `patterns` is present, at least one selector must match or the scan aborts.
- Selector metadata is scan-time only and is not injected into the materialized runtime campaign.

Optional selector tuning is supported via per-pattern `weight`, optional per-pattern `group`,
and top-level `selector_policy`:

```yaml
patterns:
  - id: contains_nullifier
    kind: regex
    pattern: "\\bnullifier\\b"
    weight: 1.0
    group: core
  - id: zkevm_context
    kind: regex
    pattern: "{{zkevm}}"
    weight: 0.8
    group: context
  - id: contains_smt
    kind: regex
    pattern: "\\bSMT\\b|inclusion"
    weight: 0.6
    group: context

selector_policy:
  k_of_n: 1          # required matched selector count (default: 1)
  min_score: 1.0     # required sum of matched weights (default: 0.0)
  groups:
    - name: core
      k_of_n: 1      # group-local minimum matches (default: 1)
      min_score: 0.0 # group-local minimum score (default: 0.0)

selector_synonyms:
  zkevm:
    - "zkEVM"
    - "zk evm"
    - "zk-evm"

selector_normalization:
  synonym_flexible_separators: true
```

- If `selector_policy` is omitted, behavior stays backward-compatible: at least one selector must match.
- Group rules are optional and apply only to patterns that declare that `group`.
- Invalid policies (for example `k_of_n` larger than available patterns) fail fast at scan startup.
- Synonym bundles are optional and are referenced from selector regexes via `{{bundle_name}}`.
- With `synonym_flexible_separators: true`, synonym terms are normalized to tolerate style changes
  (for example camelCase/snake_case/kebab-case/space-separated variants).

## Family Dispatch

`zk-fuzzer scan <pattern.yaml> --family <auto|mono|multi> ...`

- Regex-focused selectors are the primary dispatch mechanism.
- When `patterns:` is present, scan may force mono execution and ignore chain topology.

## Catalog Concept (SCPF-Style, Applied to Fuzzer)

Use a registry file (`targets/fuzzer_registry.yaml`) with:
- `registries`
- `collections`
- `aliases`

Run via batch catalog runner (`zk0d_batch`):

```bash
# Inspect catalog
cargo run --release --bin zk0d_batch -- --list-catalog

# Run always-on collection
cargo run --release --bin zk0d_batch -- \
  --alias always \
  --target-circuit /path/to/target.circom \
  --main-component Main \
  --framework circom

# Run selected collection
cargo run --release --bin zk0d_batch -- \
  --collection always \
  --target-circuit /path/to/target.circom \
  --main-component Main \
  --framework circom
```

## Output Organization

Output paths and report format are code-managed and unchanged.
