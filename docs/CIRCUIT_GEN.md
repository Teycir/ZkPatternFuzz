# Circuit Generation

`crates/zk-circuit-gen` is the generator and compiler-testing lab inside ZkPatternFuzz. It is separate from the runtime attack catalog and exists to create hostile targets, stress backend toolchains, and compare intended semantics against compiled constraints.

## What It Covers

- backend-specific DSL rendering for Circom, Noir, Halo2, and Cairo
- random bulk corpus generation
- mutation-driven adversarial circuit generation
- compiler crash and timeout probes
- differential compiler and version-matrix testing
- semantic intent extraction from code/comments/docs
- compiled-constraint versus intended-semantics matching

## Why It Matters

Most ZK security tools assume the target circuits already exist. `zk-circuit-gen` turns circuit creation itself into a testing surface:

- generate new fuzz targets instead of waiting for hand-written fixtures
- synthesize compiler-regression inputs across multiple backends
- compare "what the docs say" against "what the compiled constraints enforce"
- ingest externally curated adversarial patterns and turn them into concrete circuit corpora

## Main Example Entry Points

All of these live under `crates/zk-circuit-gen/examples/`.

| Example | Purpose | Typical artifact root |
| --- | --- | --- |
| `generate_bulk_corpus.rs` | Generate large random corpora across backends | `artifacts/circuit_gen/bulk_latest` |
| `generate_adversarial_corpus.rs` | Build adversarial corpora from external pattern bundles and feedback | `artifacts/circuit_gen/adversarial_latest` |
| `extract_semantic_intent.rs` | Extract developer intent from source/comments/docs | operator-chosen JSON output |
| `compile_and_extract_structure.rs` | Compile DSL and extract backend structure metrics | operator-chosen JSON output |
| `verify_semantic_constraint_match.rs` | Compare intended semantics against compiled constraints | operator-chosen JSON/Markdown output |
| `run_differential_compiler_matrix.rs` | Compare the same DSL across backends/compiler IDs | operator-chosen JSON output |
| `run_differential_version_matrix.rs` | Run many circuits across multiple compiler versions | `artifacts/circuit_gen/differential_version_matrix_latest` |
| `run_compiler_crash_detector.rs` | Probe compiler crash/timeout regressions | operator-chosen output dir |
| `run_backend_compile_integration.rs` | Validate backend compile success on generated circuits | `artifacts/circuit_gen/backend_compile_integration_sample` |

## Quick Discovery Commands

```bash
cargo run -q -p zk-circuit-gen --example generate_bulk_corpus -- --help
cargo run -q -p zk-circuit-gen --example generate_adversarial_corpus -- --help
cargo run -q -p zk-circuit-gen --example run_differential_version_matrix -- --help
cargo run -q -p zk-circuit-gen --example run_compiler_crash_detector -- --help
```

## Relationship To The Rest Of The Repo

- `zkpatternfuzz` and `zk-fuzzer` execute attacks against targets.
- `zk0d_benchmark` measures recall and false-positive behavior on curated suites.
- `zk-circuit-gen` creates new targets and compiler regression inputs that those other lanes can consume.

That makes it a source of new hostile fixtures, not a side utility.

## Related References

- [docs/SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md](SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md)
- [docs/PLUGIN_API.md](PLUGIN_API.md)
- [docs/GROUND_TRUTH_REPORT.md](GROUND_TRUTH_REPORT.md)
- [ROADMAP.md](../ROADMAP.md)
