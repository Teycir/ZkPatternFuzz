# Compiler Circuit DSL

This document defines the first version of the post-roadmap compiler-fuzzing circuit DSL.

## Scope

The DSL is a backend-neutral representation of a small arithmetic circuit:

- named public/private inputs
- named outputs
- assignment statements
- equality constraints

The same DSL can be rendered into backend-specific syntax templates for:

- Circom (`.circom`)
- Noir (`.nr`)
- Halo2 Rust scaffold (`.rs`)
- Cairo (`.cairo`)

Implementation lives in `crates/zk-circuit-gen`.

## DSL Schema

Top-level fields:

- `name`: circuit identifier
- `public_inputs`: array of signal names
- `private_inputs`: array of signal names
- `outputs`: array of output signal names
- `assignments`: ordered assignment list
- `constraints`: ordered equality constraints

Expression schema (`expression`, `left`, `right`):

- `op: signal` + `name`
- `op: constant` + `value`
- `op: add|sub|mul` + `left` + `right`

## Example (YAML)

```yaml
name: range_gate
public_inputs: [bound]
private_inputs: [x]
outputs: [out]
assignments:
  - target: tmp
    expression:
      op: sub
      left: { op: signal, name: bound }
      right: { op: signal, name: x }
  - target: out
    expression:
      op: mul
      left: { op: signal, name: tmp }
      right: { op: signal, name: x }
constraints:
  - left: { op: signal, name: out }
    right: { op: constant, value: 0 }
```

## Validation Rules

The generator rejects DSL payloads when:

- identifiers are invalid or duplicated
- assignment expressions reference unknown signals
- outputs are declared but never assigned
- no assignments and no constraints are provided

## Rendering API

Use `zk_circuit_gen::render_backend_template`:

```rust
use zk_circuit_gen::{Backend, parse_dsl_yaml, render_backend_template};

let dsl = parse_dsl_yaml(include_str!("range_gate.yaml"))?;
let circom = render_backend_template(&dsl, Backend::Circom)?;
let noir = render_backend_template(&dsl, Backend::Noir)?;
```

## Notes

- This is a syntax-template layer for generator design and corpus creation.
- It is intentionally conservative and deterministic for reproducible fuzz artifacts.
- Advanced constructs (lookups, custom gates, recursive templates) are future extensions.

## Bulk Generator

Use the bundled bulk generator to produce random circuits per backend:

```bash
scripts/run_circuit_gen_bulk_sample.sh
```

Defaults:
- `CIRCUITS_PER_BACKEND=1000`
- `BACKENDS=circom,noir,halo2,cairo`
- `SEED=1337`
- output root: `artifacts/circuit_gen/bulk_latest`
- no mutation strategies enabled by default

Artifacts:
- `<output>/circom/*.circom`, `<output>/noir/*.nr`, `<output>/halo2/*.rs`, `<output>/cairo/*.cairo`
- `<output>/<backend>/*.dsl.json` source DSL payloads
- `<output>/latest_report.json` generation summary

## Mutation Strategies

Enable mutation variants during generation with:

```bash
MUTATION_STRATEGIES=deep_nesting,wide_constraints,pathological_loops,mixed_types,malformed_ir \
MUTATION_INTENSITY=3 \
scripts/run_circuit_gen_bulk_sample.sh
```

Implemented strategies:
- `deep_nesting`: deep arithmetic expression chains (stack/recursion pressure)
- `wide_constraints`: large batches of extra equality constraints (memory/optimizer pressure)
- `pathological_loops`: backend-specific high-iteration loop snippets (compiler pass stress)
- `mixed_types`: backend-specific type-mixing snippets (`Field`/integer or felt/u128 boundaries)
- `malformed_ir`: deliberately broken token injection (`@@MALFORMED_IR@@`) for parser/validator fail paths

## External AI Adversarial Pattern Flow

The generator supports external AI as a producer of adversarial pattern bundles.
No in-process AI API calls are used; the operator supplies JSON.

Run sample flow:

```bash
scripts/run_circuit_gen_adversarial_sample.sh
```

Core entrypoint:

```bash
cargo run -q -p zk-circuit-gen --example generate_adversarial_corpus -- \
  --patterns-json tests/datasets/circuit_gen/external_ai_patterns.sample.json \
  --feedback-json tests/datasets/circuit_gen/external_ai_feedback.sample.json \
  --output-dir artifacts/circuit_gen/adversarial_sample
```

Generated artifacts:
- `<output>/effective_patterns.json` (post-feedback evolved bundle)
- `<output>/<pattern_id>/<backend>/*` generated circuits and DSL payloads
- `<output>/latest_report.json` summary of counts per pattern/backend

### Pattern Bundle Schema (JSON)

- `source`: producer identity (for example `external_ai_user`)
- `generated_at`: timestamp string
- `patterns[]`:
  - `pattern_id`: stable identifier
  - `rationale`: why this should trigger compiler edge behavior
  - `issue_refs[]`: issue links/ids used by external AI analysis
  - `target_backends[]`: any of `circom|noir|halo2|cairo`
  - `mutation_strategies[]`: optional strategy list
  - `circuits_per_backend`: base circuits per backend
  - `mutation_intensity`: intensity for mutation rendering
  - `priority`: optional scheduling priority

### Feedback Evolution

`generate_adversarial_corpus` accepts optional feedback JSON (`PatternFeedbackBatch`) and
updates priority/intensity from compiler outcomes:

- crash-like outcomes (`crash`, `timeout`, `internal_compiler_error`) raise priority
- crash-like outcomes increase `mutation_intensity` and `circuits_per_backend`
- patterns are re-sorted by priority before generation

## Semantic Intent Extraction

Use the semantic intent extractor to collect requirement statements from circuit comments
and optional operator docs:

```bash
scripts/run_circuit_gen_semantic_sample.sh
```

Direct command:

```bash
cargo run -q -p zk-circuit-gen --example extract_semantic_intent -- \
  --backend circom \
  --source-file tests/datasets/circuit_gen/semantic_source.sample.circom \
  --doc-file tests/datasets/circuit_gen/semantic_doc.sample.md \
  --output-json artifacts/circuit_gen/semantic_intent_sample/latest_report.json
```

Extraction output includes:
- `signals[]`: normalized semantic requirement statements with kind/confidence
- `comment_lines[]`: raw comment-derived statements
- `documentation_lines[]`: raw doc-derived statements

## Compile + Structure Extraction

Use the structure extractor to compile DSL into backend template output and emit
constraint/shape metrics:

```bash
scripts/run_circuit_gen_structure_sample.sh
```

Direct command:

```bash
cargo run -q -p zk-circuit-gen --example compile_and_extract_structure -- \
  --dsl-file tests/datasets/circuit_gen/structure_dsl.sample.yaml \
  --backend circom \
  --output-json artifacts/circuit_gen/structure_sample/latest_report.json
```

Reported metrics include:
- `constraint_count`, `assignment_count`
- `signal_count`, `intermediate_count`
- `expression_node_count`, `max_expression_depth`
- `signal_reference_count`, `unique_signal_references`
- rendered template size (`rendered_line_count`, `rendered_byte_size`)

## Semantic Constraint Match Verification

Use semantic match verification to check if compiled constraints align with extracted intent:

```bash
scripts/run_circuit_gen_semantic_match_sample.sh
```

Direct command:

```bash
cargo run -q -p zk-circuit-gen --example verify_semantic_constraint_match -- \
  --source-file tests/datasets/circuit_gen/semantic_source.sample.circom \
  --doc-file tests/datasets/circuit_gen/semantic_doc.sample.md \
  --dsl-file tests/datasets/circuit_gen/structure_dsl.sample.yaml \
  --backend circom \
  --output-json artifacts/circuit_gen/semantic_constraint_match_sample/latest_report.json \
  --output-markdown artifacts/circuit_gen/semantic_constraint_match_sample/latest_report.md
```

Verification output includes:
- `total_intents`, `matched_intents`, `mismatched_intents`
- `checks[]` per intent statement (`matched` + `evidence[]`)
- `constraint_gaps[]` for mismatched intents (`reason`, `satisfiable_candidate`)
- `narrative_findings[]` with explicit phrasing:
  `Circuit allows X, but docs say "Y".`
- embedded `compiled_structure` metrics for correlation

## Differential Compiler Matrix

Use differential matrix mode to compare structure metrics across compiler labels and backends:

```bash
scripts/run_circuit_gen_differential_sample.sh
```

Direct command:

```bash
cargo run -q -p zk-circuit-gen --example run_differential_compiler_matrix -- \
  --dsl-file tests/datasets/circuit_gen/structure_dsl.sample.yaml \
  --backends circom,noir \
  --compiler-ids circom_v2_0,circom_v2_1 \
  --output-json artifacts/circuit_gen/differential_sample/latest_report.json
```

Matrix report includes:
- `observations[]`: per `(compiler_id, backend)` compiled structure metrics
- `comparisons[]`:
  - `axis=compiler_version` (same backend, different compiler labels)
  - `axis=backend` (same compiler label, different backends)
- `constraint_delta` and other structure deltas
- `optimization_regression` (true when candidate constraint count increases)
