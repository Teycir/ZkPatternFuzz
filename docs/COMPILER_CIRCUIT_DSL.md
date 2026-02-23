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
