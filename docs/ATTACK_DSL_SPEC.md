# Attack DSL Specification

Normative spec for the `attacks` section in campaign YAML.

## 1. Scope

This DSL defines attack intent in config. Engine behavior is determined by:
- `type` (required, enum-backed)
- `config` (attack-specific free-form map)
- optional metadata (`description`, `plugin`)

## 2. Grammar

```yaml
attacks:
  - type: <attack_type>          # required, snake_case
    description: <string>        # optional
    plugin: <string>             # optional
    config:                      # optional map/object
      <key>: <value>
```

## 3. Attack Type Vocabulary

Current supported values:

- `underconstrained`
- `soundness`
- `arithmetic_overflow`
- `constraint_bypass`
- `trusted_setup`
- `witness_leakage`
- `replay_attack`
- `collision`
- `boundary`
- `bit_decomposition`
- `malleability`
- `verification_fuzzing`
- `witness_fuzzing`
- `differential`
- `information_leakage`
- `timing_side_channel`
- `circuit_composition`
- `recursive_proof`
- `constraint_inference`
- `metamorphic`
- `constraint_slice`
- `spec_inference`
- `witness_collision`
- `mev`
- `front_running`
- `zk_evm`
- `batch_verification`
- `sidechannel_advanced`
- `quantum_resistance`
- `privacy_advanced`
- `defi_advanced`
- `circom_static_lint`

Values are deserialized from `AttackType` and must match snake_case names.

## 4. Semantics

- `type`: selects attack implementation family.
- `description`: human-readable context for reports/logs.
- `plugin`: optional external plugin identifier.
- `config`: attack-local parameters (schema is attack-dependent).

Unknown `type` values fail config parsing.  
Unknown keys inside `config` are preserved for attack-specific handlers.

## 5. Relationship To Schedule DSL (v2)

`schedule[].attacks` contains string references to attack families for each phase:

```yaml
schedule:
  - phase: exploration
    duration_sec: 60
    attacks: ["underconstrained", "boundary"]
```

Use the same snake_case naming as `attacks[].type`.

## 6. Examples

Minimal:

```yaml
attacks:
  - type: underconstrained
    description: "Witness ambiguity probe"
```

Mixed campaign:

```yaml
attacks:
  - type: soundness
    description: "Forgery and verification checks"
    config:
      proof_malleability:
        enabled: true
        proof_samples: 16
        algebraic_mutations: true
        negative_control_random_mutations: 8

  - type: differential
    description: "Cross-backend drift detection"
    config:
      backends: ["circom", "noir", "halo2", "cairo"]
      cross_backend:
        enabled: true
        sample_count: 100

  - type: collision
    description: "Nullifier/hash collision sweep"
    config:
      samples: 10000
```

Plugin-backed extension:

```yaml
attacks:
  - type: underconstrained
    description: "Core baseline"
  - type: soundness
    plugin: "custom_soundness_ext"
    description: "Plugin-assisted soundness variant"
    config:
      strategy: "aggressive"
```

## 7. Validation Workflow

```bash
cargo run -- --dry-run --config <campaign.yaml>
scripts/validate_yaml.sh <campaign.yaml>
cargo run --bin zk0d_config_migrate -- <campaign.yaml> --check
```

## 8. Recommended Readiness Baseline Set

For non-Circom readiness (Noir/Cairo/Halo2), keep this baseline in every lane:
- `underconstrained`
- `soundness`
- `boundary`
- `arithmetic_overflow`
- `collision`

Then add backend-specific deep attacks as needed.
