# Plugin API

This is the minimal contract for external attack plugins. For discovery rules, strict-mode policy, and operational safeguards, use [PLUGIN_SYSTEM_GUIDE.md](PLUGIN_SYSTEM_GUIDE.md).

## Host Requirements

- build the host with `--features attack-plugins`
- build plugin crates as `cdylib`
- keep plugin and host Rust toolchains aligned
- load only trusted plugin binaries

## Required Rust Surface

A plugin must:

1. implement `zk_core::Attack`
2. implement `zk_attacks::AttackPlugin`
3. export the symbol `zk_attacks_plugins`

Minimal shape:

```rust
use zk_attacks::{AttackMetadata, AttackPlugin};
use zk_core::{Attack, AttackContext, AttackType, Finding};

struct MyAttack;

impl Attack for MyAttack {
    fn run(&self, context: &AttackContext) -> Vec<Finding> { vec![] }
    fn attack_type(&self) -> AttackType { AttackType::Boundary }
    fn description(&self) -> &str { "my plugin attack" }
}

impl AttackPlugin for MyAttack {
    fn metadata(&self) -> AttackMetadata {
        AttackMetadata::new("my_plugin", self.description(), "0.1.0")
    }
}

#[no_mangle]
pub unsafe extern "Rust" fn zk_attacks_plugins() -> Vec<Box<dyn AttackPlugin>> {
    vec![Box::new(MyAttack)]
}
```

The working example crate is [`crates/zk-attacks-plugin-example`](../crates/zk-attacks-plugin-example).

## Build And Select

Build the example plugin:

```bash
cargo build -p zk-attacks-plugin-example --release
```

Reference it from a campaign:

```yaml
attacks:
  - type: boundary
    plugin: example_plugin

campaign:
  parameters:
    additional:
      attack_plugin_dirs:
        - "./target/release"
      engagement_strict: true
```

Plugin names resolve from:

- `attacks[].plugin`
- `attacks[].config.plugin`

## Safety Model

- the loader uses Rust ABI trait objects, so ABI drift can break plugins
- strict engagements fail when an explicitly requested plugin cannot be found
- plugin directories should be absolute, trusted, and not writable by untrusted users

## Related References

- [docs/PLUGIN_SYSTEM_GUIDE.md](PLUGIN_SYSTEM_GUIDE.md)
- [docs/ATTACK_DSL_SPEC.md](ATTACK_DSL_SPEC.md)
- [docs/CIRCUIT_GEN.md](CIRCUIT_GEN.md)
