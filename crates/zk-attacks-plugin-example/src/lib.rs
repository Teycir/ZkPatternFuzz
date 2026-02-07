//! Example zk-attacks dynamic plugin.

use zk_attacks::{AttackMetadata, AttackPlugin};
use zk_core::{Attack, AttackContext, AttackType, Finding, ProofOfConcept, Severity};

#[derive(Default)]
struct ExampleAttack;

impl Attack for ExampleAttack {
    fn run(&self, _context: &AttackContext) -> Vec<Finding> {
        vec![Finding {
            attack_type: AttackType::Boundary,
            severity: Severity::Info,
            description: "Example plugin attack executed".to_string(),
            poc: ProofOfConcept::default(),
            location: None,
        }]
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Boundary
    }

    fn description(&self) -> &str {
        "Example plugin attack"
    }
}

impl AttackPlugin for ExampleAttack {
    fn metadata(&self) -> AttackMetadata {
        AttackMetadata::new("example_plugin", self.description(), "0.1.0")
    }
}

/// Exported plugin entry point.
///
/// This symbol is discovered by the dynamic loader when the `attack-plugins`
/// feature is enabled. It must return boxed `AttackPlugin` trait objects.
///
/// Note: This uses the Rust ABI, so the plugin must be built with a compatible
/// Rust toolchain and dependency set.
#[no_mangle]
pub unsafe extern "Rust" fn zk_attacks_plugins() -> Vec<Box<dyn AttackPlugin>> {
    vec![Box::new(ExampleAttack::default())]
}
