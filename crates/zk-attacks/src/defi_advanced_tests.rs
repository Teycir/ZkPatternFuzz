use super::*;
use zk_core::{CircuitInfo, ExecutionCoverage, ExecutionResult, Framework};

struct OrderSensitiveExecutor;

impl CircuitExecutor for OrderSensitiveExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        "order-sensitive"
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo::new("order-sensitive".to_string(), 32, 2, 0, 1)
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        let first = inputs
            .first()
            .cloned()
            .unwrap_or_else(FieldElement::zero);
        ExecutionResult::success(vec![first], ExecutionCoverage::default())
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![1])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[test]
fn defi_advanced_default_config_is_sane() {
    let config = DefiAdvancedConfig::default();
    assert!(config.ordering_permutations > 0);
    assert!(config.detect_ordering);
}

#[test]
fn defi_advanced_detects_ordering_sensitivity() {
    let config = DefiAdvancedConfig {
        detect_ordering: true,
        detect_front_running_signals: false,
        ordering_permutations: 16,
        ordering_delta_threshold: 0.1,
        seed: Some(42),
        ..Default::default()
    };

    let mut attack = DefiAdvancedAttack::new(config);
    let findings = attack
        .run(
            &OrderSensitiveExecutor,
            &[
                FieldElement::from_u64(10),
                FieldElement::from_u64(20),
                FieldElement::from_u64(30),
            ],
        )
        .expect("defi run");

    assert!(!findings.is_empty());
    assert!(
        findings
            .iter()
            .any(|f| f.attack_type == AttackType::DefiAdvanced)
    );
}
