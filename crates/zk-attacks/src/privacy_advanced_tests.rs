use super::*;
use zk_core::{CircuitInfo, ExecutionCoverage, ExecutionResult, Framework};

struct ConstantOutputExecutor;

impl CircuitExecutor for ConstantOutputExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        "privacy-constant-output"
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo::new("privacy-constant-output".to_string(), 16, 2, 1, 1)
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(
            vec![FieldElement::from_u64(99)],
            ExecutionCoverage::default(),
        )
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![0])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[test]
fn privacy_advanced_default_config_is_sane() {
    let config = PrivacyAdvancedConfig::default();
    assert!(config.sample_count > 0);
    assert!(config.detect_metadata_leakage);
}

#[test]
fn privacy_advanced_detects_low_entropy() {
    let config = PrivacyAdvancedConfig {
        detect_metadata_leakage: true,
        detect_timing_leakage: false,
        sample_count: 16,
        entropy_threshold_bits: 1.0,
        seed: Some(1337),
        ..Default::default()
    };

    let mut attack = PrivacyAdvancedAttack::new(config);
    let findings = attack
        .run(
            &ConstantOutputExecutor,
            &[FieldElement::from_u64(4), FieldElement::from_u64(5)],
        )
        .expect("privacy run");

    assert!(!findings.is_empty());
    assert_eq!(findings[0].attack_type, AttackType::PrivacyAdvanced);
}
