use super::*;
use zk_core::{CircuitInfo, ExecutionCoverage, ExecutionResult, Framework};

struct ConstantOutputExecutor;

impl CircuitExecutor for ConstantOutputExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        "constant-output"
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo::new("constant-output".to_string(), 32, 2, 1, 1)
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(vec![FieldElement::from_u64(7)], ExecutionCoverage::default())
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![1, 2, 3])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[test]
fn sidechannel_advanced_default_config_is_sane() {
    let config = SidechannelAdvancedConfig::default();
    assert!(config.timing_samples > 0);
    assert!(config.leakage_samples > 0);
    assert!(config.detect_timing);
    assert!(config.detect_leakage);
}

#[test]
fn sidechannel_advanced_detects_low_uniqueness() {
    let config = SidechannelAdvancedConfig {
        detect_timing: false,
        detect_leakage: true,
        leakage_samples: 16,
        leakage_uniqueness_threshold: 0.9,
        seed: Some(7),
        ..Default::default()
    };
    let mut attack = SidechannelAdvancedAttack::new(config);
    let findings = attack
        .run(
            &ConstantOutputExecutor,
            &[FieldElement::from_u64(1), FieldElement::from_u64(2)],
        )
        .expect("sidechannel run");

    assert!(!findings.is_empty());
    assert!(
        findings
            .iter()
            .any(|f| f.attack_type == AttackType::SidechannelAdvanced)
    );
}
