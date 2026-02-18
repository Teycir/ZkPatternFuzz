use super::*;
use zk_core::{CircuitInfo, ExecutionCoverage, ExecutionResult, Framework};

struct LenientProofExecutor {
    name: String,
}

impl LenientProofExecutor {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl CircuitExecutor for LenientProofExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo::new(self.name.clone(), 1, 1, 1, 1)
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(vec![FieldElement::one()], ExecutionCoverage::default())
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![0xAB; 96])
    }

    fn verify(&self, proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(!proof.is_empty())
    }
}

#[test]
fn trusted_setup_config_from_yaml_parses_section() {
    let raw: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_setup_test:
  enabled: true
  attempts: 3
  ptau_file_a: a.ptau
  ptau_file_b: b.ptau
"#,
    )
    .expect("yaml parse");

    let config = TrustedSetupConfig::from_yaml(&raw);
    assert!(config.enabled);
    assert_eq!(config.attempts, 3);
    assert_eq!(config.ptau_file_a.as_deref(), Some("a.ptau"));
    assert_eq!(config.ptau_file_b.as_deref(), Some("b.ptau"));
}

#[test]
fn trusted_setup_attack_detects_cross_setup_verification() {
    let attack = TrustedSetupAttack::new(TrustedSetupConfig {
        enabled: true,
        attempts: 1,
        ..TrustedSetupConfig::default()
    });

    let witness = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
    let findings = attack.run(
        &LenientProofExecutor::new("setup_a"),
        &LenientProofExecutor::new("setup_b"),
        &[witness],
    );

    assert!(!findings.is_empty());
    let finding = &findings[0];
    assert_eq!(finding.attack_type, AttackType::TrustedSetup);
    assert_eq!(finding.severity, Severity::Critical);
}

#[test]
fn setup_poisoning_detector_compatibility_api_still_works() {
    let detector = SetupPoisoningDetector::new().with_attempts(1);
    let witness = vec![FieldElement::from_u64(5), FieldElement::from_u64(8)];

    let findings = detector.run(
        &LenientProofExecutor::new("setup_a"),
        &LenientProofExecutor::new("setup_b"),
        &[witness],
    );
    assert!(!findings.is_empty());
}
