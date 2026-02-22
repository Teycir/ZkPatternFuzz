use std::collections::HashMap;

use num_bigint::BigUint;
use zk_constraints::LinearCombination;
use zk_core::{
    AttackType, CircuitExecutor, CircuitInfo, ExecutionCoverage, ExecutionResult, FieldElement,
    Framework, Severity,
};
use zk_fuzzer::oracles::NonNativeFieldOracle;
use zk_fuzzer::{ExtendedConstraint, R1CSConstraint, RangeConstraint, RangeMethod, WireRef};

struct SignatureLimbExecutor {
    name: String,
    enforce_limb_bounds: bool,
    enforce_sum_modulus: bool,
}

impl SignatureLimbExecutor {
    fn new(name: &str, enforce_limb_bounds: bool, enforce_sum_modulus: bool) -> Self {
        Self {
            name: name.to_string(),
            enforce_limb_bounds,
            enforce_sum_modulus,
        }
    }

    fn modulus() -> BigUint {
        BigUint::from(1000u64)
    }
}

impl CircuitExecutor for SignatureLimbExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: self.name.clone(),
            num_constraints: 3,
            num_private_inputs: 2,
            num_public_inputs: 1,
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        if inputs.len() < 3 {
            return ExecutionResult::failure("insufficient witness width".to_string());
        }

        let limb0 = inputs[0].to_biguint();
        let limb1 = inputs[1].to_biguint();
        let limb_bound = BigUint::from(1u64 << 16);

        if self.enforce_limb_bounds && (limb0 >= limb_bound || limb1 >= limb_bound) {
            return ExecutionResult::failure("limb out of range".to_string());
        }

        let packed = &limb0 + (&limb1 << 16usize);
        let modulus = Self::modulus();

        if self.enforce_sum_modulus && packed >= modulus {
            return ExecutionResult::failure("reconstruction overflow".to_string());
        }

        let reduced = packed % &modulus;
        let output = FieldElement::from_bytes(&reduced.to_bytes_be());
        ExecutionResult::success(vec![output], ExecutionCoverage::default())
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![0xAA; 32])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }

    fn field_modulus(&self) -> [u8; 32] {
        let bytes = Self::modulus().to_bytes_be();
        let mut out = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        out[start..start + bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        out
    }
}

fn non_native_constraints() -> Vec<ExtendedConstraint> {
    let limb0 = WireRef::named(0, "limb0_u16");
    let limb1 = WireRef::named(1, "limb1_u16");
    let packed = WireRef::named(2, "packed");

    let mut sum = LinearCombination::new();
    sum.add_term(limb0.clone(), FieldElement::one());
    sum.add_term(limb1.clone(), FieldElement::from_u64(1 << 16));

    let mut output = LinearCombination::new();
    output.add_term(packed.clone(), FieldElement::one());

    vec![
        ExtendedConstraint::Range(RangeConstraint {
            wire: limb0,
            bits: 16,
            method: RangeMethod::Plookup,
        }),
        ExtendedConstraint::Range(RangeConstraint {
            wire: limb1,
            bits: 16,
            method: RangeMethod::Plookup,
        }),
        ExtendedConstraint::R1CS(R1CSConstraint {
            a: LinearCombination::constant(FieldElement::one()),
            b: sum,
            c: output,
        }),
    ]
}

fn non_native_wire_labels() -> HashMap<usize, String> {
    HashMap::from([
        (0usize, "limb0_u16".to_string()),
        (1usize, "limb1_u16".to_string()),
        (2usize, "packed".to_string()),
    ])
}

fn base_witnesses() -> Vec<Vec<FieldElement>> {
    vec![vec![
        FieldElement::from_u64(10),
        FieldElement::from_u64(0),
        FieldElement::from_u64(10),
    ]]
}

fn run_non_native_oracle(executor: &dyn CircuitExecutor) -> Vec<zk_core::Finding> {
    let oracle = NonNativeFieldOracle::new()
        .with_sample_count(1)
        .with_case_limit(64)
        .with_finding_limit(16);
    oracle.run(
        executor,
        &non_native_constraints(),
        &non_native_wire_labels(),
        &base_witnesses(),
    )
}

#[test]
fn test_non_native_oracle_detects_eddsa_malleability_pattern() {
    let executor = SignatureLimbExecutor::new("eddsa_signature_vulnerable", false, false);
    let findings = run_non_native_oracle(&executor);

    assert!(
        !findings.is_empty(),
        "Expected non-native field findings for vulnerable EdDSA circuit"
    );
    assert!(
        findings
            .iter()
            .all(|f| f.attack_type == AttackType::BitDecomposition),
        "Expected BitDecomposition findings"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("CVE-2024-42459")),
        "Expected EdDSA CVE hint in findings"
    );
}

#[test]
fn test_non_native_oracle_detects_ecdsa_s_value_overflow_pattern() {
    let executor = SignatureLimbExecutor::new("ecdsa_signature_vulnerable", false, false);
    let findings = run_non_native_oracle(&executor);

    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("ECDSA s-value overflow pattern")),
        "Expected ECDSA overflow hint in findings"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("ECDSA s-value overflow pattern")
                && f.severity >= Severity::High),
        "Expected high-severity ECDSA overflow-class finding"
    );
}

#[test]
fn test_non_native_oracle_finds_overflow_across_three_signature_variants() {
    let executors = vec![
        SignatureLimbExecutor::new("eddsa_sig_variant_a", false, false),
        SignatureLimbExecutor::new("ecdsa_sig_variant_b", false, false),
        SignatureLimbExecutor::new("ecdsa_sig_variant_c", false, false),
    ];

    let mut vulnerable_variants = 0usize;
    for executor in &executors {
        let findings = run_non_native_oracle(executor);
        if !findings.is_empty() {
            vulnerable_variants += 1;
        }
    }

    assert_eq!(
        vulnerable_variants, 3,
        "Expected limb overflow oracle to find bugs in three signature variants"
    );
}

#[test]
fn test_non_native_oracle_zero_false_positive_on_strict_signature_executor() {
    let executor = SignatureLimbExecutor::new("ecdsa_signature_secure", true, true);
    let findings = run_non_native_oracle(&executor);
    assert!(
        findings.is_empty(),
        "Expected zero findings for strict non-native field checks"
    );
}
