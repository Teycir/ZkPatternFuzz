use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

use crate::generators::{
    generate_pairing_input, PairingInputSample, PairingInputType, TOY_PAIRING_GENERATOR,
    TOY_PAIRING_ORDER, TOY_PAIRING_TARGET_MODULUS,
};
use crate::oracle::{add_mod_u64, mod_pow_u64, mul_mod_u64};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PairingProperty {
    Bilinearity,
    NonDegeneracy,
    Identity,
    LinearityG1,
    LinearityG2,
}

impl PairingProperty {
    pub const ALL: [PairingProperty; 5] = [
        Self::Bilinearity,
        Self::NonDegeneracy,
        Self::Identity,
        Self::LinearityG1,
        Self::LinearityG2,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bilinearity => "bilinearity",
            Self::NonDegeneracy => "non_degeneracy",
            Self::Identity => "identity",
            Self::LinearityG1 => "linearity_g1",
            Self::LinearityG2 => "linearity_g2",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PairingImplementationProfile {
    StrictSubgroupChecks,
    WeakSubgroupChecks,
}

impl PairingImplementationProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictSubgroupChecks => "strict_subgroup_checks",
            Self::WeakSubgroupChecks => "weak_subgroup_checks",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingFuzzConfig {
    pub seed: u64,
    pub g1_inputs: Vec<PairingInputType>,
    pub g2_inputs: Vec<PairingInputType>,
    pub properties: Vec<PairingProperty>,
    pub implementation_profile: PairingImplementationProfile,
}

impl PairingFuzzConfig {
    pub fn new() -> Self {
        Self {
            seed: 20_260_223,
            g1_inputs: PairingInputType::ALL.to_vec(),
            g2_inputs: PairingInputType::ALL.to_vec(),
            properties: PairingProperty::ALL.to_vec(),
            implementation_profile: PairingImplementationProfile::StrictSubgroupChecks,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingFuzzFinding {
    pub case_id: String,
    pub g1_input_type: PairingInputType,
    pub g2_input_type: PairingInputType,
    pub property: PairingProperty,
    pub reason: String,
    pub expected: String,
    pub observed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingFuzzReport {
    pub seed: u64,
    pub implementation_profile: PairingImplementationProfile,
    pub total_g1_inputs: usize,
    pub total_g2_inputs: usize,
    pub total_combinations: usize,
    pub total_checks: usize,
    pub property_failures: usize,
    pub candidate_accepts_invalid_cases: usize,
    pub checks_by_property: BTreeMap<String, usize>,
    pub failures_by_property: BTreeMap<String, usize>,
    pub checks_by_g1_input: BTreeMap<String, usize>,
    pub checks_by_g2_input: BTreeMap<String, usize>,
    pub failures_by_g1_input: BTreeMap<String, usize>,
    pub failures_by_g2_input: BTreeMap<String, usize>,
    pub findings: Vec<PairingFuzzFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PairingEval {
    Bool(bool),
    Error(&'static str),
}

pub fn run_pairing_fuzz_campaign(config: &PairingFuzzConfig) -> PairingFuzzReport {
    let g1_inputs = dedup_inputs(&config.g1_inputs);
    let g2_inputs = dedup_inputs(&config.g2_inputs);
    let properties = dedup_properties(&config.properties);
    let total_combinations = g1_inputs.len() * g2_inputs.len();
    let mut rng = StdRng::seed_from_u64(config.seed);

    let mut report = PairingFuzzReport {
        seed: config.seed,
        implementation_profile: config.implementation_profile,
        total_g1_inputs: g1_inputs.len(),
        total_g2_inputs: g2_inputs.len(),
        total_combinations,
        total_checks: 0,
        property_failures: 0,
        candidate_accepts_invalid_cases: 0,
        checks_by_property: BTreeMap::new(),
        failures_by_property: BTreeMap::new(),
        checks_by_g1_input: BTreeMap::new(),
        checks_by_g2_input: BTreeMap::new(),
        failures_by_g1_input: BTreeMap::new(),
        failures_by_g2_input: BTreeMap::new(),
        findings: Vec::new(),
    };

    for (g1_idx, g1_type) in g1_inputs.iter().enumerate() {
        for (g2_idx, g2_type) in g2_inputs.iter().enumerate() {
            let g1 = generate_pairing_input(*g1_type, g1_idx, &mut rng);
            let g2 = generate_pairing_input(*g2_type, g2_idx + 101, &mut rng);

            for property in &properties {
                report.total_checks += 1;
                *report
                    .checks_by_property
                    .entry(property.as_str().to_string())
                    .or_insert(0) += 1;
                *report
                    .checks_by_g1_input
                    .entry(g1_type.as_str().to_string())
                    .or_insert(0) += 1;
                *report
                    .checks_by_g2_input
                    .entry(g2_type.as_str().to_string())
                    .or_insert(0) += 1;

                let expected = evaluate_pairing_property(
                    *property,
                    &g1,
                    &g2,
                    PairingImplementationProfile::StrictSubgroupChecks,
                );
                let observed =
                    evaluate_pairing_property(*property, &g1, &g2, config.implementation_profile);

                if expected != observed {
                    report.property_failures += 1;
                    *report
                        .failures_by_property
                        .entry(property.as_str().to_string())
                        .or_insert(0) += 1;
                    *report
                        .failures_by_g1_input
                        .entry(g1_type.as_str().to_string())
                        .or_insert(0) += 1;
                    *report
                        .failures_by_g2_input
                        .entry(g2_type.as_str().to_string())
                        .or_insert(0) += 1;

                    if matches!(expected, PairingEval::Error(_))
                        && matches!(observed, PairingEval::Bool(_))
                    {
                        report.candidate_accepts_invalid_cases += 1;
                    }

                    report.findings.push(PairingFuzzFinding {
                        case_id: format!("pairing-{g1_idx:02}-{g2_idx:02}"),
                        g1_input_type: *g1_type,
                        g2_input_type: *g2_type,
                        property: *property,
                        reason: "candidate pairing behavior diverged from strict model".to_string(),
                        expected: pairing_eval_to_string(&expected),
                        observed: pairing_eval_to_string(&observed),
                    });
                }
            }
        }
    }

    report
}

fn dedup_inputs(values: &[PairingInputType]) -> Vec<PairingInputType> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(value) {
            deduped.push(*value);
        }
    }
    if deduped.is_empty() {
        PairingInputType::ALL.to_vec()
    } else {
        deduped
    }
}

fn dedup_properties(values: &[PairingProperty]) -> Vec<PairingProperty> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(value) {
            deduped.push(*value);
        }
    }
    if deduped.is_empty() {
        PairingProperty::ALL.to_vec()
    } else {
        deduped
    }
}

fn evaluate_pairing_property(
    property: PairingProperty,
    g1: &PairingInputSample,
    g2: &PairingInputSample,
    profile: PairingImplementationProfile,
) -> PairingEval {
    let g1_value = match resolve_pairing_input(g1, profile) {
        Ok(value) => value,
        Err(error) => return PairingEval::Error(error),
    };
    let g2_value = match resolve_pairing_input(g2, profile) {
        Ok(value) => value,
        Err(error) => return PairingEval::Error(error),
    };

    let evaluate = |left: u64, right: u64| -> u64 { pairing_value(left, right, profile) };

    match property {
        PairingProperty::Bilinearity => {
            let a = 3;
            let b = 5;
            let left = evaluate(
                mul_mod_u64(g1_value, a, TOY_PAIRING_ORDER),
                mul_mod_u64(g2_value, b, TOY_PAIRING_ORDER),
            );
            let base = evaluate(g1_value, g2_value);
            let right = mod_pow_u64(base, a * b, TOY_PAIRING_TARGET_MODULUS);
            PairingEval::Bool(left == right)
        }
        PairingProperty::NonDegeneracy => {
            let value = evaluate(1, 1);
            PairingEval::Bool(value != 1)
        }
        PairingProperty::Identity => {
            let left_identity = evaluate(0, g2_value) == 1;
            let right_identity = evaluate(g1_value, 0) == 1;
            PairingEval::Bool(left_identity && right_identity)
        }
        PairingProperty::LinearityG1 => {
            let p1_plus_p2 = add_mod_u64(g1_value, 1, TOY_PAIRING_ORDER);
            let left = evaluate(p1_plus_p2, g2_value);
            let right = mul_mod_u64(
                evaluate(g1_value, g2_value),
                evaluate(1, g2_value),
                TOY_PAIRING_TARGET_MODULUS,
            );
            PairingEval::Bool(left == right)
        }
        PairingProperty::LinearityG2 => {
            let q1_plus_q2 = add_mod_u64(g2_value, 1, TOY_PAIRING_ORDER);
            let left = evaluate(g1_value, q1_plus_q2);
            let right = mul_mod_u64(
                evaluate(g1_value, g2_value),
                evaluate(g1_value, 1),
                TOY_PAIRING_TARGET_MODULUS,
            );
            PairingEval::Bool(left == right)
        }
    }
}

fn resolve_pairing_input(
    input: &PairingInputSample,
    profile: PairingImplementationProfile,
) -> Result<u64, &'static str> {
    if input.value.is_none() {
        if profile == PairingImplementationProfile::WeakSubgroupChecks {
            return Ok(0);
        }
        return Err("invalid_input");
    }

    if input.low_order_hint && profile == PairingImplementationProfile::StrictSubgroupChecks {
        return Err("low_order_input");
    }

    Ok(input.value.unwrap_or(0) % TOY_PAIRING_ORDER)
}

fn pairing_value(left: u64, right: u64, profile: PairingImplementationProfile) -> u64 {
    let base = if profile == PairingImplementationProfile::WeakSubgroupChecks {
        TOY_PAIRING_GENERATOR + 2
    } else {
        TOY_PAIRING_GENERATOR
    };
    let exponent = mul_mod_u64(left, right, TOY_PAIRING_ORDER);
    mod_pow_u64(base, exponent, TOY_PAIRING_TARGET_MODULUS)
}

fn pairing_eval_to_string(eval: &PairingEval) -> String {
    match eval {
        PairingEval::Bool(value) => format!("bool:{value}"),
        PairingEval::Error(error) => format!("error:{error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_has_zero_pairing_failures() {
        let config = PairingFuzzConfig::new();
        let report = run_pairing_fuzz_campaign(&config);
        assert_eq!(report.property_failures, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn weak_profile_detects_pairing_issues() {
        let mut config = PairingFuzzConfig::new();
        config.implementation_profile = PairingImplementationProfile::WeakSubgroupChecks;

        let report = run_pairing_fuzz_campaign(&config);
        assert!(report.property_failures > 0);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn default_matrix_checks_all_combinations_and_properties() {
        let report = run_pairing_fuzz_campaign(&PairingFuzzConfig::new());
        assert_eq!(report.total_combinations, 25);
        assert_eq!(report.total_checks, 125);
    }
}
