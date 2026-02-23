use std::collections::BTreeMap;

use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};

use crate::generators::{field_modulus, generate_field_values};
use crate::oracle::{mod_add, mod_inverse, mod_mul, mod_pow, mod_reduce, mod_sub};
use crate::property_checker::{bool_property, PropertyCheckRecord};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FieldOperation {
    Addition,
    Subtraction,
    Multiplication,
    Division,
    Exponentiation,
    ModularReduction,
}

impl FieldOperation {
    pub const ALL: [FieldOperation; 6] = [
        Self::Addition,
        Self::Subtraction,
        Self::Multiplication,
        Self::Division,
        Self::Exponentiation,
        Self::ModularReduction,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Addition => "addition",
            Self::Subtraction => "subtraction",
            Self::Multiplication => "multiplication",
            Self::Division => "division",
            Self::Exponentiation => "exponentiation",
            Self::ModularReduction => "modular_reduction",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FieldProperty {
    Commutativity,
    Associativity,
    Distributivity,
    Identity,
    Inverse,
}

impl FieldProperty {
    pub const ALL: [FieldProperty; 5] = [
        Self::Commutativity,
        Self::Associativity,
        Self::Distributivity,
        Self::Identity,
        Self::Inverse,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commutativity => "commutativity",
            Self::Associativity => "associativity",
            Self::Distributivity => "distributivity",
            Self::Identity => "identity",
            Self::Inverse => "inverse",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FieldImplementationProfile {
    StrictReference,
    WeakReduction,
}

impl FieldImplementationProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictReference => "strict_reference",
            Self::WeakReduction => "weak_reduction",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldArithmeticFuzzConfig {
    pub seed: u64,
    pub random_values: usize,
    pub operations: Vec<FieldOperation>,
    pub properties: Vec<FieldProperty>,
    pub implementation_profile: FieldImplementationProfile,
}

impl FieldArithmeticFuzzConfig {
    pub fn new() -> Self {
        Self {
            seed: 20_260_223,
            random_values: 8,
            operations: FieldOperation::ALL.to_vec(),
            properties: FieldProperty::ALL.to_vec(),
            implementation_profile: FieldImplementationProfile::StrictReference,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldArithmeticFuzzFinding {
    pub case_id: String,
    pub category: String,
    pub check_name: String,
    pub reason: String,
    pub expected: String,
    pub observed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldArithmeticFuzzReport {
    pub seed: u64,
    pub implementation_profile: FieldImplementationProfile,
    pub field_modulus: String,
    pub edge_case_values: usize,
    pub random_values: usize,
    pub total_values: usize,
    pub total_checks: usize,
    pub operation_checks: usize,
    pub property_checks: usize,
    pub operation_divergences: usize,
    pub property_failures: usize,
    pub checks_by_operation: BTreeMap<String, usize>,
    pub divergences_by_operation: BTreeMap<String, usize>,
    pub checks_by_property: BTreeMap<String, usize>,
    pub failures_by_property: BTreeMap<String, usize>,
    pub findings: Vec<FieldArithmeticFuzzFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FieldEval {
    Value(BigUint),
    Error(&'static str),
}

pub fn run_field_arithmetic_fuzz_campaign(
    config: &FieldArithmeticFuzzConfig,
) -> FieldArithmeticFuzzReport {
    let modulus = field_modulus().clone();
    let edge_case_values = 10;
    let random_values = config.random_values;
    let values = generate_field_values(config.seed, random_values);
    let operations = dedup_operations(&config.operations);
    let properties = dedup_properties(&config.properties);

    let mut report = FieldArithmeticFuzzReport {
        seed: config.seed,
        implementation_profile: config.implementation_profile,
        field_modulus: modulus.to_string(),
        edge_case_values,
        random_values,
        total_values: values.len(),
        total_checks: 0,
        operation_checks: 0,
        property_checks: 0,
        operation_divergences: 0,
        property_failures: 0,
        checks_by_operation: BTreeMap::new(),
        divergences_by_operation: BTreeMap::new(),
        checks_by_property: BTreeMap::new(),
        failures_by_property: BTreeMap::new(),
        findings: Vec::new(),
    };

    for (left_idx, left) in values.iter().enumerate() {
        for (right_idx, right) in values.iter().enumerate() {
            for operation in &operations {
                let expected = reference_field_eval(*operation, left, right, &modulus);
                let observed = candidate_field_eval(
                    *operation,
                    left,
                    right,
                    &modulus,
                    config.implementation_profile,
                );

                report.total_checks += 1;
                report.operation_checks += 1;
                *report
                    .checks_by_operation
                    .entry(operation.as_str().to_string())
                    .or_insert(0) += 1;

                if !field_eval_equals(&expected, &observed) {
                    report.operation_divergences += 1;
                    *report
                        .divergences_by_operation
                        .entry(operation.as_str().to_string())
                        .or_insert(0) += 1;

                    report.findings.push(FieldArithmeticFuzzFinding {
                        case_id: format!("field-op-{left_idx:03}-{right_idx:03}"),
                        category: "operation_mismatch".to_string(),
                        check_name: operation.as_str().to_string(),
                        reason: format!("candidate {} diverged from reference", operation.as_str()),
                        expected: field_eval_to_string(&expected),
                        observed: field_eval_to_string(&observed),
                    });
                }
            }
        }
    }

    for property in properties {
        run_property_checks(
            property,
            &values,
            &modulus,
            config.implementation_profile,
            &mut report,
        );
    }

    report
}

fn dedup_operations(values: &[FieldOperation]) -> Vec<FieldOperation> {
    let mut deduped = Vec::new();
    for operation in values {
        if !deduped.contains(operation) {
            deduped.push(*operation);
        }
    }
    if deduped.is_empty() {
        FieldOperation::ALL.to_vec()
    } else {
        deduped
    }
}

fn dedup_properties(values: &[FieldProperty]) -> Vec<FieldProperty> {
    let mut deduped = Vec::new();
    for property in values {
        if !deduped.contains(property) {
            deduped.push(*property);
        }
    }
    if deduped.is_empty() {
        FieldProperty::ALL.to_vec()
    } else {
        deduped
    }
}

fn exponent_from(value: &BigUint) -> BigUint {
    let bytes = value.to_bytes_be();
    let mut reduced = 0u64;
    for byte in bytes.iter().take(4) {
        reduced = (reduced << 8) | *byte as u64;
    }
    BigUint::from(reduced % 32)
}

fn reference_field_eval(
    operation: FieldOperation,
    left: &BigUint,
    right: &BigUint,
    modulus: &BigUint,
) -> FieldEval {
    let left = mod_reduce(left, modulus);
    let right = mod_reduce(right, modulus);
    match operation {
        FieldOperation::Addition => FieldEval::Value(mod_add(&left, &right, modulus)),
        FieldOperation::Subtraction => FieldEval::Value(mod_sub(&left, &right, modulus)),
        FieldOperation::Multiplication => FieldEval::Value(mod_mul(&left, &right, modulus)),
        FieldOperation::Division => {
            if right.is_zero() {
                FieldEval::Error("division_by_zero")
            } else {
                match mod_inverse(&right, modulus) {
                    Some(inverse) => FieldEval::Value(mod_mul(&left, &inverse, modulus)),
                    None => FieldEval::Error("missing_inverse"),
                }
            }
        }
        FieldOperation::Exponentiation => {
            let exponent = exponent_from(&right);
            FieldEval::Value(mod_pow(&left, &exponent, modulus))
        }
        FieldOperation::ModularReduction => FieldEval::Value(mod_reduce(&(left + right), modulus)),
    }
}

fn candidate_field_eval(
    operation: FieldOperation,
    left: &BigUint,
    right: &BigUint,
    modulus: &BigUint,
    profile: FieldImplementationProfile,
) -> FieldEval {
    if profile == FieldImplementationProfile::StrictReference {
        return reference_field_eval(operation, left, right, modulus);
    }

    let left_raw = left.clone();
    let right_raw = right.clone();
    let left = mod_reduce(left, modulus);
    let right = mod_reduce(right, modulus);

    match operation {
        FieldOperation::Addition => {
            let raw = left_raw + right_raw;
            if raw == *modulus {
                FieldEval::Value(raw)
            } else {
                FieldEval::Value(raw % modulus)
            }
        }
        FieldOperation::Subtraction => {
            if left_raw < right_raw {
                FieldEval::Value(right_raw - left_raw)
            } else {
                FieldEval::Value((left_raw - right_raw) % modulus)
            }
        }
        FieldOperation::Multiplication => {
            let raw = left_raw * right_raw;
            if raw == *modulus {
                FieldEval::Value(raw)
            } else {
                FieldEval::Value(raw % modulus)
            }
        }
        FieldOperation::Division => {
            if right.is_zero() {
                FieldEval::Value(BigUint::zero())
            } else if left.is_zero() {
                FieldEval::Value(modulus.clone())
            } else {
                match mod_inverse(&right, modulus) {
                    Some(inverse) => FieldEval::Value(mod_mul(&left, &inverse, modulus)),
                    None => FieldEval::Error("missing_inverse"),
                }
            }
        }
        FieldOperation::Exponentiation => {
            let exponent = exponent_from(&right);
            if exponent.is_zero() {
                FieldEval::Value(BigUint::zero())
            } else {
                FieldEval::Value(mod_pow(&left, &exponent, modulus))
            }
        }
        FieldOperation::ModularReduction => {
            let raw = left_raw + right_raw;
            if raw >= *modulus && raw <= (modulus + BigUint::from(2u8)) {
                FieldEval::Value(raw)
            } else {
                FieldEval::Value(raw % modulus)
            }
        }
    }
}

fn field_eval_equals(left: &FieldEval, right: &FieldEval) -> bool {
    match (left, right) {
        (FieldEval::Value(left), FieldEval::Value(right)) => left == right,
        (FieldEval::Error(left), FieldEval::Error(right)) => left == right,
        _ => false,
    }
}

fn field_eval_to_string(value: &FieldEval) -> String {
    match value {
        FieldEval::Value(value) => value.to_string(),
        FieldEval::Error(error) => format!("error:{error}"),
    }
}

fn run_property_checks(
    property: FieldProperty,
    values: &[BigUint],
    modulus: &BigUint,
    profile: FieldImplementationProfile,
    report: &mut FieldArithmeticFuzzReport,
) {
    match property {
        FieldProperty::Commutativity => {
            let budget = values.len().min(20);
            for left_idx in 0..budget {
                for right_idx in 0..budget {
                    let left = &values[left_idx];
                    let right = &values[right_idx];

                    let observed_add = bool_property(
                        "commutativity:addition",
                        true,
                        field_eval_equals(
                            &candidate_field_eval(
                                FieldOperation::Addition,
                                left,
                                right,
                                modulus,
                                profile,
                            ),
                            &candidate_field_eval(
                                FieldOperation::Addition,
                                right,
                                left,
                                modulus,
                                profile,
                            ),
                        ),
                        "candidate addition commutativity",
                    );
                    commit_property_record(report, observed_add, property, left_idx, right_idx);

                    let observed_mul = bool_property(
                        "commutativity:multiplication",
                        true,
                        field_eval_equals(
                            &candidate_field_eval(
                                FieldOperation::Multiplication,
                                left,
                                right,
                                modulus,
                                profile,
                            ),
                            &candidate_field_eval(
                                FieldOperation::Multiplication,
                                right,
                                left,
                                modulus,
                                profile,
                            ),
                        ),
                        "candidate multiplication commutativity",
                    );
                    commit_property_record(report, observed_mul, property, left_idx, right_idx);
                }
            }
        }
        FieldProperty::Associativity => {
            let budget = values.len().min(24);
            for idx in 0..budget {
                let left = &values[idx];
                let mid = &values[(idx + 1) % budget];
                let right = &values[(idx + 2) % budget];

                let lhs = candidate_field_eval(
                    FieldOperation::Addition,
                    &as_value(candidate_field_eval(
                        FieldOperation::Addition,
                        left,
                        mid,
                        modulus,
                        profile,
                    )),
                    right,
                    modulus,
                    profile,
                );
                let rhs = candidate_field_eval(
                    FieldOperation::Addition,
                    left,
                    &as_value(candidate_field_eval(
                        FieldOperation::Addition,
                        mid,
                        right,
                        modulus,
                        profile,
                    )),
                    modulus,
                    profile,
                );
                let record = bool_property(
                    "associativity:addition",
                    true,
                    field_eval_equals(&lhs, &rhs),
                    "candidate addition associativity",
                );
                commit_property_record(report, record, property, idx, idx + 1);
            }
        }
        FieldProperty::Distributivity => {
            let budget = values.len().min(24);
            for idx in 0..budget {
                let left = &values[idx];
                let mid = &values[(idx + 3) % budget];
                let right = &values[(idx + 7) % budget];

                let sum = as_value(candidate_field_eval(
                    FieldOperation::Addition,
                    mid,
                    right,
                    modulus,
                    profile,
                ));
                let lhs = candidate_field_eval(
                    FieldOperation::Multiplication,
                    left,
                    &sum,
                    modulus,
                    profile,
                );
                let lm = as_value(candidate_field_eval(
                    FieldOperation::Multiplication,
                    left,
                    mid,
                    modulus,
                    profile,
                ));
                let lr = as_value(candidate_field_eval(
                    FieldOperation::Multiplication,
                    left,
                    right,
                    modulus,
                    profile,
                ));
                let rhs =
                    candidate_field_eval(FieldOperation::Addition, &lm, &lr, modulus, profile);

                let record = bool_property(
                    "distributivity",
                    true,
                    field_eval_equals(&lhs, &rhs),
                    "candidate distributivity",
                );
                commit_property_record(report, record, property, idx, idx + 2);
            }
        }
        FieldProperty::Identity => {
            for (idx, value) in values.iter().enumerate() {
                let add_identity = candidate_field_eval(
                    FieldOperation::Addition,
                    value,
                    &BigUint::zero(),
                    modulus,
                    profile,
                );
                let record_add = bool_property(
                    "identity:addition",
                    true,
                    field_eval_equals(&add_identity, &FieldEval::Value(mod_reduce(value, modulus))),
                    "a + 0 == a",
                );
                commit_property_record(report, record_add, property, idx, idx);

                let mul_identity = candidate_field_eval(
                    FieldOperation::Multiplication,
                    value,
                    &BigUint::from(1u8),
                    modulus,
                    profile,
                );
                let record_mul = bool_property(
                    "identity:multiplication",
                    true,
                    field_eval_equals(&mul_identity, &FieldEval::Value(mod_reduce(value, modulus))),
                    "a * 1 == a",
                );
                commit_property_record(report, record_mul, property, idx, idx);
            }
        }
        FieldProperty::Inverse => {
            for (idx, value) in values.iter().enumerate() {
                let reduced = mod_reduce(value, modulus);
                if reduced.is_zero() {
                    continue;
                }

                let result = candidate_field_eval(
                    FieldOperation::Division,
                    &reduced,
                    &reduced,
                    modulus,
                    profile,
                );
                let record = bool_property(
                    "inverse:division",
                    true,
                    field_eval_equals(&result, &FieldEval::Value(BigUint::from(1u8))),
                    "a / a == 1",
                );
                commit_property_record(report, record, property, idx, idx);
            }
        }
    }
}

fn as_value(value: FieldEval) -> BigUint {
    match value {
        FieldEval::Value(value) => value,
        FieldEval::Error(_) => BigUint::zero(),
    }
}

fn commit_property_record(
    report: &mut FieldArithmeticFuzzReport,
    record: PropertyCheckRecord,
    property: FieldProperty,
    left_idx: usize,
    right_idx: usize,
) {
    report.total_checks += 1;
    report.property_checks += 1;
    *report
        .checks_by_property
        .entry(property.as_str().to_string())
        .or_insert(0) += 1;

    if !record.passed {
        report.property_failures += 1;
        *report
            .failures_by_property
            .entry(property.as_str().to_string())
            .or_insert(0) += 1;

        report.findings.push(FieldArithmeticFuzzFinding {
            case_id: format!("field-prop-{left_idx:03}-{right_idx:03}"),
            category: "property_failure".to_string(),
            check_name: record.property,
            reason: record.reason,
            expected: record.expected,
            observed: record.observed,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_reports_no_findings() {
        let mut config = FieldArithmeticFuzzConfig::new();
        config.random_values = 4;
        config.implementation_profile = FieldImplementationProfile::StrictReference;

        let report = run_field_arithmetic_fuzz_campaign(&config);
        assert_eq!(report.operation_divergences, 0);
        assert_eq!(report.property_failures, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn weak_profile_surfaces_field_findings() {
        let mut config = FieldArithmeticFuzzConfig::new();
        config.random_values = 2;
        config.implementation_profile = FieldImplementationProfile::WeakReduction;

        let report = run_field_arithmetic_fuzz_campaign(&config);
        assert!(report.operation_divergences > 0 || report.property_failures > 0);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn default_campaign_exceeds_thousand_checks() {
        let report = run_field_arithmetic_fuzz_campaign(&FieldArithmeticFuzzConfig::new());
        assert!(report.total_checks >= 1_000);
    }
}
