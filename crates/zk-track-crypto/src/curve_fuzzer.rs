use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

use crate::generators::{generate_curve_point, CurvePointSample, CurvePointType, TOY_CURVE_ORDER};
use crate::oracle::{add_mod_u64, mul_mod_u64, sub_mod_u64};
use crate::property_checker::bool_property;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CurveOperation {
    PointAddition,
    PointDoubling,
    ScalarMultiplication,
    MultiScalarMultiplication,
    PointNegation,
    PointValidation,
}

impl CurveOperation {
    pub const ALL: [CurveOperation; 6] = [
        Self::PointAddition,
        Self::PointDoubling,
        Self::ScalarMultiplication,
        Self::MultiScalarMultiplication,
        Self::PointNegation,
        Self::PointValidation,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PointAddition => "point_addition",
            Self::PointDoubling => "point_doubling",
            Self::ScalarMultiplication => "scalar_multiplication",
            Self::MultiScalarMultiplication => "multi_scalar_multiplication",
            Self::PointNegation => "point_negation",
            Self::PointValidation => "point_validation",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CurveEdgeCase {
    AddingIdentity,
    AddingInverse,
    DoublingIdentity,
    ZeroScalar,
    OneScalar,
    LargeScalarWraparound,
    InvalidPointRejection,
}

impl CurveEdgeCase {
    pub const ALL: [CurveEdgeCase; 7] = [
        Self::AddingIdentity,
        Self::AddingInverse,
        Self::DoublingIdentity,
        Self::ZeroScalar,
        Self::OneScalar,
        Self::LargeScalarWraparound,
        Self::InvalidPointRejection,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddingIdentity => "adding_identity",
            Self::AddingInverse => "adding_inverse",
            Self::DoublingIdentity => "doubling_identity",
            Self::ZeroScalar => "zero_scalar",
            Self::OneScalar => "one_scalar",
            Self::LargeScalarWraparound => "large_scalar_wraparound",
            Self::InvalidPointRejection => "invalid_point_rejection",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CurveImplementationProfile {
    StrictValidation,
    WeakInvalidHandling,
}

impl CurveImplementationProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictValidation => "strict_validation",
            Self::WeakInvalidHandling => "weak_invalid_handling",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurveOperationFuzzConfig {
    pub seed: u64,
    pub iterations: usize,
    pub point_types: Vec<CurvePointType>,
    pub operations: Vec<CurveOperation>,
    pub edge_cases: Vec<CurveEdgeCase>,
    pub implementation_profile: CurveImplementationProfile,
}

impl CurveOperationFuzzConfig {
    pub fn new() -> Self {
        Self {
            seed: 20_260_223,
            iterations: 50,
            point_types: CurvePointType::ALL.to_vec(),
            operations: CurveOperation::ALL.to_vec(),
            edge_cases: CurveEdgeCase::ALL.to_vec(),
            implementation_profile: CurveImplementationProfile::StrictValidation,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurveOperationFuzzFinding {
    pub case_id: String,
    pub category: String,
    pub check_name: String,
    pub reason: String,
    pub expected: String,
    pub observed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurveOperationFuzzReport {
    pub seed: u64,
    pub implementation_profile: CurveImplementationProfile,
    pub iterations: usize,
    pub point_type_count: usize,
    pub total_checks: usize,
    pub operation_checks: usize,
    pub edge_case_checks: usize,
    pub operation_divergences: usize,
    pub edge_case_failures: usize,
    pub checks_by_operation: BTreeMap<String, usize>,
    pub divergences_by_operation: BTreeMap<String, usize>,
    pub checks_by_edge_case: BTreeMap<String, usize>,
    pub failures_by_edge_case: BTreeMap<String, usize>,
    pub findings: Vec<CurveOperationFuzzFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CurveEval {
    Point(u64),
    Validation(bool),
    Error(&'static str),
}

pub fn run_curve_operation_fuzz_campaign(
    config: &CurveOperationFuzzConfig,
) -> CurveOperationFuzzReport {
    let point_types = dedup_point_types(&config.point_types);
    let operations = dedup_operations(&config.operations);
    let edge_cases = dedup_edge_cases(&config.edge_cases);
    let mut rng = StdRng::seed_from_u64(config.seed);

    let mut report = CurveOperationFuzzReport {
        seed: config.seed,
        implementation_profile: config.implementation_profile,
        iterations: config.iterations,
        point_type_count: point_types.len(),
        total_checks: 0,
        operation_checks: 0,
        edge_case_checks: 0,
        operation_divergences: 0,
        edge_case_failures: 0,
        checks_by_operation: BTreeMap::new(),
        divergences_by_operation: BTreeMap::new(),
        checks_by_edge_case: BTreeMap::new(),
        failures_by_edge_case: BTreeMap::new(),
        findings: Vec::new(),
    };

    for iteration in 0..config.iterations {
        for (point_idx, point_type) in point_types.iter().enumerate() {
            let left = generate_curve_point(*point_type, iteration + point_idx, &mut rng);
            let right_type = point_types[(point_idx + iteration + 1) % point_types.len()];
            let right = generate_curve_point(right_type, iteration + point_idx + 17, &mut rng);
            let scalar = ((iteration as u64) + (point_idx as u64) + 2) % (TOY_CURVE_ORDER * 2);

            for operation in &operations {
                let expected = evaluate_curve_operation(
                    *operation,
                    &left,
                    &right,
                    scalar,
                    CurveImplementationProfile::StrictValidation,
                );
                let observed = evaluate_curve_operation(
                    *operation,
                    &left,
                    &right,
                    scalar,
                    config.implementation_profile,
                );

                report.total_checks += 1;
                report.operation_checks += 1;
                *report
                    .checks_by_operation
                    .entry(operation.as_str().to_string())
                    .or_insert(0) += 1;

                if expected != observed {
                    report.operation_divergences += 1;
                    *report
                        .divergences_by_operation
                        .entry(operation.as_str().to_string())
                        .or_insert(0) += 1;
                    report.findings.push(CurveOperationFuzzFinding {
                        case_id: format!("curve-op-{iteration:03}-{point_idx:03}"),
                        category: "operation_mismatch".to_string(),
                        check_name: operation.as_str().to_string(),
                        reason: "candidate operation diverged from strict validation model"
                            .to_string(),
                        expected: curve_eval_to_string(&expected),
                        observed: curve_eval_to_string(&observed),
                    });
                }
            }
        }
    }

    run_edge_case_checks(&edge_cases, config.implementation_profile, &mut report);

    report
}

fn dedup_point_types(values: &[CurvePointType]) -> Vec<CurvePointType> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(value) {
            deduped.push(*value);
        }
    }
    if deduped.is_empty() {
        CurvePointType::ALL.to_vec()
    } else {
        deduped
    }
}

fn dedup_operations(values: &[CurveOperation]) -> Vec<CurveOperation> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(value) {
            deduped.push(*value);
        }
    }
    if deduped.is_empty() {
        CurveOperation::ALL.to_vec()
    } else {
        deduped
    }
}

fn dedup_edge_cases(values: &[CurveEdgeCase]) -> Vec<CurveEdgeCase> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(value) {
            deduped.push(*value);
        }
    }
    if deduped.is_empty() {
        CurveEdgeCase::ALL.to_vec()
    } else {
        deduped
    }
}

fn evaluate_curve_operation(
    operation: CurveOperation,
    left: &CurvePointSample,
    right: &CurvePointSample,
    scalar: u64,
    profile: CurveImplementationProfile,
) -> CurveEval {
    match operation {
        CurveOperation::PointValidation => {
            CurveEval::Validation(resolve_curve_value(left, profile).is_ok())
        }
        CurveOperation::PointAddition => {
            let lhs = match resolve_curve_value(left, profile) {
                Ok(value) => value,
                Err(error) => return CurveEval::Error(error),
            };
            let rhs = match resolve_curve_value(right, profile) {
                Ok(value) => value,
                Err(error) => return CurveEval::Error(error),
            };
            let mut sum = add_mod_u64(lhs, rhs, TOY_CURVE_ORDER);
            if profile == CurveImplementationProfile::WeakInvalidHandling
                && lhs != 0
                && rhs != 0
                && sum == 0
            {
                sum = 1;
            }
            CurveEval::Point(sum)
        }
        CurveOperation::PointDoubling => {
            let lhs = match resolve_curve_value(left, profile) {
                Ok(value) => value,
                Err(error) => return CurveEval::Error(error),
            };
            CurveEval::Point(add_mod_u64(lhs, lhs, TOY_CURVE_ORDER))
        }
        CurveOperation::ScalarMultiplication => {
            let lhs = match resolve_curve_value(left, profile) {
                Ok(value) => value,
                Err(error) => return CurveEval::Error(error),
            };
            if profile == CurveImplementationProfile::WeakInvalidHandling && scalar == 0 {
                CurveEval::Point(lhs)
            } else {
                CurveEval::Point(mul_mod_u64(lhs, scalar % TOY_CURVE_ORDER, TOY_CURVE_ORDER))
            }
        }
        CurveOperation::MultiScalarMultiplication => {
            let lhs = match resolve_curve_value(left, profile) {
                Ok(value) => value,
                Err(error) => return CurveEval::Error(error),
            };
            let rhs = match resolve_curve_value(right, profile) {
                Ok(value) => value,
                Err(error) => return CurveEval::Error(error),
            };
            let first = mul_mod_u64(lhs, scalar % TOY_CURVE_ORDER, TOY_CURVE_ORDER);
            let second = mul_mod_u64(rhs, (scalar + 1) % TOY_CURVE_ORDER, TOY_CURVE_ORDER);
            CurveEval::Point(add_mod_u64(first, second, TOY_CURVE_ORDER))
        }
        CurveOperation::PointNegation => {
            let lhs = match resolve_curve_value(left, profile) {
                Ok(value) => value,
                Err(error) => return CurveEval::Error(error),
            };
            CurveEval::Point(sub_mod_u64(0, lhs, TOY_CURVE_ORDER))
        }
    }
}

fn resolve_curve_value(
    point: &CurvePointSample,
    profile: CurveImplementationProfile,
) -> Result<u64, &'static str> {
    if point.value.is_none() {
        if profile == CurveImplementationProfile::WeakInvalidHandling {
            return Ok(0);
        }
        return Err("invalid_point");
    }

    let value = point.value.unwrap_or(0) % TOY_CURVE_ORDER;
    if point.low_order_hint && profile == CurveImplementationProfile::StrictValidation {
        return Err("low_order_point");
    }

    Ok(value)
}

fn curve_eval_to_string(value: &CurveEval) -> String {
    match value {
        CurveEval::Point(value) => format!("point:{value}"),
        CurveEval::Validation(value) => format!("validation:{value}"),
        CurveEval::Error(error) => format!("error:{error}"),
    }
}

fn run_edge_case_checks(
    edge_cases: &[CurveEdgeCase],
    profile: CurveImplementationProfile,
    report: &mut CurveOperationFuzzReport,
) {
    let generator = CurvePointSample {
        point_type: CurvePointType::Generator,
        value: Some(1),
        low_order_hint: false,
        infinity_encoding: false,
    };
    let identity = CurvePointSample {
        point_type: CurvePointType::Identity,
        value: Some(0),
        low_order_hint: false,
        infinity_encoding: false,
    };
    let invalid = CurvePointSample {
        point_type: CurvePointType::InvalidNotOnCurve,
        value: None,
        low_order_hint: false,
        infinity_encoding: false,
    };

    for edge_case in edge_cases {
        *report
            .checks_by_edge_case
            .entry(edge_case.as_str().to_string())
            .or_insert(0) += 1;
        report.total_checks += 1;
        report.edge_case_checks += 1;

        let (expected, observed, reason) = match edge_case {
            CurveEdgeCase::AddingIdentity => {
                let observed = evaluate_curve_operation(
                    CurveOperation::PointAddition,
                    &generator,
                    &identity,
                    0,
                    profile,
                );
                (
                    CurveEval::Point(1),
                    observed,
                    "P + O must equal P".to_string(),
                )
            }
            CurveEdgeCase::AddingInverse => {
                let inverse = CurvePointSample {
                    point_type: CurvePointType::RandomValidAlt,
                    value: Some(sub_mod_u64(0, 1, TOY_CURVE_ORDER)),
                    low_order_hint: false,
                    infinity_encoding: false,
                };
                let observed = evaluate_curve_operation(
                    CurveOperation::PointAddition,
                    &generator,
                    &inverse,
                    0,
                    profile,
                );
                (
                    CurveEval::Point(0),
                    observed,
                    "P + (-P) must be identity".to_string(),
                )
            }
            CurveEdgeCase::DoublingIdentity => {
                let observed = evaluate_curve_operation(
                    CurveOperation::PointDoubling,
                    &identity,
                    &identity,
                    0,
                    profile,
                );
                (
                    CurveEval::Point(0),
                    observed,
                    "2O must stay identity".to_string(),
                )
            }
            CurveEdgeCase::ZeroScalar => {
                let observed = evaluate_curve_operation(
                    CurveOperation::ScalarMultiplication,
                    &generator,
                    &identity,
                    0,
                    profile,
                );
                (
                    CurveEval::Point(0),
                    observed,
                    "[0]P must equal identity".to_string(),
                )
            }
            CurveEdgeCase::OneScalar => {
                let observed = evaluate_curve_operation(
                    CurveOperation::ScalarMultiplication,
                    &generator,
                    &identity,
                    1,
                    profile,
                );
                (
                    CurveEval::Point(1),
                    observed,
                    "[1]P must equal P".to_string(),
                )
            }
            CurveEdgeCase::LargeScalarWraparound => {
                let observed = evaluate_curve_operation(
                    CurveOperation::ScalarMultiplication,
                    &generator,
                    &identity,
                    TOY_CURVE_ORDER,
                    profile,
                );
                (
                    CurveEval::Point(0),
                    observed,
                    "[order]P must wrap to identity".to_string(),
                )
            }
            CurveEdgeCase::InvalidPointRejection => {
                let observed = evaluate_curve_operation(
                    CurveOperation::PointAddition,
                    &invalid,
                    &generator,
                    0,
                    profile,
                );
                (
                    CurveEval::Error("invalid_point"),
                    observed,
                    "invalid inputs must be rejected".to_string(),
                )
            }
        };

        let check = bool_property(edge_case.as_str(), true, expected == observed, &reason);
        if !check.passed {
            report.edge_case_failures += 1;
            *report
                .failures_by_edge_case
                .entry(edge_case.as_str().to_string())
                .or_insert(0) += 1;
            report.findings.push(CurveOperationFuzzFinding {
                case_id: format!("curve-edge-{}", edge_case.as_str()),
                category: "edge_case_failure".to_string(),
                check_name: edge_case.as_str().to_string(),
                reason,
                expected: curve_eval_to_string(&expected),
                observed: curve_eval_to_string(&observed),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_has_clean_curve_report() {
        let mut config = CurveOperationFuzzConfig::new();
        config.iterations = 10;
        config.implementation_profile = CurveImplementationProfile::StrictValidation;

        let report = run_curve_operation_fuzz_campaign(&config);
        assert_eq!(report.operation_divergences, 0);
        assert_eq!(report.edge_case_failures, 0);
    }

    #[test]
    fn weak_profile_surfaces_curve_findings() {
        let mut config = CurveOperationFuzzConfig::new();
        config.iterations = 8;
        config.implementation_profile = CurveImplementationProfile::WeakInvalidHandling;

        let report = run_curve_operation_fuzz_campaign(&config);
        assert!(report.operation_divergences > 0 || report.edge_case_failures > 0);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn default_curve_campaign_exceeds_target_checks() {
        let report = run_curve_operation_fuzz_campaign(&CurveOperationFuzzConfig::new());
        assert!(report.operation_checks >= 350);
    }
}
