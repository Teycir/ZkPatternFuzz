//! Oracle Validation Framework
//!
//! Phase 0 Fix: Provides mechanisms to validate oracles themselves,
//! reducing false positives from buggy or misconfigured oracles.
//!
//! # Validation Strategies
//!
//! 1. **Differential Validation**: Run multiple oracles on the same inputs
//!    and flag disagreements for review.
//!
//! 2. **Ground Truth Validation**: Test oracles against known-good and
//!    known-bad circuits to verify correct detection.
//!
//! 3. **Oracle Mutation Testing**: Inject known bugs and verify oracles
//!    detect them (tests for false negatives).
//!
//! # Usage
//!
//! ```ignore
//! let validator = OracleValidator::new()
//!     .with_differential(vec![oracle1, oracle2])
//!     .with_ground_truth(known_good_circuits);
//!
//! let validation_result = validator.validate(&finding);
//! if !validation_result.is_valid {
//!     // Finding may be a false positive
//! }
//! ```

use super::oracle::BugOracle;
use std::collections::HashMap;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, Severity, TestCase};

/// Result of validating a finding
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the finding passed validation
    pub is_valid: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Reasons for the validation decision
    pub reasons: Vec<String>,
    /// Oracles that agreed with the finding
    pub agreeing_oracles: Vec<String>,
    /// Oracles that disagreed with the finding
    pub disagreeing_oracles: Vec<String>,
}

impl ValidationResult {
    /// Create a valid result with high confidence
    pub fn valid(reasons: Vec<String>) -> Self {
        Self {
            is_valid: true,
            confidence: 1.0,
            reasons,
            agreeing_oracles: vec![],
            disagreeing_oracles: vec![],
        }
    }

    /// Create an invalid result (likely false positive)
    pub fn invalid(reasons: Vec<String>) -> Self {
        Self {
            is_valid: false,
            confidence: 0.0,
            reasons,
            agreeing_oracles: vec![],
            disagreeing_oracles: vec![],
        }
    }

    /// Create a result with partial confidence
    pub fn partial(confidence: f64, reasons: Vec<String>) -> Self {
        Self {
            is_valid: confidence >= 0.5,
            confidence,
            reasons,
            agreeing_oracles: vec![],
            disagreeing_oracles: vec![],
        }
    }
}

/// Configuration for oracle validation
///
/// # Phase 0 Fix: Evidence Confidence Thresholds
///
/// The default configuration now allows single-oracle findings to pass validation
/// when they are reproducible, aligning with the documented confidence model:
/// - MEDIUM confidence: 1 oracle + successful validation/reproduction
/// - HIGH confidence: 2+ independent oracle groups agree
/// - CRITICAL confidence: all groups + invariant violation
///
/// Previously, `cross_oracle_threshold` defaulted to 2, which would drop valid
/// single-oracle findings. This has been fixed by lowering `min_agreement_ratio`
/// and adding `allow_single_oracle_with_reproduction`.
#[derive(Debug, Clone)]
pub struct OracleValidationConfig {
    /// Minimum oracle agreement ratio to consider finding valid
    /// Phase 0 Fix: Lowered from 0.6 to 0.5 to allow single-oracle findings
    pub min_agreement_ratio: f64,
    /// Whether to require ground truth validation
    pub require_ground_truth: bool,
    /// Number of mutation tests to run
    pub mutation_test_count: usize,
    /// Minimum mutation detection rate to trust oracle
    pub min_mutation_detection_rate: f64,
    /// Whether to skip stateful oracles during differential validation
    pub skip_stateful_oracles: bool,
    /// Whether to allow cross-attack-type validation using related families
    pub allow_cross_attack_type: bool,
    /// Weight assigned to cross-attack-type agreement (0.0 - 1.0)
    pub cross_attack_weight: f64,
    /// Whether to reset stateful oracles between validations
    pub reset_stateful_oracles: bool,
    /// Phase 0 Fix: Allow single-oracle findings if reproduction succeeds
    /// When true, a single oracle can produce a valid finding if the
    /// reproduction step succeeds (witness executes and produces expected output)
    pub allow_single_oracle_with_reproduction: bool,
    /// Minimum confidence level for filtering in reports (not validation)
    /// Phase 0 Fix: Filtering should happen at report generation, not validation
    pub min_confidence_for_report: ConfidenceLevel,
}

/// Re-export ConfidenceLevel for use in config
pub use super::oracle_correlation::ConfidenceLevel;

impl Default for OracleValidationConfig {
    fn default() -> Self {
        Self {
            // Phase 0 Fix: Allow single oracle findings to pass validation
            min_agreement_ratio: 0.5,
            require_ground_truth: false,
            mutation_test_count: 10,
            min_mutation_detection_rate: 0.7,
            skip_stateful_oracles: false,
            allow_cross_attack_type: true,
            cross_attack_weight: 0.5,
            reset_stateful_oracles: true,
            // Phase 0 Fix: Single-oracle reproducible findings are valid
            allow_single_oracle_with_reproduction: true,
            // Phase 0 Fix: Filter at report level, not validation level
            min_confidence_for_report: ConfidenceLevel::Low,
        }
    }
}

impl OracleValidationConfig {
    /// Create a strict config that requires cross-oracle confirmation
    /// Use this for high-stakes audits where false positives are costly
    pub fn strict() -> Self {
        Self {
            min_agreement_ratio: 0.7,
            require_ground_truth: true,
            mutation_test_count: 20,
            min_mutation_detection_rate: 0.8,
            skip_stateful_oracles: false,
            allow_cross_attack_type: true,
            cross_attack_weight: 0.5,
            reset_stateful_oracles: true,
            allow_single_oracle_with_reproduction: false,
            min_confidence_for_report: ConfidenceLevel::Medium,
        }
    }

    /// Create a permissive config for exploratory fuzzing
    /// Use this when you want to see all potential findings
    pub fn permissive() -> Self {
        Self {
            min_agreement_ratio: 0.3,
            require_ground_truth: false,
            mutation_test_count: 5,
            min_mutation_detection_rate: 0.5,
            skip_stateful_oracles: false,
            allow_cross_attack_type: true,
            cross_attack_weight: 0.7,
            reset_stateful_oracles: true,
            allow_single_oracle_with_reproduction: true,
            min_confidence_for_report: ConfidenceLevel::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttackFamily {
    ConstraintIntegrity,
    Soundness,
    Range,
    Leakage,
    Authorization,
    Setup,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttackMatch {
    Exact,
    Related,
}

impl AttackMatch {
    fn weight(self, cross_weight: f64) -> f64 {
        match self {
            AttackMatch::Exact => 1.0,
            AttackMatch::Related => cross_weight,
        }
    }
}

fn attack_family(attack_type: AttackType) -> AttackFamily {
    match attack_type {
        AttackType::Underconstrained
        | AttackType::ConstraintInference
        | AttackType::ConstraintBypass
        | AttackType::ConstraintSlice
        | AttackType::WitnessCollision
        | AttackType::Metamorphic
        | AttackType::SpecInference
        | AttackType::Collision => AttackFamily::ConstraintIntegrity,
        AttackType::Soundness
        | AttackType::VerificationFuzzing
        | AttackType::Differential
        | AttackType::RecursiveProof
        | AttackType::CircuitComposition => AttackFamily::Soundness,
        AttackType::ArithmeticOverflow | AttackType::Boundary | AttackType::BitDecomposition => {
            AttackFamily::Range
        }
        AttackType::WitnessLeakage
        | AttackType::InformationLeakage
        | AttackType::TimingSideChannel => AttackFamily::Leakage,
        AttackType::Malleability | AttackType::ReplayAttack => AttackFamily::Authorization,
        AttackType::TrustedSetup => AttackFamily::Setup,
        _ => AttackFamily::Other,
    }
}

pub(crate) struct ValidationSample<'a> {
    test_case: &'a TestCase,
    outputs: &'a [FieldElement],
}

/// Ground truth test case for oracle validation
#[derive(Debug, Clone)]
pub struct GroundTruthCase {
    /// Test inputs
    pub inputs: Vec<FieldElement>,
    /// Expected finding (None if no bug should be detected)
    pub expected_bug: Option<ExpectedBug>,
    /// Description of the test case
    pub description: String,
}

/// Expected bug for ground truth validation
#[derive(Debug, Clone)]
pub struct ExpectedBug {
    /// Attack type that should detect this
    pub attack_type: zk_core::AttackType,
    /// Minimum severity expected
    pub min_severity: Severity,
}

/// Statistics about oracle validation
#[derive(Debug, Clone, Default)]
pub struct OracleValidationStats {
    /// Total findings validated
    pub total_validated: usize,
    /// Findings that passed validation
    pub passed: usize,
    /// Findings that failed validation (likely false positives)
    pub failed: usize,
    /// Findings with partial confidence
    pub uncertain: usize,
    /// Oracle agreement statistics
    pub oracle_agreements: HashMap<String, usize>,
    /// Oracle disagreement statistics
    pub oracle_disagreements: HashMap<String, usize>,
}

impl OracleValidationStats {
    /// Get false positive rate estimate
    pub fn estimated_false_positive_rate(&self) -> f64 {
        if self.total_validated == 0 {
            return 0.0;
        }
        self.failed as f64 / self.total_validated as f64
    }
}

/// Oracle validator for reducing false positives
pub struct OracleValidator {
    config: OracleValidationConfig,
    /// Ground truth test cases
    ground_truth: Vec<GroundTruthCase>,
    /// Validation statistics
    stats: OracleValidationStats,
}

impl OracleValidator {
    /// Create a new oracle validator with default config
    pub fn new() -> Self {
        Self {
            config: OracleValidationConfig::default(),
            ground_truth: Vec::new(),
            stats: OracleValidationStats::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: OracleValidationConfig) -> Self {
        Self {
            config,
            ground_truth: Vec::new(),
            stats: OracleValidationStats::default(),
        }
    }

    /// Add ground truth test cases
    pub fn with_ground_truth(mut self, cases: Vec<GroundTruthCase>) -> Self {
        self.ground_truth = cases;
        self
    }

    fn attack_match_kind(&self, expected: AttackType, observed: AttackType) -> Option<AttackMatch> {
        if expected == observed {
            return Some(AttackMatch::Exact);
        }
        if !self.config.allow_cross_attack_type {
            return None;
        }
        let expected_family = attack_family(expected);
        let observed_family = attack_family(observed);
        if expected_family == AttackFamily::Other || observed_family == AttackFamily::Other {
            return None;
        }
        if expected_family == observed_family {
            return Some(AttackMatch::Related);
        }
        None
    }

    /// Validate a finding using differential oracle validation
    ///
    /// Runs multiple oracles on the same test case and checks for agreement.
    pub(crate) fn validate_differential(
        &mut self,
        finding: &Finding,
        oracles: &mut [Box<dyn BugOracle>],
        samples: &[ValidationSample<'_>],
    ) -> ValidationResult {
        if oracles.is_empty() {
            return ValidationResult::valid(vec!["No oracles to compare".to_string()]);
        }

        let finding_attack = finding.attack_type.clone();
        let mut agreeing = Vec::new();
        let mut disagreeing = Vec::new();
        let mut considered = 0usize;
        let mut considered_weight = 0.0f64;
        let mut agreeing_weight = 0.0f64;
        let mut exact_considered = 0usize;
        let mut related_considered = 0usize;
        let mut stateful_skipped = 0usize;

        for oracle in oracles.iter_mut() {
            let stateful = oracle.is_stateful();
            if self.config.skip_stateful_oracles && stateful {
                continue;
            }
            if stateful && self.config.reset_stateful_oracles {
                oracle.reset();
            }

            let relevance = oracle.attack_type().and_then(|attack_type| {
                self.attack_match_kind(finding_attack.clone(), attack_type)
            });
            let Some(relevance) = relevance else {
                continue;
            };

            let oracle_name = oracle.name().to_string();
            let mut found_similar = false;
            for sample in samples {
                let oracle_finding = oracle.check(sample.test_case, sample.outputs);
                if let Some(oracle_finding) = oracle_finding {
                    if oracle_finding.severity >= Severity::Low
                        && self
                            .attack_match_kind(finding_attack.clone(), oracle_finding.attack_type)
                            .is_some()
                    {
                        found_similar = true;
                        break;
                    }
                }
            }

            if stateful && samples.len() < 2 && !found_similar {
                stateful_skipped += 1;
                continue;
            }

            let weight = relevance.weight(self.config.cross_attack_weight);
            if weight <= 0.0 {
                continue;
            }
            considered += 1;
            considered_weight += weight;
            match relevance {
                AttackMatch::Exact => exact_considered += 1,
                AttackMatch::Related => related_considered += 1,
            }

            if found_similar {
                agreeing_weight += weight;
                agreeing.push(oracle_name);
            } else {
                disagreeing.push(oracle_name);
            }
        }

        let total_oracles = agreeing.len() + disagreeing.len();
        self.stats.total_validated += 1;

        if considered == 0 {
            self.stats.uncertain += 1;
            return ValidationResult::partial(
                0.5,
                vec!["No applicable oracles for validation".to_string()],
            );
        }

        let agreement_ratio = if considered_weight > 0.0 {
            agreeing_weight / considered_weight
        } else {
            1.0
        };

        let mut reasons = Vec::new();
        let is_valid = agreement_ratio >= self.config.min_agreement_ratio;

        if is_valid {
            self.stats.passed += 1;
            reasons.push(format!(
                "Oracle agreement: {}/{} ({:.0}%)",
                agreeing.len(),
                total_oracles,
                agreement_ratio * 100.0
            ));
        } else {
            self.stats.failed += 1;
            reasons.push(format!(
                "Low oracle agreement: {}/{} ({:.0}%) - possible false positive",
                agreeing.len(),
                total_oracles,
                agreement_ratio * 100.0
            ));
        }

        if related_considered > 0 {
            reasons.push(format!(
                "Cross-attack validation used ({} related, {} exact)",
                related_considered, exact_considered
            ));
        }
        if stateful_skipped > 0 {
            reasons.push(format!(
                "Skipped {} stateful oracle(s) due to insufficient samples",
                stateful_skipped
            ));
        }

        // Update per-oracle stats
        for name in &agreeing {
            *self
                .stats
                .oracle_agreements
                .entry(name.clone())
                .or_insert(0) += 1;
        }
        for name in &disagreeing {
            *self
                .stats
                .oracle_disagreements
                .entry(name.clone())
                .or_insert(0) += 1;
        }

        ValidationResult {
            is_valid,
            confidence: agreement_ratio,
            reasons,
            agreeing_oracles: agreeing,
            disagreeing_oracles: disagreeing,
        }
    }

    /// Validate an oracle against ground truth test cases
    ///
    /// Tests the oracle on known-good and known-bad cases to estimate
    /// its false positive and false negative rates.
    pub fn validate_against_ground_truth(
        &self,
        oracle: &mut dyn BugOracle,
        executor: &dyn CircuitExecutor,
    ) -> GroundTruthValidationResult {
        let mut true_positives = 0;
        let mut false_positives = 0;
        let mut true_negatives = 0;
        let mut false_negatives = 0;

        for case in &self.ground_truth {
            let test_case = TestCase {
                inputs: case.inputs.clone(),
                expected_output: None,
                metadata: zk_core::TestMetadata::default(),
            };

            let exec_result = executor.execute_sync(&test_case.inputs);
            let outputs = if exec_result.success {
                exec_result.outputs
            } else {
                vec![FieldElement::zero()]
            };
            let finding_result = oracle.check(&test_case, &outputs);

            let found_bug = finding_result.is_some();
            let expected_bug = case.expected_bug.is_some();

            match (found_bug, expected_bug) {
                (true, true) => true_positives += 1,
                (true, false) => false_positives += 1,
                (false, true) => false_negatives += 1,
                (false, false) => true_negatives += 1,
            }
        }

        GroundTruthValidationResult {
            oracle_name: oracle.name().to_string(),
            true_positives,
            false_positives,
            true_negatives,
            false_negatives,
            total_cases: self.ground_truth.len(),
        }
    }

    /// Get current validation statistics
    pub fn stats(&self) -> &OracleValidationStats {
        &self.stats
    }

    /// Reset validation statistics
    pub fn reset_stats(&mut self) {
        self.stats = OracleValidationStats::default();
    }
}

impl Default for OracleValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of ground truth validation for an oracle
#[derive(Debug, Clone)]
pub struct GroundTruthValidationResult {
    pub oracle_name: String,
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
    pub total_cases: usize,
}

impl GroundTruthValidationResult {
    /// Calculate precision (true positives / all positives)
    pub fn precision(&self) -> f64 {
        let total_positives = self.true_positives + self.false_positives;
        if total_positives == 0 {
            return 1.0;
        }
        self.true_positives as f64 / total_positives as f64
    }

    /// Calculate recall (true positives / all expected positives)
    pub fn recall(&self) -> f64 {
        let expected_positives = self.true_positives + self.false_negatives;
        if expected_positives == 0 {
            return 1.0;
        }
        self.true_positives as f64 / expected_positives as f64
    }

    /// Calculate F1 score (harmonic mean of precision and recall)
    pub fn f1_score(&self) -> f64 {
        let precision = self.precision();
        let recall = self.recall();
        if precision + recall == 0.0 {
            return 0.0;
        }
        2.0 * (precision * recall) / (precision + recall)
    }

    /// Check if oracle passes quality threshold
    pub fn passes_threshold(&self, min_precision: f64, min_recall: f64) -> bool {
        self.precision() >= min_precision && self.recall() >= min_recall
    }
}

impl std::fmt::Display for GroundTruthValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: precision={:.1}%, recall={:.1}%, F1={:.1}% (TP={}, FP={}, TN={}, FN={})",
            self.oracle_name,
            self.precision() * 100.0,
            self.recall() * 100.0,
            self.f1_score() * 100.0,
            self.true_positives,
            self.false_positives,
            self.true_negatives,
            self.false_negatives
        )
    }
}

/// Filter findings using oracle validation
pub fn filter_validated_findings(
    findings: Vec<Finding>,
    validator: &mut OracleValidator,
    oracles: &mut [Box<dyn BugOracle>],
    executor: &dyn CircuitExecutor,
    evidence_mode: bool,
) -> Vec<Finding> {
    let expected_inputs = executor.num_public_inputs() + executor.num_private_inputs();
    findings
        .into_iter()
        .filter(|finding| {
            let mut test_cases = Vec::new();
            let mut outputs = Vec::new();

            let mut push_sample = |inputs: Vec<FieldElement>, label: &str| {
                if inputs.len() != expected_inputs {
                    tracing::debug!(
                        "Oracle validation skipped for '{:?}' ({}): wrong input length (got {}, expected {})",
                        finding.attack_type,
                        label,
                        inputs.len(),
                        expected_inputs
                    );
                    return;
                }
                let test_case = TestCase {
                    inputs,
                    expected_output: None,
                    metadata: zk_core::TestMetadata::default(),
                };
                let exec_result = executor.execute_sync(&test_case.inputs);
                if !exec_result.success {
                    tracing::debug!(
                        "Oracle validation skipped for '{:?}' ({}): execution failed ({})",
                        finding.attack_type,
                        label,
                        exec_result
                            .error
                            .as_deref()
                            .unwrap_or("execution failed without backend error message")
                    );
                    return;
                }
                test_cases.push(test_case);
                outputs.push(exec_result.outputs);
            };

            push_sample(finding.poc.witness_a.clone(), "witness_a");
            if let Some(witness_b) = &finding.poc.witness_b {
                push_sample(witness_b.clone(), "witness_b");
            }

            if test_cases.is_empty() {
                // In evidence mode, findings must be reproducible with an executable witness.
                // In non-evidence mode, keep as a hint even if we couldn't validate.
                return !evidence_mode;
            }

            let samples: Vec<ValidationSample<'_>> = test_cases
                .iter()
                .zip(outputs.iter())
                .map(|(test_case, output)| ValidationSample {
                    test_case,
                    outputs: output,
                })
                .collect();

            let result = validator.validate_differential(finding, oracles, &samples);

            if !result.is_valid {
                tracing::warn!(
                    "Finding '{:?}' failed oracle validation: {:?}",
                    finding.attack_type,
                    result.reasons
                );
            }

            result.is_valid
        })
        .collect()
}

#[cfg(test)]
#[path = "oracle_validation_tests.rs"]
mod tests;
