//! Underconstrained circuit detection
//!
//! An underconstrained circuit allows multiple valid witnesses
//! for the same public input/output, which can lead to:
//! - Proof forgery
//! - Double spending
//! - Identity theft in privacy protocols

use super::{Attack, AttackContext, CircuitInfo};
use zk_core::{AttackType, Finding, ProofOfConcept, Severity};

/// Detector for underconstrained circuits
pub struct UnderconstrainedDetector {
    /// Number of witness samples to generate for collision testing
    samples: usize,
    /// Tolerance for DOF ratio (constraints/inputs must be >= 1.0 - tolerance)
    tolerance: f64,
}

impl UnderconstrainedDetector {
    pub fn new(samples: usize) -> Self {
        Self {
            samples,
            tolerance: 0.0001,
        }
    }

    /// Set the tolerance for constraint ratio analysis
    pub fn with_tolerance(mut self, tolerance: f64) -> Self {
        self.tolerance = tolerance.clamp(0.0, 1.0);
        self
    }

    /// Get the configured number of samples
    pub fn samples(&self) -> usize {
        self.samples
    }

    /// Get the configured tolerance
    pub fn tolerance(&self) -> f64 {
        self.tolerance
    }

    /// Perform degree-of-freedom analysis
    ///
    /// Uses `tolerance` to determine if the constraint ratio is acceptable.
    /// A circuit is considered underconstrained if:
    /// - num_constraints < num_private_inputs, OR
    /// - constraint_ratio < (1.0 - tolerance) where there may be issues
    pub fn dof_analysis(&self, circuit_info: &CircuitInfo) -> Option<Finding> {
        let num_constraints = circuit_info.num_constraints;
        let num_private_inputs = circuit_info.num_private_inputs;

        if num_private_inputs == 0 {
            return None;
        }

        let constraint_ratio = num_constraints as f64 / num_private_inputs as f64;
        let min_acceptable_ratio = 1.0 - self.tolerance;

        if constraint_ratio < min_acceptable_ratio {
            let dof = num_private_inputs.saturating_sub(num_constraints);

            return Some(Finding {
                attack_type: AttackType::Underconstrained,
                severity: if dof > 0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                description: format!(
                    "Circuit has {} constraints but {} private inputs (ratio: {:.3}). \
                     Likely underconstrained (DOF = {}, tolerance = {:.4})",
                    num_constraints, num_private_inputs, constraint_ratio, dof, self.tolerance
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        None
    }

    /// Check for unused signals
    ///
    /// Uses `samples` to limit the analysis scope for large circuits
    pub fn unused_signal_analysis(&self, _circuit_info: &CircuitInfo) -> Vec<Finding> {
        // In real implementation, this would analyze the constraint system
        // to find signals that are declared but never constrained.
        // The `samples` parameter would limit how many signals to analyze
        // for very large circuits.
        tracing::debug!("Unused signal analysis with {} sample limit", self.samples);
        vec![]
    }

    /// Check for weak constraints
    ///
    /// Uses `samples` to limit the number of constraint evaluations
    pub fn weak_constraint_analysis(&self, _circuit_info: &CircuitInfo) -> Vec<Finding> {
        // In real implementation, this would look for constraints that
        // don't sufficiently limit the witness space.
        // The `samples` parameter controls how many random evaluations
        // to perform per constraint.
        tracing::debug!(
            "Weak constraint analysis with {} samples per constraint",
            self.samples
        );
        vec![]
    }
}

impl Attack for UnderconstrainedDetector {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // DOF analysis
        if let Some(finding) = self.dof_analysis(&context.circuit_info) {
            findings.push(finding);
        }

        // Unused signal analysis
        findings.extend(self.unused_signal_analysis(&context.circuit_info));

        // Weak constraint analysis
        findings.extend(self.weak_constraint_analysis(&context.circuit_info));

        findings
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Underconstrained
    }

    fn description(&self) -> &str {
        "Detect underconstrained circuits that allow multiple valid witnesses"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dof_analysis_underconstrained() {
        let detector = UnderconstrainedDetector::new(1000);
        let circuit_info = CircuitInfo {
            name: "test".to_string(),
            num_constraints: 5,
            num_private_inputs: 10,
            num_public_inputs: 2,
            num_outputs: 1,
        };

        let finding = detector.dof_analysis(&circuit_info);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().attack_type, AttackType::Underconstrained);
    }

    #[test]
    fn test_dof_analysis_properly_constrained() {
        let detector = UnderconstrainedDetector::new(1000);
        let circuit_info = CircuitInfo {
            name: "test".to_string(),
            num_constraints: 10,
            num_private_inputs: 5,
            num_public_inputs: 2,
            num_outputs: 1,
        };

        let finding = detector.dof_analysis(&circuit_info);
        assert!(finding.is_none());
    }
}
