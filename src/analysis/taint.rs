//! Taint Analysis for ZK Circuits
//!
//! Tracks how public inputs influence private witnesses to detect:
//! - Information leakage through constraints
//! - Improper input segregation
//! - Privacy violations

use std::collections::{HashMap, HashSet};
use zk_core::ConstraintEquation;
use zk_core::Severity;
use zk_core::{Finding, ProofOfConcept};

/// Taint label for tracking data flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintLabel {
    /// Public input (known to verifier)
    Public(usize),
    /// Private input (known only to prover)
    Private(usize),
    /// Constant value
    Constant,
    /// Mixed taint from multiple sources
    Mixed,
    /// Unknown/untainted
    Clean,
}

/// Taint state for a signal
#[derive(Debug, Clone, Default)]
pub struct TaintState {
    /// Labels that contribute to this signal's value
    pub labels: HashSet<TaintLabel>,
    /// Constraint IDs that influenced this signal
    pub influencing_constraints: Vec<usize>,
    /// Is this signal considered "leaked"?
    pub is_leaked: bool,
}

impl TaintState {
    pub fn new_public(index: usize) -> Self {
        let mut labels = HashSet::new();
        labels.insert(TaintLabel::Public(index));
        Self {
            labels,
            influencing_constraints: Vec::new(),
            is_leaked: false,
        }
    }

    pub fn new_private(index: usize) -> Self {
        let mut labels = HashSet::new();
        labels.insert(TaintLabel::Private(index));
        Self {
            labels,
            influencing_constraints: Vec::new(),
            is_leaked: false,
        }
    }

    /// Check if this state contains any private labels
    pub fn has_private_taint(&self) -> bool {
        self.labels
            .iter()
            .any(|l| matches!(l, TaintLabel::Private(_)))
    }

    /// Check if this state contains any public labels
    pub fn has_public_taint(&self) -> bool {
        self.labels
            .iter()
            .any(|l| matches!(l, TaintLabel::Public(_)))
    }

    /// Merge taint states (union of labels)
    pub fn merge(&mut self, other: &TaintState) {
        self.labels.extend(other.labels.iter().cloned());
        self.influencing_constraints
            .extend(&other.influencing_constraints);
    }
}

/// Taint analyzer for ZK circuits
pub struct TaintAnalyzer {
    /// Taint states for each signal
    signal_taints: HashMap<usize, TaintState>,
    /// Number of public inputs
    num_public_inputs: usize,
    /// Number of private inputs
    num_private_inputs: usize,
    /// Configuration
    config: TaintConfig,
}

/// Configuration for taint analysis
#[derive(Debug, Clone)]
pub struct TaintConfig {
    /// Consider output signals only, or all signals
    pub analyze_outputs_only: bool,
    /// Depth limit for taint propagation
    pub max_propagation_depth: usize,
    /// Report implicit flows (control dependencies)
    pub report_implicit_flows: bool,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            analyze_outputs_only: true,
            max_propagation_depth: 100,
            report_implicit_flows: true,
        }
    }
}

impl TaintAnalyzer {
    pub fn new(num_public_inputs: usize, num_private_inputs: usize) -> Self {
        Self {
            signal_taints: HashMap::new(),
            num_public_inputs,
            num_private_inputs,
            config: TaintConfig::default(),
        }
    }

    pub fn with_config(mut self, config: TaintConfig) -> Self {
        self.config = config;
        self
    }

    /// Initialize taint labels for inputs
    pub fn initialize_inputs(&mut self) {
        // Label public inputs
        for i in 0..self.num_public_inputs {
            self.signal_taints.insert(i, TaintState::new_public(i));
        }

        // Label private inputs (after public inputs)
        for i in 0..self.num_private_inputs {
            let signal_idx = self.num_public_inputs + i;
            self.signal_taints
                .insert(signal_idx, TaintState::new_private(i));
        }
    }

    /// Initialize taint labels for inputs using explicit signal indices
    pub fn initialize_inputs_with_indices(
        &mut self,
        public_indices: &[usize],
        private_indices: &[usize],
    ) {
        for (i, idx) in public_indices.iter().enumerate() {
            self.signal_taints.insert(*idx, TaintState::new_public(i));
        }

        for (i, idx) in private_indices.iter().enumerate() {
            self.signal_taints.insert(*idx, TaintState::new_private(i));
        }
    }

    /// Propagate taint through a constraint
    ///
    /// In R1CS form: A * B = C
    /// If A or B is tainted, C becomes tainted
    pub fn propagate_constraint(
        &mut self,
        constraint_id: usize,
        input_signals: &[usize],
        output_signal: usize,
    ) {
        // Collect taint from all input signals
        let mut combined_taint = TaintState::default();

        for &signal in input_signals {
            if let Some(taint) = self.signal_taints.get(&signal) {
                combined_taint.merge(taint);
            }
        }

        combined_taint.influencing_constraints.push(constraint_id);

        // Update output signal taint
        self.signal_taints
            .entry(output_signal)
            .or_default()
            .merge(&combined_taint);
    }

    /// Analyze taint flow and detect potential leakage
    pub fn analyze(&self) -> Vec<TaintFinding> {
        let mut findings = Vec::new();

        for (signal_idx, taint_state) in &self.signal_taints {
            if self.config.analyze_outputs_only && !taint_state.is_leaked {
                continue;
            }

            // Check for mixed public/private taint (potential leakage)
            if taint_state.has_public_taint() && taint_state.has_private_taint() {
                let private_indices: Vec<_> = taint_state
                    .labels
                    .iter()
                    .filter_map(|l| match l {
                        TaintLabel::Private(i) => Some(*i),
                        _ => None,
                    })
                    .collect();

                let public_indices: Vec<_> = taint_state
                    .labels
                    .iter()
                    .filter_map(|l| match l {
                        TaintLabel::Public(i) => Some(*i),
                        _ => None,
                    })
                    .collect();

                findings.push(TaintFinding {
                    signal_index: *signal_idx,
                    finding_type: TaintFindingType::MixedFlow,
                    severity: Severity::High,
                    description: format!(
                        "Signal {} has mixed taint from public inputs {:?} and private inputs {:?}",
                        signal_idx, public_indices, private_indices
                    ),
                    influencing_constraints: taint_state.influencing_constraints.clone(),
                });
            }

            // Check if private data flows to public outputs
            if taint_state.has_private_taint() && taint_state.is_leaked {
                findings.push(TaintFinding {
                    signal_index: *signal_idx,
                    finding_type: TaintFindingType::PrivateToPublicLeak,
                    severity: Severity::Critical,
                    description: format!(
                        "Private data leaks to public output at signal {}",
                        signal_idx
                    ),
                    influencing_constraints: taint_state.influencing_constraints.clone(),
                });
            }
        }

        findings
    }

    /// Mark a signal as a public output (potential leak point)
    pub fn mark_as_output(&mut self, signal_idx: usize) {
        self.signal_taints.entry(signal_idx).or_default().is_leaked = true;
    }

    /// Mark a list of signals as public outputs (potential leak points)
    pub fn mark_outputs(&mut self, output_indices: &[usize]) {
        for idx in output_indices {
            self.mark_as_output(*idx);
        }
    }

    /// Mark output signals based on constraint definitions
    pub fn mark_outputs_from_constraints(&mut self, constraints: &[ConstraintEquation]) {
        for constraint in constraints {
            for (signal_idx, _) in &constraint.c_terms {
                self.mark_as_output(*signal_idx);
            }
        }
    }

    /// Propagate taint across all constraints until convergence
    pub fn propagate_constraints(&mut self, constraints: &[ConstraintEquation]) {
        let mut depth = 0;
        let max_depth = self.config.max_propagation_depth.max(1);

        loop {
            let mut changed = false;

            for constraint in constraints {
                let mut input_signals: Vec<usize> = constraint
                    .a_terms
                    .iter()
                    .chain(constraint.b_terms.iter())
                    .map(|(idx, _)| *idx)
                    .collect();
                input_signals.sort_unstable();
                input_signals.dedup();

                for (output_idx, _) in &constraint.c_terms {
                    let before = self.signal_taints.get(output_idx).map(|t| t.labels.len());
                    let before = match before {
                        Some(value) => value,
                        None => {
                            panic!(
                                "Missing taint state for output signal {} before propagation",
                                output_idx
                            )
                        }
                    };
                    self.propagate_constraint(constraint.id, &input_signals, *output_idx);
                    let after = self.signal_taints.get(output_idx).map(|t| t.labels.len());
                    let after = match after {
                        Some(value) => value,
                        None => {
                            panic!(
                                "Missing taint state for output signal {} after propagation",
                                output_idx
                            )
                        }
                    };
                    if after > before {
                        changed = true;
                    }
                }
            }

            depth += 1;
            if !changed || depth >= max_depth {
                break;
            }
        }
    }

    /// Get taint state for a signal
    pub fn get_taint(&self, signal_idx: usize) -> Option<&TaintState> {
        self.signal_taints.get(&signal_idx)
    }

    /// Convert findings to fuzzer Findings
    pub fn to_findings(&self) -> Vec<Finding> {
        self.analyze()
            .into_iter()
            .map(|tf| Finding {
                attack_type: zk_core::AttackType::InformationLeakage,
                severity: tf.severity,
                description: tf.description,
                poc: ProofOfConcept::default(),
                location: Some(format!("signal_{}", tf.signal_index)),
            })
            .collect()
    }
}

/// A finding from taint analysis
#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub signal_index: usize,
    pub finding_type: TaintFindingType,
    pub severity: Severity,
    pub description: String,
    pub influencing_constraints: Vec<usize>,
}

/// Type of taint finding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintFindingType {
    /// Mixed flow from public and private inputs
    MixedFlow,
    /// Private data flows to public output
    PrivateToPublicLeak,
    /// Uncontrolled taint propagation
    UncontrolledPropagation,
    /// Implicit flow through control dependency
    ImplicitFlow,
}

#[cfg(test)]
#[path = "taint_tests.rs"]
mod tests;
