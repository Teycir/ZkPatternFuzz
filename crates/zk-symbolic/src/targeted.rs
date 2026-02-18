//! Targeted Symbolic Execution for Bug-Directed Analysis
//!
//! This module provides directed symbolic execution capabilities:
//! - **Bug-Directed Execution**: Target specific vulnerability patterns
//! - **Differential Symbolic Execution**: Compare circuit versions
//! - **Regression Testing**: Find inputs where patched/unpatched differ
//!
//! # Performance Targets
//! - 5x speedup for targeted bugs
//! - Find regressions in <10 minutes
//! - Differential mode finds all patch differences

use crate::enhanced::{ConstraintSimplifier, PathPruner, PruningStrategy};
use crate::executor::{
    PathCondition, SolverResult, SymbolicConstraint, SymbolicState, SymbolicValue, Z3Solver,
};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::Instant;
use zk_core::FieldElement;

// ============================================================================
// Bug-Directed Symbolic Execution
// ============================================================================

/// Type of vulnerability to target
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulnerabilityTarget {
    /// Under-constrained outputs (multiple valid witnesses for same public)
    Underconstrained,
    /// Nullifier reuse vulnerabilities
    NullifierReuse,
    /// Arithmetic overflow/underflow
    ArithmeticOverflow,
    /// Range constraint violations
    RangeViolation,
    /// Hash collision resistance
    HashCollision,
    /// Merkle tree path manipulation
    MerklePathManipulation,
    /// Signature forgery
    SignatureForgery,
    /// Information leakage
    InformationLeakage,
    /// Custom vulnerability pattern
    Custom(String),
}

impl VulnerabilityTarget {
    /// Get constraint patterns for this vulnerability
    pub fn constraint_patterns(&self) -> Vec<String> {
        match self {
            VulnerabilityTarget::Underconstrained => {
                vec!["output".into(), "public".into(), "result".into()]
            }
            VulnerabilityTarget::NullifierReuse => {
                vec!["nullifier".into(), "hash".into(), "commit".into()]
            }
            VulnerabilityTarget::ArithmeticOverflow => {
                vec!["Mul".into(), "Add".into(), "overflow".into()]
            }
            VulnerabilityTarget::RangeViolation => {
                vec!["range".into(), "bound".into(), "limit".into(), "max".into()]
            }
            VulnerabilityTarget::HashCollision => {
                vec![
                    "hash".into(),
                    "poseidon".into(),
                    "mimc".into(),
                    "pedersen".into(),
                ]
            }
            VulnerabilityTarget::MerklePathManipulation => {
                vec!["merkle".into(), "root".into(), "path".into(), "leaf".into()]
            }
            VulnerabilityTarget::SignatureForgery => {
                vec![
                    "signature".into(),
                    "eddsa".into(),
                    "verify".into(),
                    "sign".into(),
                ]
            }
            VulnerabilityTarget::InformationLeakage => {
                vec!["secret".into(), "private".into(), "witness".into()]
            }
            VulnerabilityTarget::Custom(pattern) => vec![pattern.clone()],
        }
    }

    /// Get priority boost for this vulnerability type
    pub fn priority_boost(&self) -> f64 {
        match self {
            VulnerabilityTarget::Underconstrained => 3.0,
            VulnerabilityTarget::NullifierReuse => 3.5,
            VulnerabilityTarget::ArithmeticOverflow => 2.5,
            VulnerabilityTarget::RangeViolation => 2.0,
            VulnerabilityTarget::HashCollision => 4.0,
            VulnerabilityTarget::MerklePathManipulation => 3.0,
            VulnerabilityTarget::SignatureForgery => 4.0,
            VulnerabilityTarget::InformationLeakage => 2.5,
            VulnerabilityTarget::Custom(_) => 2.0,
        }
    }
}

/// Configuration for bug-directed execution
#[derive(Debug, Clone)]
pub struct BugDirectedConfig {
    /// Vulnerability types to target
    pub targets: Vec<VulnerabilityTarget>,
    /// Maximum paths to explore
    pub max_paths: usize,
    /// Maximum depth
    pub max_depth: usize,
    /// Solver timeout (ms)
    pub solver_timeout_ms: u32,
    /// Enable path pruning
    pub enable_pruning: bool,
    /// Pruning aggressiveness (0.0 - 1.0)
    pub pruning_aggressiveness: f64,
    /// Early termination on first finding
    pub stop_on_first: bool,
    /// Minimum confidence for reporting
    pub min_confidence: f64,
}

impl Default for BugDirectedConfig {
    fn default() -> Self {
        Self {
            targets: vec![
                VulnerabilityTarget::Underconstrained,
                VulnerabilityTarget::NullifierReuse,
            ],
            max_paths: 5_000,
            max_depth: 500,
            solver_timeout_ms: 15_000,
            enable_pruning: true,
            pruning_aggressiveness: 0.7,
            stop_on_first: false,
            min_confidence: 0.5,
        }
    }
}

/// Finding from bug-directed execution
#[derive(Debug, Clone)]
pub struct DirectedFinding {
    /// Type of vulnerability found
    pub vuln_type: VulnerabilityTarget,
    /// Witness input that triggers vulnerability
    pub witness: Vec<FieldElement>,
    /// Path condition that led to finding
    pub path_condition: PathCondition,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Constraint indices involved
    pub involved_constraints: Vec<usize>,
}

/// Statistics for bug-directed execution
#[derive(Debug, Clone, Default)]
pub struct BugDirectedStats {
    pub paths_explored: u64,
    pub paths_pruned: u64,
    pub paths_matching_target: u64,
    pub findings: u64,
    pub execution_time_ms: u64,
    pub solver_calls: u64,
    pub solver_time_ms: u64,
}

/// Bug-directed symbolic executor
pub struct BugDirectedExecutor {
    /// Work queue ordered by vulnerability relevance
    worklist: BinaryHeap<PrioritizedDirectedState>,
    /// Solver
    solver: Z3Solver,
    /// Simplifier
    simplifier: ConstraintSimplifier,
    /// Configuration
    config: BugDirectedConfig,
    /// Findings
    findings: Vec<DirectedFinding>,
    /// Number of inputs
    num_inputs: usize,
    /// Statistics
    stats: BugDirectedStats,
}

#[derive(Debug, Clone)]
struct PrioritizedDirectedState {
    state: SymbolicState,
    relevance_score: f64,
}

impl PartialEq for PrioritizedDirectedState {
    fn eq(&self, other: &Self) -> bool {
        self.relevance_score == other.relevance_score
    }
}

impl Eq for PrioritizedDirectedState {}

impl PartialOrd for PrioritizedDirectedState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedDirectedState {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.relevance_score.partial_cmp(&other.relevance_score) {
            Some(ordering) => ordering,
            None => std::cmp::Ordering::Equal,
        }
    }
}

impl BugDirectedExecutor {
    pub fn new(num_inputs: usize) -> Self {
        Self::with_config(num_inputs, BugDirectedConfig::default())
    }

    pub fn with_config(num_inputs: usize, config: BugDirectedConfig) -> Self {
        let solver = Z3Solver::new().with_timeout(config.solver_timeout_ms);

        let pruning_strategy = if config.enable_pruning {
            PruningStrategy::CoverageGuided
        } else {
            PruningStrategy::None
        };
        let _pruner = PathPruner::new(pruning_strategy)
            .with_max_depth(config.max_depth)
            .with_max_paths(config.max_paths);

        // Initialize with starting state
        let initial_state = SymbolicState::new(num_inputs);
        let mut worklist = BinaryHeap::new();
        worklist.push(PrioritizedDirectedState {
            state: initial_state,
            relevance_score: 1.0,
        });

        Self {
            worklist,
            solver,
            simplifier: ConstraintSimplifier::new(),
            config,
            findings: Vec::new(),
            num_inputs,
            stats: BugDirectedStats::default(),
        }
    }

    /// Compute relevance score for a state relative to target vulnerabilities
    fn compute_relevance(&self, state: &SymbolicState) -> f64 {
        let mut total_score = 0.0;
        let mut matched = Vec::new();

        for target in &self.config.targets {
            let patterns = target.constraint_patterns();
            let boost = target.priority_boost();

            for pattern in patterns {
                // Check path condition constraints
                for constraint in &state.path_condition.constraints {
                    let constraint_str = format!("{:?}", constraint);
                    if constraint_str
                        .to_lowercase()
                        .contains(&pattern.to_lowercase())
                    {
                        total_score += boost;
                        matched.push(pattern.clone());
                    }
                }

                // Check signal names
                for name in state.named_signals.keys() {
                    if name.to_lowercase().contains(&pattern.to_lowercase()) {
                        total_score += boost * 0.5;
                        matched.push(format!("signal:{}", name));
                    }
                }
            }
        }

        // Penalize deep paths
        total_score -= state.depth as f64 * 0.02;

        total_score.max(0.0)
    }

    /// Check if state should be pruned based on relevance
    fn should_prune(&self, state: &SymbolicState, relevance: f64) -> bool {
        if !self.config.enable_pruning {
            return false;
        }

        // Prune if too deep
        if state.depth > self.config.max_depth {
            return true;
        }

        // Prune low-relevance paths more aggressively as we explore more
        let explored_ratio = self.stats.paths_explored as f64 / self.config.max_paths as f64;
        let threshold = (1.0 - self.config.pruning_aggressiveness) * (1.0 - explored_ratio);

        relevance < threshold
    }

    /// Process a state and check for vulnerabilities
    fn process_state(&mut self, state: SymbolicState) {
        self.stats.paths_explored += 1;

        // Check if state matches any patterns
        let mut matched_patterns = Vec::new();
        for target in &self.config.targets {
            let patterns = target.constraint_patterns();
            for pattern in patterns {
                for constraint in &state.path_condition.constraints {
                    let constraint_str = format!("{:?}", constraint);
                    if constraint_str
                        .to_lowercase()
                        .contains(&pattern.to_lowercase())
                    {
                        matched_patterns.push(pattern.clone());
                    }
                }
                for name in state.named_signals.keys() {
                    if name.to_lowercase().contains(&pattern.to_lowercase()) {
                        matched_patterns.push(format!("signal:{}", name));
                    }
                }
            }
        }

        // If patterns matched, try to generate witness
        if !matched_patterns.is_empty() {
            self.stats.paths_matching_target += 1;

            // Simplify and solve
            let path = self.simplifier.simplify_path(&state.path_condition);

            let start = Instant::now();
            self.stats.solver_calls += 1;
            let result = self.solver.solve(&path);
            self.stats.solver_time_ms += start.elapsed().as_millis() as u64;

            if let SolverResult::Sat(assignments) = result {
                // Determine which vulnerability was matched
                let vuln_type = self.determine_vuln_type(&matched_patterns);
                let witness = self.assignments_to_inputs(&assignments);
                let confidence = self.compute_confidence(&matched_patterns, &state);

                if confidence >= self.config.min_confidence {
                    let finding = DirectedFinding {
                        vuln_type,
                        witness,
                        path_condition: state.path_condition.clone(),
                        confidence,
                        description: format!("Matched patterns: {}", matched_patterns.join(", ")),
                        involved_constraints: (0..state.path_condition.constraints.len()).collect(),
                    };

                    self.findings.push(finding);
                    self.stats.findings += 1;

                    if self.config.stop_on_first {
                        // Signal early termination by clearing worklist
                        self.worklist.clear();
                    }
                }
            }
        }
    }

    fn determine_vuln_type(&self, patterns: &[String]) -> VulnerabilityTarget {
        for target in &self.config.targets {
            let target_patterns = target.constraint_patterns();
            for pattern in patterns {
                if target_patterns.iter().any(|p| pattern.contains(p)) {
                    return target.clone();
                }
            }
        }
        VulnerabilityTarget::Custom("unknown".to_string())
    }

    fn compute_confidence(&self, patterns: &[String], state: &SymbolicState) -> f64 {
        let pattern_count = patterns.len() as f64;
        let constraint_ratio = pattern_count / state.path_condition.constraints.len().max(1) as f64;
        let depth_factor = 1.0 - (state.depth as f64 / self.config.max_depth as f64);

        (pattern_count.min(5.0) / 5.0 * 0.4 + constraint_ratio * 0.3 + depth_factor * 0.3).min(1.0)
    }

    fn assignments_to_inputs(
        &self,
        assignments: &HashMap<String, FieldElement>,
    ) -> Vec<FieldElement> {
        (0..self.num_inputs)
            .map(|i| {
                let key = format!("input_{}", i);
                match assignments.get(&key).cloned() {
                    Some(value) => value,
                    None => FieldElement::zero(),
                }
            })
            .collect()
    }

    /// Run bug-directed exploration
    pub fn explore(&mut self) -> &[DirectedFinding] {
        let start = Instant::now();

        while let Some(prioritized) = self.worklist.pop() {
            // Check limits
            if self.stats.paths_explored as usize >= self.config.max_paths {
                break;
            }

            let relevance = self.compute_relevance(&prioritized.state);

            // Check pruning
            if self.should_prune(&prioritized.state, relevance) {
                self.stats.paths_pruned += 1;
                continue;
            }

            self.process_state(prioritized.state);
        }

        self.stats.execution_time_ms = start.elapsed().as_millis() as u64;
        &self.findings
    }

    /// Add a state to explore
    pub fn add_state(&mut self, state: SymbolicState) {
        let relevance = self.compute_relevance(&state);
        self.worklist.push(PrioritizedDirectedState {
            state,
            relevance_score: relevance,
        });
    }

    /// Get findings
    pub fn findings(&self) -> &[DirectedFinding] {
        &self.findings
    }

    /// Get statistics
    pub fn stats(&self) -> &BugDirectedStats {
        &self.stats
    }

    /// Reset for new exploration
    pub fn reset(&mut self) {
        self.worklist.clear();
        self.findings.clear();
        self.stats = BugDirectedStats::default();

        let initial_state = SymbolicState::new(self.num_inputs);
        self.worklist.push(PrioritizedDirectedState {
            state: initial_state,
            relevance_score: 1.0,
        });
    }
}

// ============================================================================
// Differential Symbolic Execution
// ============================================================================

/// Configuration for differential symbolic execution
#[derive(Debug, Clone)]
pub struct DifferentialConfig {
    /// Maximum paths to explore
    pub max_paths: usize,
    /// Maximum depth
    pub max_depth: usize,
    /// Solver timeout (ms)
    pub solver_timeout_ms: u32,
    /// Minimum difference threshold
    pub min_difference_threshold: f64,
    /// Compare public outputs only
    pub compare_public_only: bool,
}

impl Default for DifferentialConfig {
    fn default() -> Self {
        Self {
            max_paths: 5_000,
            max_depth: 500,
            solver_timeout_ms: 15_000,
            min_difference_threshold: 0.0,
            compare_public_only: true,
        }
    }
}

/// Represents a difference between two circuit versions
#[derive(Debug, Clone)]
pub struct CircuitDifference {
    /// Input that causes different outputs
    pub diverging_input: Vec<FieldElement>,
    /// Output from version A
    pub output_a: Option<Vec<FieldElement>>,
    /// Output from version B
    pub output_b: Option<Vec<FieldElement>>,
    /// Path condition leading to difference
    pub path_condition: PathCondition,
    /// Constraint indices that differ
    pub differing_constraints: Vec<usize>,
    /// Description of difference
    pub description: String,
    /// Severity (0.0 - 1.0)
    pub severity: f64,
}

/// Statistics for differential execution
#[derive(Debug, Clone, Default)]
pub struct DifferentialStats {
    pub paths_explored: u64,
    pub common_paths: u64,
    pub diverging_paths: u64,
    pub differences_found: u64,
    pub execution_time_ms: u64,
    pub solver_calls: u64,
}

/// Differential symbolic executor
pub struct DifferentialExecutor {
    /// Constraints for version A
    constraints_a: Vec<SymbolicConstraint>,
    /// Constraints for version B
    constraints_b: Vec<SymbolicConstraint>,
    /// Solver
    solver: Z3Solver,
    /// Found differences
    differences: Vec<CircuitDifference>,
    /// Number of inputs
    num_inputs: usize,
    /// Statistics
    stats: DifferentialStats,
}

impl DifferentialExecutor {
    pub fn new(
        constraints_a: Vec<SymbolicConstraint>,
        constraints_b: Vec<SymbolicConstraint>,
        num_inputs: usize,
    ) -> Self {
        Self::with_config(
            constraints_a,
            constraints_b,
            num_inputs,
            DifferentialConfig::default(),
        )
    }

    pub fn with_config(
        constraints_a: Vec<SymbolicConstraint>,
        constraints_b: Vec<SymbolicConstraint>,
        num_inputs: usize,
        config: DifferentialConfig,
    ) -> Self {
        let solver = Z3Solver::new().with_timeout(config.solver_timeout_ms);

        Self {
            constraints_a,
            constraints_b,
            solver,
            differences: Vec::new(),
            num_inputs,
            stats: DifferentialStats::default(),
        }
    }

    /// Find inputs where the two versions behave differently
    pub fn find_differences(&mut self) -> &[CircuitDifference] {
        let start = Instant::now();

        // Strategy 1: Find constraints that exist in A but not B (and vice versa)
        self.find_constraint_differences();

        // Strategy 2: Find inputs that satisfy A but not B (and vice versa)
        self.find_exclusive_inputs();

        // Strategy 3: Check boundary conditions
        self.find_boundary_differences();

        self.stats.execution_time_ms = start.elapsed().as_millis() as u64;
        &self.differences
    }

    /// Find structural differences between constraint sets
    fn find_constraint_differences(&mut self) {
        let set_a: HashSet<String> = self
            .constraints_a
            .iter()
            .map(|c| format!("{:?}", c))
            .collect();
        let set_b: HashSet<String> = self
            .constraints_b
            .iter()
            .map(|c| format!("{:?}", c))
            .collect();

        // Constraints in A but not B
        let only_in_a: Vec<_> = set_a.difference(&set_b).cloned().collect();
        // Constraints in B but not A
        let only_in_b: Vec<_> = set_b.difference(&set_a).cloned().collect();

        if !only_in_a.is_empty() || !only_in_b.is_empty() {
            // Try to find an input that exploits this difference
            self.exploit_structural_difference(&only_in_a, &only_in_b);
        }
    }

    fn exploit_structural_difference(&mut self, only_in_a: &[String], only_in_b: &[String]) {
        // Build path condition from constraints only in A
        let mut pc = PathCondition::new();
        for constraint in &self.constraints_a {
            pc.add_constraint(constraint.clone());
        }

        // Negate constraints only in B
        for constraint in &self.constraints_b {
            let constraint_str = format!("{:?}", constraint);
            if only_in_b.iter().any(|s| s == &constraint_str) {
                pc.add_constraint(constraint.clone().negate());
            }
        }

        self.stats.solver_calls += 1;
        if let SolverResult::Sat(assignments) = self.solver.solve(&pc) {
            let input = self.assignments_to_inputs(&assignments);

            self.differences.push(CircuitDifference {
                diverging_input: input,
                output_a: None,
                output_b: None,
                path_condition: pc,
                differing_constraints: Vec::new(),
                description: format!(
                    "Structural difference: {} constraints only in A, {} only in B",
                    only_in_a.len(),
                    only_in_b.len()
                ),
                severity: 0.8,
            });
            self.stats.differences_found += 1;
        }
    }

    /// Find inputs that satisfy one version but not the other
    fn find_exclusive_inputs(&mut self) {
        // Inputs that satisfy A but not B
        self.find_exclusive_for_version(true);
        // Inputs that satisfy B but not A
        self.find_exclusive_for_version(false);
    }

    fn find_exclusive_for_version(&mut self, for_version_a: bool) {
        let (satisfied, unsatisfied) = if for_version_a {
            (&self.constraints_a, &self.constraints_b)
        } else {
            (&self.constraints_b, &self.constraints_a)
        };

        // Build: satisfies all of `satisfied` AND violates at least one of `unsatisfied`
        let mut pc = PathCondition::new();

        // Must satisfy all constraints in target version
        for constraint in satisfied {
            pc.add_constraint(constraint.clone());
        }

        // Must violate at least one constraint in other version
        // (disjunction of negations)
        if !unsatisfied.is_empty() {
            let negated: Vec<_> = unsatisfied.iter().map(|c| c.clone().negate()).collect();
            if let Some(first) = negated.first() {
                let mut disjunction = first.clone();
                for c in negated.iter().skip(1) {
                    disjunction = disjunction.or(c.clone());
                }
                pc.add_constraint(disjunction);
            }
        }

        self.stats.solver_calls += 1;
        self.stats.paths_explored += 1;

        if let SolverResult::Sat(assignments) = self.solver.solve(&pc) {
            let input = self.assignments_to_inputs(&assignments);

            let description = if for_version_a {
                "Input valid for version A but rejected by version B"
            } else {
                "Input valid for version B but rejected by version A"
            };

            self.differences.push(CircuitDifference {
                diverging_input: input,
                output_a: None,
                output_b: None,
                path_condition: pc,
                differing_constraints: Vec::new(),
                description: description.to_string(),
                severity: 0.9,
            });
            self.stats.differences_found += 1;
            self.stats.diverging_paths += 1;
        } else {
            self.stats.common_paths += 1;
        }
    }

    /// Check boundary conditions for differences
    fn find_boundary_differences(&mut self) {
        // Generate boundary inputs
        let boundary_inputs = self.generate_boundary_inputs();

        for inputs in boundary_inputs {
            // Check if versions behave differently on this input
            let result_a = self.check_satisfiable_with_input(&self.constraints_a, &inputs);
            let result_b = self.check_satisfiable_with_input(&self.constraints_b, &inputs);

            self.stats.solver_calls += 2;

            if result_a != result_b {
                self.differences.push(CircuitDifference {
                    diverging_input: inputs,
                    output_a: None,
                    output_b: None,
                    path_condition: PathCondition::new(),
                    differing_constraints: Vec::new(),
                    description: format!(
                        "Boundary difference: A={}, B={}",
                        if result_a { "accepts" } else { "rejects" },
                        if result_b { "accepts" } else { "rejects" }
                    ),
                    severity: 0.7,
                });
                self.stats.differences_found += 1;
            }
        }
    }

    fn generate_boundary_inputs(&self) -> Vec<Vec<FieldElement>> {
        let mut inputs = Vec::new();

        // All zeros
        inputs.push(vec![FieldElement::zero(); self.num_inputs]);

        // All ones
        inputs.push(vec![FieldElement::one(); self.num_inputs]);

        // Max field value
        inputs.push(vec![FieldElement::max_value(); self.num_inputs]);

        // Each input at boundary, others zero
        for i in 0..self.num_inputs {
            let mut input = vec![FieldElement::zero(); self.num_inputs];
            input[i] = FieldElement::max_value();
            inputs.push(input);
        }

        inputs
    }

    fn check_satisfiable_with_input(
        &self,
        constraints: &[SymbolicConstraint],
        inputs: &[FieldElement],
    ) -> bool {
        let mut pc = PathCondition::new();

        // Add concrete value constraints
        for (i, value) in inputs.iter().enumerate() {
            let name = format!("input_{}", i);
            pc.add_constraint(SymbolicConstraint::Eq(
                SymbolicValue::Symbol(name),
                SymbolicValue::Concrete(value.clone()),
            ));
        }

        // Add circuit constraints
        for constraint in constraints {
            pc.add_constraint(constraint.clone());
        }

        self.solver.solve(&pc).is_sat()
    }

    fn assignments_to_inputs(
        &self,
        assignments: &HashMap<String, FieldElement>,
    ) -> Vec<FieldElement> {
        (0..self.num_inputs)
            .map(|i| {
                let key = format!("input_{}", i);
                match assignments.get(&key).cloned() {
                    Some(value) => value,
                    None => FieldElement::zero(),
                }
            })
            .collect()
    }

    /// Get found differences
    pub fn differences(&self) -> &[CircuitDifference] {
        &self.differences
    }

    /// Get statistics
    pub fn stats(&self) -> &DifferentialStats {
        &self.stats
    }

    /// Check if versions are equivalent (no differences found)
    pub fn are_equivalent(&self) -> bool {
        self.differences.is_empty()
    }
}

#[cfg(test)]
#[path = "targeted_tests.rs"]
mod tests;
