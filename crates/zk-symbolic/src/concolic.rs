//! Concolic Execution for ZK Circuits
//!
//! Combines concrete and symbolic execution:
//! - Executes circuit concretely while building symbolic constraints
//! - Uses symbolic solver to generate new inputs that explore different paths
//! - Alternates between concrete and symbolic phases for efficiency
//!
//! This approach is more scalable than pure symbolic execution for large circuits.

use crate::executor::{PathCondition, SolverResult, SymbolicConstraint, SymbolicValue};
use crate::enhanced::{ConstraintSimplifier, IncrementalSolver};
use zk_core::{CircuitExecutor, ExecutionResult};
use zk_core::FieldElement;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Configuration for concolic execution
#[derive(Debug, Clone)]
pub struct ConcolicConfig {
    /// Maximum iterations of concrete-symbolic alternation
    pub max_iterations: usize,
    /// Maximum path conditions to track
    pub max_path_conditions: usize,
    /// Solver timeout in milliseconds
    pub solver_timeout_ms: u32,
    /// Enable constraint simplification
    pub simplify_constraints: bool,
    /// Ratio of concrete to symbolic phases
    pub concrete_ratio: f64,
    /// Maximum negations per path (for path exploration)
    pub max_negations: usize,
}

impl Default for ConcolicConfig {
    fn default() -> Self {
        Self {
            max_iterations: 1000,
            max_path_conditions: 100,
            solver_timeout_ms: 5000,
            simplify_constraints: true,
            concrete_ratio: 0.7, // 70% concrete execution
            max_negations: 10,
        }
    }
}

/// Represents a constraint from concrete execution with its branch decision
#[derive(Debug, Clone)]
pub struct BranchPoint {
    /// The constraint at this branch
    pub constraint: SymbolicConstraint,
    /// Whether the branch was taken (true) or not taken (false)
    pub taken: bool,
    /// Depth in the execution
    pub depth: usize,
    /// Whether this branch has been explored both ways
    pub fully_explored: bool,
}

/// Concolic execution trace from a single concrete run
#[derive(Debug, Clone)]
pub struct ConcolicTrace {
    /// Concrete inputs used
    pub inputs: Vec<FieldElement>,
    /// Concrete outputs produced
    pub outputs: Vec<FieldElement>,
    /// Branch points encountered
    pub branch_points: Vec<BranchPoint>,
    /// Full path condition (conjunction of all constraints)
    pub path_condition: PathCondition,
    /// Execution succeeded
    pub success: bool,
    /// Coverage hash for this execution
    pub coverage_hash: u64,
}

impl ConcolicTrace {
    pub fn new(inputs: Vec<FieldElement>) -> Self {
        Self {
            inputs,
            outputs: Vec::new(),
            branch_points: Vec::new(),
            path_condition: PathCondition::new(),
            success: false,
            coverage_hash: 0,
        }
    }

    /// Add a branch point to the trace
    pub fn add_branch(&mut self, constraint: SymbolicConstraint, taken: bool) {
        let depth = self.branch_points.len();
        self.branch_points.push(BranchPoint {
            constraint: constraint.clone(),
            taken,
            depth,
            fully_explored: false,
        });

        // Add to path condition based on branch direction
        if taken {
            self.path_condition.add_constraint(constraint);
        } else {
            self.path_condition.add_constraint(constraint.negate());
        }
    }

    /// Get unexplored branch alternatives
    pub fn unexplored_branches(&self) -> Vec<usize> {
        self.branch_points
            .iter()
            .enumerate()
            .filter(|(_, bp)| !bp.fully_explored)
            .map(|(i, _)| i)
            .collect()
    }
}

/// Concolic executor that alternates between concrete and symbolic execution
pub struct ConcolicExecutor {
    /// Circuit executor for concrete execution
    executor: Arc<dyn CircuitExecutor>,
    /// Symbolic solver for constraint solving
    solver: IncrementalSolver,
    /// Constraint simplifier
    simplifier: ConstraintSimplifier,
    /// Configuration
    config: ConcolicConfig,
    /// Queue of path conditions to explore
    path_queue: VecDeque<PathCondition>,
    /// Set of explored path hashes (to avoid duplicates)
    explored_paths: HashSet<u64>,
    /// Generated test cases
    generated_tests: Vec<Vec<FieldElement>>,
    /// All execution traces
    traces: Vec<ConcolicTrace>,
    /// Number of inputs
    num_inputs: usize,
    /// Statistics
    stats: ConcolicStats,
}

impl ConcolicExecutor {
    pub fn new(executor: Arc<dyn CircuitExecutor>) -> Self {
        let num_inputs = executor.num_private_inputs() + executor.num_public_inputs();
        Self {
            executor,
            solver: IncrementalSolver::new(),
            simplifier: ConstraintSimplifier::new(),
            config: ConcolicConfig::default(),
            path_queue: VecDeque::new(),
            explored_paths: HashSet::new(),
            generated_tests: Vec::new(),
            traces: Vec::new(),
            num_inputs,
            stats: ConcolicStats::default(),
        }
    }

    pub fn with_config(mut self, config: ConcolicConfig) -> Self {
        self.solver = IncrementalSolver::new().with_timeout(config.solver_timeout_ms);
        self.config = config;
        self
    }

    /// Run concolic execution starting from seed inputs
    pub fn run(&mut self, seeds: Vec<Vec<FieldElement>>) -> Vec<Vec<FieldElement>> {
        // Phase 1: Execute seeds concretely and collect traces
        for seed in seeds {
            self.execute_concrete(seed);
        }

        // Phase 2: Explore unexplored paths using symbolic solving
        for iteration in 0..self.config.max_iterations {
            if self.path_queue.is_empty() {
                // Generate new paths from existing traces
                self.generate_alternative_paths();
            }

            if self.path_queue.is_empty() {
                tracing::info!(
                    "Concolic exploration complete after {} iterations",
                    iteration
                );
                break;
            }

            // Get next path condition to explore
            if let Some(path) = self.path_queue.pop_front() {
                self.explore_path(path);
            }

            // Periodically do concrete execution to stay grounded
            if iteration % 10 == 0 && !self.generated_tests.is_empty() {
                let idx = iteration % self.generated_tests.len();
                let inputs = self.generated_tests[idx].clone();
                self.execute_concrete(inputs);
            }
        }

        self.generated_tests.clone()
    }

    /// Execute circuit concretely and build symbolic trace
    fn execute_concrete(&mut self, inputs: Vec<FieldElement>) -> Option<ConcolicTrace> {
        let mut trace = ConcolicTrace::new(inputs.clone());

        // Execute circuit
        let result = self.executor.execute_sync(&inputs);
        trace.success = result.success;
        trace.outputs = result.outputs.clone();
        trace.coverage_hash = result.coverage.coverage_hash;

        if !result.success {
            self.stats.failed_executions += 1;
            return None;
        }

        self.stats.concrete_executions += 1;

        // Build symbolic constraints from the execution
        // This is an approximation - real concolic would instrument the circuit
        self.build_symbolic_trace(&mut trace, &result);

        // Check if this is a new path
        let path_hash = self.hash_path(&trace.path_condition);
        if !self.explored_paths.insert(path_hash) {
            return Some(trace);
        }

        // Add to traces and generated tests
        self.traces.push(trace.clone());
        if !self.generated_tests.contains(&inputs) {
            self.generated_tests.push(inputs);
        }

        Some(trace)
    }

    /// Build symbolic trace from execution result
    fn build_symbolic_trace(&self, trace: &mut ConcolicTrace, result: &ExecutionResult) {
        // Stable identifier for this concrete execution path.
        trace.path_condition.path_id = result.coverage.coverage_hash;

        // Create symbolic inputs
        let inputs_snapshot = trace.inputs.clone();
        for (i, input) in inputs_snapshot.iter().enumerate() {
            let symbolic_input = SymbolicValue::symbol(&format!("input_{}", i));
            let concrete_value = SymbolicValue::concrete(input.clone());

            // Add equality constraint (symbolic == concrete)
            trace.add_branch(SymbolicConstraint::Eq(symbolic_input, concrete_value), true);
        }

        // Heuristic approximation:
        // generate lightweight branch predicates from concrete inputs so
        // path negation can still explore nearby alternatives without full
        // backend-level branch instrumentation.
        let inputs_snapshot = trace.inputs.clone();
        for (i, input) in inputs_snapshot.iter().enumerate() {
            let sym = SymbolicValue::symbol(&format!("input_{}", i));

            // Add range constraint
            if !input.is_zero() {
                trace.add_branch(
                    SymbolicConstraint::Neq(
                        sym.clone(),
                        SymbolicValue::concrete(FieldElement::zero()),
                    ),
                    true,
                );
            }

            // Add boolean constraint if value is 0 or 1
            if input.is_zero() || input.is_one() {
                trace.add_branch(SymbolicConstraint::Boolean(sym), true);
            }
        }
    }

    /// Generate alternative paths by negating branch points
    fn generate_alternative_paths(&mut self) {
        let mut new_paths = Vec::new();

        for trace in &self.traces {
            let unexplored = trace.unexplored_branches();

            for &branch_idx in unexplored.iter().take(self.config.max_negations) {
                // Create path condition by taking original path up to this branch,
                // then negating this branch
                let mut new_path = PathCondition::new();

                for (i, bp) in trace.branch_points.iter().enumerate() {
                    if i < branch_idx {
                        // Keep original direction
                        if bp.taken {
                            new_path.add_constraint(bp.constraint.clone());
                        } else {
                            new_path.add_constraint(bp.constraint.clone().negate());
                        }
                    } else if i == branch_idx {
                        // Negate this branch
                        if bp.taken {
                            new_path.add_constraint(bp.constraint.clone().negate());
                        } else {
                            new_path.add_constraint(bp.constraint.clone());
                        }
                        break; // Don't include constraints after the negated branch
                    }
                }

                // Check if this path is new
                let path_hash = self.hash_path(&new_path);
                if !self.explored_paths.contains(&path_hash) {
                    new_paths.push(new_path);
                }
            }
        }

        // Add new paths to queue
        for path in new_paths {
            if self.path_queue.len() < self.config.max_path_conditions {
                self.path_queue.push_back(path);
            }
        }
    }

    /// Explore a path condition by solving for satisfying inputs
    fn explore_path(&mut self, path: PathCondition) {
        self.stats.symbolic_queries += 1;

        // Simplify if enabled
        let path = if self.config.simplify_constraints {
            self.simplifier.simplify_path(&path)
        } else {
            path
        };

        // Solve for satisfying assignment
        let result = self
            .solver
            .solve_incremental(&PathCondition::new(), &path.constraints);

        match result {
            SolverResult::Sat(assignments) => {
                self.stats.sat_results += 1;

                // Convert to concrete inputs
                let inputs = self.assignments_to_inputs(&assignments);

                // Execute concretely with new inputs
                if let Some(_trace) = self.execute_concrete(inputs) {
                    self.stats.new_paths_found += 1;
                }
            }
            SolverResult::Unsat => {
                self.stats.unsat_results += 1;
            }
            SolverResult::Unknown => {
                self.stats.unknown_results += 1;
            }
        }
    }

    /// Convert symbol assignments to input vector
    fn assignments_to_inputs(
        &self,
        assignments: &HashMap<String, FieldElement>,
    ) -> Vec<FieldElement> {
        let mut inputs = Vec::with_capacity(self.num_inputs);
        for i in 0..self.num_inputs {
            let key = format!("input_{}", i);
            if let Some(value) = assignments.get(&key) {
                inputs.push(value.clone());
            } else {
                inputs.push(FieldElement::zero());
            }
        }
        inputs
    }

    fn hash_path(&self, path: &PathCondition) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        for constraint in &path.constraints {
            format!("{:?}", constraint).hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Get generated test cases
    pub fn get_test_cases(&self) -> &[Vec<FieldElement>] {
        &self.generated_tests
    }

    /// Get statistics
    pub fn stats(&self) -> &ConcolicStats {
        &self.stats
    }

    /// Reset for new exploration
    pub fn reset(&mut self) {
        self.path_queue.clear();
        self.explored_paths.clear();
        self.generated_tests.clear();
        self.traces.clear();
        self.stats = ConcolicStats::default();
        self.solver.clear_cache();
    }
}

/// Statistics for concolic execution
#[derive(Debug, Clone, Default)]
pub struct ConcolicStats {
    pub concrete_executions: usize,
    pub failed_executions: usize,
    pub symbolic_queries: usize,
    pub sat_results: usize,
    pub unsat_results: usize,
    pub unknown_results: usize,
    pub new_paths_found: usize,
}

/// Integration with the fuzzing loop
pub struct ConcolicFuzzerIntegration {
    executor: Option<ConcolicExecutor>,
    /// Pending test cases to be used by fuzzer
    pending_tests: VecDeque<Vec<FieldElement>>,
    /// Number of inputs
    num_inputs: usize,
    /// Configuration
    config: ConcolicConfig,
}

impl ConcolicFuzzerIntegration {
    pub fn new(num_inputs: usize) -> Self {
        Self {
            executor: None,
            pending_tests: VecDeque::new(),
            num_inputs,
            config: ConcolicConfig::default(),
        }
    }

    pub fn with_config(mut self, config: ConcolicConfig) -> Self {
        self.config = config;
        self
    }

    /// Initialize with circuit executor
    pub fn initialize(&mut self, executor: Arc<dyn CircuitExecutor>) {
        self.executor = Some(ConcolicExecutor::new(executor).with_config(self.config.clone()));
    }

    /// Run concolic exploration with seeds
    pub fn explore(&mut self, seeds: Vec<Vec<FieldElement>>) {
        if let Some(ref mut executor) = self.executor {
            let expected = self.num_inputs;
            let seeds = if expected == 0 {
                seeds
            } else {
                seeds
                    .into_iter()
                    .filter(|inputs| inputs.len() == expected)
                    .collect()
            };
            if seeds.is_empty() {
                return;
            }
            let tests = executor.run(seeds);
            for test in tests {
                self.pending_tests.push_back(test);
            }
        }
    }

    /// Get next test case
    pub fn next_test(&mut self) -> Option<Vec<FieldElement>> {
        self.pending_tests.pop_front()
    }

    /// Check if executor is initialized
    pub fn is_initialized(&self) -> bool {
        self.executor.is_some()
    }

    /// Get statistics
    pub fn stats(&self) -> Option<ConcolicStats> {
        self.executor.as_ref().map(|e| e.stats().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_core::{CircuitExecutor, CircuitInfo, ExecutionCoverage, ExecutionResult, Framework};

    struct DummyExecutor {
        private_inputs: usize,
        public_inputs: usize,
    }

    impl DummyExecutor {
        fn new(private_inputs: usize, public_inputs: usize) -> Self {
            Self {
                private_inputs,
                public_inputs,
            }
        }
    }

    impl CircuitExecutor for DummyExecutor {
        fn framework(&self) -> Framework {
            Framework::Circom
        }

        fn name(&self) -> &str {
            "dummy"
        }

        fn circuit_info(&self) -> CircuitInfo {
            CircuitInfo {
                name: "dummy".to_string(),
                num_constraints: 0,
                num_private_inputs: self.private_inputs,
                num_public_inputs: self.public_inputs,
                num_outputs: 0,
            }
        }

        fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
            ExecutionResult::success(Vec::new(), ExecutionCoverage::default())
        }

        fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn test_concolic_trace() {
        let mut trace = ConcolicTrace::new(vec![FieldElement::zero(), FieldElement::one()]);

        let constraint = SymbolicConstraint::Eq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::zero()),
        );

        trace.add_branch(constraint, true);
        assert_eq!(trace.branch_points.len(), 1);
        assert!(trace.branch_points[0].taken);
    }

    #[test]
    fn test_concolic_executor_creation() {
        let dummy = Arc::new(DummyExecutor::new(3, 1));
        let executor = ConcolicExecutor::new(dummy);

        assert_eq!(executor.num_inputs, 4); // 3 private + 1 public
    }

    #[test]
    fn test_concolic_integration() {
        let mut integration = ConcolicFuzzerIntegration::new(3);
        assert!(!integration.is_initialized());

        let dummy = Arc::new(DummyExecutor::new(3, 1));
        integration.initialize(dummy);
        assert!(integration.is_initialized());
    }
}
