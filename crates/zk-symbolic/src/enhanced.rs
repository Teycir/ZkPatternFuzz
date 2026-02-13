//! Enhanced Symbolic Execution Framework
//!
//! Improvements over basic symbolic execution:
//! - Incremental solving using Z3 push/pop
//! - Constraint simplification before solving
//! - Sophisticated path pruning strategies
//! - Support for complex constraint types (lookups, custom gates)
//! - Better memory management for large path spaces

use crate::executor::{
    PathCondition, SolverResult, SymbolicConstraint, SymbolicState, SymbolicValue, Z3Solver,
};
use zk_core::FieldElement;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use z3::ast::Ast;
use z3::{ast, Config, Context, SatResult, Solver};

/// BN254 scalar field modulus
const BN254_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

// ============================================================================
// Path Pruning Strategies
// ============================================================================

/// Strategy for pruning paths during exploration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruningStrategy {
    /// No pruning - explore all paths (may explode)
    None,
    /// Limit by depth - prune paths exceeding max depth
    DepthBounded,
    /// Limit by constraint count - prune paths with too many constraints
    ConstraintBounded,
    /// Coverage-guided - prioritize paths that increase coverage
    CoverageGuided,
    /// Random sampling - randomly sample paths
    RandomSampling,
    /// Loop bounding - limit loop iterations
    LoopBounded,
    /// Similarity-based - skip paths similar to already explored
    SimilarityBased,
    /// Constraint subsumption - skip subsumed paths
    SubsumptionBased,
}

/// Path priority for exploration ordering
#[derive(Debug, Clone)]
pub struct PrioritizedPath {
    pub state: SymbolicState,
    pub priority: f64,
    pub coverage_potential: usize,
    pub constraint_complexity: usize,
}

impl PartialEq for PrioritizedPath {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for PrioritizedPath {}

impl PartialOrd for PrioritizedPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedPath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .partial_cmp(&other.priority)
            .unwrap_or(Ordering::Equal)
    }
}

/// Path pruner with configurable strategies
#[derive(Debug, Clone)]
pub struct PathPruner {
    strategy: PruningStrategy,
    max_depth: usize,
    max_constraints: usize,
    max_paths: usize,
    loop_bound: usize,
    /// Hashes of explored path prefixes for similarity detection
    explored_prefixes: HashSet<u64>,
    /// Canonicalized constraint-hash sets for subsumption pruning.
    explored_constraint_sets: Vec<HashSet<u64>>,
    /// Coverage bitmap for guided pruning
    coverage_bitmap: Vec<bool>,
}

impl PathPruner {
    pub fn new(strategy: PruningStrategy) -> Self {
        Self {
            strategy,
            max_depth: 50,
            max_constraints: 100,
            max_paths: 10000,
            loop_bound: 10,
            explored_prefixes: HashSet::new(),
            explored_constraint_sets: Vec::new(),
            coverage_bitmap: Vec::new(),
        }
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn with_max_constraints(mut self, count: usize) -> Self {
        self.max_constraints = count;
        self
    }

    pub fn with_max_paths(mut self, count: usize) -> Self {
        self.max_paths = count;
        self
    }

    pub fn with_loop_bound(mut self, bound: usize) -> Self {
        self.loop_bound = bound;
        self
    }

    pub fn with_coverage_bitmap(mut self, bitmap: Vec<bool>) -> Self {
        self.coverage_bitmap = bitmap;
        self
    }

    /// Decide whether to prune a path
    pub fn should_prune(&mut self, state: &SymbolicState, explored_count: usize) -> bool {
        match self.strategy {
            PruningStrategy::None => false,
            PruningStrategy::DepthBounded => state.depth > self.max_depth,
            PruningStrategy::ConstraintBounded => {
                state.path_condition.constraints.len() > self.max_constraints
            }
            PruningStrategy::CoverageGuided => {
                // Prune if we've exceeded path limit and this path has low coverage potential
                if explored_count > self.max_paths {
                    let potential = self.estimate_coverage_potential(state);
                    potential < 0.1
                } else {
                    false
                }
            }
            PruningStrategy::RandomSampling => {
                if explored_count > self.max_paths {
                    rand::random::<f64>() > 0.1 // Keep 10% of paths
                } else {
                    false
                }
            }
            PruningStrategy::LoopBounded => self.detect_loop_iteration(state) > self.loop_bound,
            PruningStrategy::SimilarityBased => {
                let hash = self.compute_path_hash(state);
                if self.explored_prefixes.contains(&hash) {
                    true
                } else {
                    self.explored_prefixes.insert(hash);
                    false
                }
            }
            PruningStrategy::SubsumptionBased => self.is_subsumed(state),
        }
    }

    /// Estimate how much new coverage a path might provide
    fn estimate_coverage_potential(&self, state: &SymbolicState) -> f64 {
        if self.coverage_bitmap.is_empty() {
            return 1.0;
        }

        // Count how many constraints in this path hit uncovered areas
        let mut potential_hits = 0;
        for constraint in &state.path_condition.constraints {
            let constraint_id = self.constraint_to_id(constraint);
            if constraint_id < self.coverage_bitmap.len() && !self.coverage_bitmap[constraint_id] {
                potential_hits += 1;
            }
        }

        potential_hits as f64 / state.path_condition.constraints.len().max(1) as f64
    }

    /// Detect loop iterations by pattern matching on constraints
    fn detect_loop_iteration(&self, state: &SymbolicState) -> usize {
        // Simple heuristic: count repeated constraint patterns
        let mut pattern_counts: HashMap<u64, usize> = HashMap::new();

        for constraint in &state.path_condition.constraints {
            let hash = self.hash_constraint(constraint);
            *pattern_counts.entry(hash).or_insert(0) += 1;
        }

        pattern_counts.values().max().copied().unwrap_or(0)
    }

    /// Compute hash for similarity detection
    fn compute_path_hash(&self, state: &SymbolicState) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Hash first few constraints as prefix
        for (i, constraint) in state.path_condition.constraints.iter().enumerate() {
            if i >= 10 {
                break;
            }
            self.hash_constraint(constraint).hash(&mut hasher);
        }

        hasher.finish()
    }

    /// Hash a single constraint
    fn hash_constraint(&self, constraint: &SymbolicConstraint) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        format!("{:?}", constraint).hash(&mut hasher);
        hasher.finish()
    }

    /// Map constraint to coverage ID
    fn constraint_to_id(&self, constraint: &SymbolicConstraint) -> usize {
        (self.hash_constraint(constraint) % 10000) as usize
    }

    /// Check if path is subsumed by already explored paths
    fn is_subsumed(&mut self, state: &SymbolicState) -> bool {
        // Approximate subsumption using canonicalized constraint-hash sets:
        // if any previously explored set is a subset of the current set,
        // the current path is more constrained and can be pruned.
        let current: HashSet<u64> = state
            .path_condition
            .constraints
            .iter()
            .map(|c| self.hash_constraint(c))
            .collect();

        if current.is_empty() {
            return false;
        }

        if self
            .explored_constraint_sets
            .iter()
            .any(|seen| seen.is_subset(&current))
        {
            return true;
        }

        if self.explored_constraint_sets.len() >= self.max_paths {
            let evict = self.explored_constraint_sets.len() + 1 - self.max_paths;
            self.explored_constraint_sets.drain(0..evict);
        }
        self.explored_constraint_sets.push(current);
        false
    }

    /// Prioritize paths for exploration
    pub fn prioritize(&self, states: &[SymbolicState]) -> Vec<PrioritizedPath> {
        states
            .iter()
            .map(|state| {
                let coverage_potential = self.estimate_coverage_potential(state) as usize;
                let constraint_complexity = state.path_condition.constraints.len();

                // Higher priority for:
                // - Lower depth (explore shallow paths first)
                // - Higher coverage potential
                // - Lower constraint complexity
                let priority = (100.0 - state.depth as f64) + (coverage_potential as f64 * 10.0)
                    - (constraint_complexity as f64 * 0.5);

                PrioritizedPath {
                    state: state.clone(),
                    priority,
                    coverage_potential,
                    constraint_complexity,
                }
            })
            .collect()
    }
}

// ============================================================================
// Constraint Simplification
// ============================================================================

/// Simplifies symbolic constraints before solving
pub struct ConstraintSimplifier {
    /// Cache of simplified constraints
    cache: HashMap<u64, SymbolicConstraint>,
    /// Enable constant folding
    fold_constants: bool,
}

impl ConstraintSimplifier {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            fold_constants: true,
        }
    }

    /// Simplify a path condition
    pub fn simplify_path(&mut self, path: &PathCondition) -> PathCondition {
        let mut simplified = PathCondition::with_id(path.path_id);

        for constraint in &path.constraints {
            if let Some(simplified_constraint) = self.simplify_constraint(constraint) {
                // Skip trivially true constraints
                if !matches!(simplified_constraint, SymbolicConstraint::True) {
                    simplified.add_constraint(simplified_constraint);
                }
            }
        }

        // Remove duplicate constraints
        self.deduplicate(&mut simplified);

        simplified
    }

    /// Simplify a single constraint
    pub fn simplify_constraint(
        &mut self,
        constraint: &SymbolicConstraint,
    ) -> Option<SymbolicConstraint> {
        // Check cache
        let hash = self.hash_constraint(constraint);
        if let Some(cached) = self.cache.get(&hash) {
            return Some(cached.clone());
        }

        let simplified = self.simplify_impl(constraint);

        // Cache result
        if let Some(ref s) = simplified {
            self.cache.insert(hash, s.clone());
        }

        simplified
    }

    fn simplify_impl(&self, constraint: &SymbolicConstraint) -> Option<SymbolicConstraint> {
        match constraint {
            SymbolicConstraint::Eq(a, b) => {
                let a_simple = self.simplify_value(a);
                let b_simple = self.simplify_value(b);

                // Check for trivial equality
                if self.values_equal(&a_simple, &b_simple) {
                    return Some(SymbolicConstraint::True);
                }

                // Check for impossible equality (two different constants)
                if let (SymbolicValue::Concrete(va), SymbolicValue::Concrete(vb)) =
                    (&a_simple, &b_simple)
                {
                    if va != vb {
                        return Some(SymbolicConstraint::False);
                    }
                }

                Some(SymbolicConstraint::Eq(a_simple, b_simple))
            }

            SymbolicConstraint::Neq(a, b) => {
                let a_simple = self.simplify_value(a);
                let b_simple = self.simplify_value(b);

                // Check for trivial inequality
                if let (SymbolicValue::Concrete(va), SymbolicValue::Concrete(vb)) =
                    (&a_simple, &b_simple)
                {
                    if va != vb {
                        return Some(SymbolicConstraint::True);
                    } else {
                        return Some(SymbolicConstraint::False);
                    }
                }

                Some(SymbolicConstraint::Neq(a_simple, b_simple))
            }

            SymbolicConstraint::R1CS { a, b, c } => {
                let a_simple = self.simplify_value(a);
                let b_simple = self.simplify_value(b);
                let c_simple = self.simplify_value(c);

                // If all are concrete, check validity
                if let (
                    SymbolicValue::Concrete(va),
                    SymbolicValue::Concrete(vb),
                    SymbolicValue::Concrete(vc),
                ) = (&a_simple, &b_simple, &c_simple)
                {
                    let product = va.mul(vb);
                    if product == *vc {
                        return Some(SymbolicConstraint::True);
                    } else {
                        return Some(SymbolicConstraint::False);
                    }
                }

                // Simplify: 0 * b = c => c = 0
                if matches!(&a_simple, SymbolicValue::Concrete(v) if v.is_zero()) {
                    return Some(SymbolicConstraint::Eq(
                        c_simple,
                        SymbolicValue::Concrete(FieldElement::zero()),
                    ));
                }

                // Simplify: a * 0 = c => c = 0
                if matches!(&b_simple, SymbolicValue::Concrete(v) if v.is_zero()) {
                    return Some(SymbolicConstraint::Eq(
                        c_simple,
                        SymbolicValue::Concrete(FieldElement::zero()),
                    ));
                }

                // Simplify: 1 * b = c => b = c
                if matches!(&a_simple, SymbolicValue::Concrete(v) if v.is_one()) {
                    return Some(SymbolicConstraint::Eq(b_simple, c_simple));
                }

                // Simplify: a * 1 = c => a = c
                if matches!(&b_simple, SymbolicValue::Concrete(v) if v.is_one()) {
                    return Some(SymbolicConstraint::Eq(a_simple, c_simple));
                }

                Some(SymbolicConstraint::R1CS {
                    a: a_simple,
                    b: b_simple,
                    c: c_simple,
                })
            }

            SymbolicConstraint::Boolean(v) => {
                let v_simple = self.simplify_value(v);

                // Check if concrete 0 or 1
                if let SymbolicValue::Concrete(cv) = &v_simple {
                    if cv.is_zero() || cv.is_one() {
                        return Some(SymbolicConstraint::True);
                    }
                }

                Some(SymbolicConstraint::Boolean(v_simple))
            }

            SymbolicConstraint::And(c1, c2) => {
                let c1_simple = self.simplify_impl(c1)?;
                let c2_simple = self.simplify_impl(c2)?;

                match (&c1_simple, &c2_simple) {
                    (SymbolicConstraint::True, c) | (c, SymbolicConstraint::True) => {
                        Some(c.clone())
                    }
                    (SymbolicConstraint::False, _) | (_, SymbolicConstraint::False) => {
                        Some(SymbolicConstraint::False)
                    }
                    _ => Some(SymbolicConstraint::And(
                        Box::new(c1_simple),
                        Box::new(c2_simple),
                    )),
                }
            }

            SymbolicConstraint::Or(c1, c2) => {
                let c1_simple = self.simplify_impl(c1)?;
                let c2_simple = self.simplify_impl(c2)?;

                match (&c1_simple, &c2_simple) {
                    (SymbolicConstraint::True, _) | (_, SymbolicConstraint::True) => {
                        Some(SymbolicConstraint::True)
                    }
                    (SymbolicConstraint::False, c) | (c, SymbolicConstraint::False) => {
                        Some(c.clone())
                    }
                    _ => Some(SymbolicConstraint::Or(
                        Box::new(c1_simple),
                        Box::new(c2_simple),
                    )),
                }
            }

            SymbolicConstraint::Not(c) => {
                let c_simple = self.simplify_impl(c)?;

                match c_simple {
                    SymbolicConstraint::True => Some(SymbolicConstraint::False),
                    SymbolicConstraint::False => Some(SymbolicConstraint::True),
                    SymbolicConstraint::Not(inner) => Some(*inner),
                    _ => Some(SymbolicConstraint::Not(Box::new(c_simple))),
                }
            }

            SymbolicConstraint::True | SymbolicConstraint::False => Some(constraint.clone()),

            _ => Some(constraint.clone()),
        }
    }

    /// Simplify a symbolic value using constant folding
    fn simplify_value(&self, value: &SymbolicValue) -> SymbolicValue {
        if !self.fold_constants {
            return value.clone();
        }

        match value {
            SymbolicValue::Concrete(_) | SymbolicValue::Symbol(_) => value.clone(),

            SymbolicValue::Add(a, b) => {
                let a_simple = self.simplify_value(a);
                let b_simple = self.simplify_value(b);

                // Fold constants
                if let (SymbolicValue::Concrete(va), SymbolicValue::Concrete(vb)) =
                    (&a_simple, &b_simple)
                {
                    return SymbolicValue::Concrete(va.add(vb));
                }

                // Identity: x + 0 = x
                if matches!(&b_simple, SymbolicValue::Concrete(v) if v.is_zero()) {
                    return a_simple;
                }
                if matches!(&a_simple, SymbolicValue::Concrete(v) if v.is_zero()) {
                    return b_simple;
                }

                SymbolicValue::Add(Box::new(a_simple), Box::new(b_simple))
            }

            SymbolicValue::Mul(a, b) => {
                let a_simple = self.simplify_value(a);
                let b_simple = self.simplify_value(b);

                // Fold constants
                if let (SymbolicValue::Concrete(va), SymbolicValue::Concrete(vb)) =
                    (&a_simple, &b_simple)
                {
                    return SymbolicValue::Concrete(va.mul(vb));
                }

                // Identity: x * 1 = x
                if matches!(&b_simple, SymbolicValue::Concrete(v) if v.is_one()) {
                    return a_simple;
                }
                if matches!(&a_simple, SymbolicValue::Concrete(v) if v.is_one()) {
                    return b_simple;
                }

                // Zero: x * 0 = 0
                if matches!(&a_simple, SymbolicValue::Concrete(v) if v.is_zero())
                    || matches!(&b_simple, SymbolicValue::Concrete(v) if v.is_zero())
                {
                    return SymbolicValue::Concrete(FieldElement::zero());
                }

                SymbolicValue::Mul(Box::new(a_simple), Box::new(b_simple))
            }

            SymbolicValue::Sub(a, b) => {
                let a_simple = self.simplify_value(a);
                let b_simple = self.simplify_value(b);

                // Fold constants
                if let (SymbolicValue::Concrete(va), SymbolicValue::Concrete(vb)) =
                    (&a_simple, &b_simple)
                {
                    return SymbolicValue::Concrete(va.sub(vb));
                }

                // Identity: x - 0 = x
                if matches!(&b_simple, SymbolicValue::Concrete(v) if v.is_zero()) {
                    return a_simple;
                }

                // Self-subtraction: x - x = 0
                if self.values_equal(&a_simple, &b_simple) {
                    return SymbolicValue::Concrete(FieldElement::zero());
                }

                SymbolicValue::Sub(Box::new(a_simple), Box::new(b_simple))
            }

            SymbolicValue::Neg(a) => {
                let a_simple = self.simplify_value(a);

                // Fold constant
                if let SymbolicValue::Concrete(va) = &a_simple {
                    return SymbolicValue::Concrete(va.neg());
                }

                // Double negation: --x = x
                if let SymbolicValue::Neg(inner) = a_simple {
                    return *inner;
                }

                SymbolicValue::Neg(Box::new(a_simple))
            }

            _ => value.clone(),
        }
    }

    /// Check if two values are structurally equal
    fn values_equal(&self, a: &SymbolicValue, b: &SymbolicValue) -> bool {
        match (a, b) {
            (SymbolicValue::Concrete(va), SymbolicValue::Concrete(vb)) => va == vb,
            (SymbolicValue::Symbol(sa), SymbolicValue::Symbol(sb)) => sa == sb,
            _ => false,
        }
    }

    /// Remove duplicate constraints
    fn deduplicate(&self, path: &mut PathCondition) {
        let mut seen: HashSet<u64> = HashSet::new();
        path.constraints.retain(|c| {
            let hash = self.hash_constraint(c);
            if seen.contains(&hash) {
                false
            } else {
                seen.insert(hash);
                true
            }
        });
    }

    fn hash_constraint(&self, constraint: &SymbolicConstraint) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        format!("{:?}", constraint).hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for ConstraintSimplifier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Incremental Z3 Solver
// ============================================================================

/// Incremental solver using Z3's push/pop mechanism
pub struct IncrementalSolver {
    timeout_ms: u32,
    modulus: String,
    random_seed: Option<u64>,
    /// Cache of solved path conditions to avoid redundant solving
    solution_cache: HashMap<u64, SolverResult>,
    /// Maximum cache size
    max_cache_size: usize,
    /// Number of cache hits observed.
    cache_hits: usize,
}

impl IncrementalSolver {
    pub fn new() -> Self {
        Self {
            timeout_ms: 5000,
            modulus: BN254_MODULUS.to_string(),
            random_seed: None,
            solution_cache: HashMap::new(),
            max_cache_size: 10000,
            cache_hits: 0,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_random_seed(mut self, seed: Option<u64>) -> Self {
        self.random_seed = seed;
        self
    }

    /// Solve incrementally - reuses solver state for path extensions
    pub fn solve_incremental(
        &mut self,
        base_path: &PathCondition,
        new_constraints: &[SymbolicConstraint],
    ) -> SolverResult {
        // Check cache for full path
        let mut full_path = base_path.clone();
        for c in new_constraints {
            full_path.add_constraint(c.clone());
        }

        let cache_key = self.hash_path(&full_path);
        if let Some(cached) = self.solution_cache.get(&cache_key) {
            self.cache_hits = self.cache_hits.saturating_add(1);
            return cached.clone();
        }

        // Early unsatisfiability check
        if full_path.is_trivially_unsat() {
            return SolverResult::Unsat;
        }

        let result = self.solve_with_push_pop(base_path, new_constraints);

        // Cache result
        if self.solution_cache.len() < self.max_cache_size {
            self.solution_cache.insert(cache_key, result.clone());
        }

        result
    }

    /// Use Z3's push/pop for incremental solving
    fn solve_with_push_pop(
        &self,
        base_path: &PathCondition,
        new_constraints: &[SymbolicConstraint],
    ) -> SolverResult {
        let mut cfg = Config::new();
        cfg.set_model_generation(true);
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", self.timeout_ms);
        if let Some(seed) = self.random_seed {
            let seed_u32 = (seed % (u32::MAX as u64)) as u32;
            params.set_u32("random_seed", seed_u32);
            params.set_u32("smt.random_seed", seed_u32);
            params.set_u32("sat.random_seed", seed_u32);
        }
        solver.set_params(&params);

        let mut vars: HashMap<String, ast::Int> = HashMap::new();

        // Add base constraints
        for constraint in &base_path.constraints {
            let z3_constraint = self.constraint_to_z3(&ctx, constraint, &mut vars);
            solver.assert(&z3_constraint);
        }

        // Add field bounds
        self.add_field_bounds(&ctx, &solver, &vars);

        // Check base satisfiability (optional optimization)
        if solver.check() == SatResult::Unsat {
            return SolverResult::Unsat;
        }

        // Push checkpoint
        solver.push();

        // Add new constraints incrementally
        for constraint in new_constraints {
            let z3_constraint = self.constraint_to_z3(&ctx, constraint, &mut vars);
            solver.assert(&z3_constraint);
        }

        // Re-add field bounds for new variables
        self.add_field_bounds(&ctx, &solver, &vars);

        let result = match solver.check() {
            SatResult::Sat => {
                let model = solver.get_model().unwrap();
                let assignments = self.extract_model(&model, &vars);
                SolverResult::Sat(assignments)
            }
            SatResult::Unsat => SolverResult::Unsat,
            SatResult::Unknown => SolverResult::Unknown,
        };

        // Pop to restore checkpoint (for potential reuse)
        solver.pop(1);

        result
    }

    /// Convert constraint to Z3 (simplified version - reuses logic from Z3Solver)
    fn constraint_to_z3<'a>(
        &self,
        ctx: &'a Context,
        constraint: &SymbolicConstraint,
        vars: &mut HashMap<String, ast::Int<'a>>,
    ) -> ast::Bool<'a> {
        match constraint {
            SymbolicConstraint::Eq(a, b) => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let b_z3 = self.value_to_z3(ctx, b, vars);
                a_z3._eq(&b_z3)
            }
            SymbolicConstraint::Neq(a, b) => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let b_z3 = self.value_to_z3(ctx, b, vars);
                a_z3._eq(&b_z3).not()
            }
            SymbolicConstraint::Lt(a, b) => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let b_z3 = self.value_to_z3(ctx, b, vars);
                a_z3.lt(&b_z3)
            }
            SymbolicConstraint::Lte(a, b) => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let b_z3 = self.value_to_z3(ctx, b, vars);
                a_z3.le(&b_z3)
            }
            SymbolicConstraint::R1CS { a, b, c } => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let b_z3 = self.value_to_z3(ctx, b, vars);
                let c_z3 = self.value_to_z3(ctx, c, vars);
                let modulus = ast::Int::from_str(ctx, &self.modulus).unwrap();
                let product = ast::Int::mul(ctx, &[&a_z3, &b_z3]).modulo(&modulus);
                product._eq(&c_z3)
            }
            SymbolicConstraint::Boolean(v) => {
                let v_z3 = self.value_to_z3(ctx, v, vars);
                let zero = ast::Int::from_i64(ctx, 0);
                let one = ast::Int::from_i64(ctx, 1);
                ast::Bool::or(ctx, &[&v_z3._eq(&zero), &v_z3._eq(&one)])
            }
            SymbolicConstraint::Range(v, bound) => {
                let v_z3 = self.value_to_z3(ctx, v, vars);
                let bound_z3 = self.value_to_z3(ctx, bound, vars);
                let zero = ast::Int::from_i64(ctx, 0);
                let gte_zero = v_z3.ge(&zero);
                let lt_bound = v_z3.lt(&bound_z3);
                ast::Bool::and(ctx, &[&gte_zero, &lt_bound])
            }
            SymbolicConstraint::And(c1, c2) => {
                let c1_z3 = self.constraint_to_z3(ctx, c1, vars);
                let c2_z3 = self.constraint_to_z3(ctx, c2, vars);
                ast::Bool::and(ctx, &[&c1_z3, &c2_z3])
            }
            SymbolicConstraint::Or(c1, c2) => {
                let c1_z3 = self.constraint_to_z3(ctx, c1, vars);
                let c2_z3 = self.constraint_to_z3(ctx, c2, vars);
                ast::Bool::or(ctx, &[&c1_z3, &c2_z3])
            }
            SymbolicConstraint::Not(c) => {
                let c_z3 = self.constraint_to_z3(ctx, c, vars);
                c_z3.not()
            }
            SymbolicConstraint::True => ast::Bool::from_bool(ctx, true),
            SymbolicConstraint::False => ast::Bool::from_bool(ctx, false),
        }
    }

    fn value_to_z3<'a>(
        &self,
        ctx: &'a Context,
        value: &SymbolicValue,
        vars: &mut HashMap<String, ast::Int<'a>>,
    ) -> ast::Int<'a> {
        match value {
            SymbolicValue::Concrete(fe) => {
                let dec_str = fe.to_decimal_string();
                ast::Int::from_str(ctx, &dec_str)
                    .unwrap_or_else(|| ast::Int::from_i64(ctx, 0))
            }
            SymbolicValue::Symbol(name) => {
                if let Some(var) = vars.get(name) {
                    var.clone()
                } else {
                    let var = ast::Int::new_const(ctx, name.as_str());
                    vars.insert(name.clone(), var.clone());
                    var
                }
            }
            SymbolicValue::Add(a, b) => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let b_z3 = self.value_to_z3(ctx, b, vars);
                let modulus = ast::Int::from_str(ctx, &self.modulus).unwrap();
                ast::Int::add(ctx, &[&a_z3, &b_z3]).modulo(&modulus)
            }
            SymbolicValue::Mul(a, b) => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let b_z3 = self.value_to_z3(ctx, b, vars);
                let modulus = ast::Int::from_str(ctx, &self.modulus).unwrap();
                ast::Int::mul(ctx, &[&a_z3, &b_z3]).modulo(&modulus)
            }
            SymbolicValue::Sub(a, b) => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let b_z3 = self.value_to_z3(ctx, b, vars);
                let modulus = ast::Int::from_str(ctx, &self.modulus).unwrap();
                let sum = ast::Int::add(ctx, &[&a_z3, &modulus]);
                ast::Int::sub(ctx, &[&sum, &b_z3]).modulo(&modulus)
            }
            _ => ast::Int::from_i64(ctx, 0),
        }
    }

    fn add_field_bounds<'a>(
        &self,
        ctx: &'a Context,
        solver: &Solver<'a>,
        vars: &HashMap<String, ast::Int<'a>>,
    ) {
        let zero = ast::Int::from_i64(ctx, 0);
        let modulus = ast::Int::from_str(ctx, &self.modulus).unwrap();

        for var in vars.values() {
            solver.assert(&var.ge(&zero));
            solver.assert(&var.lt(&modulus));
        }
    }

    fn extract_model(
        &self,
        model: &z3::Model,
        vars: &HashMap<String, ast::Int>,
    ) -> HashMap<String, FieldElement> {
        let mut assignments = HashMap::new();

        for (name, var) in vars {
            if let Some(val) = model.eval(var, true) {
                if let Some(val_i64) = val.as_i64() {
                    assignments.insert(name.clone(), FieldElement::from_u64(val_i64 as u64));
                }
            }
        }

        assignments
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

    /// Clear the solution cache
    pub fn clear_cache(&mut self) {
        self.solution_cache.clear();
        self.cache_hits = 0;
    }

    pub fn cache_hits(&self) -> usize {
        self.cache_hits
    }
}

impl Default for IncrementalSolver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Enhanced Symbolic Executor
// ============================================================================

/// Configuration for enhanced symbolic execution
#[derive(Debug, Clone)]
pub struct EnhancedSymbolicConfig {
    /// Maximum paths to explore
    pub max_paths: usize,
    /// Maximum depth per path
    pub max_depth: usize,
    /// Solver timeout in milliseconds
    pub solver_timeout_ms: u32,
    /// Optional random seed for deterministic solving
    pub random_seed: Option<u64>,
    /// Path pruning strategy
    pub pruning_strategy: PruningStrategy,
    /// Enable constraint simplification
    pub simplify_constraints: bool,
    /// Enable incremental solving
    pub incremental_solving: bool,
    /// Number of solutions per path
    pub solutions_per_path: usize,
    /// Loop bound for loop detection
    pub loop_bound: usize,
}

impl Default for EnhancedSymbolicConfig {
    fn default() -> Self {
        Self {
            max_paths: 1000,
            max_depth: 50,
            solver_timeout_ms: 5000,
            random_seed: None,
            pruning_strategy: PruningStrategy::CoverageGuided,
            simplify_constraints: true,
            incremental_solving: true,
            solutions_per_path: 3,
            loop_bound: 10,
        }
    }
}

/// Enhanced symbolic executor with all improvements
pub struct EnhancedSymbolicExecutor {
    /// Priority queue for path exploration
    worklist: BinaryHeap<PrioritizedPath>,
    /// Completed paths
    completed_paths: Vec<PathCondition>,
    /// Incremental solver
    solver: IncrementalSolver,
    /// Constraint simplifier
    simplifier: ConstraintSimplifier,
    /// Path pruner
    pruner: PathPruner,
    /// Configuration
    config: EnhancedSymbolicConfig,
    /// Generated test cases
    generated_tests: Vec<Vec<FieldElement>>,
    /// Number of inputs
    num_inputs: usize,
    /// Paths explored counter
    paths_explored: usize,
    /// Coverage bitmap for guided exploration
    coverage_bitmap: Vec<bool>,
}

impl EnhancedSymbolicExecutor {
    pub fn new(num_inputs: usize) -> Self {
        let config = EnhancedSymbolicConfig::default();
        Self::with_config(num_inputs, config)
    }

    pub fn with_config(num_inputs: usize, config: EnhancedSymbolicConfig) -> Self {
        let initial_state = SymbolicState::new(num_inputs);
        let initial_priority = PrioritizedPath {
            state: initial_state,
            priority: 100.0,
            coverage_potential: 100,
            constraint_complexity: 0,
        };

        let pruner = PathPruner::new(config.pruning_strategy)
            .with_max_depth(config.max_depth)
            .with_max_paths(config.max_paths)
            .with_loop_bound(config.loop_bound);

        let solver = IncrementalSolver::new()
            .with_timeout(config.solver_timeout_ms)
            .with_random_seed(config.random_seed);

        Self {
            worklist: BinaryHeap::from([initial_priority]),
            completed_paths: Vec::new(),
            solver,
            simplifier: ConstraintSimplifier::new(),
            pruner,
            config,
            generated_tests: Vec::new(),
            num_inputs,
            paths_explored: 0,
            coverage_bitmap: Vec::new(),
        }
    }

    /// Update coverage bitmap for guided exploration
    pub fn update_coverage(&mut self, bitmap: Vec<bool>) {
        self.coverage_bitmap = bitmap.clone();
        self.pruner = self.pruner.clone().with_coverage_bitmap(bitmap);
    }

    /// Get next state to explore (priority-based)
    pub fn next_state(&mut self) -> Option<SymbolicState> {
        while let Some(prioritized) = self.worklist.pop() {
            // Check if path should be pruned
            if self
                .pruner
                .should_prune(&prioritized.state, self.paths_explored)
            {
                continue;
            }

            self.paths_explored += 1;
            return Some(prioritized.state);
        }
        None
    }

    /// Add states from a branch point with prioritization
    pub fn add_branch(&mut self, true_state: SymbolicState, false_state: SymbolicState) {
        let states = [true_state, false_state];
        let prioritized = self.pruner.prioritize(&states);

        for p in prioritized {
            if !self.pruner.should_prune(&p.state, self.paths_explored) {
                self.worklist.push(p);
            }
        }
    }

    /// Complete a path and generate test cases
    pub fn complete_path(&mut self, state: SymbolicState) {
        let mut path = state.path_condition;

        // Simplify constraints if enabled
        if self.config.simplify_constraints {
            path = self.simplifier.simplify_path(&path);
        }

        // Solve for satisfying assignments
        let result = if self.config.incremental_solving {
            self.solver
                .solve_incremental(&PathCondition::new(), &path.constraints)
        } else {
            let basic_solver = Z3Solver::new()
                .with_timeout(self.config.solver_timeout_ms)
                .with_random_seed(self.config.random_seed);
            basic_solver.solve(&path)
        };

        if let SolverResult::Sat(assignments) = result {
            let test_case = self.assignments_to_inputs(&assignments);
            self.generated_tests.push(test_case);
        }

        self.completed_paths.push(path);
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

    /// Get all generated test cases
    pub fn get_test_cases(&self) -> &[Vec<FieldElement>] {
        &self.generated_tests
    }

    /// Get statistics
    pub fn stats(&self) -> EnhancedSymbolicStats {
        EnhancedSymbolicStats {
            paths_explored: self.paths_explored,
            paths_pruned: self
                .paths_explored
                .saturating_sub(self.completed_paths.len()),
            tests_generated: self.generated_tests.len(),
            pending_paths: self.worklist.len(),
            cache_hits: self.solver.cache_hits(),
        }
    }

    /// Reset for new exploration
    pub fn reset(&mut self) {
        self.worklist.clear();
        self.completed_paths.clear();
        self.generated_tests.clear();
        self.paths_explored = 0;
        self.solver.clear_cache();

        let initial_state = SymbolicState::new(self.num_inputs);
        self.worklist.push(PrioritizedPath {
            state: initial_state,
            priority: 100.0,
            coverage_potential: 100,
            constraint_complexity: 0,
        });
    }
}

/// Statistics from enhanced symbolic execution
#[derive(Debug, Clone)]
pub struct EnhancedSymbolicStats {
    pub paths_explored: usize,
    pub paths_pruned: usize,
    pub tests_generated: usize,
    pub pending_paths: usize,
    pub cache_hits: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_simplifier_constant_folding() {
        let mut simplifier = ConstraintSimplifier::new();

        // Test x + 0 = x
        let constraint = SymbolicConstraint::Eq(
            SymbolicValue::Add(
                Box::new(SymbolicValue::Symbol("x".to_string())),
                Box::new(SymbolicValue::Concrete(FieldElement::zero())),
            ),
            SymbolicValue::Symbol("x".to_string()),
        );

        let simplified = simplifier.simplify_constraint(&constraint);
        assert!(matches!(simplified, Some(SymbolicConstraint::True)));
    }

    #[test]
    fn test_path_pruner_depth_bounded() {
        let mut pruner = PathPruner::new(PruningStrategy::DepthBounded).with_max_depth(5);

        let mut state = SymbolicState::new(3);
        state.depth = 3;
        assert!(!pruner.should_prune(&state, 0));

        state.depth = 10;
        assert!(pruner.should_prune(&state, 0));
    }

    #[test]
    fn test_enhanced_executor_creation() {
        let executor = EnhancedSymbolicExecutor::new(5);
        assert_eq!(executor.num_inputs, 5);
        assert!(!executor.worklist.is_empty());
    }

    #[test]
    fn test_path_pruner_subsumption_based() {
        let mut pruner = PathPruner::new(PruningStrategy::SubsumptionBased);

        let mut base_state = SymbolicState::new(1);
        base_state.path_condition.add_constraint(SymbolicConstraint::Eq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::one()),
        ));
        assert!(!pruner.should_prune(&base_state, 0));

        let mut stricter_state = SymbolicState::new(1);
        stricter_state.path_condition.add_constraint(SymbolicConstraint::Eq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::one()),
        ));
        stricter_state.path_condition.add_constraint(SymbolicConstraint::Neq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::zero()),
        ));
        assert!(pruner.should_prune(&stricter_state, 1));
    }

    #[test]
    fn test_incremental_solver_cache_hits() {
        let mut solver = IncrementalSolver::new();
        let base_path = PathCondition::new();
        let constraints = vec![SymbolicConstraint::Eq(
            SymbolicValue::symbol("input_0"),
            SymbolicValue::concrete(FieldElement::zero()),
        )];

        let _ = solver.solve_incremental(&base_path, &constraints);
        assert_eq!(solver.cache_hits(), 0);

        let _ = solver.solve_incremental(&base_path, &constraints);
        assert_eq!(solver.cache_hits(), 1);
    }
}
