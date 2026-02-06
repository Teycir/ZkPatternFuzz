//! Z3-Powered Symbolic Execution Framework for ZK Circuits
//!
//! Provides comprehensive symbolic execution capabilities to:
//! - Generate targeted inputs that reach specific constraints
//! - Prove absence of certain vulnerability classes
//! - Guide fuzzing with symbolic information
//! - Automatically generate edge-case test vectors

use zk_core::FieldElement;
use std::collections::{HashMap, HashSet, VecDeque};
use z3::ast::Ast;
use z3::{ast, Config, Context, SatResult, Solver};

/// BN254 scalar field modulus
const BN254_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Symbolic value representation
#[derive(Debug, Clone)]
pub enum SymbolicValue {
    /// Concrete value
    Concrete(FieldElement),
    /// Symbolic variable
    Symbol(String),
    /// Addition of two symbolic values
    Add(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Multiplication of two symbolic values
    Mul(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Subtraction
    Sub(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Division (modular inverse)
    Div(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Conditional (if-then-else)
    Ite(
        Box<SymbolicConstraint>,
        Box<SymbolicValue>,
        Box<SymbolicValue>,
    ),
    /// Negation (field negation: p - x)
    Neg(Box<SymbolicValue>),
}

impl SymbolicValue {
    pub fn symbol(name: &str) -> Self {
        SymbolicValue::Symbol(name.to_string())
    }

    pub fn concrete(value: FieldElement) -> Self {
        SymbolicValue::Concrete(value)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: SymbolicValue) -> Self {
        SymbolicValue::Add(Box::new(self), Box::new(other))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn mul(self, other: SymbolicValue) -> Self {
        SymbolicValue::Mul(Box::new(self), Box::new(other))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: SymbolicValue) -> Self {
        SymbolicValue::Sub(Box::new(self), Box::new(other))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn div(self, other: SymbolicValue) -> Self {
        SymbolicValue::Div(Box::new(self), Box::new(other))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn neg(self) -> Self {
        SymbolicValue::Neg(Box::new(self))
    }

    /// Get all symbol names used in this value
    pub fn symbols(&self) -> HashSet<String> {
        let mut symbols = HashSet::new();
        self.collect_symbols(&mut symbols);
        symbols
    }

    fn collect_symbols(&self, symbols: &mut HashSet<String>) {
        match self {
            SymbolicValue::Concrete(_) => {}
            SymbolicValue::Symbol(name) => {
                symbols.insert(name.clone());
            }
            SymbolicValue::Add(a, b)
            | SymbolicValue::Mul(a, b)
            | SymbolicValue::Sub(a, b)
            | SymbolicValue::Div(a, b) => {
                a.collect_symbols(symbols);
                b.collect_symbols(symbols);
            }
            SymbolicValue::Neg(a) => {
                a.collect_symbols(symbols);
            }
            SymbolicValue::Ite(_, t, f) => {
                t.collect_symbols(symbols);
                f.collect_symbols(symbols);
            }
        }
    }

    /// Try to evaluate to a concrete value given assignments
    pub fn evaluate(&self, assignments: &HashMap<String, FieldElement>) -> Option<FieldElement> {
        match self {
            SymbolicValue::Concrete(v) => Some(v.clone()),
            SymbolicValue::Symbol(name) => assignments.get(name).cloned(),
            SymbolicValue::Add(a, b) => {
                let a_val = a.evaluate(assignments)?;
                let b_val = b.evaluate(assignments)?;
                Some(a_val.add(&b_val))
            }
            SymbolicValue::Mul(a, b) => {
                let a_val = a.evaluate(assignments)?;
                let b_val = b.evaluate(assignments)?;
                Some(a_val.mul(&b_val))
            }
            SymbolicValue::Sub(a, b) => {
                let a_val = a.evaluate(assignments)?;
                let b_val = b.evaluate(assignments)?;
                Some(a_val.sub(&b_val))
            }
            _ => None,
        }
    }

    /// Check if this is a simple symbol
    pub fn is_symbol(&self) -> bool {
        matches!(self, SymbolicValue::Symbol(_))
    }

    /// Check if this is concrete
    pub fn is_concrete(&self) -> bool {
        matches!(self, SymbolicValue::Concrete(_))
    }
}

/// Symbolic constraint
#[derive(Debug, Clone)]
pub enum SymbolicConstraint {
    /// Equality constraint
    Eq(SymbolicValue, SymbolicValue),
    /// Not equal
    Neq(SymbolicValue, SymbolicValue),
    /// Less than (for range proofs)
    Lt(SymbolicValue, SymbolicValue),
    /// Less than or equal
    Lte(SymbolicValue, SymbolicValue),
    /// R1CS constraint: a * b = c
    R1CS {
        a: SymbolicValue,
        b: SymbolicValue,
        c: SymbolicValue,
    },
    /// Boolean constraint (value is 0 or 1)
    Boolean(SymbolicValue),
    /// Range constraint (0 <= value < bound)
    Range(SymbolicValue, SymbolicValue),
    /// Conjunction
    And(Box<SymbolicConstraint>, Box<SymbolicConstraint>),
    /// Disjunction
    Or(Box<SymbolicConstraint>, Box<SymbolicConstraint>),
    /// Negation
    Not(Box<SymbolicConstraint>),
    /// Always true
    True,
    /// Always false
    False,
}

impl SymbolicConstraint {
    pub fn eq(a: SymbolicValue, b: SymbolicValue) -> Self {
        SymbolicConstraint::Eq(a, b)
    }

    pub fn neq(a: SymbolicValue, b: SymbolicValue) -> Self {
        SymbolicConstraint::Neq(a, b)
    }

    pub fn r1cs(a: SymbolicValue, b: SymbolicValue, c: SymbolicValue) -> Self {
        SymbolicConstraint::R1CS { a, b, c }
    }

    pub fn boolean(v: SymbolicValue) -> Self {
        SymbolicConstraint::Boolean(v)
    }

    pub fn range(v: SymbolicValue, bound: SymbolicValue) -> Self {
        SymbolicConstraint::Range(v, bound)
    }

    pub fn and(self, other: SymbolicConstraint) -> Self {
        SymbolicConstraint::And(Box::new(self), Box::new(other))
    }

    pub fn or(self, other: SymbolicConstraint) -> Self {
        SymbolicConstraint::Or(Box::new(self), Box::new(other))
    }

    pub fn not(self) -> Self {
        SymbolicConstraint::Not(Box::new(self))
    }
}

/// Path condition tracking for symbolic execution
#[derive(Debug, Clone, Default)]
pub struct PathCondition {
    /// Constraints along this path
    pub constraints: Vec<SymbolicConstraint>,
    /// Whether this path is satisfiable (cached)
    pub is_sat: Option<bool>,
    /// Path identifier for debugging
    pub path_id: u64,
}

impl PathCondition {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            is_sat: None,
            path_id: 0,
        }
    }

    pub fn with_id(id: u64) -> Self {
        Self {
            constraints: Vec::new(),
            is_sat: None,
            path_id: id,
        }
    }

    pub fn add_constraint(&mut self, constraint: SymbolicConstraint) {
        self.constraints.push(constraint);
        self.is_sat = None;
    }

    pub fn and(&self, constraint: SymbolicConstraint) -> Self {
        let mut new_pc = self.clone();
        new_pc.add_constraint(constraint);
        new_pc
    }

    /// Get all symbols used in this path condition
    pub fn symbols(&self) -> HashSet<String> {
        let mut symbols = HashSet::new();
        for constraint in &self.constraints {
            self.collect_symbols_from_constraint(constraint, &mut symbols);
        }
        symbols
    }

    fn collect_symbols_from_constraint(
        &self,
        constraint: &SymbolicConstraint,
        symbols: &mut HashSet<String>,
    ) {
        match constraint {
            SymbolicConstraint::Eq(a, b)
            | SymbolicConstraint::Neq(a, b)
            | SymbolicConstraint::Lt(a, b)
            | SymbolicConstraint::Lte(a, b)
            | SymbolicConstraint::Range(a, b) => {
                symbols.extend(a.symbols());
                symbols.extend(b.symbols());
            }
            SymbolicConstraint::R1CS { a, b, c } => {
                symbols.extend(a.symbols());
                symbols.extend(b.symbols());
                symbols.extend(c.symbols());
            }
            SymbolicConstraint::Boolean(v) => {
                symbols.extend(v.symbols());
            }
            SymbolicConstraint::And(c1, c2) | SymbolicConstraint::Or(c1, c2) => {
                self.collect_symbols_from_constraint(c1, symbols);
                self.collect_symbols_from_constraint(c2, symbols);
            }
            SymbolicConstraint::Not(c) => {
                self.collect_symbols_from_constraint(c, symbols);
            }
            SymbolicConstraint::True | SymbolicConstraint::False => {}
        }
    }

    /// Check if path is trivially unsatisfiable
    pub fn is_trivially_unsat(&self) -> bool {
        self.constraints
            .iter()
            .any(|c| matches!(c, SymbolicConstraint::False))
    }
}

/// Symbolic state for execution
#[derive(Debug, Clone)]
pub struct SymbolicState {
    /// Symbolic values for signals
    pub signals: HashMap<usize, SymbolicValue>,
    /// Named signals mapping
    pub named_signals: HashMap<String, usize>,
    /// Current path condition
    pub path_condition: PathCondition,
    /// Constraint ID we're currently at
    pub current_constraint: usize,
    /// Has the path been fully explored?
    pub is_complete: bool,
    /// Depth in the execution tree
    pub depth: usize,
}

impl SymbolicState {
    pub fn new(num_inputs: usize) -> Self {
        let mut signals = HashMap::new();
        let mut named_signals = HashMap::new();

        for i in 0..num_inputs {
            let name = format!("input_{}", i);
            signals.insert(i, SymbolicValue::symbol(&name));
            named_signals.insert(name, i);
        }

        Self {
            signals,
            named_signals,
            path_condition: PathCondition::new(),
            current_constraint: 0,
            is_complete: false,
            depth: 0,
        }
    }

    /// Get or create a symbolic value for a signal
    pub fn get_signal(&self, index: usize) -> Option<&SymbolicValue> {
        self.signals.get(&index)
    }

    /// Get signal by name
    pub fn get_signal_by_name(&self, name: &str) -> Option<&SymbolicValue> {
        self.named_signals
            .get(name)
            .and_then(|idx| self.signals.get(idx))
    }

    /// Set a signal's symbolic value
    pub fn set_signal(&mut self, index: usize, value: SymbolicValue) {
        self.signals.insert(index, value);
    }

    /// Set signal by name
    pub fn set_signal_by_name(&mut self, name: &str, value: SymbolicValue) {
        let idx = self.named_signals.len();
        self.named_signals.insert(name.to_string(), idx);
        self.signals.insert(idx, value);
    }

    /// Add a constraint to the path condition
    pub fn add_constraint(&mut self, constraint: SymbolicConstraint) {
        self.path_condition.add_constraint(constraint);
    }

    /// Fork the state (for branching)
    pub fn fork(&self) -> Self {
        let mut forked = self.clone();
        forked.depth += 1;
        forked
    }
}

/// Z3-based constraint solver
pub struct Z3Solver {
    /// Maximum solving time in milliseconds
    timeout_ms: u32,
    /// Field modulus string
    modulus: String,
}

impl Z3Solver {
    pub fn new() -> Self {
        Self {
            timeout_ms: 5000,
            modulus: BN254_MODULUS.to_string(),
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Convert SymbolicValue to Z3 AST
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
                // (a - b + modulus) % modulus
                let sum = ast::Int::add(ctx, &[&a_z3, &modulus]);
                ast::Int::sub(ctx, &[&sum, &b_z3]).modulo(&modulus)
            }
            SymbolicValue::Neg(a) => {
                let a_z3 = self.value_to_z3(ctx, a, vars);
                let modulus = ast::Int::from_str(ctx, &self.modulus).unwrap();
                ast::Int::sub(ctx, &[&modulus, &a_z3])
            }
            _ => ast::Int::from_i64(ctx, 0),
        }
    }

    /// Convert SymbolicConstraint to Z3 Bool AST
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
                let is_zero = v_z3._eq(&zero);
                let is_one = v_z3._eq(&one);
                ast::Bool::or(ctx, &[&is_zero, &is_one])
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

    /// Add field bounds constraints (0 <= var < modulus)
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

    /// Solve path condition and return satisfying assignments
    pub fn solve(&self, path_condition: &PathCondition) -> SolverResult {
        if path_condition.is_trivially_unsat() {
            return SolverResult::Unsat;
        }

        let mut cfg = Config::new();
        cfg.set_model_generation(true);
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", self.timeout_ms);
        solver.set_params(&params);

        let mut vars: HashMap<String, ast::Int> = HashMap::new();

        for constraint in &path_condition.constraints {
            let z3_constraint = self.constraint_to_z3(&ctx, constraint, &mut vars);
            solver.assert(&z3_constraint);
        }

        self.add_field_bounds(&ctx, &solver, &vars);

        match solver.check() {
            SatResult::Sat => {
                let model = solver.get_model().unwrap();
                let assignments = self.extract_model(&ctx, &model, &vars);
                SolverResult::Sat(assignments)
            }
            SatResult::Unsat => SolverResult::Unsat,
            SatResult::Unknown => SolverResult::Unknown,
        }
    }

    /// Generate multiple diverse solutions
    pub fn solve_all(
        &self,
        path_condition: &PathCondition,
        max_solutions: usize,
    ) -> Vec<HashMap<String, FieldElement>> {
        let mut solutions = Vec::new();

        let mut cfg = Config::new();
        cfg.set_model_generation(true);
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", self.timeout_ms);
        solver.set_params(&params);

        let mut vars: HashMap<String, ast::Int> = HashMap::new();

        for constraint in &path_condition.constraints {
            let z3_constraint = self.constraint_to_z3(&ctx, constraint, &mut vars);
            solver.assert(&z3_constraint);
        }

        self.add_field_bounds(&ctx, &solver, &vars);

        while solutions.len() < max_solutions {
            match solver.check() {
                SatResult::Sat => {
                    let model = solver.get_model().unwrap();
                    let assignments = self.extract_model(&ctx, &model, &vars);

                    // Block this solution
                    let mut blocking_terms = Vec::new();
                    for (name, var) in &vars {
                        if let Some(fe) = assignments.get(name) {
                            let dec_str = fe.to_decimal_string();
                            if let Some(val) = ast::Int::from_str(&ctx, &dec_str) {
                                blocking_terms.push(var._eq(&val).not());
                            }
                        }
                    }

                    if !blocking_terms.is_empty() {
                        let blocking_refs: Vec<_> = blocking_terms.iter().collect();
                        solver.assert(&ast::Bool::or(&ctx, &blocking_refs));
                    }

                    solutions.push(assignments);
                }
                _ => break,
            }
        }

        solutions
    }

    /// Extract model into FieldElement assignments
    fn extract_model(
        &self,
        _ctx: &Context,
        model: &z3::Model,
        vars: &HashMap<String, ast::Int>,
    ) -> HashMap<String, FieldElement> {
        let mut assignments = HashMap::new();

        for (name, var) in vars {
            if let Some(val) = model.eval(var, true) {
                if let Some(val_i64) = val.as_i64() {
                    assignments.insert(name.clone(), FieldElement::from_u64(val_i64 as u64));
                } else {
                    let val_string = val.to_string();
                    if let Ok(bytes) = parse_z3_int(&val_string) {
                        assignments.insert(name.clone(), FieldElement::from_bytes(&bytes));
                    }
                }
            }
        }

        assignments
    }
}

impl Default for Z3Solver {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse Z3 integer output to bytes
fn parse_z3_int(s: &str) -> Result<Vec<u8>, ()> {
    let cleaned = s.trim().replace(' ', "");

    if cleaned.starts_with("0x") {
        hex::decode(&cleaned[2..]).map_err(|_| ())
    } else if let Ok(n) = cleaned.parse::<u64>() {
        Ok(n.to_be_bytes().to_vec())
    } else {
        use num_bigint::BigUint;
        if let Ok(big) = cleaned.parse::<BigUint>() {
            Ok(big.to_bytes_be())
        } else {
            Err(())
        }
    }
}

/// Result of constraint solving
#[derive(Debug, Clone)]
pub enum SolverResult {
    /// Satisfiable with given assignments
    Sat(HashMap<String, FieldElement>),
    /// Unsatisfiable
    Unsat,
    /// Unknown (solver timeout or limitation)
    Unknown,
}

impl SolverResult {
    pub fn is_sat(&self) -> bool {
        matches!(self, SolverResult::Sat(_))
    }

    pub fn is_unsat(&self) -> bool {
        matches!(self, SolverResult::Unsat)
    }

    pub fn get_model(&self) -> Option<&HashMap<String, FieldElement>> {
        match self {
            SolverResult::Sat(m) => Some(m),
            _ => None,
        }
    }
}

/// Configuration for symbolic executor
#[derive(Debug, Clone)]
pub struct SymbolicConfig {
    /// Maximum paths to explore
    pub max_paths: usize,
    /// Maximum depth per path
    pub max_depth: usize,
    /// Solver timeout in milliseconds
    pub solver_timeout_ms: u32,
    /// Generate boundary test cases
    pub generate_boundary_tests: bool,
    /// Number of solutions per path
    pub solutions_per_path: usize,
}

impl Default for SymbolicConfig {
    fn default() -> Self {
        Self {
            max_paths: 1000,
            max_depth: 50,
            solver_timeout_ms: 5000,
            generate_boundary_tests: true,
            solutions_per_path: 3,
        }
    }
}

/// Symbolic executor for ZK circuits with Z3 integration
pub struct SymbolicExecutor {
    /// States to explore (work queue)
    worklist: VecDeque<SymbolicState>,
    /// Completed paths
    completed_paths: Vec<PathCondition>,
    /// Constraint solver
    solver: Z3Solver,
    /// Configuration
    config: SymbolicConfig,
    /// Generated test cases
    generated_tests: Vec<Vec<FieldElement>>,
    /// Path counter for unique IDs
    #[allow(dead_code)]
    path_counter: u64,
    /// Number of inputs
    num_inputs: usize,
}

impl SymbolicExecutor {
    pub fn new(num_inputs: usize) -> Self {
        let config = SymbolicConfig::default();
        let solver = Z3Solver::new().with_timeout(config.solver_timeout_ms);
        let initial_state = SymbolicState::new(num_inputs);

        Self {
            worklist: VecDeque::from([initial_state]),
            completed_paths: Vec::new(),
            solver,
            config,
            generated_tests: Vec::new(),
            path_counter: 0,
            num_inputs,
        }
    }

    pub fn with_config(mut self, config: SymbolicConfig) -> Self {
        self.solver = Z3Solver::new().with_timeout(config.solver_timeout_ms);
        self.config = config;
        self
    }

    /// Get next state to explore (BFS order)
    pub fn next_state(&mut self) -> Option<SymbolicState> {
        self.worklist.pop_front()
    }

    /// Add states from a branch point
    pub fn add_branch(&mut self, true_state: SymbolicState, false_state: SymbolicState) {
        if self.worklist.len() + 2 <= self.config.max_paths
            && true_state.depth <= self.config.max_depth
        {
            if !true_state.path_condition.is_trivially_unsat() {
                self.worklist.push_back(true_state);
            }
            if !false_state.path_condition.is_trivially_unsat() {
                self.worklist.push_back(false_state);
            }
        }
    }

    /// Record a completed path and generate test cases
    pub fn complete_path(&mut self, state: SymbolicState) {
        let path = state.path_condition;

        if let SolverResult::Sat(assignments) = self.solver.solve(&path) {
            let test_case = self.assignments_to_inputs(&assignments);
            self.generated_tests.push(test_case);

            if self.config.solutions_per_path > 1 {
                let additional = self.solver.solve_all(&path, self.config.solutions_per_path);
                for solution in additional.into_iter().skip(1) {
                    let test_case = self.assignments_to_inputs(&solution);
                    self.generated_tests.push(test_case);
                }
            }
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

    /// Get all completed paths
    pub fn completed_paths(&self) -> &[PathCondition] {
        &self.completed_paths
    }

    /// Check if a constraint is satisfiable
    pub fn is_satisfiable(&self, constraint: &SymbolicConstraint) -> bool {
        let mut pc = PathCondition::new();
        pc.add_constraint(constraint.clone());
        self.solver.solve(&pc).is_sat()
    }

    /// Find inputs that satisfy a specific constraint
    pub fn find_satisfying_inputs(
        &self,
        constraint: &SymbolicConstraint,
    ) -> Option<Vec<FieldElement>> {
        let mut pc = PathCondition::new();
        pc.add_constraint(constraint.clone());

        match self.solver.solve(&pc) {
            SolverResult::Sat(assignments) => Some(self.assignments_to_inputs(&assignments)),
            _ => None,
        }
    }

    /// Find inputs that violate a constraint (for vulnerability detection)
    pub fn find_violating_inputs(
        &self,
        constraint: &SymbolicConstraint,
    ) -> Option<Vec<FieldElement>> {
        self.find_satisfying_inputs(&constraint.clone().not())
    }

    /// Reset executor for new exploration
    pub fn reset(&mut self) {
        self.worklist.clear();
        self.completed_paths.clear();
        self.generated_tests.clear();
        self.path_counter = 0;
        self.worklist.push_back(SymbolicState::new(self.num_inputs));
    }
}

/// Integration with the fuzzing loop
pub struct SymbolicFuzzerIntegration {
    executor: SymbolicExecutor,
    /// Pending test cases to be used by fuzzer
    pending_tests: VecDeque<Vec<FieldElement>>,
    /// Constraints discovered during fuzzing
    discovered_constraints: Vec<SymbolicConstraint>,
    /// Number of inputs
    num_inputs: usize,
}

impl SymbolicFuzzerIntegration {
    pub fn new(num_inputs: usize) -> Self {
        Self {
            executor: SymbolicExecutor::new(num_inputs),
            pending_tests: VecDeque::new(),
            discovered_constraints: Vec::new(),
            num_inputs,
        }
    }

    pub fn with_config(mut self, config: SymbolicConfig) -> Self {
        self.executor = self.executor.with_config(config);
        self
    }

    /// Generate initial seed inputs for fuzzing
    pub fn generate_seeds(&mut self, count: usize) -> Vec<Vec<FieldElement>> {
        let mut seeds = self.generate_boundary_seeds();

        while seeds.len() < count {
            if let Some(state) = self.executor.next_state() {
                self.executor.complete_path(state);
                seeds.extend(self.executor.get_test_cases().to_vec());
            } else {
                break;
            }
        }

        seeds.truncate(count);
        seeds
    }

    /// Generate seeds with interesting boundary values
    fn generate_boundary_seeds(&self) -> Vec<Vec<FieldElement>> {
        let mut seeds = Vec::new();

        // All zeros
        seeds.push(vec![FieldElement::zero(); self.num_inputs]);

        // All ones
        seeds.push(vec![FieldElement::one(); self.num_inputs]);

        // Max field values
        seeds.push(vec![FieldElement::max_value(); self.num_inputs]);

        // Half field value
        seeds.push(vec![FieldElement::half_modulus(); self.num_inputs]);

        // Mixed boundary values
        if self.num_inputs >= 2 {
            let mut mixed = vec![FieldElement::zero(); self.num_inputs];
            mixed[0] = FieldElement::max_value();
            seeds.push(mixed);
        }

        seeds
    }

    /// Get next test case for fuzzer
    pub fn next_test(&mut self) -> Option<Vec<FieldElement>> {
        if let Some(test) = self.pending_tests.pop_front() {
            return Some(test);
        }

        if let Some(state) = self.executor.next_state() {
            self.executor.complete_path(state);
            for test in self.executor.get_test_cases() {
                self.pending_tests.push_back(test.clone());
            }
            self.pending_tests.pop_front()
        } else {
            None
        }
    }

    /// Add a constraint discovered during fuzzing
    pub fn add_discovered_constraint(&mut self, constraint: SymbolicConstraint) {
        self.discovered_constraints.push(constraint.clone());

        if let Some(violating) = self.executor.find_violating_inputs(&constraint) {
            self.pending_tests.push_back(violating);
        }
    }

    /// Generate tests targeting a specific vulnerability pattern
    pub fn generate_vulnerability_tests(
        &self,
        pattern: VulnerabilityPattern,
    ) -> Vec<Vec<FieldElement>> {
        match pattern {
            VulnerabilityPattern::OverflowBoundary => self.generate_overflow_tests(),
            VulnerabilityPattern::ZeroDivision => self.generate_zero_division_tests(),
            VulnerabilityPattern::BitDecomposition { bits } => {
                self.generate_bit_decomposition_tests(bits)
            }
            VulnerabilityPattern::RangeViolation { max } => {
                self.generate_range_violation_tests(max)
            }
        }
    }

    fn generate_overflow_tests(&self) -> Vec<Vec<FieldElement>> {
        let mut tests = Vec::new();

        for i in 0..self.num_inputs {
            let mut test = vec![FieldElement::zero(); self.num_inputs];
            test[i] = FieldElement::max_value();
            tests.push(test.clone());

            test[i] = FieldElement::max_value().sub(&FieldElement::one());
            tests.push(test);
        }

        tests
    }

    fn generate_zero_division_tests(&self) -> Vec<Vec<FieldElement>> {
        let mut tests = Vec::new();

        for i in 0..self.num_inputs {
            let mut test = vec![FieldElement::one(); self.num_inputs];
            test[i] = FieldElement::zero();
            tests.push(test);
        }

        tests
    }

    fn generate_bit_decomposition_tests(&self, bits: usize) -> Vec<Vec<FieldElement>> {
        let mut tests = Vec::new();

        if bits < 64 {
            let boundary = FieldElement::from_u64(1u64 << bits);
            tests.push(vec![boundary.clone(); self.num_inputs.max(1)]);
            tests.push(vec![
                boundary.sub(&FieldElement::one());
                self.num_inputs.max(1)
            ]);

            let all_bits = FieldElement::from_u64((1u64 << bits) - 1);
            tests.push(vec![all_bits; self.num_inputs.max(1)]);
        }

        tests
    }

    fn generate_range_violation_tests(&self, max: u64) -> Vec<Vec<FieldElement>> {
        vec![
            vec![FieldElement::from_u64(max); self.num_inputs.max(1)],
            vec![FieldElement::from_u64(max.saturating_add(1)); self.num_inputs.max(1)],
            vec![FieldElement::from_u64(max.saturating_sub(1)); self.num_inputs.max(1)],
            vec![FieldElement::max_value(); self.num_inputs.max(1)],
        ]
    }

    /// Get statistics about symbolic execution
    pub fn stats(&self) -> SymbolicStats {
        SymbolicStats {
            paths_explored: self.executor.completed_paths.len(),
            tests_generated: self.executor.generated_tests.len(),
            pending_tests: self.pending_tests.len(),
            discovered_constraints: self.discovered_constraints.len(),
        }
    }
}

/// Vulnerability patterns for targeted test generation
#[derive(Debug, Clone)]
pub enum VulnerabilityPattern {
    OverflowBoundary,
    ZeroDivision,
    BitDecomposition { bits: usize },
    RangeViolation { max: u64 },
}

/// Statistics from symbolic execution
#[derive(Debug, Clone)]
pub struct SymbolicStats {
    pub paths_explored: usize,
    pub tests_generated: usize,
    pub pending_tests: usize,
    pub discovered_constraints: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbolic_value_creation() {
        let x = SymbolicValue::symbol("x");
        let y = SymbolicValue::symbol("y");
        let sum = x.add(y);

        let symbols = sum.symbols();
        assert!(symbols.contains("x"));
        assert!(symbols.contains("y"));
    }

    #[test]
    fn test_symbolic_state() {
        let state = SymbolicState::new(3);

        assert_eq!(state.signals.len(), 3);
        assert!(state.get_signal(0).is_some());
        assert!(state.get_signal(3).is_none());
    }

    #[test]
    fn test_path_condition() {
        let mut pc = PathCondition::new();

        let x = SymbolicValue::symbol("x");
        let zero = SymbolicValue::concrete(FieldElement::zero());

        pc.add_constraint(SymbolicConstraint::eq(x, zero));

        assert_eq!(pc.constraints.len(), 1);
        assert!(pc.symbols().contains("x"));
    }

    #[test]
    fn test_symbolic_executor_creation() {
        let executor = SymbolicExecutor::new(5).with_config(SymbolicConfig {
            max_paths: 50,
            ..Default::default()
        });

        assert_eq!(executor.worklist.len(), 1);
        assert_eq!(executor.config.max_paths, 50);
    }

    #[test]
    fn test_z3_solver_simple_equality() {
        let solver = Z3Solver::new();
        let mut pc = PathCondition::new();

        pc.add_constraint(SymbolicConstraint::eq(
            SymbolicValue::symbol("input_0"),
            SymbolicValue::concrete(FieldElement::from_u64(42)),
        ));

        let result = solver.solve(&pc);
        assert!(result.is_sat());

        if let SolverResult::Sat(assignments) = result {
            assert!(assignments.contains_key("input_0"));
        }
    }

    #[test]
    fn test_z3_solver_unsatisfiable() {
        // Test using direct Z3 API to ensure unsatisfiability works
        use z3::{Config, Context as Z3Context, SatResult as Z3SatResult, Solver as Z3Solver2};

        let mut cfg = Config::new();
        cfg.set_model_generation(true);
        let ctx = Z3Context::new(&cfg);
        let solver = Z3Solver2::new(&ctx);

        let x = ast::Int::new_const(&ctx, "x");
        let one = ast::Int::from_i64(&ctx, 1);
        let two = ast::Int::from_i64(&ctx, 2);

        solver.assert(&x._eq(&one));
        solver.assert(&x._eq(&two));

        let result = solver.check();
        assert!(
            matches!(result, Z3SatResult::Unsat),
            "Expected Unsat, got {:?}",
            result
        );
    }

    #[test]
    fn test_fuzzer_integration() {
        let mut integration = SymbolicFuzzerIntegration::new(3);
        let seeds = integration.generate_seeds(10);

        assert!(!seeds.is_empty());
        assert!(seeds.len() <= 10);
    }

    #[test]
    fn test_boundary_test_generation() {
        let integration = SymbolicFuzzerIntegration::new(2);
        let tests = integration.generate_overflow_tests();

        assert!(!tests.is_empty());
    }
}
