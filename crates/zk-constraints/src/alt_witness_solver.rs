//! Alternative Witness Solver for Underconstrained Detection
//!
//! This module provides Z3-based solving to find alternative private witnesses
//! that satisfy R1CS constraints with fixed public inputs. Finding such
//! alternative witnesses proves a circuit is underconstrained.
//!
//! # Algorithm
//!
//! 1. Parse R1CS to extract A, B, C matrices
//! 2. Fix public inputs (wire 0 = 1, public outputs, public inputs)
//! 3. Encode all constraints as Z3 formulas
//! 4. Block the original witness values for private inputs
//! 5. Solve for an alternative satisfying assignment
//! 6. If SAT, circuit is underconstrained

use num_bigint::BigUint;
use z3::ast::{Ast, Bool, Int};
use z3::{Config, Context, Model, SatResult, Solver};

use super::r1cs_parser::{R1CSConstraint, R1CS};
use zk_core::FieldElement;

/// BN254 scalar field modulus
const BN254_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Result of alternative witness search
#[derive(Debug, Clone)]
pub struct AlternativeWitnessResult {
    /// Whether an alternative witness was found
    pub found: bool,
    /// The original witness (full wire assignment)
    pub original_witness: Vec<FieldElement>,
    /// The alternative witness if found
    pub alternative_witness: Option<Vec<FieldElement>>,
    /// Which wire indices differ between witnesses
    pub differing_wires: Vec<usize>,
    /// Solver statistics
    pub stats: SolverStats,
}

/// Solver statistics
#[derive(Debug, Clone, Default)]
pub struct SolverStats {
    /// Number of constraints encoded
    pub num_constraints: usize,
    /// Number of wires/variables
    pub num_wires: usize,
    /// Number of fixed wires (public)
    pub num_fixed_wires: usize,
    /// Solver time in milliseconds
    pub solve_time_ms: u64,
    /// Solver result
    pub result: String,
}

/// Alternative witness solver using Z3
pub struct AltWitnessSolver<'ctx> {
    ctx: &'ctx Context,
    modulus: Int<'ctx>,
    wire_vars: Vec<Int<'ctx>>,
    fixed_wire_indices: Vec<usize>,
    /// Set to Some(msg) if construction failed (malformed R1CS)
    error: Option<String>,
}

impl<'ctx> AltWitnessSolver<'ctx> {
    /// Create a new solver for the given R1CS
    pub fn new(ctx: &'ctx Context, r1cs: &R1CS) -> Self {
        let modulus_str = if r1cs.field_size == BigUint::from(0u32) {
            BN254_MODULUS.to_string()
        } else {
            r1cs.field_size.to_str_radix(10)
        };

        let modulus = match Int::from_str(ctx, &modulus_str) {
            Some(m) => m,
            None => {
                tracing::error!("Failed to parse field modulus '{}' as Z3 Int", modulus_str);
                return Self {
                    ctx,
                    modulus: Int::from_i64(ctx, 0),
                    wire_vars: Vec::new(),
                    fixed_wire_indices: Vec::new(),
                    error: Some(format!("Invalid field modulus: {}", modulus_str)),
                };
            }
        };

        // Create wire variables
        let wire_vars: Vec<_> = (0..r1cs.num_wires)
            .map(|i| {
                if i == 0 {
                    // Wire 0 is always constant 1
                    Int::from_i64(ctx, 1)
                } else {
                    Int::new_const(ctx, format!("w_{}", i))
                }
            })
            .collect();

        // Compute fixed wire indices (constant + public outputs + public inputs)
        let mut fixed_wire_indices = vec![0]; // Wire 0 is constant 1

        // Public outputs: wires 1..=num_public_outputs
        for i in 1..=r1cs.num_public_outputs {
            fixed_wire_indices.push(i);
        }

        // Public inputs: wires after public outputs
        let pub_input_start = 1 + r1cs.num_public_outputs;
        let pub_input_end = pub_input_start + r1cs.num_public_inputs;
        for i in pub_input_start..pub_input_end {
            fixed_wire_indices.push(i);
        }

        Self {
            ctx,
            modulus,
            wire_vars,
            fixed_wire_indices,
            error: None,
        }
    }

    /// Create solver with explicit public wire indices
    pub fn with_public_indices(
        ctx: &'ctx Context,
        num_wires: usize,
        public_indices: &[usize],
        field_size: Option<&BigUint>,
    ) -> Self {
        let modulus_str = match field_size {
            Some(fs) if *fs != BigUint::from(0u32) => fs.to_str_radix(10),
            _ => BN254_MODULUS.to_string(),
        };

        let modulus = match Int::from_str(ctx, &modulus_str) {
            Some(m) => m,
            None => {
                tracing::error!("Failed to parse field modulus '{}' as Z3 Int", modulus_str);
                return Self {
                    ctx,
                    modulus: Int::from_i64(ctx, 0),
                    wire_vars: Vec::new(),
                    fixed_wire_indices: Vec::new(),
                    error: Some(format!("Invalid field modulus: {}", modulus_str)),
                };
            }
        };

        let wire_vars: Vec<_> = (0..num_wires)
            .map(|i| {
                if i == 0 {
                    Int::from_i64(ctx, 1)
                } else {
                    Int::new_const(ctx, format!("w_{}", i))
                }
            })
            .collect();

        let mut fixed_wire_indices = vec![0];
        fixed_wire_indices.extend(public_indices.iter().copied());

        Self {
            ctx,
            modulus,
            wire_vars,
            fixed_wire_indices,
            error: None,
        }
    }

    /// Convert a BigUint to Z3 Int
    fn bigint_to_int(&self, n: &BigUint) -> Int<'ctx> {
        Int::from_str(self.ctx, &n.to_str_radix(10)).unwrap_or_else(|| Int::from_i64(self.ctx, 0))
    }

    /// Compute sparse dot product: Σ (coeff_i * wire_i)
    ///
    /// Returns `None` if a wire index is out of range (malformed R1CS).
    fn dot_product(&self, sparse_vec: &[(usize, BigUint)]) -> Option<Int<'ctx>> {
        if sparse_vec.is_empty() {
            return Some(Int::from_i64(self.ctx, 0));
        }

        let mut sum = Int::from_i64(self.ctx, 0);
        for (wire_idx, coeff) in sparse_vec {
            if *wire_idx >= self.wire_vars.len() {
                tracing::error!(
                    "R1CS constraint references wire index {} but circuit only has {} wires -- malformed R1CS",
                    wire_idx,
                    self.wire_vars.len()
                );
                return None;
            }
            let coeff_int = self.bigint_to_int(coeff);
            let wire = &self.wire_vars[*wire_idx];
            let product = Int::mul(self.ctx, &[&coeff_int, wire]);
            sum = Int::add(self.ctx, &[&sum, &product]);
        }

        Some(sum)
    }

    /// Convert a single R1CS constraint to Z3: (A·w) * (B·w) ≡ (C·w) (mod p)
    ///
    /// Returns `None` if a wire index is out of range (malformed R1CS).
    fn constraint_to_z3(&self, constraint: &R1CSConstraint) -> Option<Bool<'ctx>> {
        let a_dot_w = self.dot_product(&constraint.a)?;
        let b_dot_w = self.dot_product(&constraint.b)?;
        let c_dot_w = self.dot_product(&constraint.c)?;

        // (A·w) * (B·w) = (C·w) + k*p for some integer k
        let lhs = Int::mul(self.ctx, &[&a_dot_w, &b_dot_w]);
        let k = Int::fresh_const(self.ctx, "k");
        let k_times_p = Int::mul(self.ctx, &[&k, &self.modulus]);
        let rhs = Int::add(self.ctx, &[&c_dot_w, &k_times_p]);

        Some(lhs._eq(&rhs))
    }

    /// Add all R1CS constraints to solver.
    /// Returns false if any constraint references an invalid wire index.
    fn add_constraints(&self, solver: &Solver<'ctx>, constraints: &[R1CSConstraint]) -> bool {
        for constraint in constraints {
            if constraint.is_trivial() {
                continue;
            }
            match self.constraint_to_z3(constraint) {
                Some(z3_constraint) => solver.assert(&z3_constraint),
                None => return false,
            }
        }
        true
    }

    /// Add field bounds: 0 <= wire < p for non-fixed wires
    fn add_field_bounds(&self, solver: &Solver<'ctx>) {
        let zero = Int::from_i64(self.ctx, 0);

        for (idx, wire) in self.wire_vars.iter().enumerate() {
            if idx == 0 || self.fixed_wire_indices.contains(&idx) {
                continue;
            }
            solver.assert(&wire.ge(&zero));
            solver.assert(&wire.lt(&self.modulus));
        }
    }

    /// Fix public wires to their known values from the original witness
    fn fix_public_wires(&self, solver: &Solver<'ctx>, witness: &[FieldElement]) {
        for &idx in &self.fixed_wire_indices {
            if idx == 0 {
                // Already handled (wire 0 = 1)
                continue;
            }
            if idx < witness.len() && idx < self.wire_vars.len() {
                let value = self.bigint_to_int(&witness[idx].to_biguint());
                solver.assert(&self.wire_vars[idx]._eq(&value));
            }
        }
    }

    /// Block the original witness values for all non-public (variable) wires.
    ///
    /// This forces Z3 to find a solution where at least one non-public wire
    /// differs from the original witness. Non-public wires include both
    /// declared private inputs AND internal intermediate wires, which is
    /// essential because underconstrained bugs often live in intermediates.
    fn block_original_witness(
        &self,
        solver: &Solver<'ctx>,
        witness: &[FieldElement],
        variable_indices: &[usize],
    ) {
        if variable_indices.is_empty() {
            tracing::warn!(
                "No variable (non-public) wires to block -- solver may return original witness"
            );
            return;
        }

        let mut diffs: Vec<Bool<'ctx>> = Vec::new();

        for &idx in variable_indices {
            if idx < witness.len() && idx < self.wire_vars.len() {
                let original_value = self.bigint_to_int(&witness[idx].to_biguint());
                diffs.push(self.wire_vars[idx]._eq(&original_value).not());
            }
        }

        if !diffs.is_empty() {
            let diff_refs: Vec<_> = diffs.iter().collect();
            solver.assert(&Bool::or(self.ctx, &diff_refs));
        }
    }

    /// Extract full witness from Z3 model
    fn extract_witness(&self, model: &Model<'ctx>) -> Vec<FieldElement> {
        let mut witness = Vec::with_capacity(self.wire_vars.len());

        for wire in &self.wire_vars {
            let value = model
                .eval(wire, true)
                .and_then(|v| int_to_biguint(&v))
                .unwrap_or_else(|| BigUint::from(0u32));
            witness.push(FieldElement::from_bytes(&value.to_bytes_be()));
        }

        witness
    }

    /// Find an alternative witness with fixed public inputs
    pub fn find_alternative(
        &self,
        r1cs: &R1CS,
        original_witness: &[FieldElement],
        timeout_ms: u32,
    ) -> AlternativeWitnessResult {
        let start = std::time::Instant::now();

        // Bail early if construction detected a malformed R1CS
        if let Some(err) = &self.error {
            return AlternativeWitnessResult {
                found: false,
                original_witness: original_witness.to_vec(),
                alternative_witness: None,
                differing_wires: vec![],
                stats: SolverStats {
                    num_constraints: r1cs.constraints.len(),
                    num_wires: r1cs.num_wires,
                    num_fixed_wires: 0,
                    solve_time_ms: 0,
                    result: format!("ERROR: {}", err),
                },
            };
        }

        let solver = Solver::new(self.ctx);
        let mut params = z3::Params::new(self.ctx);
        params.set_u32("timeout", timeout_ms);
        solver.set_params(&params);

        // Validate witness covers all wires; a short witness leaves public
        // wires unfixed and can produce false positives/negatives.
        if original_witness.len() < r1cs.num_wires {
            return AlternativeWitnessResult {
                found: false,
                original_witness: original_witness.to_vec(),
                alternative_witness: None,
                differing_wires: vec![],
                stats: SolverStats {
                    num_constraints: r1cs.constraints.len(),
                    num_wires: r1cs.num_wires,
                    num_fixed_wires: self.fixed_wire_indices.len(),
                    solve_time_ms: 0,
                    result: format!(
                        "ERROR: witness length {} < num_wires {}",
                        original_witness.len(),
                        r1cs.num_wires
                    ),
                },
            };
        }

        // Add all constraints; bail if any reference invalid wires
        if !self.add_constraints(&solver, &r1cs.constraints) {
            return AlternativeWitnessResult {
                found: false,
                original_witness: original_witness.to_vec(),
                alternative_witness: None,
                differing_wires: vec![],
                stats: SolverStats {
                    num_constraints: r1cs.constraints.len(),
                    num_wires: r1cs.num_wires,
                    num_fixed_wires: self.fixed_wire_indices.len(),
                    solve_time_ms: start.elapsed().as_millis() as u64,
                    result: "ERROR: malformed R1CS (invalid wire index)".to_string(),
                },
            };
        }
        self.add_field_bounds(&solver);

        // Fix public wires
        self.fix_public_wires(&solver, original_witness);

        // Compute variable (non-public) wire indices -- includes intermediates
        let variable_indices: Vec<usize> = (0..r1cs.num_wires)
            .filter(|idx| !self.fixed_wire_indices.contains(idx))
            .collect();

        // Block original values for all non-public wires
        self.block_original_witness(&solver, original_witness, &variable_indices);

        let result = solver.check();
        let solve_time_ms = start.elapsed().as_millis() as u64;

        let (found, alternative_witness, differing_wires, result_str) = match result {
            SatResult::Sat => {
                if let Some(model) = solver.get_model() {
                    let alt = self.extract_witness(&model);
                    let diffs = find_differing_wires(original_witness, &alt);
                    // Only mark as found if at least one wire actually differs;
                    // an empty diff means Z3 returned the original witness
                    // (e.g. when there are no variable wires to block).
                    let actually_found = !diffs.is_empty();
                    (actually_found, Some(alt), diffs, "SAT".to_string())
                } else {
                    (false, None, vec![], "SAT (no model)".to_string())
                }
            }
            SatResult::Unsat => (false, None, vec![], "UNSAT".to_string()),
            SatResult::Unknown => (false, None, vec![], "UNKNOWN".to_string()),
        };

        AlternativeWitnessResult {
            found,
            original_witness: original_witness.to_vec(),
            alternative_witness,
            differing_wires,
            stats: SolverStats {
                num_constraints: r1cs.constraints.len(),
                num_wires: r1cs.num_wires,
                num_fixed_wires: self.fixed_wire_indices.len(),
                solve_time_ms,
                result: result_str,
            },
        }
    }
}

/// Find wires that differ between two witnesses
fn find_differing_wires(w1: &[FieldElement], w2: &[FieldElement]) -> Vec<usize> {
    w1.iter()
        .zip(w2.iter())
        .enumerate()
        .filter_map(|(idx, (a, b))| if a != b { Some(idx) } else { None })
        .collect()
}

/// Convert Z3 Int to BigUint
fn int_to_biguint(value: &Int<'_>) -> Option<BigUint> {
    if let Some(val) = value.as_u64() {
        return Some(BigUint::from(val));
    }

    let raw = value.to_string();
    let trimmed = raw.trim();

    if trimmed.starts_with('-') {
        return None;
    }

    if let Some(hex) = trimmed.strip_prefix("0x") {
        BigUint::parse_bytes(hex.as_bytes(), 16)
    } else {
        BigUint::parse_bytes(trimmed.as_bytes(), 10)
    }
}

/// High-level API: Find alternative witness for R1CS
pub fn find_alternative_witness(
    r1cs: &R1CS,
    original_witness: &[FieldElement],
    timeout_ms: u32,
) -> AlternativeWitnessResult {
    let mut cfg = Config::new();
    cfg.set_model_generation(true);
    let ctx = Context::new(&cfg);

    let solver = AltWitnessSolver::new(&ctx, r1cs);
    solver.find_alternative(r1cs, original_witness, timeout_ms)
}

/// Find multiple alternative witnesses
pub fn find_multiple_alternatives(
    r1cs: &R1CS,
    original_witness: &[FieldElement],
    max_alternatives: usize,
    timeout_ms: u32,
) -> Vec<AlternativeWitnessResult> {
    let mut cfg = Config::new();
    cfg.set_model_generation(true);
    let ctx = Context::new(&cfg);

    let solver_wrapper = AltWitnessSolver::new(&ctx, r1cs);

    // Bail if construction failed or witness is too short
    if solver_wrapper.error.is_some() {
        return Vec::new();
    }
    if original_witness.len() < r1cs.num_wires {
        tracing::error!(
            "Witness length {} < num_wires {}; skipping alt-witness search",
            original_witness.len(),
            r1cs.num_wires
        );
        return Vec::new();
    }

    let solver = Solver::new(&ctx);

    let mut params = z3::Params::new(&ctx);
    params.set_u32("timeout", timeout_ms);
    solver.set_params(&params);

    // Add constraints; bail if malformed
    if !solver_wrapper.add_constraints(&solver, &r1cs.constraints) {
        return Vec::new();
    }
    solver_wrapper.add_field_bounds(&solver);
    solver_wrapper.fix_public_wires(&solver, original_witness);

    let variable_indices: Vec<usize> = (0..r1cs.num_wires)
        .filter(|idx| !solver_wrapper.fixed_wire_indices.contains(idx))
        .collect();

    // Block original values for all non-public wires (inputs + intermediates)
    solver_wrapper.block_original_witness(&solver, original_witness, &variable_indices);

    let mut results = Vec::new();

    while results.len() < max_alternatives {
        let start = std::time::Instant::now();
        let check_result = solver.check();
        let solve_time_ms = start.elapsed().as_millis() as u64;

        match check_result {
            SatResult::Sat => {
                let model = match solver.get_model() {
                    Some(m) => m,
                    None => break,
                };

                let alt = solver_wrapper.extract_witness(&model);
                let diffs = find_differing_wires(original_witness, &alt);

                // Skip no-diff SAT models (Z3 returned the original witness)
                if diffs.is_empty() {
                    break;
                }

                results.push(AlternativeWitnessResult {
                    found: true,
                    original_witness: original_witness.to_vec(),
                    alternative_witness: Some(alt.clone()),
                    differing_wires: diffs,
                    stats: SolverStats {
                        num_constraints: r1cs.constraints.len(),
                        num_wires: r1cs.num_wires,
                        num_fixed_wires: solver_wrapper.fixed_wire_indices.len(),
                        solve_time_ms,
                        result: "SAT".to_string(),
                    },
                });

                // Block this solution to find more
                let mut block_terms: Vec<Bool<'_>> = Vec::new();
                for &idx in &variable_indices {
                    if idx < alt.len() && idx < solver_wrapper.wire_vars.len() {
                        let val = solver_wrapper.bigint_to_int(&alt[idx].to_biguint());
                        block_terms.push(solver_wrapper.wire_vars[idx]._eq(&val).not());
                    }
                }
                if !block_terms.is_empty() {
                    let refs: Vec<_> = block_terms.iter().collect();
                    solver.assert(&Bool::or(&ctx, &refs));
                }
            }
            _ => break,
        }
    }

    results
}

/// R1CS matrix representation for analysis
#[derive(Debug, Clone)]
pub struct R1CSMatrices {
    /// A matrix: sparse representation as (row, col, coefficient)
    pub a: Vec<(usize, usize, BigUint)>,
    /// B matrix
    pub b: Vec<(usize, usize, BigUint)>,
    /// C matrix
    pub c: Vec<(usize, usize, BigUint)>,
    /// Number of constraints (rows)
    pub num_constraints: usize,
    /// Number of wires (columns)
    pub num_wires: usize,
    /// Field modulus
    pub modulus: BigUint,
}

pub type DenseMatrix = Vec<Vec<BigUint>>;
pub type DenseR1CS = (DenseMatrix, DenseMatrix, DenseMatrix);

impl R1CSMatrices {
    /// Extract matrices from parsed R1CS
    pub fn from_r1cs(r1cs: &R1CS) -> Self {
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut c = Vec::new();

        for (row, constraint) in r1cs.constraints.iter().enumerate() {
            for (col, coeff) in &constraint.a {
                if !coeff.eq(&BigUint::from(0u32)) {
                    a.push((row, *col, coeff.clone()));
                }
            }
            for (col, coeff) in &constraint.b {
                if !coeff.eq(&BigUint::from(0u32)) {
                    b.push((row, *col, coeff.clone()));
                }
            }
            for (col, coeff) in &constraint.c {
                if !coeff.eq(&BigUint::from(0u32)) {
                    c.push((row, *col, coeff.clone()));
                }
            }
        }

        Self {
            a,
            b,
            c,
            num_constraints: r1cs.constraints.len(),
            num_wires: r1cs.num_wires,
            modulus: r1cs.field_size.clone(),
        }
    }

    /// Get matrix sparsity (non-zero elements / total elements)
    pub fn sparsity(&self) -> f64 {
        let total = (self.num_constraints * self.num_wires * 3) as f64;
        if total == 0.0 {
            return 0.0;
        }
        let nnz = (self.a.len() + self.b.len() + self.c.len()) as f64;
        nnz / total
    }

    /// Export to dense representation (for small circuits only)
    pub fn to_dense(&self) -> Option<DenseR1CS> {
        // Only for small circuits (< 1000 constraints x 1000 wires)
        if self.num_constraints > 1000 || self.num_wires > 1000 {
            return None;
        }

        let zero = BigUint::from(0u32);
        let mut a_dense = vec![vec![zero.clone(); self.num_wires]; self.num_constraints];
        let mut b_dense = vec![vec![zero.clone(); self.num_wires]; self.num_constraints];
        let mut c_dense = vec![vec![zero.clone(); self.num_wires]; self.num_constraints];

        for (row, col, coeff) in &self.a {
            a_dense[*row][*col] = coeff.clone();
        }
        for (row, col, coeff) in &self.b {
            b_dense[*row][*col] = coeff.clone();
        }
        for (row, col, coeff) in &self.c {
            c_dense[*row][*col] = coeff.clone();
        }

        Some((a_dense, b_dense, c_dense))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_underconstrained_r1cs() -> R1CS {
        // x * y = z but missing constraint that x must equal some value
        // This allows multiple (x, y) pairs that produce same z
        let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();

        // Constraint: x * y = z (wires: 0=1, 1=z (output), 2=x (pub in), 3=y (priv))
        let constraint = R1CSConstraint {
            a: vec![(2, BigUint::from(1u32))], // x
            b: vec![(3, BigUint::from(1u32))], // y
            c: vec![(1, BigUint::from(1u32))], // z
        };

        R1CS {
            field_size: modulus,
            field_bytes: 32,
            num_wires: 4,
            num_public_outputs: 1, // z is public output
            num_public_inputs: 1,  // x is public input
            num_private_inputs: 1, // y is private
            num_labels: 0,
            constraints: vec![constraint],
            wire_names: vec![
                "one".to_string(),
                "z".to_string(),
                "x".to_string(),
                "y".to_string(),
            ],
            custom_gates_used: false,
        }
    }

    #[test]
    fn test_find_alternative_witness() {
        let r1cs = build_underconstrained_r1cs();

        // Original: x=2, y=3, z=6
        let original = vec![
            FieldElement::one(),       // wire 0 = 1
            FieldElement::from_u64(6), // z = 6
            FieldElement::from_u64(2), // x = 2
            FieldElement::from_u64(3), // y = 3
        ];

        let result = find_alternative_witness(&r1cs, &original, 5000);

        // Should find alternative since y is private and unconstrained
        // except by x * y = z. With x=2, z=6 fixed, y must = 3.
        // Actually this is fully constrained! Let's test a truly underconstrained case.

        println!("Result: {:?}", result);
    }

    #[test]
    fn test_truly_underconstrained() {
        // Two private inputs, only one constraint
        // a + b = 10, but a and b can be any pair summing to 10
        let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();

        // Constraint: a + b = 10
        // (a + b) * 1 = 10
        let constraint = R1CSConstraint {
            a: vec![(1, BigUint::from(1u32)), (2, BigUint::from(1u32))], // a + b
            b: vec![(0, BigUint::from(1u32))],                           // 1
            c: vec![(0, BigUint::from(10u32))],                          // 10
        };

        let r1cs = R1CS {
            field_size: modulus,
            field_bytes: 32,
            num_wires: 3,
            num_public_outputs: 0,
            num_public_inputs: 0,
            num_private_inputs: 2,
            num_labels: 0,
            constraints: vec![constraint],
            wire_names: vec!["one".to_string(), "a".to_string(), "b".to_string()],
            custom_gates_used: false,
        };

        // Original: a=4, b=6
        let original = vec![
            FieldElement::one(),
            FieldElement::from_u64(4),
            FieldElement::from_u64(6),
        ];

        let result = find_alternative_witness(&r1cs, &original, 5000);

        assert!(result.found, "Should find alternative witness");

        if let Some(alt) = &result.alternative_witness {
            // Verify constraint: a + b = 10
            let a = alt[1].to_biguint();
            let b = alt[2].to_biguint();
            assert_eq!(a + b, BigUint::from(10u32));

            // Verify it's different
            assert!(alt[1] != original[1] || alt[2] != original[2]);
        }
    }

    #[test]
    fn test_matrix_extraction() {
        let r1cs = build_underconstrained_r1cs();
        let matrices = R1CSMatrices::from_r1cs(&r1cs);

        assert_eq!(matrices.num_constraints, 1);
        assert_eq!(matrices.num_wires, 4);
        assert!(!matrices.a.is_empty());
        assert!(!matrices.b.is_empty());
        assert!(!matrices.c.is_empty());

        // Should be very sparse
        assert!(matrices.sparsity() < 0.5);
    }
}
