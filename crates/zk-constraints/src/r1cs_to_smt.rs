//! R1CS to SMT translation using Z3.
//!
//! This module provides a direct R1CS -> Z3 encoding that can be used to
//! generate concrete inputs satisfying a circuit's constraints.

use num_bigint::BigUint;
use z3::ast::{Ast, Bool, Int};
use z3::{Config, Context, SatResult, Solver};

use super::r1cs_parser::{R1CSConstraint, R1CS};
use zk_core::constants::BN254_SCALAR_MODULUS_DECIMAL;
use zk_core::FieldElement;

#[cfg(test)]
const BN254_MODULUS: &str = BN254_SCALAR_MODULUS_DECIMAL;

/// R1CS to SMT translator using integer arithmetic with modular reduction.
pub struct R1CSToSMT<'ctx> {
    ctx: &'ctx Context,
    modulus: Int<'ctx>,
    wire_vars: Vec<Int<'ctx>>,
}

impl<'ctx> R1CSToSMT<'ctx> {
    /// Create a new translator for a given R1CS instance.
    pub fn new(ctx: &'ctx Context, r1cs: &R1CS) -> Self {
        let modulus_str = if r1cs.field_size == BigUint::from(0u32) {
            BN254_SCALAR_MODULUS_DECIMAL.to_string()
        } else {
            r1cs.field_size.to_str_radix(10)
        };

        let modulus = match Int::from_str(ctx, &modulus_str) {
            Some(value) => value,
            None => panic!("Failed to parse field modulus into Z3 Int: {}", modulus_str),
        };

        let wire_vars: Vec<_> = (0..r1cs.num_wires)
            .map(|i| {
                if i == 0 {
                    Int::from_i64(ctx, 1)
                } else {
                    Int::new_const(ctx, format!("wire_{}", i))
                }
            })
            .collect();

        Self {
            ctx,
            modulus,
            wire_vars,
        }
    }

    /// Convert a BigUint to Z3 Int.
    fn bigint_to_int(&self, n: &BigUint) -> Int<'ctx> {
        let decimal = n.to_str_radix(10);
        match Int::from_str(self.ctx, &decimal) {
            Some(value) => value,
            None => panic!("Failed to parse BigUint into Z3 Int: {}", decimal),
        }
    }

    /// Compute sparse dot product: Σ (coeff_i * wire_i)
    fn dot_product(&self, sparse_vec: &[(usize, BigUint)]) -> Int<'ctx> {
        if sparse_vec.is_empty() {
            return Int::from_i64(self.ctx, 0);
        }

        let mut sum = Int::from_i64(self.ctx, 0);
        for (wire_idx, coeff) in sparse_vec {
            let coeff_int = self.bigint_to_int(coeff);
            let wire = &self.wire_vars[*wire_idx];
            let product = Int::mul(self.ctx, &[&coeff_int, wire]);
            sum = Int::add(self.ctx, &[&sum, &product]);
        }

        sum
    }

    /// Convert a single R1CS constraint to a Z3 boolean assertion.
    pub fn constraint_to_z3(&self, constraint: &R1CSConstraint) -> Bool<'ctx> {
        let a_dot_w = self.dot_product(&constraint.a);
        let b_dot_w = self.dot_product(&constraint.b);
        let c_dot_w = self.dot_product(&constraint.c);

        // Enforce (A·w) * (B·w) == (C·w) (mod p)
        // by introducing k such that lhs - rhs = k * p
        let lhs = Int::mul(self.ctx, &[&a_dot_w, &b_dot_w]);
        let k = Int::fresh_const(self.ctx, "k");
        let rhs = Int::add(
            self.ctx,
            &[&c_dot_w, &Int::mul(self.ctx, &[&k, &self.modulus])],
        );

        lhs._eq(&rhs)
    }

    /// Add all R1CS constraints and field bounds to the solver.
    pub fn add_constraints(&self, solver: &Solver<'ctx>, r1cs: &R1CS) {
        for constraint in &r1cs.constraints {
            solver.assert(&self.constraint_to_z3(constraint));
        }

        let zero = Int::from_i64(self.ctx, 0);
        for wire in self.wire_vars.iter().skip(1) {
            solver.assert(&wire.ge(&zero));
            solver.assert(&wire.lt(&self.modulus));
        }
    }

    /// Extract input assignments from a model.
    fn model_to_inputs(
        &self,
        model: &z3::Model,
        input_wire_indices: &[usize],
    ) -> Option<Vec<FieldElement>> {
        let mut inputs = Vec::with_capacity(input_wire_indices.len());

        for wire_idx in input_wire_indices {
            let wire = &self.wire_vars[*wire_idx];
            let value = model.eval(wire, true)?;
            let big = int_to_biguint(&value)?;
            inputs.push(FieldElement::from_bytes(&big.to_bytes_be()));
        }

        Some(inputs)
    }

    /// Build a blocking clause for the given model over the input wires.
    fn block_inputs(
        &self,
        model: &z3::Model<'ctx>,
        input_wire_indices: &[usize],
    ) -> Option<Bool<'ctx>> {
        let mut diffs = Vec::new();

        for wire_idx in input_wire_indices {
            let wire = &self.wire_vars[*wire_idx];
            let value = model.eval(wire, true)?;
            diffs.push(wire._eq(&value).not());
        }

        if diffs.is_empty() {
            return None;
        }

        let diff_refs: Vec<_> = diffs.iter().collect();
        Some(Bool::or(self.ctx, &diff_refs))
    }
}

/// High-level API: generate constraint-guided inputs for an R1CS instance.
pub fn generate_constraint_guided_inputs(
    r1cs: &R1CS,
    num_solutions: usize,
    timeout_ms: u32,
) -> Vec<Vec<FieldElement>> {
    let mut cfg = Config::new();
    cfg.set_model_generation(true);
    let ctx = Context::new(&cfg);

    let translator = R1CSToSMT::new(&ctx, r1cs);
    let solver = Solver::new(&ctx);

    let mut params = z3::Params::new(&ctx);
    params.set_u32("timeout", timeout_ms);
    solver.set_params(&params);

    translator.add_constraints(&solver, r1cs);

    let mut input_indices = r1cs.public_input_indices();
    input_indices.extend(r1cs.private_input_indices());

    let mut solutions = Vec::new();
    while solutions.len() < num_solutions {
        let result = solver.check();
        match result {
            SatResult::Sat | SatResult::Unknown => {
                let model = match solver.get_model() {
                    Some(model) => model,
                    None => break,
                };

                if let Some(inputs) = translator.model_to_inputs(&model, &input_indices) {
                    solutions.push(inputs);
                }

                if let Some(block) = translator.block_inputs(&model, &input_indices) {
                    solver.assert(&block);
                } else {
                    break;
                }
            }
            SatResult::Unsat => break,
        }
    }

    solutions
}

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

#[cfg(test)]
#[path = "r1cs_to_smt_tests.rs"]
mod tests;
