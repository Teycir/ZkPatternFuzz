//! Wrapper around zk-constraints R1CS -> SMT translation with fallback.

pub use zk_constraints::r1cs_to_smt::R1CSToSMT;

use zk_constraints::r1cs_parser::R1CS;
use zk_constraints::r1cs_to_smt as core;
use zk_core::FieldElement;

/// Generate constraint-guided inputs with a symbolic fallback when needed.
pub fn generate_constraint_guided_inputs(
    r1cs: &R1CS,
    num_solutions: usize,
    timeout_ms: u32,
) -> Vec<Vec<FieldElement>> {
    let solutions = core::generate_constraint_guided_inputs(r1cs, num_solutions, timeout_ms);
    if solutions.is_empty() {
        return crate::analysis::r1cs_parser::R1CSConstraintGuidedExt::generate_smt_inputs(
            r1cs,
            num_solutions,
            timeout_ms,
        );
    }

    solutions
}
