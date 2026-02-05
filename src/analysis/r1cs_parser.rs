//! Wrapper around zk-constraints R1CS parser with symbolic helpers.

pub use zk_constraints::r1cs_parser::*;

use super::{ConstraintSeedGenerator, EnhancedSymbolicConfig, PruningStrategy};
use zk_core::FieldElement;

/// Extension trait for generating SMT inputs via the symbolic engine.
pub trait R1CSConstraintGuidedExt {
    fn generate_smt_inputs(&self, num_solutions: usize, timeout_ms: u32) -> Vec<Vec<FieldElement>>;
}

impl R1CSConstraintGuidedExt for R1CS {
    fn generate_smt_inputs(&self, num_solutions: usize, timeout_ms: u32) -> Vec<Vec<FieldElement>> {
        let config = EnhancedSymbolicConfig {
            solver_timeout_ms: timeout_ms,
            simplify_constraints: true,
            pruning_strategy: PruningStrategy::CoverageGuided,
            solutions_per_path: num_solutions,
            max_depth: self.constraints.len().min(1000),
            ..Default::default()
        };

        let mut generator = ConstraintSeedGenerator::new(config);

        let extended = self.to_extended_constraints();
        let mut input_indices = self.public_input_indices();
        input_indices.extend(self.private_input_indices());
        let expected_len = self.num_public_inputs + self.num_private_inputs;

        let output = generator.generate_from_extended(
            &extended,
            &std::collections::HashMap::new(),
            &input_indices,
            expected_len,
        );

        tracing::info!(
            "SMT generated {} inputs from {} constraints (skipped: {}, pruned: {})",
            output.seeds.len(),
            output.stats.total_constraints,
            output.stats.skipped_constraints,
            output.stats.pruned_constraints
        );

        output.seeds
    }
}
