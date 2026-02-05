//! Constraint-guided symbolic seed generation.
//!
//! Builds symbolic constraints from extracted circuit constraints (R1CS/ACIR/PLONK)
//! and uses the enhanced symbolic solver to generate seed inputs. This provides
//! real constraint extraction and pruning-based seed generation for the fuzzer.

use crate::analysis::{
    constraint_types::LinearCombination, ConstraintSimplifier, EnhancedSymbolicConfig,
    ExtendedConstraint, LookupTable, PathCondition, PruningStrategy, R1CSConstraint,
    ExtendedConstraintSymbolicExt, SymbolicConstraint, SymbolicConversionOptions, WireRef,
    Z3Solver,
};
use zk_core::{ConstraintEquation, ConstraintInspector};
use zk_core::FieldElement;
use std::collections::{HashMap, HashSet};

/// Stats for constraint-guided seed generation.
#[derive(Debug, Clone, Default)]
pub struct ConstraintSeedStats {
    pub total_constraints: usize,
    pub symbolic_constraints: usize,
    pub skipped_constraints: usize,
    pub pruned_constraints: usize,
    pub solutions: usize,
}

/// Result of constraint-guided seed generation.
#[derive(Debug, Clone, Default)]
pub struct ConstraintSeedOutput {
    pub seeds: Vec<Vec<FieldElement>>,
    pub stats: ConstraintSeedStats,
}

/// Generator that converts constraints into symbolic form and solves for inputs.
pub struct ConstraintSeedGenerator {
    config: EnhancedSymbolicConfig,
    simplifier: ConstraintSimplifier,
}

impl ConstraintSeedGenerator {
    pub fn new(config: EnhancedSymbolicConfig) -> Self {
        Self {
            config,
            simplifier: ConstraintSimplifier::new(),
        }
    }

    /// Generate seeds from R1CS constraint equations.
    pub fn generate_from_r1cs(
        &mut self,
        equations: &[ConstraintEquation],
        input_wire_indices: &[usize],
        expected_len: usize,
    ) -> ConstraintSeedOutput {
        let total_constraints = equations.len();
        if total_constraints == 0 {
            return ConstraintSeedOutput::default();
        }

        let extended: Vec<ExtendedConstraint> =
            equations.iter().map(r1cs_equation_to_extended).collect();

        let (symbolic_constraints, skipped_constraints) =
            extended_to_symbolic(&extended, &HashMap::new());

        let stats = ConstraintSeedStats {
            total_constraints,
            symbolic_constraints: symbolic_constraints.len(),
            skipped_constraints,
            ..ConstraintSeedStats::default()
        };

        self.generate_from_symbolic(
            symbolic_constraints,
            input_wire_indices,
            expected_len,
            stats,
        )
    }

    /// Generate seeds from extended constraints with lookup tables.
    pub fn generate_from_extended(
        &mut self,
        constraints: &[ExtendedConstraint],
        lookup_tables: &HashMap<usize, LookupTable>,
        input_wire_indices: &[usize],
        expected_len: usize,
    ) -> ConstraintSeedOutput {
        let total_constraints = constraints.len();
        if total_constraints == 0 {
            return ConstraintSeedOutput::default();
        }

        let (symbolic_constraints, skipped_constraints) =
            extended_to_symbolic(constraints, lookup_tables);

        let stats = ConstraintSeedStats {
            total_constraints,
            symbolic_constraints: symbolic_constraints.len(),
            skipped_constraints,
            ..ConstraintSeedStats::default()
        };

        self.generate_from_symbolic(
            symbolic_constraints,
            input_wire_indices,
            expected_len,
            stats,
        )
    }

    fn generate_from_symbolic(
        &mut self,
        constraints: Vec<SymbolicConstraint>,
        input_wire_indices: &[usize],
        expected_len: usize,
        mut stats: ConstraintSeedStats,
    ) -> ConstraintSeedOutput {
        if constraints.is_empty() {
            return ConstraintSeedOutput {
                seeds: Vec::new(),
                stats,
            };
        }

        let mut path = PathCondition::new();
        for constraint in constraints {
            path.add_constraint(constraint);
        }

        if self.config.simplify_constraints {
            path = self.simplifier.simplify_path(&path);
        }

        let original_len = path.constraints.len();
        let pruned = prune_constraints(
            &path.constraints,
            self.config.pruning_strategy,
            self.config.max_depth,
        );

        stats.pruned_constraints = original_len.saturating_sub(pruned.len());

        let mut pruned_path = PathCondition::new();
        for constraint in pruned {
            pruned_path.add_constraint(constraint);
        }

        let solver = Z3Solver::new().with_timeout(self.config.solver_timeout_ms);
        let solutions = if self.config.solutions_per_path <= 1 {
            match solver.solve(&pruned_path) {
                crate::analysis::SolverResult::Sat(assignments) => vec![assignments],
                _ => Vec::new(),
            }
        } else {
            solver.solve_all(&pruned_path, self.config.solutions_per_path)
        };

        let mut seeds = Vec::new();
        let mut seen = HashSet::new();

        for assignments in solutions {
            let inputs = assignments_to_inputs(&assignments, input_wire_indices, expected_len);
            let mut key = Vec::with_capacity(inputs.len() * 32);
            for fe in &inputs {
                key.extend_from_slice(&fe.0);
            }
            if seen.insert(key) {
                seeds.push(inputs);
            }
        }

        stats.solutions = seeds.len();

        ConstraintSeedOutput { seeds, stats }
    }
}

/// Collect input wire indices in fuzzer input order (public first, then private).
pub fn collect_input_wire_indices(
    inspector: &dyn ConstraintInspector,
    expected_len: usize,
) -> Vec<usize> {
    let mut indices = inspector.public_input_indices();
    indices.extend(inspector.private_input_indices());

    if indices.is_empty() {
        indices = (0..expected_len).collect();
    } else if indices.len() > expected_len {
        indices.truncate(expected_len);
    }

    indices
}

fn r1cs_equation_to_extended(eq: &ConstraintEquation) -> ExtendedConstraint {
    ExtendedConstraint::R1CS(R1CSConstraint {
        a: linear_combination_from_terms(&eq.a_terms),
        b: linear_combination_from_terms(&eq.b_terms),
        c: linear_combination_from_terms(&eq.c_terms),
    })
}

fn linear_combination_from_terms(terms: &[(usize, FieldElement)]) -> LinearCombination {
    let mut lc = LinearCombination::new();
    for (idx, coeff) in terms {
        lc.add_term(WireRef::new(*idx), coeff.clone());
    }
    lc
}

fn extended_to_symbolic(
    constraints: &[ExtendedConstraint],
    lookup_tables: &HashMap<usize, LookupTable>,
) -> (Vec<SymbolicConstraint>, usize) {
    let options = SymbolicConversionOptions::default();
    let mut symbolic = Vec::new();
    let mut skipped = 0usize;

    for constraint in constraints {
        match constraint.to_symbolic_with_tables(lookup_tables, &options) {
            Some(sym) => symbolic.push(sym),
            None => skipped += 1,
        }
    }

    (symbolic, skipped)
}

fn prune_constraints(
    constraints: &[SymbolicConstraint],
    strategy: PruningStrategy,
    max_depth: usize,
) -> Vec<SymbolicConstraint> {
    if strategy == PruningStrategy::None || constraints.len() <= max_depth {
        return constraints.to_vec();
    }

    let limit = max_depth.max(1);
    match strategy {
        PruningStrategy::RandomSampling => {
            let step = (constraints.len() / limit).max(1);
            constraints
                .iter()
                .step_by(step)
                .take(limit)
                .cloned()
                .collect()
        }
        _ => constraints.iter().take(limit).cloned().collect(),
    }
}

fn assignments_to_inputs(
    assignments: &HashMap<String, FieldElement>,
    input_wire_indices: &[usize],
    expected_len: usize,
) -> Vec<FieldElement> {
    let mut inputs = Vec::with_capacity(expected_len);

    for i in 0..expected_len {
        let value = if let Some(wire_idx) = input_wire_indices.get(i) {
            let input_key = format!("input_{}", i);
            let wire_key = format!("wire_{}", wire_idx);
            assignments
                .get(&input_key)
                .cloned()
                .or_else(|| assignments.get(&wire_key).cloned())
        } else {
            let input_key = format!("input_{}", i);
            assignments.get(&input_key).cloned()
        };

        inputs.push(value.unwrap_or_else(FieldElement::zero));
    }

    inputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assignments_to_inputs_wire_mapping() {
        let mut assignments = HashMap::new();
        assignments.insert("wire_5".to_string(), FieldElement::from_u64(42));

        let inputs = assignments_to_inputs(&assignments, &[5], 1);
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0], FieldElement::from_u64(42));
    }
}
