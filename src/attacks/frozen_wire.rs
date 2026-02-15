//! Frozen Wire Detector (P1)
//!
//! Finds output wires that never change value across diverse inputs.

use std::collections::{HashMap, HashSet};
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, Severity};

pub struct FrozenWireDetector {
    /// Minimum executions before flagging
    min_samples: usize,
    /// Exclude wires known to be constants (e.g., wire 0 = 1 in R1CS)
    known_constants: HashSet<usize>,
}

impl Default for FrozenWireDetector {
    fn default() -> Self {
        Self {
            min_samples: 100,
            known_constants: HashSet::from([0]),
        }
    }
}

impl FrozenWireDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_min_samples(mut self, n: usize) -> Self {
        self.min_samples = n;
        self
    }

    pub fn with_known_constants(mut self, constants: HashSet<usize>) -> Self {
        if !constants.is_empty() {
            self.known_constants = constants;
        }
        self
    }

    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if self.min_samples == 0 {
            return Vec::new();
        }

        let mut value_sets: HashMap<usize, HashSet<[u8; 32]>> = HashMap::new();

        let mut success_count = 0usize;
        for witness in witnesses.iter().take(self.min_samples) {
            let result = executor.execute_sync(witness);
            if !result.success {
                continue;
            }
            success_count += 1;
            for (idx, output) in result.outputs.iter().enumerate() {
                value_sets.entry(idx).or_default().insert(output.0);
            }
        }

        if success_count < self.min_samples {
            return Vec::new();
        }

        let constraint_wires = executor.constraint_inspector().map(|inspector| {
            let constraints = inspector.get_constraints();
            let mut used_wires: HashSet<usize> = HashSet::new();
            for c in &constraints {
                for (wire, _) in &c.a_terms {
                    used_wires.insert(*wire);
                }
                for (wire, _) in &c.b_terms {
                    used_wires.insert(*wire);
                }
                for (wire, _) in &c.c_terms {
                    used_wires.insert(*wire);
                }
            }
            used_wires
        });

        let output_wire_indices = executor
            .constraint_inspector()
            .map(|inspector| inspector.output_indices());
        let apply_known_constants = match output_wire_indices.as_ref().map(|indices| !indices.is_empty()) {
            Some(value) => value,
            None => false,
        };

        let mut findings = Vec::new();
        for (idx, values) in &value_sets {
            let wire_idx = output_wire_indices
                .as_ref()
                .and_then(|indices| indices.get(*idx))
                .copied();
            let wire_idx = match wire_idx {
                Some(value) => value,
                None => *idx,
            };

            if apply_known_constants && self.known_constants.contains(&wire_idx) {
                continue;
            }

            if values.len() == 1 {
                let frozen_value = values.iter().next().unwrap();
                let is_zero = frozen_value.iter().all(|b| *b == 0);
                let is_one = {
                    let mut one = [0u8; 32];
                    one[31] = 1;
                    frozen_value == &one
                };

                let severity = if is_zero {
                    Severity::Medium
                } else if is_one {
                    Severity::Low
                } else {
                    Severity::Medium
                };

                let constrained = constraint_wires
                    .as_ref()
                    .map(|wires| wires.contains(&wire_idx));
                let constrained = match constrained {
                    Some(value) => value,
                    None => true,
                };

                findings.push(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity,
                    description: format!(
                        "Output wire {} (wire idx {}) is frozen: same value across {} executions. Value={} (zero={}, one={}). Constrained={}",
                        idx,
                        wire_idx,
                        self.min_samples,
                        hex::encode(frozen_value),
                        is_zero,
                        is_one,
                        constrained
                    ),
                    poc: Default::default(),
                    location: None,
                });
            }
        }

        findings
    }
}
